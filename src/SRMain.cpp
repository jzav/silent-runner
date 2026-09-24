// SilentRunner - entrypoint
// -------------------------
// Windows subsystem (no console window), with wide entrypoint.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>

#include <string>
#include <vector>
#include <exception>
#include <new>
#include <cstdlib>
#include <memory>
#include <cstdint>

#include "SRTypes.h"
#include "SRConfigsBuilder.h"
#include "SRRuntime.h"
#include "HelpGenerator.h"
#include "FileHelpers.h"
#include "ErrorHelpers.h"
#include "ParentStdEmitter.h"
#include "SRPrepareRuntime.h"
#include "SRLifecycleDiagnostics.h"
#include "SRLifecycleFinalizeExecution.h"
#include "SRParentEmitPolicy.h"
#include "SRWorkerCommonPolicy.h"
#include "SRWorkerTypes.h"
#include "SRBufferLimiter.h"


// Linker hint (MSVC-style). With MinGW, you typically pass subsystem via linker flags,
// but keeping this is harmless if your toolchain ignores it.
#pragma comment(linker, "/SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup")


namespace {

struct LocalFreeArgsDeleter {
    void operator()(wchar_t** args) const noexcept {
        if (args) {
            LocalFree(args);
        }
    }
};

using LocalFreeArgsPtr =
    std::unique_ptr<wchar_t*, LocalFreeArgsDeleter>;

[[noreturn]] void SilentRunnerTerminateHandler() noexcept;

} // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    std::set_terminate(&SilentRunnerTerminateHandler);

    int argsCount = 0;
    LocalFreeArgsPtr argsVector(
        CommandLineToArgvW(
            GetCommandLineW(),
            &argsCount
        )
    );

    if (!argsVector) {
        const DWORD gle = GetLastError();
        SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
            FileHelpers::MakeRunUtcTimestamp(),
            SR::DiagnosticSeverity::Fatal,
            SR::LifecyclePhase::Prepare,
            L"CommandLineToArgvW failed; " + ErrorHelpers::FormatGle(gle)
        );
        return 2;
    }

    SR::SRConfigsBuilder configsBuilder;
    if (!configsBuilder.Build(argsCount, argsVector.get())) {
        SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
            FileHelpers::MakeRunUtcTimestamp(),
            SR::DiagnosticSeverity::Fatal,
            SR::LifecyclePhase::Prepare,
            configsBuilder.err
        );
        return 2;
    }
    auto& configs = configsBuilder.configs;

    if (configsBuilder.helpRequested) {
        ParentStdEmitter::EmitStdoutUtf16(
            HelpGenerator::Generate() + L"\n"
        );
        return 0;
    }
    
    auto executionTimeline = std::make_shared<ExecutionTimeline>();
    
    if (!executionTimeline->Init(configsBuilder.configs.executionTimeline)) {

        SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
            FileHelpers::MakeRunUtcTimestamp(),
            SR::DiagnosticSeverity::Fatal,
            SR::LifecyclePhase::Prepare,
            L"Failed to initialize execution timeline"
        );
        return 255;
    }
    
    if (!executionTimeline->StartPhase(executionTimeline->PrepareContext())) {
        SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
            FileHelpers::MakeRunUtcTimestamp(),
            SR::DiagnosticSeverity::Fatal,
            SR::LifecyclePhase::Prepare,
            L"Failed to start prepare phase"
        );
        return 255;
    }

    SRParentEmitPolicy parentEmitPolicy;
    if (!parentEmitPolicy.Init(configsBuilder.configs.parentEmitPolicy)) {
        SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
            FileHelpers::MakeRunUtcTimestamp(),
            SR::DiagnosticSeverity::Fatal,
            SR::LifecyclePhase::Prepare,
            L"Failed to initialize parent emit policy"
        );
        return 255;
    }
    SRBufferLimiter bufferLimiter;
    SRBufferLimiter* bufferLimitPtr = nullptr;

    

    SRLifecycleDiagnostics lifecycleDiag;
    if (!lifecycleDiag.Init(
        configsBuilder.configs.lifecycleDiagnostics,
        parentEmitPolicy,
        executionTimeline.get()
    )) {
        SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
            FileHelpers::MakeRunUtcTimestamp(),
            SR::DiagnosticSeverity::Fatal,
            SR::LifecyclePhase::Prepare,
            L"Failed to initialize lifecycle diagnostics"
        );
        return 255;
    }
    executionTimeline->SetLifecycleDiagnostics(lifecycleDiag);
    SRWorkerCommonPolicy workerCommonPolicy;
    if (!workerCommonPolicy.Init(configsBuilder.configs.workerCommonPolicy)) {
        SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
            FileHelpers::MakeRunUtcTimestamp(),
            SR::DiagnosticSeverity::Fatal,
            SR::LifecyclePhase::Prepare,
            L"Failed to initialize worker common policy"
        );

        return 255;
    }


    SRPrepareResult prepareResult;
    SRWorkers workers;
           
    workers.supervisor = std::make_unique<SR::SRWorkerSupervisor>();
    workers.fileSink = std::make_unique<SRFileSinkWorker>();
    workers.parentEmit = std::make_unique<SRParentEmitWorker>();
    workers.jobsExchange = std::make_unique<SRJobsExchange>();

    workers.fileSink->SetWorkerSupervisor(
        workers.supervisor.get()
    );
    workers.parentEmit->SetWorkerSupervisor(
        workers.supervisor.get()
    );

    if (!workers.fileSink->Init(
            &lifecycleDiag,
            SR::kFileSinkWorkerTargetLayout,
            configsBuilder.configs.fileSinkWorker,
            workerCommonPolicy
        )) {


        SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
            FileHelpers::MakeRunUtcTimestamp(),
            SR::DiagnosticSeverity::Fatal,
            SR::LifecyclePhase::Prepare,
            L"Failed to initialize file sink worker"
        );
        return 255;
    }

    if (!workers.parentEmit->Init(
            &lifecycleDiag,
            &parentEmitPolicy,
            SR::kParentEmitWorkerTargetLayout,
            workerCommonPolicy
        )) {
        SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
            FileHelpers::MakeRunUtcTimestamp(),
            SR::DiagnosticSeverity::Fatal,
            SR::LifecyclePhase::Prepare,
            L"Failed to initialize parent emit worker"
        );
        return 255;
    }

    if (!workers.jobsExchange->Init(&lifecycleDiag)) {
        SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
            FileHelpers::MakeRunUtcTimestamp(),
            SR::DiagnosticSeverity::Fatal,
            SR::LifecyclePhase::Prepare,
            L"Failed to initialize jobs exchange"
        );
        return 255;
    }

    workers.jobsExchange->SetWorkerSupervisor(*workers.supervisor);
    workers.jobsExchange->SetFileSinkWorker(*workers.fileSink);
    workers.jobsExchange->SetParentEmitWorker(*workers.parentEmit);

    if (!workers.fileSink->StartPaused()) {
        SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
            FileHelpers::MakeRunUtcTimestamp(),
            SR::DiagnosticSeverity::Fatal,
            SR::LifecyclePhase::Prepare,
            L"Failed to start file sink worker"
        );
        return 255;
    }

    if (!workers.parentEmit->Start()) {
        SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
            FileHelpers::MakeRunUtcTimestamp(),
            SR::DiagnosticSeverity::Fatal,
            SR::LifecyclePhase::Prepare,
            L"Failed to start parent emit worker"
        );
        return 255;
    }
    
    executionTimeline->SetJobsExchange(*workers.jobsExchange);



    
    const bool needStdoutReplayBuffer =
        parentEmitPolicy.NeedsStdoutReplayBuffer();
    const bool needStderrReplayBuffer =
        parentEmitPolicy.NeedsStderrReplayBuffer();

    if (needStdoutReplayBuffer || needStderrReplayBuffer) {
        bufferLimiter.Init(configsBuilder.configs.bufferLimiter, &lifecycleDiag);
        bufferLimitPtr = &bufferLimiter;
    }

    lifecycleDiag.SetBufferLimiter(bufferLimitPtr);


    executionTimeline->SetParentEmitPolicy(parentEmitPolicy);
    
    lifecycleDiag.InfoLine(
        L"SilentRunner starts; std::terminate handler registered"
    );

    lifecycleDiag.DebugLine(
        L"PrepareRuntime phase starts"
    );

    try {
        PrepareRuntime(
            configs,
            *workers.fileSink,
            parentEmitPolicy,
            lifecycleDiag,
            prepareResult
        );
    } catch (const std::bad_alloc&) {
        lifecycleDiag.FatalErrorLine(
            L"PrepareRuntime phase failed: std::bad_alloc"
        );
        const int finalExitCode = FinalizeExecution(configsBuilder.configs.finalizeExecution, workers, prepareResult.logFiles, parentEmitPolicy, workerCommonPolicy.ParsingToken(), 255, lifecycleDiag, nullptr, executionTimeline.get());


        return finalExitCode;
    } catch (const std::exception& ex) {
        const std::wstring detail = FileHelpers::Utf8ToWide(ex.what());
        if (!detail.empty()) {
            lifecycleDiag.FatalErrorLine(
                L"PrepareRuntime phase failed: unhandled std::exception; " + detail
            );
        } else {
            lifecycleDiag.FatalErrorLine(
                L"PrepareRuntime phase failed: unhandled std::exception"
            );
        }
        const int finalExitCode = FinalizeExecution(configsBuilder.configs.finalizeExecution, workers, prepareResult.logFiles, parentEmitPolicy, workerCommonPolicy.ParsingToken(), 255, lifecycleDiag, nullptr, executionTimeline.get());


        return finalExitCode;
    } catch (...) {
        lifecycleDiag.FatalErrorLine(
            L"PrepareRuntime phase failed: unhandled unknown exception"
        );
        const int finalExitCode = FinalizeExecution(configsBuilder.configs.finalizeExecution, workers, prepareResult.logFiles, parentEmitPolicy, workerCommonPolicy.ParsingToken(), 255, lifecycleDiag, nullptr, executionTimeline.get());


        return finalExitCode;
    }

    if (!prepareResult.ok) {

        const int finalExitCode = FinalizeExecution(configsBuilder.configs.finalizeExecution, workers, prepareResult.logFiles, parentEmitPolicy, workerCommonPolicy.ParsingToken(), prepareResult.earlyExitCode, lifecycleDiag, nullptr, executionTimeline.get());


        return finalExitCode;
    }

    if (!workers.fileSink || !workers.parentEmit || !workers.jobsExchange) {
        lifecycleDiag.FatalErrorLine(
            L"PrepareRuntime phase failed: worker infrastructure missing"
        );
        const int finalExitCode = FinalizeExecution(configsBuilder.configs.finalizeExecution, workers, prepareResult.logFiles, parentEmitPolicy, workerCommonPolicy.ParsingToken(), 255, lifecycleDiag, nullptr, executionTimeline.get());

        return finalExitCode;
    }
    workers.fileSink->Resume();

    if (!executionTimeline->EndPhase(executionTimeline->PrepareContext())) {
        lifecycleDiag.FatalErrorLine(
            L"Failed to end prepare phase"
        );
        return 255;
    }

    lifecycleDiag.DebugLine(
        L"PrepareRuntime phase ends"
    );




    if (!executionTimeline->StartPhase(executionTimeline->RuntimeContext())) {
        lifecycleDiag.FatalErrorLine(
            L"Failed to start runtime phase"
        );
        return 255;
    }

    lifecycleDiag.DebugLine(
        L"Runtime phase starts"
    );

    SRRuntimeResult runtimeResult;


    bool runtimeFatal = false;
    try {
        runtimeResult = RunHiddenWithRouting(
            configsBuilder.configs.runHiddenWithRouting,
            prepareResult.logFiles.paths,
            prepareResult.fullCmdLineForCreateProcess,
            prepareResult.stdoutStdHandleProbe,
            prepareResult.stderrStdHandleProbe,
            prepareResult.specialCharactersDebugMessage,
            prepareResult.unboundedReplayBufferDebugMessages,
            lifecycleDiag,
            executionTimeline,
            parentEmitPolicy,
            workerCommonPolicy,
            bufferLimitPtr
        );
    } catch (const std::bad_alloc&) {
        lifecycleDiag.FatalErrorLine(
            L"Runtime phase failed: std::bad_alloc"
        );
        runtimeFatal = true;
        runtimeResult.exitCode = 255;
    } catch (const std::exception& ex) {
        const std::wstring detail = FileHelpers::Utf8ToWide(ex.what());
        if (!detail.empty()) {
            lifecycleDiag.FatalErrorLine(
                L"Runtime phase failed: unhandled std::exception; " + detail
            );
        } else {
            lifecycleDiag.FatalErrorLine(
                L"Runtime phase failed: unhandled std::exception"
            );
        }
        runtimeFatal = true;
        runtimeResult.exitCode = 255;
    } catch (...) {
        lifecycleDiag.FatalErrorLine(
            L"Runtime phase failed: unhandled unknown exception"
        );
        runtimeFatal = true;
        runtimeResult.exitCode = 255;
    }
    // Runtime-call exception, or a fatal runtime result before child start:
    // skip the normal runtime phase close path and finalize immediately.
    // FinalizeExecution still performs any eligible parent replay before shutdown.

    if (runtimeFatal || (runtimeResult.fatal && !runtimeResult.childStarted)) {
        const int finalExitCode = FinalizeExecution(configsBuilder.configs.finalizeExecution, workers, prepareResult.logFiles, parentEmitPolicy, workerCommonPolicy.ParsingToken(), 255, lifecycleDiag, &runtimeResult, executionTimeline.get());


        // emitJsonSummaryFullIfRequested(runtimeResult, finalExitCode);

        return finalExitCode;
    }

    int finalizationExitCode = runtimeResult.exitCode;


    if (!executionTimeline->EndPhase(executionTimeline->RuntimeContext())) {
        lifecycleDiag.FatalErrorLine(
            L"Failed to end runtime phase"
        );
        finalizationExitCode = 255;

    }

    lifecycleDiag.DebugLine(
        L"Runtime phase ends; exitCode=" +
            std::to_wstring(runtimeResult.exitCode)
    );

    const int finalExitCode = FinalizeExecution(configsBuilder.configs.finalizeExecution, workers, prepareResult.logFiles, parentEmitPolicy, workerCommonPolicy.ParsingToken(), finalizationExitCode, lifecycleDiag, &runtimeResult, executionTimeline.get());
    // emitJsonSummaryFullIfRequested(runtimeResult, finalExitCode);

    return finalExitCode;
}


namespace {

// Global terminate handler for last-resort diagnostics.
// Invoked when std::terminate is called (e.g. unhandled C++ exception).
//
// IMPORTANT LIMITS:
// - This handler is NOT guaranteed to run for hard-fail scenarios such as:
//   * TerminateProcess / Stop-Process -Force / End Task
//   * access violations (SEH), stack overflow
//   * CRT abort paths that bypass std::terminate
// - Process state may be partially corrupted (heap/stack/CRT), so all logic
//   here must be best-effort only and must not throw.
//
// Design:
// - Try to report the active exception via shared SRLifecycleDiagnostics helpers.
// - On any failure, fall back to the shared last-resort lifecycle helper.
// - Always terminate the process via std::abort().
[[noreturn]] void SilentRunnerTerminateHandler() noexcept {
    // Best effort only. Do not throw from here.
    try {
        const auto emitTerminateError = [&](const std::wstring& msg) {
            SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
                FileHelpers::MakeRunUtcTimestamp(),
                SR::DiagnosticSeverity::Fatal,
                SR::LifecyclePhase::Runtime, 
                msg
            );
        };

        std::exception_ptr current = std::current_exception();
        if (current) {
            try {
                std::rethrow_exception(current);
            } catch (const std::bad_alloc&) {
                emitTerminateError(
                    L"std::terminate called; active exception=std::bad_alloc"
                );
            } catch (const std::exception& ex) {
                const std::wstring detail = FileHelpers::Utf8ToWide(ex.what());
                if (!detail.empty()) {
                    emitTerminateError(
                        L"std::terminate called; active exception=std::exception; " + detail
                    );
                } else {
                    emitTerminateError(
                        L"std::terminate called; active exception=std::exception"
                    );
                }
            } catch (...) {
                emitTerminateError(
                    L"std::terminate called; active exception=unknown non-std exception"
                );
            }
        } else {
            emitTerminateError(
                L"std::terminate called; no active exception"
            );
        }
    } catch (...) {
        // Absolute last fallback: do not let terminate handler throw.
        SRLifecycleDiagnostics::LastResortEmitFormattedToParentStderr(
            FileHelpers::MakeRunUtcTimestamp(),
            SR::DiagnosticSeverity::Fatal,
            SR::LifecyclePhase::Runtime,
            L"std::terminate called; terminate handler failed"
        );
    }

    std::abort();
}
} // namespace
