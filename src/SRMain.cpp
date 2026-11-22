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
#include "SRExecutionTimeline.h"
#include "HelpGenerator.h"
#include "FileHelpers.h"
#include "ErrorHelpers.h"
#include "ParentStdEmitter.h"
#include "HandleHelpers.h"
#include "SRPrepareRuntime.h"
#include "SRTargetLogFiles.h"
#include "SRLifecycleDiagnostics.h"
#include "SRLifecycleFinalizeExecution.h"
#include "SRParentEmitPolicy.h"
#include "SRWorkerCommonPolicy.h"
#include "SRWorkers.h"
#include "SRBufferLimiter.h"
#include "SRRuntimeCoordinator.h"
#include "SRTimeLimiter.h"


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

// Check standard handles using the existing write probe.
bool IsUsableStdHandle(HANDLE handle) noexcept {
    const auto probe = HandleHelpers::ProbeStdHandleForWrite(handle);

    return !probe.isNull &&
           !probe.isInvalid &&
           (probe.fileType != FILE_TYPE_UNKNOWN ||
            probe.fileTypeGle == ERROR_SUCCESS);
}

// Attach only to an existing parent console. Never allocate a new console.
// Preserve inherited redirections and initialize missing output handles.
void AttachParentConsoleIfNeeded() noexcept {
    const HANDLE originalStdin = GetStdHandle(STD_INPUT_HANDLE);
    const HANDLE originalStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    const HANDLE originalStderr = GetStdHandle(STD_ERROR_HANDLE);

    const bool stdinValid = IsUsableStdHandle(originalStdin);
    const bool stdoutValid = IsUsableStdHandle(originalStdout);
    const bool stderrValid = IsUsableStdHandle(originalStderr);

    if (stdoutValid && stderrValid) {
        return;
    }

    if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
        return;
    }

    // Restore inherited handles in case console attachment replaced them.
    if (stdinValid) {
        SetStdHandle(STD_INPUT_HANDLE, originalStdin);
    }
    if (stdoutValid) {
        SetStdHandle(STD_OUTPUT_HANDLE, originalStdout);
    }
    if (stderrValid) {
        SetStdHandle(STD_ERROR_HANDLE, originalStderr);
    }

    // AttachConsole may initialize standard handles automatically.
    // Open the existing console only for outputs that remain unavailable.
    const bool stdoutMissing =
        !IsUsableStdHandle(GetStdHandle(STD_OUTPUT_HANDLE));
    const bool stderrMissing =
        !IsUsableStdHandle(GetStdHandle(STD_ERROR_HANDLE));

    if (stdoutMissing || stderrMissing) {
        HANDLE consoleOutput = CreateFileW(
            L"CONOUT$",
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr
        );

        if (consoleOutput != INVALID_HANDLE_VALUE) {
            bool assigned = false;

            if (stdoutMissing) {
                assigned |= SetStdHandle(STD_OUTPUT_HANDLE, consoleOutput) != 0;
            }
            if (stderrMissing) {
                assigned |= SetStdHandle(STD_ERROR_HANDLE, consoleOutput) != 0;
            }

            // Keep the handle open while referenced by a standard stream.
            if (!assigned) {
                CloseHandle(consoleOutput);
            }
        }
    }
}
} // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    AttachParentConsoleIfNeeded();
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
            FileHelpers::MakeEventUtcTimestamp(),
            SR::DiagnosticSeverity::Fatal,
            SR::LifecyclePhase::Prepare,
            L"CommandLineToArgvW failed; " + ErrorHelpers::FormatGle(gle)
        );
        return 2;
    }

    SR::SRConfigsBuilder configsBuilder;
    configsBuilder.Init(
        SR::kFileSinkWorkerTargetLayout,
        SR::kParentEmitWorkerTargetLayout
    );

    if (!configsBuilder.Build(
            argsCount,
            argsVector.get()
        )) {
        SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
            FileHelpers::MakeEventUtcTimestamp(),
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
    
    // Initialize common execution identity before timeline events are created.
    SRWorkerCommonPolicy workerCommonPolicy;
    if (!workerCommonPolicy.Init(configs.workerCommonPolicy)) {
        SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
            FileHelpers::MakeEventUtcTimestamp(),
            SR::DiagnosticSeverity::Fatal,
            SR::LifecyclePhase::Prepare,
            L"Failed to initialize worker common policy"
        );
        return 255;
    }
    configs.finalizeExecution.executionId = workerCommonPolicy.ExecutionId();

    auto executionTimeline = std::make_shared<ExecutionTimeline>();
    
    if (!executionTimeline->Init(
            configsBuilder.configs.executionTimeline.verbose
        )) {

        SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
            FileHelpers::MakeEventUtcTimestamp(),
            SR::DiagnosticSeverity::Fatal,
            SR::LifecyclePhase::Prepare,
            L"Failed to initialize execution timeline"
        );
        return 255;
    }
    
    if (!executionTimeline->StartPhase(executionTimeline->PrepareContext())) {
        SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
            FileHelpers::MakeEventUtcTimestamp(),
            SR::DiagnosticSeverity::Fatal,
            SR::LifecyclePhase::Prepare,
            L"Failed to start prepare phase"
        );
        return 255;
    }


    SRTargetLogFiles targetLogFiles;
    targetLogFiles.Init(
        SR::kFileSinkWorkerTargetLayout,
        configsBuilder.configs.targetLogFiles
    );
    
    SRParentEmitPolicy parentEmitPolicy;
    if (!parentEmitPolicy.Init(
            configsBuilder.configs.parentEmitPolicy,
            targetLogFiles.BuildReplaySourceAvailability(),
            SR::kParentReplaySourceLayout
        )) {
        SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
            FileHelpers::MakeEventUtcTimestamp(),
            SR::DiagnosticSeverity::Fatal,
            SR::LifecyclePhase::Prepare,
            L"Failed to initialize parent emit policy"
        );
        return 255;
    }
    SRRuntimeCoordinator runtimeCoordinator;
    runtimeCoordinator.Init(configs.runtimeCoordinator.abortOnRuntimeFailure);
    SRTimeLimiter timeLimiter;
    timeLimiter.Init(runtimeCoordinator, configsBuilder.configs.timeLimiter);

    SRBufferLimiter bufferLimiter(runtimeCoordinator);
    SRBufferLimiter* bufferLimitPtr = nullptr;

    

    SRLifecycleDiagnostics lifecycleDiag;
    if (!lifecycleDiag.Init(
            configsBuilder.configs.lifecycleDiagnostics,
            parentEmitPolicy,
            executionTimeline.get()
        )) {

        SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
            FileHelpers::MakeEventUtcTimestamp(),
            SR::DiagnosticSeverity::Fatal,
            SR::LifecyclePhase::Prepare,
            L"Failed to initialize lifecycle diagnostics"
        );
        return 255;
    }
    executionTimeline->SetLifecycleDiagnostics(lifecycleDiag);

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
            configsBuilder.configs.fileSinkWorker.jsonlPayloadRepresentation,
            workerCommonPolicy
        )) {


        SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
            FileHelpers::MakeEventUtcTimestamp(),
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
            FileHelpers::MakeEventUtcTimestamp(),
            SR::DiagnosticSeverity::Fatal,
            SR::LifecyclePhase::Prepare,
            L"Failed to initialize parent emit worker"
        );
        return 255;
    }

    if (!workers.jobsExchange->Init(&lifecycleDiag)) {
        SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
            FileHelpers::MakeEventUtcTimestamp(),
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
            FileHelpers::MakeEventUtcTimestamp(),
            SR::DiagnosticSeverity::Fatal,
            SR::LifecyclePhase::Prepare,
            L"Failed to start file sink worker"
        );
        return 255;
    }

    if (!workers.parentEmit->Start()) {
        SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
            FileHelpers::MakeEventUtcTimestamp(),
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
        bufferLimiter.Init(
            configsBuilder.configs.bufferLimiter,
            &lifecycleDiag
        );

        bufferLimitPtr = &bufferLimiter;
    }

    lifecycleDiag.SetBufferLimiter(bufferLimitPtr);


    executionTimeline->SetParentEmitPolicy(parentEmitPolicy);
    
    lifecycleDiag.InfoLine(L"SilentRunner starts");
    lifecycleDiag.VerboseLine(L"std::terminate handler registered");

    lifecycleDiag.DebugLine(
        L"PrepareRuntime phase starts; phaseStartUtc=" +
            executionTimeline->GetPhaseStartUtc(executionTimeline->PrepareContext())
    );

    const auto finalize = [&](
        int exitCode,
        const SRRuntimeResult* runtimeResult
    ) -> int {
        const PhaseContext phaseContext = runtimeResult
            ? executionTimeline->RuntimeContext()
            : executionTimeline->PrepareContext();

        if (!executionTimeline->GetPhaseExitCode(phaseContext).has_value()) {
            const int phaseExitCode = runtimeResult
                ? runtimeResult->exitCode
                : exitCode;

            if (!executionTimeline->SetPhaseExitCode(
                    phaseContext,
                    phaseExitCode
                )) {
                lifecycleDiag.FatalErrorLine(
                    L"Failed to capture phase exit code"
                );
                return 255;
            }

            lifecycleDiag.DebugLine(
                SR::ExecutionExitCodeKey(
                    runtimeResult
                        ? SR::LifecyclePhase::Runtime
                        : SR::LifecyclePhase::Prepare
                ) + L"=" + std::to_wstring(phaseExitCode)
            );
        }

        return FinalizeExecution(
            configsBuilder.configs.finalizeExecution,
            workers,
            targetLogFiles,
            SR::kFileSinkWorkerTargetLayout,
            parentEmitPolicy,
            workerCommonPolicy.ParsingToken(),
            exitCode,
            lifecycleDiag,
            runtimeResult,
            executionTimeline.get(),
            executionTimeline->GetPhaseExitCode(
                executionTimeline->PrepareContext()
            ),
            executionTimeline->GetPhaseExitCode(
                executionTimeline->RuntimeContext()
            )
        );
    };
    
    try {
        PrepareRuntime(
            configs.prepareRuntime,
            configs.executeChildProcess,
            configs.finalizeExecution,
            workerCommonPolicy,
            *workers.fileSink,
            targetLogFiles,
            parentEmitPolicy,
            lifecycleDiag,
            prepareResult
        );
    } catch (const std::bad_alloc&) {
        lifecycleDiag.FatalErrorLine(
            L"PrepareRuntime phase failed: std::bad_alloc"
        );
        const int finalExitCode = finalize(255, nullptr);


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
        const int finalExitCode = finalize(255, nullptr);


        return finalExitCode;
    } catch (...) {
        lifecycleDiag.FatalErrorLine(
            L"PrepareRuntime phase failed: unhandled unknown exception"
        );
        const int finalExitCode = finalize(255, nullptr);


        return finalExitCode;
    }

    if (!prepareResult.ok) {

        const int finalExitCode =
            finalize(prepareResult.earlyExitCode, nullptr);


        return finalExitCode;
    }

    if (!workers.fileSink || !workers.parentEmit || !workers.jobsExchange) {
        lifecycleDiag.FatalErrorLine(
            L"PrepareRuntime phase failed: worker infrastructure missing"
        );
        const int finalExitCode = finalize(255, nullptr);

        return finalExitCode;
    }
    workers.fileSink->Resume();

    if (!executionTimeline->EndPhase(executionTimeline->PrepareContext())) {
        lifecycleDiag.FatalErrorLine(
            L"Failed to end prepare phase"
        );
        return 255;
    }

    if (!executionTimeline->SetPhaseExitCode(
            executionTimeline->PrepareContext(),
            0
        )) {
        lifecycleDiag.FatalErrorLine(
                L"Failed to capture prepare phase exit code"
            );
        return 255;
    }

    lifecycleDiag.DebugLine(
        SR::ExecutionExitCodeKey(SR::LifecyclePhase::Prepare) + L"=0"
    );

    lifecycleDiag.DebugLine(
        L"PrepareRuntime phase ends; phaseEndUtc=" +
            executionTimeline->GetPhaseEndUtc(executionTimeline->PrepareContext())
    );




    if (!executionTimeline->StartPhase(executionTimeline->RuntimeContext())) {
        lifecycleDiag.FatalErrorLine(
            L"Failed to start runtime phase"
        );
        return 255;
    }

    lifecycleDiag.DebugLine(
        L"Runtime phase starts; phaseStartUtc=" +
            executionTimeline->GetPhaseStartUtc(executionTimeline->RuntimeContext())
    );

    SRRuntimeResult runtimeResult;


    bool runtimeFatal = false;
    try {
        SR::JobTargetFilter runtimeLogPathFilter;
        runtimeLogPathFilter.worker = SR::JobTargetWorker::SRFileSinkWorker;
        const auto runtimeLogPaths =
            targetLogFiles.BuildRunningPathBindings(runtimeLogPathFilter);
        ExecuteChildProcess(
            configsBuilder.configs.executeChildProcess,
            SR::kFileSinkWorkerTargetLayout,
            runtimeLogPaths,
            prepareResult.comspecPath,
            prepareResult.fullCmdLineForCreateProcess,
            prepareResult.stdoutStdHandleProbe,
            prepareResult.stderrStdHandleProbe,
            prepareResult.specialCharactersDebugMessage,
            prepareResult.unboundedReplayBufferDebugMessages,
            lifecycleDiag,
            executionTimeline,
            parentEmitPolicy,
            workerCommonPolicy,
            bufferLimitPtr,
            runtimeCoordinator,
            timeLimiter,
            runtimeResult
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
        const int finalExitCode =
            finalize(255, &runtimeResult);



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
        L"Runtime phase ends; phaseEndUtc=" +
            executionTimeline->GetPhaseEndUtc(executionTimeline->RuntimeContext()) +
            L"; " +
            SR::ExecutionExitCodeKey(SR::LifecyclePhase::Runtime) +
            L"=" + std::to_wstring(runtimeResult.exitCode)
    );

    const int finalExitCode =
        finalize(finalizationExitCode, &runtimeResult);

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
 // - On any failure, write a static message directly to parent stderr.
// - Always terminate the process via std::abort().
[[noreturn]] void SilentRunnerTerminateHandler() noexcept {
    // Best effort only. Do not throw from here.
    try {
        const auto emitTerminateError = [&](const std::wstring& msg) {
            SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
                FileHelpers::MakeEventUtcTimestamp(),
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
        // Absolute last fallback: no allocation, formatting, or UTF conversion.
        constexpr char message[] =
            "std::terminate called; terminate handler failed\n";
        ParentStdEmitter::EmitStderrLastResort(message, sizeof(message) - 1);
    }

    std::abort();
}
} // namespace
