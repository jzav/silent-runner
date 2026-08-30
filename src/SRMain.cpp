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

#include "SRTypes.h"
#include "SRRuntime.h"
#include "ArgumentParser.h"
#include "FileHelpers.h"
#include "ErrorHelpers.h"
#include "ParentStdEmitter.h"
#include "SRPrepareRuntime.h"
#include "SRLifecycleDiagnostics.h"
#include "SRLifecycleFinalizeExecution.h"
#include "SRParentEmitPolicy.h"
#include "SRWorkerCommonPolicy.h"

// Linker hint (MSVC-style). With MinGW, you typically pass subsystem via linker flags,
// but keeping this is harmless if your toolchain ignores it.
#pragma comment(linker, "/SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup")


namespace {

[[noreturn]] void SilentRunnerTerminateHandler() noexcept;

} // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    std::set_terminate(&SilentRunnerTerminateHandler);
    
    auto executionTimeline = std::make_shared<ExecutionTimeline>();
    
    if (!executionTimeline->Init()) {
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
    if (!parentEmitPolicy.Init()) {
        SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
            FileHelpers::MakeRunUtcTimestamp(),
            SR::DiagnosticSeverity::Fatal,
            SR::LifecyclePhase::Prepare,
            L"Failed to initialize parent emit policy"
        );
        return 255;
    }
    
    parentEmitPolicy.SetStdoutEmitMode(SR::EmitMode::Stream);
    parentEmitPolicy.SetStderrEmitMode(SR::EmitMode::Stream);
    parentEmitPolicy.SetStderrEmitSource(SR::StderrEmitSource::SrAndChild);

    SRLifecycleDiagnostics lifecycleDiag;
    if (!lifecycleDiag.Init(
        SR::EmitMode::Stream,
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

    SRPrepareResult prepareResult;
    SRPreparedRuntime& prepared = prepareResult.prepared;
    SR::LogPaths logPaths;
       
    prepared.workerSupervisor = std::make_unique<SR::SRWorkerSupervisor>();
    prepared.fileSinkWorker = std::make_unique<SRFileSinkWorker>();
    prepared.parentEmitWorker = std::make_unique<SRParentEmitWorker>();
    prepared.jobsExchange = std::make_unique<SRJobsExchange>();

    prepared.fileSinkWorker->SetWorkerSupervisor(
        prepared.workerSupervisor.get()
    );
    prepared.parentEmitWorker->SetWorkerSupervisor(
        prepared.workerSupervisor.get()
    );

    if (!prepared.fileSinkWorker->Init(&lifecycleDiag)) {
        SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
            FileHelpers::MakeRunUtcTimestamp(),
            SR::DiagnosticSeverity::Fatal,
            SR::LifecyclePhase::Prepare,
            L"Failed to initialize file sink worker"
        );
        return 255;
    }

    if (!prepared.parentEmitWorker->Init(&lifecycleDiag, &parentEmitPolicy)) {
        SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
            FileHelpers::MakeRunUtcTimestamp(),
            SR::DiagnosticSeverity::Fatal,
            SR::LifecyclePhase::Prepare,
            L"Failed to initialize parent emit worker"
        );
        return 255;
    }

    if (!prepared.jobsExchange->Init(&lifecycleDiag)) {
        SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
            FileHelpers::MakeRunUtcTimestamp(),
            SR::DiagnosticSeverity::Fatal,
            SR::LifecyclePhase::Prepare,
            L"Failed to initialize jobs exchange"
        );
        return 255;
    }

    prepared.jobsExchange->SetWorkerSupervisor(*prepared.workerSupervisor);
    prepared.jobsExchange->SetFileSinkWorker(*prepared.fileSinkWorker);
    prepared.jobsExchange->SetParentEmitWorker(*prepared.parentEmitWorker);

    if (!prepared.fileSinkWorker->StartPaused()) {
        SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
            FileHelpers::MakeRunUtcTimestamp(),
            SR::DiagnosticSeverity::Fatal,
            SR::LifecyclePhase::Prepare,
            L"Failed to start file sink worker"
        );
        return 255;
    }

    if (!prepared.parentEmitWorker->Start()) {
        SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
            FileHelpers::MakeRunUtcTimestamp(),
            SR::DiagnosticSeverity::Fatal,
            SR::LifecyclePhase::Prepare,
            L"Failed to start parent emit worker"
        );
        return 255;
    }
    
    executionTimeline->SetJobsExchange(*prepared.jobsExchange);


    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) {
        const DWORD gle = GetLastError();
        SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
            FileHelpers::MakeRunUtcTimestamp(),
            SR::DiagnosticSeverity::Fatal,
            SR::LifecyclePhase::Prepare,
            L"CommandLineToArgvW failed; " + ErrorHelpers::FormatGle(gle)
        );
        return 2;
    }

    SR::Options opt;
    std::wstring parseErr;
    if (!ArgumentParser::ParseArgs(argc, argv, opt, parseErr)) {
        if (!parseErr.empty()) {
            SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
                FileHelpers::MakeRunUtcTimestamp(),
                SR::DiagnosticSeverity::Fatal,
                SR::LifecyclePhase::Prepare,
                parseErr
            );
        }
        LocalFree(argv);
        return 2;
    }
    
    SRWorkerCommonPolicy workerCommonPolicy;
    if (!workerCommonPolicy.Init(opt)) {
        SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
            FileHelpers::MakeRunUtcTimestamp(),
            SR::DiagnosticSeverity::Fatal,
            SR::LifecyclePhase::Prepare,
            L"Failed to initialize worker common policy"
        );

        LocalFree(argv);
        return 255;
    }


    prepared.fileSinkWorker->SetParsingTokenPolicy(
        workerCommonPolicy.ParsingToken(),
        workerCommonPolicy.FileSinkParsingTokenTargets()
    );
    prepared.parentEmitWorker->SetParsingTokenPolicy(
        workerCommonPolicy.ParsingToken(),
        workerCommonPolicy.ParentParsingTokenTargets()
    );
  
    
    parentEmitPolicy.SetFromFinalizedOptions(opt);
    executionTimeline->SetParentEmitPolicy(parentEmitPolicy);
    executionTimeline->SetVerboseEnabled(opt.verbose);

    lifecycleDiag.SetDebugEnabled(opt.debug);
    lifecycleDiag.SetVerboseEnabled(opt.verbose);
    lifecycleDiag.SetEmitMode(opt.stderrEmit);
    lifecycleDiag.SetStderrEmitSource(opt.stderrEmitSource);
    
    lifecycleDiag.InfoLine(
        L"SilentRunner starts; std::terminate handler registered"
    );

    if (opt.showHelp) {
        lifecycleDiag.InfoLine(
            L"--help requested; printing usage and exiting"
        );
        ParentStdEmitter::EmitStdoutUtf16(ArgumentParser::BuildUsageText() + L"\n");
        LocalFree(argv);
        return 0;
    }
    



    lifecycleDiag.DebugLine(
        L"PrepareRuntime phase starts"
    );

    try {
        PrepareRuntime(opt, lifecycleDiag, logPaths, prepareResult);
    } catch (const std::bad_alloc&) {
        lifecycleDiag.FatalErrorLine(
            L"PrepareRuntime phase failed: std::bad_alloc"
        );
        const int finalExitCode = FinalizeExecution(opt, prepareResult.prepared, logPaths, parentEmitPolicy, workerCommonPolicy.ParsingToken(), 255, lifecycleDiag, nullptr, executionTimeline.get());

        LocalFree(argv);
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
        const int finalExitCode = FinalizeExecution(opt, prepareResult.prepared, logPaths, parentEmitPolicy, workerCommonPolicy.ParsingToken(), 255, lifecycleDiag, nullptr, executionTimeline.get());

        LocalFree(argv);
        return finalExitCode;
    } catch (...) {
        lifecycleDiag.FatalErrorLine(
            L"PrepareRuntime phase failed: unhandled unknown exception"
        );
        const int finalExitCode = FinalizeExecution(opt, prepareResult.prepared, logPaths, parentEmitPolicy, workerCommonPolicy.ParsingToken(), 255, lifecycleDiag, nullptr, executionTimeline.get());

        LocalFree(argv);
        return finalExitCode;
    }

    if (!prepareResult.ok) {

        const int finalExitCode = FinalizeExecution(opt, prepareResult.prepared, logPaths, parentEmitPolicy, workerCommonPolicy.ParsingToken(), prepareResult.earlyExitCode, lifecycleDiag, nullptr, executionTimeline.get());

        LocalFree(argv);
        return finalExitCode;
    }

    if (!prepared.fileSinkWorker || !prepared.parentEmitWorker || !prepared.jobsExchange) {
        lifecycleDiag.FatalErrorLine(
            L"PrepareRuntime phase failed: worker infrastructure missing"
        );
        const int finalExitCode = FinalizeExecution(opt, prepared, logPaths, parentEmitPolicy, workerCommonPolicy.ParsingToken(), 255, lifecycleDiag, nullptr, executionTimeline.get());
        LocalFree(argv);
        return finalExitCode;
    }
    prepared.fileSinkWorker->AttachLogWriters(
        !opt.stdoutDir.empty(),
        &prepared.stdoutLogWriter,
        logPaths.running.stdoutTxt,
        !opt.stderrDir.empty(),
        &prepared.stderrLogWriter,
        logPaths.running.stderrSrAndChildTxt,
        !opt.stderrChildDir.empty(),
        &prepared.stderrChildLogWriter,
        logPaths.running.stderrChildTxt,
        !opt.stderrSrDir.empty(),
        &prepared.stderrSrLogWriter,
        logPaths.running.stderrSrTxt,
        !opt.stderrSrAndChildInclStdoutDir.empty(),
        &prepared.stderrSrAndChildInclStdoutLogWriter,
        logPaths.running.stderrSrAndChildInclStdoutTxt
    );
    prepared.fileSinkWorker->AttachJsonlWriters(
        !opt.stdoutJsonlDir.empty(),
        &prepared.stdoutJsonlWriter,
        logPaths.running.stdoutJsonl,
        !opt.stderrJsonlDir.empty(),
        &prepared.stderrJsonlWriter,
        logPaths.running.stderrSrAndChildJsonl,
        !opt.stderrChildJsonlDir.empty(),
        &prepared.stderrChildJsonlWriter,
        logPaths.running.stderrChildJsonl,
        !opt.stderrSrJsonlDir.empty(),
        &prepared.stderrSrJsonlWriter,
        logPaths.running.stderrSrJsonl,
        !opt.stderrSrAndChildInclStdoutJsonlDir.empty(),
        &prepared.stderrSrAndChildInclStdoutJsonlWriter,
        logPaths.running.stderrSrAndChildInclStdoutJsonl
    );
    prepared.fileSinkWorker->Resume();

    if (!executionTimeline->EndPhase(executionTimeline->PrepareContext())) {
        lifecycleDiag.FatalErrorLine(
            L"Failed to end prepare phase"
        );
        return 255;
    }

    lifecycleDiag.DebugLine(
        L"PrepareRuntime phase ends; executionId=" + prepared.executionId
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
            prepared.fullCmdLineForCreateProcess,
            prepared.executionId,
            prepared.generatedSuffix,
            prepared.effectiveIdSuffixMode,
            prepared.useDefaultSuffixMode,
            lifecycleDiag,
            executionTimeline,
            parentEmitPolicy,
            workerCommonPolicy,

            opt,
            logPaths,
            prepared.stdoutStdHandleProbe,
            prepared.stderrStdHandleProbe

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
        const int finalExitCode = FinalizeExecution(opt, prepareResult.prepared, logPaths, parentEmitPolicy, workerCommonPolicy.ParsingToken(), 255, lifecycleDiag, &runtimeResult, executionTimeline.get());

        // emitJsonSummaryFullIfRequested(runtimeResult, finalExitCode);

        LocalFree(argv);
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

    const int finalExitCode = FinalizeExecution(opt, prepareResult.prepared, logPaths, parentEmitPolicy, workerCommonPolicy.ParsingToken(), finalizationExitCode, lifecycleDiag, &runtimeResult, executionTimeline.get());
    // emitJsonSummaryFullIfRequested(runtimeResult, finalExitCode);

    LocalFree(argv);
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
