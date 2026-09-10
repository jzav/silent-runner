
#include "SRLifecycleFinalizeExecution.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string>
#include <vector>

#include "ErrorHelpers.h"
#include "LogWriter.h"
#include "FileHelpers.h"
#include "SRConfigsBuilderTypes.h"
#include "SRExecutionTimeline.h"
#include "SRExecutionTimelineDiagnostics.h"
#include "SRLifecycleDiagnostics.h"
#include "SRJobsExchange.h"
#include "SRParentEmitPolicy.h"
#include "SRParentReplayRouter.h"
#include "SRPrepareRuntime.h"
#include "SRPendingJobTypes.h"
#include "SRReplayJsonlToParent.h"
#include "SRReplayTxtToParent.h"
#include "SRRunHook.h"
#include "SRTypes.h"
#include "SRRuntime.h"
#include "SRWorkerSupervisor.h"
#include "SRWorkerTypes.h"

bool FlushLogFileWriters(
    SRLogFileWriters& writers,
    SRLifecycleDiagnostics& lifecycleDiag
) {
    if (writers.stderrLogWriter.IsOpen()) {
        DWORD gle = 0;
        if (!writers.stderrLogWriter.Flush(&gle)) {
            lifecycleDiag.ErrorLine(
                L"FlushFileBuffers(stderr-sr-and-child log) failed; " + ErrorHelpers::FormatGle(gle)
            );
            return false;
        }
    }
    if (writers.stderrChildLogWriter.IsOpen()) {
        DWORD gle = 0;
        if (!writers.stderrChildLogWriter.Flush(&gle)) {
            lifecycleDiag.ErrorLine(
                L"FlushFileBuffers(stderr-child log) failed; " + ErrorHelpers::FormatGle(gle)
            );
            return false;
        }
    }

    if (writers.stderrSrLogWriter.IsOpen()) {
        DWORD gle = 0;
        if (!writers.stderrSrLogWriter.Flush(&gle)) {
            lifecycleDiag.ErrorLine(
                L"FlushFileBuffers(stderr-sr log) failed; " + ErrorHelpers::FormatGle(gle)
            );
            return false;
        }
    }
    if (writers.stderrSrAndChildInclStdoutLogWriter.IsOpen()) {
        DWORD gle = 0;
        if (!writers.stderrSrAndChildInclStdoutLogWriter.Flush(&gle)) {
            lifecycleDiag.ErrorLine(
                L"FlushFileBuffers(stderr-sr-and-child-incl-stdout log) failed; " + ErrorHelpers::FormatGle(gle)
            );
            return false;
        }
    }

    if (writers.stdoutLogWriter.IsOpen()) {
        DWORD gle = 0;
        if (!writers.stdoutLogWriter.Flush(&gle)) {
            lifecycleDiag.ErrorLine(
                L"FlushFileBuffers(stdout log) failed; " + ErrorHelpers::FormatGle(gle)
            );
            return false;
        }
    }

    if (writers.stderrJsonlWriter.IsOpen()) {
        DWORD gle = 0;
        if (!writers.stderrJsonlWriter.Flush(&gle)) {
            lifecycleDiag.ErrorLine(
                L"FlushFileBuffers(stderr-sr-and-child JSONL log) failed; " + ErrorHelpers::FormatGle(gle)
            );
            return false;
        }
    }
    if (writers.stderrChildJsonlWriter.IsOpen()) {
        DWORD gle = 0;
        if (!writers.stderrChildJsonlWriter.Flush(&gle)) {
            lifecycleDiag.ErrorLine(
                L"FlushFileBuffers(stderr-child JSONL log) failed; " + ErrorHelpers::FormatGle(gle)
            );
            return false;
        }
    }

    if (writers.stderrSrJsonlWriter.IsOpen()) {
        DWORD gle = 0;
        if (!writers.stderrSrJsonlWriter.Flush(&gle)) {
            lifecycleDiag.ErrorLine(
                L"FlushFileBuffers(stderr-sr JSONL log) failed; " + ErrorHelpers::FormatGle(gle)
            );
            return false;
        }
    }
    if (writers.stderrSrAndChildInclStdoutJsonlWriter.IsOpen()) {
        DWORD gle = 0;
        if (!writers.stderrSrAndChildInclStdoutJsonlWriter.Flush(&gle)) {
            lifecycleDiag.ErrorLine(
                L"FlushFileBuffers(stderr-sr-and-child-incl-stdout JSONL log) failed; " + ErrorHelpers::FormatGle(gle)
            );
            return false;
        }
    }

    if (writers.stdoutJsonlWriter.IsOpen()) {
        DWORD gle = 0;
        if (!writers.stdoutJsonlWriter.Flush(&gle)) {
            lifecycleDiag.ErrorLine(
                L"FlushFileBuffers(stdout JSONL log) failed; " + ErrorHelpers::FormatGle(gle)
            );
            return false;
        }
    }

    return true;
}


    // Close all log file writers that may exist in any lifecycle finalization path.
void CloseLogFileWriters(
    SRLogFileWriters& writers
) {
    if (writers.stdoutLogWriter.IsOpen()) {
        writers.stdoutLogWriter.Close();
    }
    if (writers.stderrLogWriter.IsOpen()) {
        writers.stderrLogWriter.Close();
    }
    if (writers.stderrChildLogWriter.IsOpen()) {
        writers.stderrChildLogWriter.Close();
    }
    if (writers.stderrSrLogWriter.IsOpen()) {
        writers.stderrSrLogWriter.Close();
    }
    if (writers.stderrSrAndChildInclStdoutLogWriter.IsOpen()) {
        writers.stderrSrAndChildInclStdoutLogWriter.Close();
    }
    if (writers.stdoutJsonlWriter.IsOpen()) {
        writers.stdoutJsonlWriter.Close();
    }
    if (writers.stderrJsonlWriter.IsOpen()) {
        writers.stderrJsonlWriter.Close();
    }
    if (writers.stderrChildJsonlWriter.IsOpen()) {
        writers.stderrChildJsonlWriter.Close();
    }
    if (writers.stderrSrJsonlWriter.IsOpen()) {
        writers.stderrSrJsonlWriter.Close();
    }
    if (writers.stderrSrAndChildInclStdoutJsonlWriter.IsOpen()) {
        writers.stderrSrAndChildInclStdoutJsonlWriter.Close();
    }
}

static void SetInternalFailureExitCode_(int& exitCode) noexcept {
    if (exitCode != 254) {
        exitCode = 255;
    }
}

static bool IsSuccess_(int exitCode) noexcept {
    return exitCode == 0;
}

static const std::wstring& DetermineFinalLogPath_(
    bool success,

    const std::wstring& successPath,
    const std::wstring& failurePath
) noexcept {
    if (successPath.empty()) {
        return failurePath;
    }

    return success
        ? successPath
        : failurePath;

}

// Best-effort finalization over a partially or fully prepared runtime state.
// Individual resources may be absent depending on earlier failures,
// replay mode, or logging configuration.
// The lifecycle phase is provided externally as contextual origin.
int FinalizeExecution(
    const SR::FinalizeExecutionConfig& config,
    SRWorkers& workers,
    SRLogFiles& logFiles,
    SRParentEmitPolicy& parentEmitPolicy,
    const std::string& parsingToken,
    int exitCode,
    SRLifecycleDiagnostics& lifecycleDiag,
    const SRRuntimeResult* runtimeResultOrNull,
    ExecutionTimeline* executionTimelineOrNull
) {
    const SR::LogPaths& logPaths = logFiles.paths;
    const SR::LogFileCreationResults& creationResults = logFiles.creationResults;
    SRLogFileWriters& writers = logFiles.writers;
    // Finalization is best-effort and must not short-circuit on controlled
    // cleanup/log failures. Such failures may downgrade exitCode to 255
    // and clear hook-visible log paths. The selected post-execution hook is
    // started only after routing, workers, and log file writers are finalized.
    
    bool noDiagnosticChannel = false;

    if (workers.supervisor) {
        const SR::WorkerFailureRecords workerFailures =
            workers.supervisor->RetrieveWorkerFailures();

        if (!workerFailures.empty()) {
            if (workers.supervisor->IsAnyWorkerAvailable()) {
                lifecycleDiag.ErrorLine(
                    workers.supervisor->FormatWorkerFailureDiagnostics()
                );
                SetInternalFailureExitCode_(exitCode);
            } else {
                exitCode = 254;

                noDiagnosticChannel = true;

                if (executionTimelineOrNull) {
                    executionTimelineOrNull->StopRouting();
                }
            }
        }
    }


    SR::ParentReplayPolicySnapshot replayPolicySnapshot;
    
    replayPolicySnapshot.stdoutEmitMode =
        parentEmitPolicy.RetrieveTargetEmitMode(
            SR::JobTarget::StdoutParent
        );
    const SR::StderrEmitSource stderrEmitSource =
        parentEmitPolicy.StderrEmitSource();

    replayPolicySnapshot.stderrEmitMode =
        parentEmitPolicy.RetrieveTargetEmitMode(
            SR::RetrieveStderrJobTarget(stderrEmitSource)
        );
    replayPolicySnapshot.stderrEmitSource =
        stderrEmitSource;

    replayPolicySnapshot.needsStdoutReplayBuffer =
        parentEmitPolicy.NeedsStdoutReplayBuffer();
    replayPolicySnapshot.needsStderrReplayBuffer =
        parentEmitPolicy.NeedsStderrReplayBuffer();

    const bool stdoutBufferedEmitMode =
        SRParentEmitPolicy::IsBufferedEmitMode(
            replayPolicySnapshot.stdoutEmitMode
        );

    const bool stderrBufferedEmitMode =
        SRParentEmitPolicy::IsBufferedEmitMode(
            replayPolicySnapshot.stderrEmitMode
        );

    const bool executionSucceededBeforeReplay =
        IsSuccess_(exitCode);

    const bool stdoutReplayRequested =
        SR::ShouldReplayForExecutionResult(
            replayPolicySnapshot.stdoutEmitMode,
            executionSucceededBeforeReplay
        );

    const bool stderrReplayRequested =
        SR::ShouldReplayForExecutionResult(
            replayPolicySnapshot.stderrEmitMode,
            executionSucceededBeforeReplay
        );

    const bool parentReplayRequested =
        stdoutReplayRequested ||
        stderrReplayRequested;

    const bool persistentReplaySyncNeeded =
        (stdoutReplayRequested &&
         !replayPolicySnapshot.needsStdoutReplayBuffer) ||
        (stderrReplayRequested &&
         !replayPolicySnapshot.needsStderrReplayBuffer);

    const bool timelineReplaySyncNeeded =
        (stdoutReplayRequested &&
         replayPolicySnapshot.needsStdoutReplayBuffer) ||
        (stderrReplayRequested &&
         replayPolicySnapshot.needsStderrReplayBuffer);

    if (!noDiagnosticChannel && parentReplayRequested) {
        bool fileSinkPausedForReplay = false;

        if (persistentReplaySyncNeeded && workers.fileSink) {
            fileSinkPausedForReplay =
                workers.fileSink->Drain() &&
                workers.fileSink->PauseAfterCurrentJob();
        }

        if (timelineReplaySyncNeeded && workers.parentEmit) {
            workers.parentEmit->Drain();
        }

        if ((persistentReplaySyncNeeded || timelineReplaySyncNeeded) &&
            executionTimelineOrNull) {
            if (!executionTimelineOrNull->HarvestCompletedJobs()) {
                SetInternalFailureExitCode_(exitCode);
            }
        }

        if (persistentReplaySyncNeeded &&
            !FlushLogFileWriters(writers, lifecycleDiag)) {
            SetInternalFailureExitCode_(exitCode);
        }
        if (stdoutBufferedEmitMode) {
            parentEmitPolicy.SetStdoutEmitMode(
                SR::EmitMode::Stream
            );
        }

        if (stderrBufferedEmitMode) {
            parentEmitPolicy.SetStderrEmitMode(
                SR::EmitMode::Stream
            );
        }

        SRReplayTxtToParent replayTxtToParent;
        SRReplayJsonlToParent replayJsonlToParent;
        SRParentReplayRouter parentReplayRouter;

        const bool replayInitialized =
            workers.jobsExchange &&
            replayTxtToParent.Init(
                &lifecycleDiag,
                parsingToken,
                1u << 15
            ) &&

            replayJsonlToParent.Init(&lifecycleDiag) &&
            parentReplayRouter.Init(lifecycleDiag);

        if (!replayInitialized) {
            SetInternalFailureExitCode_(exitCode);
        } else {
            replayTxtToParent.SetJobsExchange(
                *workers.jobsExchange
            );
            replayJsonlToParent.SetJobsExchange(
                *workers.jobsExchange
            );

            if (executionTimelineOrNull) {
                parentReplayRouter.SetExecutionTimeline(
                    *executionTimelineOrNull
                );
            }
            
            parentReplayRouter.SetReplayTxtToParent(
                replayTxtToParent
            );
            parentReplayRouter.SetReplayJsonlToParent(
                replayJsonlToParent
            );

            if (!parentReplayRouter.ReplayToParent(
                    replayPolicySnapshot,
                    IsSuccess_(exitCode),
                    logPaths
                )) {
                SetInternalFailureExitCode_(exitCode);
            }
        }

        if (fileSinkPausedForReplay &&
            workers.supervisor &&
            workers.supervisor->IsWorkerAvailable(
                SR::JobTargetWorker::SRFileSinkWorker
            )) {
            workers.fileSink->Resume();
        }
    }

    if (!FlushLogFileWriters(writers, lifecycleDiag)) {
        SetInternalFailureExitCode_(exitCode);
    }

    lifecycleDiag.DebugLine(
        L"FinalizeExecution decision; isSuccess=" +
            std::wstring(IsSuccess_(exitCode) ? L"true" : L"false") +
            L"; exitCode=" +
            std::to_wstring(exitCode)
    );
    
    // Freeze the execution result used for log retention and final naming.
    // Log finalization failures may change exitCode, but must not change
    // retention or naming decisions for subsequent log targets.
    const bool logFinalizationSuccess = IsSuccess_(exitCode);


    std::wstring stdoutLogPathForHook;
    std::wstring stderrLogPathForHook;
    std::wstring stderrChildLogPathForHook;
    std::wstring stderrSrLogPathForHook;
    std::wstring stderrSrAndChildInclStdoutLogPathForHook;
    std::wstring stdoutJsonlLogPathForFinal;
    std::wstring stderrJsonlLogPathForFinal;
    std::wstring stderrChildJsonlLogPathForFinal;
    std::wstring stderrSrJsonlLogPathForFinal;
    std::wstring stderrSrAndChildInclStdoutJsonlLogPathForFinal;


    bool fileSinkPausedForLogFinalization = false;

    if (workers.fileSink) {
        fileSinkPausedForLogFinalization =
            workers.fileSink->PauseAfterCurrentJob();
    }
    CloseLogFileWriters(writers);

    bool stdoutFinalLogAvailable = false;
    bool stderrFinalLogAvailable = false;
    bool stderrChildFinalLogAvailable = false;
    bool stderrSrFinalLogAvailable = false;
    bool stderrSrAndChildInclStdoutFinalLogAvailable = false;
    bool stdoutJsonlFinalLogAvailable = false;
    bool stderrJsonlFinalLogAvailable = false;
    bool stderrChildJsonlFinalLogAvailable = false;
    bool stderrSrJsonlFinalLogAvailable = false;
    bool stderrSrAndChildInclStdoutJsonlFinalLogAvailable = false;

    if (creationResults.stdoutTxt) {


        if (LogWriter::ShouldKeepLogFile(config.stdoutDirKeepLog, logFinalizationSuccess)) {


            stdoutLogPathForHook = DetermineFinalLogPath_(
                logFinalizationSuccess,

                logPaths.success.stdoutTxt,
                logPaths.failure.stdoutTxt
            );
            lifecycleDiag.DebugLine(
                L"Will rename stdout log; from=" + logPaths.running.stdoutTxt +
                L" to=" + stdoutLogPathForHook
            );
            DWORD gle = 0;
            if (LogWriter::TryRenameLogFile(logPaths.running.stdoutTxt, stdoutLogPathForHook, &gle)) {
                stdoutFinalLogAvailable = true;
                lifecycleDiag.InfoLine(
                    L"STDOUT_LOG_FINAL=" + stdoutLogPathForHook
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to rename stdout log; from=" + logPaths.running.stdoutTxt +
                    L" to=" + stdoutLogPathForHook + L" " + ErrorHelpers::FormatGle(gle)
                );
                stdoutLogPathForHook.clear();
            }
        } else {
            lifecycleDiag.DebugLine(
                L"Will delete stdout log; path=" + logPaths.running.stdoutTxt
            );
            DWORD gle = 0;
            if (LogWriter::TryDeleteLogFile(logPaths.running.stdoutTxt, &gle)) {
                lifecycleDiag.InfoLine(
                    L"STDOUT_LOG_REMOVED=" + logPaths.running.stdoutTxt
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to delete stdout log; path=" + logPaths.running.stdoutTxt +
                    L" " + ErrorHelpers::FormatGle(gle)
                );
            }
        }
    }

    if (creationResults.stderrSrAndChildTxt) {


        if (LogWriter::ShouldKeepLogFile(config.stderrDirKeepLog, logFinalizationSuccess)) {


            stderrLogPathForHook = DetermineFinalLogPath_(
                logFinalizationSuccess,

                logPaths.success.stderrSrAndChildTxt,
                logPaths.failure.stderrSrAndChildTxt
            );
            lifecycleDiag.DebugLine(
                L"Will rename stderr-sr-and-child log; from=" + logPaths.running.stderrSrAndChildTxt +
                L" to=" + stderrLogPathForHook
            );
            DWORD gle = 0;
            if (LogWriter::TryRenameLogFile(logPaths.running.stderrSrAndChildTxt, stderrLogPathForHook, &gle)) {
                stderrFinalLogAvailable = true;
                lifecycleDiag.InfoLine(
                    L"STDERR_LOG_FINAL=" + stderrLogPathForHook
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to rename stderr-sr-and-child log; from=" + logPaths.running.stderrSrAndChildTxt +
                    L" to=" + stderrLogPathForHook + L" " + ErrorHelpers::FormatGle(gle)
                );
                stderrLogPathForHook.clear();
            }
        } else {
            lifecycleDiag.DebugLine(
                L"Will delete stderr-sr-and-child log; path=" + logPaths.running.stderrSrAndChildTxt
            );
            DWORD gle = 0;
            if (LogWriter::TryDeleteLogFile(logPaths.running.stderrSrAndChildTxt, &gle)) {
                lifecycleDiag.InfoLine(
                    L"STDERR_LOG_REMOVED=" + logPaths.running.stderrSrAndChildTxt
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to delete stderr-sr-and-child log; path=" + logPaths.running.stderrSrAndChildTxt +
                    L" " + ErrorHelpers::FormatGle(gle)
                );
            }
        }
    }

    if (creationResults.stderrChildTxt) {


        if (LogWriter::ShouldKeepLogFile(config.stderrDirChildKeepLog, logFinalizationSuccess)) {


            stderrChildLogPathForHook = DetermineFinalLogPath_(
                logFinalizationSuccess,

                logPaths.success.stderrChildTxt,
                logPaths.failure.stderrChildTxt
            );
            lifecycleDiag.DebugLine(
                L"Will rename stderr-child log; from=" + logPaths.running.stderrChildTxt +
                L" to=" + stderrChildLogPathForHook
            );
            DWORD gle = 0;
            if (LogWriter::TryRenameLogFile(logPaths.running.stderrChildTxt, stderrChildLogPathForHook, &gle)) {
                stderrChildFinalLogAvailable = true;
                lifecycleDiag.InfoLine(
                    L"STDERR_CHILD_LOG_FINAL=" + stderrChildLogPathForHook
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to rename stderr-child log; from=" + logPaths.running.stderrChildTxt +
                    L" to=" + stderrChildLogPathForHook + L" " + ErrorHelpers::FormatGle(gle)
                );
                stderrChildLogPathForHook.clear();
            }
        } else {
            lifecycleDiag.DebugLine(
                L"Will delete stderr-child log; path=" + logPaths.running.stderrChildTxt
            );
            DWORD gle = 0;
            if (LogWriter::TryDeleteLogFile(logPaths.running.stderrChildTxt, &gle)) {
                lifecycleDiag.InfoLine(
                    L"STDERR_CHILD_LOG_REMOVED=" + logPaths.running.stderrChildTxt
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to delete stderr-child log; path=" + logPaths.running.stderrChildTxt +
                    L" " + ErrorHelpers::FormatGle(gle)
                );
            }
        }
    }

    if (creationResults.stderrSrTxt) {


        if (LogWriter::ShouldKeepLogFile(config.stderrDirSrKeepLog, logFinalizationSuccess)) {


            stderrSrLogPathForHook = DetermineFinalLogPath_(
                logFinalizationSuccess,

                logPaths.success.stderrSrTxt,
                logPaths.failure.stderrSrTxt
            );
            lifecycleDiag.DebugLine(
                L"Will rename stderr-sr log; from=" + logPaths.running.stderrSrTxt +
                L" to=" + stderrSrLogPathForHook
            );
            DWORD gle = 0;
            if (LogWriter::TryRenameLogFile(logPaths.running.stderrSrTxt, stderrSrLogPathForHook, &gle)) {
                stderrSrFinalLogAvailable = true;
                lifecycleDiag.InfoLine(
                    L"STDERR_SR_LOG_FINAL=" + stderrSrLogPathForHook
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to rename stderr-sr log; from=" + logPaths.running.stderrSrTxt +
                    L" to=" + stderrSrLogPathForHook + L" " + ErrorHelpers::FormatGle(gle)
                );
                stderrSrLogPathForHook.clear();
            }
        } else {
            lifecycleDiag.DebugLine(
                L"Will delete stderr-sr log; path=" + logPaths.running.stderrSrTxt
            );
            DWORD gle = 0;
            if (LogWriter::TryDeleteLogFile(logPaths.running.stderrSrTxt, &gle)) {
                lifecycleDiag.InfoLine(
                    L"STDERR_SR_LOG_REMOVED=" + logPaths.running.stderrSrTxt
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to delete stderr-sr log; path=" + logPaths.running.stderrSrTxt +
                    L" " + ErrorHelpers::FormatGle(gle)
                );
            }
        }
    }
    if (creationResults.stderrSrAndChildInclStdoutTxt) {


        if (LogWriter::ShouldKeepLogFile(config.stderrDirInclStdoutKeepLog, logFinalizationSuccess)) {

            stderrSrAndChildInclStdoutLogPathForHook = DetermineFinalLogPath_(
                logFinalizationSuccess,
                logPaths.success.stderrSrAndChildInclStdoutTxt,
                logPaths.failure.stderrSrAndChildInclStdoutTxt
            );
            lifecycleDiag.DebugLine(
                L"Will rename stderr-sr-and-child-incl-stdout log; from=" + logPaths.running.stderrSrAndChildInclStdoutTxt +
                L" to=" + stderrSrAndChildInclStdoutLogPathForHook
            );
            DWORD gle = 0;
            if (LogWriter::TryRenameLogFile(
                    logPaths.running.stderrSrAndChildInclStdoutTxt,
                    stderrSrAndChildInclStdoutLogPathForHook,
                    &gle
                )) {
                stderrSrAndChildInclStdoutFinalLogAvailable = true;
                lifecycleDiag.InfoLine(
                    L"STDERR_INCL_STDOUT_LOG_FINAL=" + stderrSrAndChildInclStdoutLogPathForHook
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to rename stderr-sr-and-child-incl-stdout log; from=" +
                    logPaths.running.stderrSrAndChildInclStdoutTxt +
                    L" to=" + stderrSrAndChildInclStdoutLogPathForHook +
                    L" " + ErrorHelpers::FormatGle(gle)
                );
                stderrSrAndChildInclStdoutLogPathForHook.clear();
            }
        } else {
            lifecycleDiag.DebugLine(
                L"Will delete stderr-sr-and-child-incl-stdout log; path=" +
                logPaths.running.stderrSrAndChildInclStdoutTxt
            );
            DWORD gle = 0;
            if (LogWriter::TryDeleteLogFile(logPaths.running.stderrSrAndChildInclStdoutTxt, &gle)) {
                lifecycleDiag.InfoLine(
                    L"STDERR_INCL_STDOUT_LOG_REMOVED=" + logPaths.running.stderrSrAndChildInclStdoutTxt
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to delete stderr-sr-and-child-incl-stdout log; path=" +
                    logPaths.running.stderrSrAndChildInclStdoutTxt +
                    L" " + ErrorHelpers::FormatGle(gle)
                );
            }
        }
    }
    if (creationResults.stdoutJsonl) {


        if (LogWriter::ShouldKeepLogFile(config.stdoutDirKeepLog, logFinalizationSuccess)) {


            stdoutJsonlLogPathForFinal = DetermineFinalLogPath_(
                logFinalizationSuccess,

                logPaths.success.stdoutJsonl,
                logPaths.failure.stdoutJsonl
            );
            lifecycleDiag.DebugLine(
                L"Will rename stdout JSONL log; from=" + logPaths.running.stdoutJsonl +
                L" to=" + stdoutJsonlLogPathForFinal
            );
            DWORD gle = 0;
            if (LogWriter::TryRenameLogFile(logPaths.running.stdoutJsonl, stdoutJsonlLogPathForFinal, &gle)) {
                stdoutJsonlFinalLogAvailable = true;
                lifecycleDiag.InfoLine(
                    L"STDOUT_JSONL_LOG_FINAL=" + stdoutJsonlLogPathForFinal
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to rename stdout JSONL log; from=" + logPaths.running.stdoutJsonl +
                    L" to=" + stdoutJsonlLogPathForFinal + L" " + ErrorHelpers::FormatGle(gle)
                );
                stdoutJsonlLogPathForFinal.clear();
            }
        } else {
            lifecycleDiag.DebugLine(
                L"Will delete stdout JSONL log; path=" + logPaths.running.stdoutJsonl
            );
            DWORD gle = 0;
            if (LogWriter::TryDeleteLogFile(logPaths.running.stdoutJsonl, &gle)) {
                lifecycleDiag.InfoLine(
                    L"STDOUT_JSONL_LOG_REMOVED=" + logPaths.running.stdoutJsonl
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to delete stdout JSONL log; path=" + logPaths.running.stdoutJsonl +
                    L" " + ErrorHelpers::FormatGle(gle)
                );
            }
        }
    }

    if (creationResults.stderrSrAndChildJsonl) {


        if (LogWriter::ShouldKeepLogFile(config.stderrDirKeepLog, logFinalizationSuccess)) {


            stderrJsonlLogPathForFinal = DetermineFinalLogPath_(
                logFinalizationSuccess,

                logPaths.success.stderrSrAndChildJsonl,
                logPaths.failure.stderrSrAndChildJsonl
            );
            lifecycleDiag.DebugLine(
                L"Will rename stderr-sr-and-child JSONL log; from=" + logPaths.running.stderrSrAndChildJsonl +
                L" to=" + stderrJsonlLogPathForFinal
            );
            DWORD gle = 0;
            if (LogWriter::TryRenameLogFile(logPaths.running.stderrSrAndChildJsonl, stderrJsonlLogPathForFinal, &gle)) {
                stderrJsonlFinalLogAvailable = true;
                lifecycleDiag.InfoLine(
                    L"STDERR_JSONL_LOG_FINAL=" + stderrJsonlLogPathForFinal
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to rename stderr-sr-and-child JSONL log; from=" + logPaths.running.stderrSrAndChildJsonl +
                    L" to=" + stderrJsonlLogPathForFinal + L" " + ErrorHelpers::FormatGle(gle)
                );
                stderrJsonlLogPathForFinal.clear();
            }
        } else {
            lifecycleDiag.DebugLine(
                L"Will delete stderr-sr-and-child JSONL log; path=" + logPaths.running.stderrSrAndChildJsonl
            );
            DWORD gle = 0;
            if (LogWriter::TryDeleteLogFile(logPaths.running.stderrSrAndChildJsonl, &gle)) {
                lifecycleDiag.InfoLine(
                    L"STDERR_JSONL_LOG_REMOVED=" + logPaths.running.stderrSrAndChildJsonl
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to delete stderr-sr-and-child JSONL log; path=" + logPaths.running.stderrSrAndChildJsonl +
                    L" " + ErrorHelpers::FormatGle(gle)
                );
            }
        }
    }

    if (creationResults.stderrChildJsonl) {


        if (LogWriter::ShouldKeepLogFile(config.stderrDirChildKeepLog, logFinalizationSuccess)) {


            stderrChildJsonlLogPathForFinal = DetermineFinalLogPath_(
                logFinalizationSuccess,

                logPaths.success.stderrChildJsonl,
                logPaths.failure.stderrChildJsonl
            );
            lifecycleDiag.DebugLine(
                L"Will rename stderr-child JSONL log; from=" + logPaths.running.stderrChildJsonl +
                L" to=" + stderrChildJsonlLogPathForFinal
            );
            DWORD gle = 0;
            if (LogWriter::TryRenameLogFile(logPaths.running.stderrChildJsonl, stderrChildJsonlLogPathForFinal, &gle)) {
                stderrChildJsonlFinalLogAvailable = true;
                lifecycleDiag.InfoLine(
                    L"STDERR_CHILD_JSONL_LOG_FINAL=" + stderrChildJsonlLogPathForFinal
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to rename stderr-child JSONL log; from=" + logPaths.running.stderrChildJsonl +
                    L" to=" + stderrChildJsonlLogPathForFinal + L" " + ErrorHelpers::FormatGle(gle)
                );
                stderrChildJsonlLogPathForFinal.clear();
            }
        } else {
            lifecycleDiag.DebugLine(
                L"Will delete stderr-child JSONL log; path=" + logPaths.running.stderrChildJsonl
            );
            DWORD gle = 0;
            if (LogWriter::TryDeleteLogFile(logPaths.running.stderrChildJsonl, &gle)) {
                lifecycleDiag.InfoLine(
                    L"STDERR_CHILD_JSONL_LOG_REMOVED=" + logPaths.running.stderrChildJsonl
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to delete stderr-child JSONL log; path=" + logPaths.running.stderrChildJsonl +
                    L" " + ErrorHelpers::FormatGle(gle)
                );
            }
        }
    }

    if (creationResults.stderrSrJsonl) {


        if (LogWriter::ShouldKeepLogFile(config.stderrDirSrKeepLog, logFinalizationSuccess)) {


            stderrSrJsonlLogPathForFinal = DetermineFinalLogPath_(
                logFinalizationSuccess,
                logPaths.success.stderrSrJsonl,
                logPaths.failure.stderrSrJsonl
            );
            lifecycleDiag.DebugLine(
                L"Will rename stderr-sr JSONL log; from=" + logPaths.running.stderrSrJsonl +
                L" to=" + stderrSrJsonlLogPathForFinal
            );
            DWORD gle = 0;
            if (LogWriter::TryRenameLogFile(logPaths.running.stderrSrJsonl, stderrSrJsonlLogPathForFinal, &gle)) {
                stderrSrJsonlFinalLogAvailable = true;
                lifecycleDiag.InfoLine(
                    L"STDERR_SR_JSONL_LOG_FINAL=" + stderrSrJsonlLogPathForFinal
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to rename stderr-sr JSONL log; from=" + logPaths.running.stderrSrJsonl +
                    L" to=" + stderrSrJsonlLogPathForFinal + L" " + ErrorHelpers::FormatGle(gle)
                );
                stderrSrJsonlLogPathForFinal.clear();
            }
        } else {
            lifecycleDiag.DebugLine(
                L"Will delete stderr-sr JSONL log; path=" + logPaths.running.stderrSrJsonl
            );
            DWORD gle = 0;
            if (LogWriter::TryDeleteLogFile(logPaths.running.stderrSrJsonl, &gle)) {
                lifecycleDiag.InfoLine(
                    L"STDERR_SR_JSONL_LOG_REMOVED=" + logPaths.running.stderrSrJsonl
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to delete stderr-sr JSONL log; path=" + logPaths.running.stderrSrJsonl +
                    L" " + ErrorHelpers::FormatGle(gle)
                );
            }
        }
    }
    if (creationResults.stderrSrAndChildInclStdoutJsonl) {

        if (LogWriter::ShouldKeepLogFile(config.stderrDirInclStdoutKeepLog, logFinalizationSuccess)) {

            stderrSrAndChildInclStdoutJsonlLogPathForFinal = DetermineFinalLogPath_(
                logFinalizationSuccess,
                logPaths.success.stderrSrAndChildInclStdoutJsonl,
                logPaths.failure.stderrSrAndChildInclStdoutJsonl
            );
            lifecycleDiag.DebugLine(
                L"Will rename stderr-sr-and-child-incl-stdout JSONL log; from=" +
                logPaths.running.stderrSrAndChildInclStdoutJsonl +
                L" to=" + stderrSrAndChildInclStdoutJsonlLogPathForFinal
            );
            DWORD gle = 0;
            if (LogWriter::TryRenameLogFile(
                    logPaths.running.stderrSrAndChildInclStdoutJsonl,
                    stderrSrAndChildInclStdoutJsonlLogPathForFinal,
                    &gle
                )) {
                stderrSrAndChildInclStdoutJsonlFinalLogAvailable = true;
                lifecycleDiag.InfoLine(
                    L"STDERR_INCL_STDOUT_JSONL_LOG_FINAL=" +
                    stderrSrAndChildInclStdoutJsonlLogPathForFinal
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to rename stderr-sr-and-child-incl-stdout JSONL log; from=" +
                    logPaths.running.stderrSrAndChildInclStdoutJsonl +
                    L" to=" + stderrSrAndChildInclStdoutJsonlLogPathForFinal +
                    L" " + ErrorHelpers::FormatGle(gle)
                );
                stderrSrAndChildInclStdoutJsonlLogPathForFinal.clear();
            }
        } else {
            lifecycleDiag.DebugLine(
                L"Will delete stderr-sr-and-child-incl-stdout JSONL log; path=" +
                logPaths.running.stderrSrAndChildInclStdoutJsonl
            );
            DWORD gle = 0;
            if (LogWriter::TryDeleteLogFile(logPaths.running.stderrSrAndChildInclStdoutJsonl, &gle)) {
                lifecycleDiag.InfoLine(
                    L"STDERR_INCL_STDOUT_JSONL_LOG_REMOVED=" +
                    logPaths.running.stderrSrAndChildInclStdoutJsonl
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to delete stderr-sr-and-child-incl-stdout JSONL log; path=" +
                    logPaths.running.stderrSrAndChildInclStdoutJsonl +
                    L" " + ErrorHelpers::FormatGle(gle)
                );
            }
        }
    }


    if (stdoutFinalLogAvailable) {
        DWORD gle = 0;
        if (writers.stdoutLogWriter.OpenAppendFile(stdoutLogPathForHook, &gle)) {
            lifecycleDiag.DebugLine(
                L"Reopened stdout log for append OK; path=" + stdoutLogPathForHook
            );
        } else {
            SetInternalFailureExitCode_(exitCode);
            lifecycleDiag.ErrorLine(
                L"Failed to reopen stdout log for append; path=" +
                stdoutLogPathForHook + L" " + ErrorHelpers::FormatGle(gle)
            );
            stdoutLogPathForHook.clear();
            stdoutFinalLogAvailable = false;
        }
    }

    if (stderrFinalLogAvailable) {
        DWORD gle = 0;
        if (writers.stderrLogWriter.OpenAppendFile(stderrLogPathForHook, &gle)) {
            lifecycleDiag.DebugLine(
                L"Reopened stderr-sr-and-child log for append OK; path=" + stderrLogPathForHook
            );
        } else {
            SetInternalFailureExitCode_(exitCode);
            lifecycleDiag.ErrorLine(
                L"Failed to reopen stderr-sr-and-child log for append; path=" +
                stderrLogPathForHook + L" " + ErrorHelpers::FormatGle(gle)
            );
            stderrLogPathForHook.clear();
        }
    }

    if (stderrChildFinalLogAvailable) {
        DWORD gle = 0;
        if (writers.stderrChildLogWriter.OpenAppendFile(stderrChildLogPathForHook, &gle)) {
            lifecycleDiag.DebugLine(
                L"Reopened stderr-child log for append OK; path=" + stderrChildLogPathForHook
            );
        } else {
            SetInternalFailureExitCode_(exitCode);
            lifecycleDiag.ErrorLine(
                L"Failed to reopen stderr-child log for append; path=" +
                stderrChildLogPathForHook + L" " + ErrorHelpers::FormatGle(gle)
            );
            stderrChildLogPathForHook.clear();
            stderrChildFinalLogAvailable = false;
        }
    }

    if (stderrSrFinalLogAvailable) {
        DWORD gle = 0;
        if (writers.stderrSrLogWriter.OpenAppendFile(stderrSrLogPathForHook, &gle)) {
            lifecycleDiag.DebugLine(
                L"Reopened stderr-sr log for append OK; path=" + stderrSrLogPathForHook
            );
        } else {
            SetInternalFailureExitCode_(exitCode);
            lifecycleDiag.ErrorLine(
                L"Failed to reopen stderr-sr log for append; path=" +
                stderrSrLogPathForHook + L" " + ErrorHelpers::FormatGle(gle)
            );
            stderrSrLogPathForHook.clear();
        }
    }
    if (stderrSrAndChildInclStdoutFinalLogAvailable) {
        DWORD gle = 0;
        if (writers.stderrSrAndChildInclStdoutLogWriter.OpenAppendFile(stderrSrAndChildInclStdoutLogPathForHook, &gle)) {
            lifecycleDiag.DebugLine(
                L"Reopened stderr-sr-and-child-incl-stdout log for append OK; path=" +
                stderrSrAndChildInclStdoutLogPathForHook
            );
        } else {
            SetInternalFailureExitCode_(exitCode);
            lifecycleDiag.ErrorLine(
                L"Failed to reopen stderr-sr-and-child-incl-stdout log for append; path=" +
                stderrSrAndChildInclStdoutLogPathForHook +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            stderrSrAndChildInclStdoutLogPathForHook.clear();
            stderrSrAndChildInclStdoutFinalLogAvailable = false;
        }
    }
    if (stdoutJsonlFinalLogAvailable) {
        DWORD gle = 0;
        if (writers.stdoutJsonlWriter.OpenAppendFile(stdoutJsonlLogPathForFinal, &gle)) {
            lifecycleDiag.DebugLine(
                L"Reopened stdout JSONL log for append OK; path=" + stdoutJsonlLogPathForFinal
            );
        } else {
            SetInternalFailureExitCode_(exitCode);
            lifecycleDiag.ErrorLine(
                L"Failed to reopen stdout JSONL log for append; path=" +
                stdoutJsonlLogPathForFinal + L" " + ErrorHelpers::FormatGle(gle)
            );
            stdoutJsonlLogPathForFinal.clear();
            stdoutJsonlFinalLogAvailable = false;
        }
    }

    if (stderrJsonlFinalLogAvailable) {
        DWORD gle = 0;
        if (writers.stderrJsonlWriter.OpenAppendFile(stderrJsonlLogPathForFinal, &gle)) {
            lifecycleDiag.DebugLine(
                L"Reopened stderr-sr-and-child JSONL log for append OK; path=" + stderrJsonlLogPathForFinal
            );
        } else {
            SetInternalFailureExitCode_(exitCode);
            lifecycleDiag.ErrorLine(
                L"Failed to reopen stderr-sr-and-child JSONL log for append; path=" +
                stderrJsonlLogPathForFinal + L" " + ErrorHelpers::FormatGle(gle)
            );
            stderrJsonlLogPathForFinal.clear();
            stderrJsonlFinalLogAvailable = false;
        }
    }

    if (stderrChildJsonlFinalLogAvailable) {
        DWORD gle = 0;
        if (writers.stderrChildJsonlWriter.OpenAppendFile(stderrChildJsonlLogPathForFinal, &gle)) {
            lifecycleDiag.DebugLine(
                L"Reopened stderr-child JSONL log for append OK; path=" + stderrChildJsonlLogPathForFinal
            );
        } else {
            SetInternalFailureExitCode_(exitCode);
            lifecycleDiag.ErrorLine(
                L"Failed to reopen stderr-child JSONL log for append; path=" +
                stderrChildJsonlLogPathForFinal + L" " + ErrorHelpers::FormatGle(gle)
            );
            stderrChildJsonlLogPathForFinal.clear();
            stderrChildJsonlFinalLogAvailable = false;
        }
    }

    if (stderrSrJsonlFinalLogAvailable) {
        DWORD gle = 0;
        if (writers.stderrSrJsonlWriter.OpenAppendFile(stderrSrJsonlLogPathForFinal, &gle)) {
            lifecycleDiag.DebugLine(
                L"Reopened stderr-sr JSONL log for append OK; path=" + stderrSrJsonlLogPathForFinal
            );
        } else {
            SetInternalFailureExitCode_(exitCode);
            lifecycleDiag.ErrorLine(
                L"Failed to reopen stderr-sr JSONL log for append; path=" +
                stderrSrJsonlLogPathForFinal + L" " + ErrorHelpers::FormatGle(gle)
            );
            stderrSrJsonlLogPathForFinal.clear();
            stderrSrJsonlFinalLogAvailable = false;
        }
    }
    if (stderrSrAndChildInclStdoutJsonlFinalLogAvailable) {
        DWORD gle = 0;
        if (writers.stderrSrAndChildInclStdoutJsonlWriter.OpenAppendFile(
                stderrSrAndChildInclStdoutJsonlLogPathForFinal,
                &gle
            )) {
            lifecycleDiag.DebugLine(
                L"Reopened stderr-sr-and-child-incl-stdout JSONL log for append OK; path=" +
                stderrSrAndChildInclStdoutJsonlLogPathForFinal
            );
        } else {
            SetInternalFailureExitCode_(exitCode);
            lifecycleDiag.ErrorLine(
                L"Failed to reopen stderr-sr-and-child-incl-stdout JSONL log for append; path=" +
                stderrSrAndChildInclStdoutJsonlLogPathForFinal +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            stderrSrAndChildInclStdoutJsonlLogPathForFinal.clear();
            stderrSrAndChildInclStdoutJsonlFinalLogAvailable = false;
        }
    }


    if (fileSinkPausedForLogFinalization) {
        workers.fileSink->AttachLogWriters(
            stdoutFinalLogAvailable && writers.stdoutLogWriter.IsOpen(),
            writers.stdoutLogWriter.IsOpen() ? &writers.stdoutLogWriter : nullptr,
            stdoutLogPathForHook,
            stderrFinalLogAvailable && writers.stderrLogWriter.IsOpen(),
            writers.stderrLogWriter.IsOpen() ? &writers.stderrLogWriter : nullptr,
            stderrLogPathForHook,
            stderrChildFinalLogAvailable && writers.stderrChildLogWriter.IsOpen(),
            writers.stderrChildLogWriter.IsOpen() ? &writers.stderrChildLogWriter : nullptr,
            stderrChildLogPathForHook,
            stderrSrFinalLogAvailable && writers.stderrSrLogWriter.IsOpen(),
            writers.stderrSrLogWriter.IsOpen() ? &writers.stderrSrLogWriter : nullptr,
            stderrSrLogPathForHook,
            stderrSrAndChildInclStdoutFinalLogAvailable && writers.stderrSrAndChildInclStdoutLogWriter.IsOpen(),
            writers.stderrSrAndChildInclStdoutLogWriter.IsOpen() ? &writers.stderrSrAndChildInclStdoutLogWriter : nullptr,
            stderrSrAndChildInclStdoutLogPathForHook
        );
        workers.fileSink->AttachJsonlWriters(
            stdoutJsonlFinalLogAvailable && writers.stdoutJsonlWriter.IsOpen(),
            writers.stdoutJsonlWriter.IsOpen() ? &writers.stdoutJsonlWriter : nullptr,
            stdoutJsonlLogPathForFinal,
            stderrJsonlFinalLogAvailable && writers.stderrJsonlWriter.IsOpen(),
            writers.stderrJsonlWriter.IsOpen() ? &writers.stderrJsonlWriter : nullptr,
            stderrJsonlLogPathForFinal,
            stderrChildJsonlFinalLogAvailable && writers.stderrChildJsonlWriter.IsOpen(),
            writers.stderrChildJsonlWriter.IsOpen() ? &writers.stderrChildJsonlWriter : nullptr,
            stderrChildJsonlLogPathForFinal,
            stderrSrJsonlFinalLogAvailable && writers.stderrSrJsonlWriter.IsOpen(),
            writers.stderrSrJsonlWriter.IsOpen() ? &writers.stderrSrJsonlWriter : nullptr,
            stderrSrJsonlLogPathForFinal,
            stderrSrAndChildInclStdoutJsonlFinalLogAvailable && writers.stderrSrAndChildInclStdoutJsonlWriter.IsOpen(),
            writers.stderrSrAndChildInclStdoutJsonlWriter.IsOpen() ? &writers.stderrSrAndChildInclStdoutJsonlWriter : nullptr,
            stderrSrAndChildInclStdoutJsonlLogPathForFinal
        );
        workers.fileSink->Resume();
    }


    if (executionTimelineOrNull) {
        executionTimelineOrNull->EndCurrentPhase();
    }

    lifecycleDiag.InfoLine(
        L"SilentRunner ends; exitCode=" + std::to_wstring(exitCode)
    );
    if (executionTimelineOrNull) {
        executionTimelineOrNull->StopRouting();
    }


    if (workers.fileSink &&
        workers.supervisor &&
        workers.supervisor->IsWorkerAvailable(
            SR::JobTargetWorker::SRFileSinkWorker
        )) {
        workers.fileSink->Drain();
    }
    if (workers.parentEmit &&
        workers.supervisor &&
        workers.supervisor->IsWorkerAvailable(
            SR::JobTargetWorker::SRParentEmitWorker
        )) {
        workers.parentEmit->Drain();
    }

    if (config.verbose && !noDiagnosticChannel && executionTimelineOrNull && workers.jobsExchange) {

        SR::EventSummary finalHarvestEventSummary;
        if (executionTimelineOrNull->BuildFinalHarvestEventSummary(
                finalHarvestEventSummary
            )) {
            SR::PendingJob finalHarvestJob;
            finalHarvestJob.payloadType = SR::JobPayloadType::SrDiag;
            finalHarvestJob.key = finalHarvestEventSummary.eventKey;
            finalHarvestJob.srDiag.key = finalHarvestJob.key;
            finalHarvestJob.srDiag.timestampUtc =
                FileHelpers::MakeRunUtcTimestamp();
            finalHarvestJob.srDiag.severity =
                SR::DiagnosticSeverity::Verbose;
            finalHarvestJob.srDiag.message =
                SR::FormatFinalEventSummary(finalHarvestEventSummary);

            SR::PendingJobs finalHarvestJobs;
            finalHarvestJobs.push_back(std::move(finalHarvestJob));
            workers.jobsExchange->EnqueuePendingJobs(finalHarvestJobs);

            if (workers.fileSink &&
                workers.supervisor &&
                workers.supervisor->IsWorkerAvailable(
                    SR::JobTargetWorker::SRFileSinkWorker
                )) {
                workers.fileSink->Drain();
            }
            if (workers.parentEmit &&
                workers.supervisor &&
                workers.supervisor->IsWorkerAvailable(
                    SR::JobTargetWorker::SRParentEmitWorker
                )) {
                workers.parentEmit->Drain();
            }
        }
    }

    if (workers.fileSink) {
        workers.fileSink->DrainAndStop();
    }
    if (workers.parentEmit) {
        workers.parentEmit->DrainAndStop();
    }
    CloseLogFileWriters(writers);
    if (!(IsSuccess_(exitCode) ? config.runOnSuccessPath : config.runOnFailurePath).empty()) {

        const std::vector<SRRunHook::EnvironmentVariable> hookEnvironment{
            { L"SILENTRUNNER_EXIT_CODE", std::to_wstring(exitCode) },
            { L"SILENTRUNNER_EXECUTION_ID", config.executionId },
            { L"SILENTRUNNER_STDOUT_LOG", stdoutFinalLogAvailable ? stdoutLogPathForHook : L"" },
            { L"SILENTRUNNER_STDOUT_JSONL_LOG", stdoutJsonlFinalLogAvailable ? stdoutJsonlLogPathForFinal : L"" },
            { L"SILENTRUNNER_STDERR_LOG", stderrFinalLogAvailable ? stderrLogPathForHook : L"" },
            { L"SILENTRUNNER_STDERR_JSONL_LOG", stderrJsonlFinalLogAvailable ? stderrJsonlLogPathForFinal : L"" },
            { L"SILENTRUNNER_STDERR_CHILD_LOG", stderrChildFinalLogAvailable ? stderrChildLogPathForHook : L"" },
            { L"SILENTRUNNER_STDERR_CHILD_JSONL_LOG", stderrChildJsonlFinalLogAvailable ? stderrChildJsonlLogPathForFinal : L"" },
            { L"SILENTRUNNER_STDERR_SR_LOG", stderrSrFinalLogAvailable ? stderrSrLogPathForHook : L"" },
            { L"SILENTRUNNER_STDERR_SR_JSONL_LOG", stderrSrJsonlFinalLogAvailable ? stderrSrJsonlLogPathForFinal : L"" },
            { L"SILENTRUNNER_STDERR_INCL_STDOUT_LOG", stderrSrAndChildInclStdoutFinalLogAvailable ? stderrSrAndChildInclStdoutLogPathForHook : L"" },
            { L"SILENTRUNNER_STDERR_INCL_STDOUT_JSONL_LOG", stderrSrAndChildInclStdoutJsonlFinalLogAvailable ? stderrSrAndChildInclStdoutJsonlLogPathForFinal : L"" }
        };
        for (const SRRunHook::EnvironmentVariable& variable : hookEnvironment) {
            lifecycleDiag.ProbeLine(
                std::wstring(L"[RUN-HOOK] Run-on-") +
                (IsSuccess_(exitCode) ? L"success" : L"failure") +
                L" hook environment " + variable.name + L"=" + variable.value
            );
        }

        DWORD hookGle = 0;
        DWORD hookPid = 0;

        if (!SRRunHook::RunHookDetached(
                IsSuccess_(exitCode) ? config.runOnSuccessPath : config.runOnFailurePath,

                config.cwd,

                hookEnvironment,
                hookGle,
                hookPid
            )) {
            lifecycleDiag.ProbeLine(
                std::wstring(L"[RUN-HOOK] Run-on-") +
                (IsSuccess_(exitCode) ? L"success" : L"failure") +
                L" hook start failed; path=" +
                (IsSuccess_(exitCode) ? config.runOnSuccessPath : config.runOnFailurePath) +

                L" " + ErrorHelpers::FormatGle(hookGle)
            );
        } else {
            lifecycleDiag.ProbeLine(
                std::wstring(L"[RUN-HOOK] Run-on-") +
                (IsSuccess_(exitCode) ? L"success" : L"failure") +
                L" hook started; pid=" + std::to_wstring(hookPid) +
                L" path=" +
                (IsSuccess_(exitCode) ? config.runOnSuccessPath : config.runOnFailurePath)

            );
        }
    }
    return exitCode;
}
