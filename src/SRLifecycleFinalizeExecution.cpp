
#include "SRLifecycleFinalizeExecution.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string>
#include <vector>

#include "ErrorHelpers.h"
#include "LogWriter.h"
#include "FileHelpers.h"
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

bool FlushPreparedRuntimeFiles(
    SRPreparedRuntime& prepared,
    SRLifecycleDiagnostics& lifecycleDiag
) {
    if (prepared.stderrLogWriter.IsOpen()) {
        DWORD gle = 0;
        if (!prepared.stderrLogWriter.Flush(&gle)) {
            lifecycleDiag.ErrorLine(
                L"FlushFileBuffers(stderr log) failed; " + ErrorHelpers::FormatGle(gle)
            );
            return false;
        }
    }
    if (prepared.stderrChildLogWriter.IsOpen()) {
        DWORD gle = 0;
        if (!prepared.stderrChildLogWriter.Flush(&gle)) {
            lifecycleDiag.ErrorLine(
                L"FlushFileBuffers(stderr child log) failed; " + ErrorHelpers::FormatGle(gle)
            );
            return false;
        }
    }

    if (prepared.stderrSrLogWriter.IsOpen()) {
        DWORD gle = 0;
        if (!prepared.stderrSrLogWriter.Flush(&gle)) {
            lifecycleDiag.ErrorLine(
                L"FlushFileBuffers(stderr SilentRunner log) failed; " + ErrorHelpers::FormatGle(gle)
            );
            return false;
        }
    }

    if (prepared.stdoutLogWriter.IsOpen()) {
        DWORD gle = 0;
        if (!prepared.stdoutLogWriter.Flush(&gle)) {
            lifecycleDiag.ErrorLine(
                L"FlushFileBuffers(stdout log) failed; " + ErrorHelpers::FormatGle(gle)
            );
            return false;
        }
    }

    if (prepared.stderrJsonlWriter.IsOpen()) {
        DWORD gle = 0;
        if (!prepared.stderrJsonlWriter.Flush(&gle)) {
            lifecycleDiag.ErrorLine(
                L"FlushFileBuffers(stderr JSONL log) failed; " + ErrorHelpers::FormatGle(gle)
            );
            return false;
        }
    }
    if (prepared.stderrChildJsonlWriter.IsOpen()) {
        DWORD gle = 0;
        if (!prepared.stderrChildJsonlWriter.Flush(&gle)) {
            lifecycleDiag.ErrorLine(
                L"FlushFileBuffers(stderr child JSONL log) failed; " + ErrorHelpers::FormatGle(gle)
            );
            return false;
        }
    }

    if (prepared.stderrSrJsonlWriter.IsOpen()) {
        DWORD gle = 0;
        if (!prepared.stderrSrJsonlWriter.Flush(&gle)) {
            lifecycleDiag.ErrorLine(
                L"FlushFileBuffers(stderr SilentRunner JSONL log) failed; " + ErrorHelpers::FormatGle(gle)
            );
            return false;
        }
    }

    if (prepared.stdoutJsonlWriter.IsOpen()) {
        DWORD gle = 0;
        if (!prepared.stdoutJsonlWriter.Flush(&gle)) {
            lifecycleDiag.ErrorLine(
                L"FlushFileBuffers(stdout JSONL log) failed; " + ErrorHelpers::FormatGle(gle)
            );
            return false;
        }
    }

    return true;
}


// Close all prepared log writers that may exist in any lifecycle finalization path.
void ClosePreparedRuntimeFiles(
    SRPreparedRuntime& prepared
) {
    if (prepared.stdoutLogWriter.IsOpen()) {
        prepared.stdoutLogWriter.Close();
    }
    if (prepared.stderrLogWriter.IsOpen()) {
        prepared.stderrLogWriter.Close();
    }
    if (prepared.stderrChildLogWriter.IsOpen()) {
        prepared.stderrChildLogWriter.Close();
    }
    if (prepared.stderrSrLogWriter.IsOpen()) {
        prepared.stderrSrLogWriter.Close();
    }
    if (prepared.stdoutJsonlWriter.IsOpen()) {
        prepared.stdoutJsonlWriter.Close();
    }
    if (prepared.stderrJsonlWriter.IsOpen()) {
        prepared.stderrJsonlWriter.Close();
    }
    if (prepared.stderrChildJsonlWriter.IsOpen()) {
        prepared.stderrChildJsonlWriter.Close();
    }
    if (prepared.stderrSrJsonlWriter.IsOpen()) {
        prepared.stderrSrJsonlWriter.Close();
    }
}

static void SetInternalFailureExitCode_(int& exitCode) noexcept {
    if (exitCode != 254) {
        exitCode = 255;
    }
}

// Best-effort finalization over a partially or fully prepared runtime state.
// Individual resources may be absent depending on earlier failures,
// replay mode, or logging configuration.
// The lifecycle phase is provided externally as contextual origin.
int FinalizeExecution(
    const SR::Options& opt,
    SRPreparedRuntime& prepared,
    const SR::LogPaths& logPaths,
    SRParentEmitPolicy& parentEmitPolicy,
    const std::string& parsingToken,
    int exitCode,
    SRLifecycleDiagnostics& lifecycleDiag,
    const SRRuntimeResult* runtimeResultOrNull,
    ExecutionTimeline* executionTimelineOrNull
) {
    // Finalization is best-effort and must not short-circuit on controlled
    // cleanup/log failures. Such failures may downgrade exitCode to 255
    // and clear hook-visible log paths. The selected post-execution hook is
    // started only after routing, workers, and prepared log writers are finalized.
    
    bool noDiagnosticChannel = false;

    if (prepared.workerSupervisor) {
        const SR::WorkerFailureRecords workerFailures =
            prepared.workerSupervisor->RetrieveWorkerFailures();

        if (!workerFailures.empty()) {
            if (prepared.workerSupervisor->IsAnyWorkerAvailable()) {
                lifecycleDiag.ErrorLine(
                    prepared.workerSupervisor->FormatWorkerFailureDiagnostics()
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

    const bool isSuccess = (exitCode == 0);

    SR::ParentReplayPolicySnapshot replayPolicySnapshot;
    
    replayPolicySnapshot.stdoutEmitMode =
        parentEmitPolicy.RetrieveTargetEmitMode(
            SR::JobTarget::StdoutParent
        );
    replayPolicySnapshot.stderrEmitMode =
        parentEmitPolicy.RetrieveTargetEmitMode(
            SR::RetrieveStderrJobTarget(
                opt.stderrEmitSource
            )
        );
    
        replayPolicySnapshot.stderrEmitSource =
        opt.stderrEmitSource;

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

    const bool parentReplayRequested =
        stdoutBufferedEmitMode ||
        stderrBufferedEmitMode;

    if (!noDiagnosticChannel && parentReplayRequested) {
        bool fileSinkPausedForReplay = false;

        if (prepared.fileSinkWorker) {
            fileSinkPausedForReplay =
                prepared.fileSinkWorker->Drain() &&
                prepared.fileSinkWorker->PauseAfterCurrentJob();
        }

        if (!FlushPreparedRuntimeFiles(prepared, lifecycleDiag)) {
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
            lifecycleDiag.SetEmitMode(SR::EmitMode::Stream);
        }

        SRReplayTxtToParent replayTxtToParent;
        SRReplayJsonlToParent replayJsonlToParent;
        SRParentReplayRouter parentReplayRouter;

        const bool replayInitialized =
            prepared.jobsExchange &&
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
                *prepared.jobsExchange
            );
            replayJsonlToParent.SetJobsExchange(
                *prepared.jobsExchange
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
                    isSuccess,
                    logPaths
                )) {
                SetInternalFailureExitCode_(exitCode);
            }
        }

        if (fileSinkPausedForReplay &&
            prepared.workerSupervisor &&
            prepared.workerSupervisor->IsWorkerAvailable(
                SR::JobTargetWorker::SRFileSinkWorker
            )) {
            prepared.fileSinkWorker->Resume();
        }
    }

    if (!FlushPreparedRuntimeFiles(prepared, lifecycleDiag)) {
        SetInternalFailureExitCode_(exitCode);
    }

    lifecycleDiag.DebugLine(
        L"FinalizeExecution decision; isSuccess=" +
            std::wstring(isSuccess ? L"true" : L"false") +
            L"; exitCode=" +
            std::to_wstring(exitCode)
    );

    const bool keepStdoutLog =
        !logPaths.running.stdoutTxt.empty() &&
        LogWriter::ShouldKeepLogFile(opt.stdoutDirKeepLog, isSuccess);

    const bool keepStderrLog =
        !logPaths.running.stderrMixedTxt.empty() &&
        LogWriter::ShouldKeepLogFile(opt.stderrDirKeepLog, isSuccess);

    const bool keepStderrChildLog =
        !logPaths.running.stderrChildTxt.empty() &&
        LogWriter::ShouldKeepLogFile(opt.stderrChildDirKeepLog, isSuccess);

    const bool keepStderrSrLog =
        !logPaths.running.stderrSrTxt.empty() &&
        LogWriter::ShouldKeepLogFile(opt.stderrSrDirKeepLog, isSuccess);
    const bool keepStdoutJsonlLog =
        !logPaths.running.stdoutJsonl.empty() &&
        LogWriter::ShouldKeepLogFile(opt.stdoutDirKeepLog, isSuccess);

    const bool keepStderrJsonlLog =
        !logPaths.running.stderrMixedJsonl.empty() &&
        LogWriter::ShouldKeepLogFile(opt.stderrDirKeepLog, isSuccess);

    const bool keepStderrChildJsonlLog =
        !logPaths.running.stderrChildJsonl.empty() &&
        LogWriter::ShouldKeepLogFile(opt.stderrChildDirKeepLog, isSuccess);

    const bool keepStderrSrJsonlLog =
        !logPaths.running.stderrSrJsonl.empty() &&
        LogWriter::ShouldKeepLogFile(opt.stderrSrDirKeepLog, isSuccess);

    std::wstring stdoutLogPathForHook = keepStdoutLog
        ? (logPaths.success.stdoutTxt.empty()
            ? logPaths.failure.stdoutTxt
            : (isSuccess ? logPaths.success.stdoutTxt : logPaths.failure.stdoutTxt))
        : L"";

    std::wstring stderrLogPathForHook = keepStderrLog
        ? (logPaths.success.stderrMixedTxt.empty()
            ? logPaths.failure.stderrMixedTxt
            : (isSuccess ? logPaths.success.stderrMixedTxt : logPaths.failure.stderrMixedTxt))
        : L"";

    std::wstring stderrChildLogPathForHook = keepStderrChildLog
        ? (logPaths.success.stderrChildTxt.empty()
            ? logPaths.failure.stderrChildTxt
            : (isSuccess ? logPaths.success.stderrChildTxt : logPaths.failure.stderrChildTxt))
        : L"";

    std::wstring stderrSrLogPathForHook = keepStderrSrLog
        ? (logPaths.success.stderrSrTxt.empty()
            ? logPaths.failure.stderrSrTxt
            : (isSuccess ? logPaths.success.stderrSrTxt : logPaths.failure.stderrSrTxt))
        : L"";
    std::wstring stdoutJsonlLogPathForFinal = keepStdoutJsonlLog
        ? (logPaths.success.stdoutJsonl.empty()
            ? logPaths.failure.stdoutJsonl
            : (isSuccess ? logPaths.success.stdoutJsonl : logPaths.failure.stdoutJsonl))
        : L"";

    std::wstring stderrJsonlLogPathForFinal = keepStderrJsonlLog
        ? (logPaths.success.stderrMixedJsonl.empty()
            ? logPaths.failure.stderrMixedJsonl
            : (isSuccess ? logPaths.success.stderrMixedJsonl : logPaths.failure.stderrMixedJsonl))
        : L"";

    std::wstring stderrChildJsonlLogPathForFinal = keepStderrChildJsonlLog
        ? (logPaths.success.stderrChildJsonl.empty()
            ? logPaths.failure.stderrChildJsonl
            : (isSuccess ? logPaths.success.stderrChildJsonl : logPaths.failure.stderrChildJsonl))
        : L"";

    std::wstring stderrSrJsonlLogPathForFinal = keepStderrSrJsonlLog
        ? (logPaths.success.stderrSrJsonl.empty()
            ? logPaths.failure.stderrSrJsonl
            : (isSuccess ? logPaths.success.stderrSrJsonl : logPaths.failure.stderrSrJsonl))
        : L"";


    if (!opt.stdoutDir.empty() && !logPaths.running.stdoutTxt.empty()) {
        if (keepStdoutLog) {
            lifecycleDiag.DebugLine(
                L"Will rename stdout log; from=" + logPaths.running.stdoutTxt +
                L" to=" + stdoutLogPathForHook
            );
        } else {
            lifecycleDiag.DebugLine(
                L"Will delete stdout log; path=" + logPaths.running.stdoutTxt
            );
        }
    }

    if (!opt.stderrDir.empty() && !logPaths.running.stderrMixedTxt.empty()) {
        if (keepStderrLog) {
            lifecycleDiag.DebugLine(
                L"Will rename stderr log; from=" + logPaths.running.stderrMixedTxt +
                L" to=" + stderrLogPathForHook
            );
        } else {
            lifecycleDiag.DebugLine(
                L"Will delete stderr log; path=" + logPaths.running.stderrMixedTxt
            );
        }
    }

    if (!opt.stderrChildDir.empty() && !logPaths.running.stderrChildTxt.empty()) {
        if (keepStderrChildLog) {
            lifecycleDiag.DebugLine(
                L"Will rename stderr child log; from=" + logPaths.running.stderrChildTxt +
                L" to=" + stderrChildLogPathForHook
            );
        } else {
            lifecycleDiag.DebugLine(
                L"Will delete stderr child log; path=" + logPaths.running.stderrChildTxt
            );
        }
    }

    if (!opt.stderrSrDir.empty() && !logPaths.running.stderrSrTxt.empty()) {
        if (keepStderrSrLog) {
            lifecycleDiag.DebugLine(
                L"Will rename stderr SilentRunner log; from=" + logPaths.running.stderrSrTxt +
                L" to=" + stderrSrLogPathForHook
            );
        } else {
            lifecycleDiag.DebugLine(
                L"Will delete stderr SilentRunner log; path=" + logPaths.running.stderrSrTxt
            );
        }
    }
    if (!opt.stdoutJsonlDir.empty() && !logPaths.running.stdoutJsonl.empty()) {
        if (keepStdoutJsonlLog) {
            lifecycleDiag.DebugLine(
                L"Will rename stdout JSONL log; from=" + logPaths.running.stdoutJsonl +
                L" to=" + stdoutJsonlLogPathForFinal
            );
        } else {
            lifecycleDiag.DebugLine(
                L"Will delete stdout JSONL log; path=" + logPaths.running.stdoutJsonl
            );
        }
    }

    if (!opt.stderrJsonlDir.empty() && !logPaths.running.stderrMixedJsonl.empty()) {
        if (keepStderrJsonlLog) {
            lifecycleDiag.DebugLine(
                L"Will rename stderr JSONL log; from=" + logPaths.running.stderrMixedJsonl +
                L" to=" + stderrJsonlLogPathForFinal
            );
        } else {
            lifecycleDiag.DebugLine(
                L"Will delete stderr JSONL log; path=" + logPaths.running.stderrMixedJsonl
            );
        }
    }

    if (!opt.stderrChildJsonlDir.empty() && !logPaths.running.stderrChildJsonl.empty()) {
        if (keepStderrChildJsonlLog) {
            lifecycleDiag.DebugLine(
                L"Will rename stderr child JSONL log; from=" + logPaths.running.stderrChildJsonl +
                L" to=" + stderrChildJsonlLogPathForFinal
            );
        } else {
            lifecycleDiag.DebugLine(
                L"Will delete stderr child JSONL log; path=" + logPaths.running.stderrChildJsonl
            );
        }
    }

    if (!opt.stderrSrJsonlDir.empty() && !logPaths.running.stderrSrJsonl.empty()) {
        if (keepStderrSrJsonlLog) {
            lifecycleDiag.DebugLine(
                L"Will rename stderr SilentRunner JSONL log; from=" + logPaths.running.stderrSrJsonl +
                L" to=" + stderrSrJsonlLogPathForFinal
            );
        } else {
            lifecycleDiag.DebugLine(
                L"Will delete stderr SilentRunner JSONL log; path=" + logPaths.running.stderrSrJsonl
            );
        }
    }


    bool fileSinkPausedForLogFinalization = false;

    if (prepared.fileSinkWorker) {
        fileSinkPausedForLogFinalization =
            prepared.fileSinkWorker->PauseAfterCurrentJob();
    }
    ClosePreparedRuntimeFiles(prepared);

    bool stdoutFinalLogAvailable = false;
    bool stderrFinalLogAvailable = false;
    bool stderrChildFinalLogAvailable = false;
    bool stderrSrFinalLogAvailable = false;
    bool stdoutJsonlFinalLogAvailable = false;
    bool stderrJsonlFinalLogAvailable = false;
    bool stderrChildJsonlFinalLogAvailable = false;
    bool stderrSrJsonlFinalLogAvailable = false;

    if (!opt.stdoutDir.empty() && !logPaths.running.stdoutTxt.empty()) {
        if (keepStdoutLog) {
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

    if (!opt.stderrDir.empty() && !logPaths.running.stderrMixedTxt.empty()) {
        if (keepStderrLog) {
            DWORD gle = 0;
            if (LogWriter::TryRenameLogFile(logPaths.running.stderrMixedTxt, stderrLogPathForHook, &gle)) {
                stderrFinalLogAvailable = true;
                lifecycleDiag.InfoLine(
                    L"STDERR_LOG_FINAL=" + stderrLogPathForHook
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to rename stderr log; from=" + logPaths.running.stderrMixedTxt +
                    L" to=" + stderrLogPathForHook + L" " + ErrorHelpers::FormatGle(gle)
                );
                stderrLogPathForHook.clear();
            }
        } else {
            DWORD gle = 0;
            if (LogWriter::TryDeleteLogFile(logPaths.running.stderrMixedTxt, &gle)) {
                lifecycleDiag.InfoLine(
                    L"STDERR_LOG_REMOVED=" + logPaths.running.stderrMixedTxt
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to delete stderr log; path=" + logPaths.running.stderrMixedTxt +
                    L" " + ErrorHelpers::FormatGle(gle)
                );
            }
        }
    }

    if (!opt.stderrChildDir.empty() && !logPaths.running.stderrChildTxt.empty()) {
        if (keepStderrChildLog) {
            DWORD gle = 0;
            if (LogWriter::TryRenameLogFile(logPaths.running.stderrChildTxt, stderrChildLogPathForHook, &gle)) {
                stderrChildFinalLogAvailable = true;
                lifecycleDiag.InfoLine(
                    L"STDERR_CHILD_LOG_FINAL=" + stderrChildLogPathForHook
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to rename stderr child log; from=" + logPaths.running.stderrChildTxt +
                    L" to=" + stderrChildLogPathForHook + L" " + ErrorHelpers::FormatGle(gle)
                );
                stderrChildLogPathForHook.clear();
            }
        } else {
            DWORD gle = 0;
            if (LogWriter::TryDeleteLogFile(logPaths.running.stderrChildTxt, &gle)) {
                lifecycleDiag.InfoLine(
                    L"STDERR_CHILD_LOG_REMOVED=" + logPaths.running.stderrChildTxt
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to delete stderr child log; path=" + logPaths.running.stderrChildTxt +
                    L" " + ErrorHelpers::FormatGle(gle)
                );
            }
        }
    }

    if (!opt.stderrSrDir.empty() && !logPaths.running.stderrSrTxt.empty()) {
        if (keepStderrSrLog) {
            DWORD gle = 0;
            if (LogWriter::TryRenameLogFile(logPaths.running.stderrSrTxt, stderrSrLogPathForHook, &gle)) {
                stderrSrFinalLogAvailable = true;
                lifecycleDiag.InfoLine(
                    L"STDERR_SR_LOG_FINAL=" + stderrSrLogPathForHook
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to rename stderr SilentRunner log; from=" + logPaths.running.stderrSrTxt +
                    L" to=" + stderrSrLogPathForHook + L" " + ErrorHelpers::FormatGle(gle)
                );
                stderrSrLogPathForHook.clear();
            }
        } else {
            DWORD gle = 0;
            if (LogWriter::TryDeleteLogFile(logPaths.running.stderrSrTxt, &gle)) {
                lifecycleDiag.InfoLine(
                    L"STDERR_SR_LOG_REMOVED=" + logPaths.running.stderrSrTxt
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to delete stderr SilentRunner log; path=" + logPaths.running.stderrSrTxt +
                    L" " + ErrorHelpers::FormatGle(gle)
                );
            }
        }
    }
    if (!opt.stdoutJsonlDir.empty() && !logPaths.running.stdoutJsonl.empty()) {
        if (keepStdoutJsonlLog) {
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

    if (!opt.stderrJsonlDir.empty() && !logPaths.running.stderrMixedJsonl.empty()) {
        if (keepStderrJsonlLog) {
            DWORD gle = 0;
            if (LogWriter::TryRenameLogFile(logPaths.running.stderrMixedJsonl, stderrJsonlLogPathForFinal, &gle)) {
                stderrJsonlFinalLogAvailable = true;
                lifecycleDiag.InfoLine(
                    L"STDERR_JSONL_LOG_FINAL=" + stderrJsonlLogPathForFinal
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to rename stderr JSONL log; from=" + logPaths.running.stderrMixedJsonl +
                    L" to=" + stderrJsonlLogPathForFinal + L" " + ErrorHelpers::FormatGle(gle)
                );
                stderrJsonlLogPathForFinal.clear();
            }
        } else {
            DWORD gle = 0;
            if (LogWriter::TryDeleteLogFile(logPaths.running.stderrMixedJsonl, &gle)) {
                lifecycleDiag.InfoLine(
                    L"STDERR_JSONL_LOG_REMOVED=" + logPaths.running.stderrMixedJsonl
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to delete stderr JSONL log; path=" + logPaths.running.stderrMixedJsonl +
                    L" " + ErrorHelpers::FormatGle(gle)
                );
            }
        }
    }

    if (!opt.stderrChildJsonlDir.empty() && !logPaths.running.stderrChildJsonl.empty()) {
        if (keepStderrChildJsonlLog) {
            DWORD gle = 0;
            if (LogWriter::TryRenameLogFile(logPaths.running.stderrChildJsonl, stderrChildJsonlLogPathForFinal, &gle)) {
                stderrChildJsonlFinalLogAvailable = true;
                lifecycleDiag.InfoLine(
                    L"STDERR_CHILD_JSONL_LOG_FINAL=" + stderrChildJsonlLogPathForFinal
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to rename stderr child JSONL log; from=" + logPaths.running.stderrChildJsonl +
                    L" to=" + stderrChildJsonlLogPathForFinal + L" " + ErrorHelpers::FormatGle(gle)
                );
                stderrChildJsonlLogPathForFinal.clear();
            }
        } else {
            DWORD gle = 0;
            if (LogWriter::TryDeleteLogFile(logPaths.running.stderrChildJsonl, &gle)) {
                lifecycleDiag.InfoLine(
                    L"STDERR_CHILD_JSONL_LOG_REMOVED=" + logPaths.running.stderrChildJsonl
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to delete stderr child JSONL log; path=" + logPaths.running.stderrChildJsonl +
                    L" " + ErrorHelpers::FormatGle(gle)
                );
            }
        }
    }

    if (!opt.stderrSrJsonlDir.empty() && !logPaths.running.stderrSrJsonl.empty()) {
        if (keepStderrSrJsonlLog) {
            DWORD gle = 0;
            if (LogWriter::TryRenameLogFile(logPaths.running.stderrSrJsonl, stderrSrJsonlLogPathForFinal, &gle)) {
                stderrSrJsonlFinalLogAvailable = true;
                lifecycleDiag.InfoLine(
                    L"STDERR_SR_JSONL_LOG_FINAL=" + stderrSrJsonlLogPathForFinal
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to rename stderr SilentRunner JSONL log; from=" + logPaths.running.stderrSrJsonl +
                    L" to=" + stderrSrJsonlLogPathForFinal + L" " + ErrorHelpers::FormatGle(gle)
                );
                stderrSrJsonlLogPathForFinal.clear();
            }
        } else {
            DWORD gle = 0;
            if (LogWriter::TryDeleteLogFile(logPaths.running.stderrSrJsonl, &gle)) {
                lifecycleDiag.InfoLine(
                    L"STDERR_SR_JSONL_LOG_REMOVED=" + logPaths.running.stderrSrJsonl
                );
            } else {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    L"Failed to delete stderr SilentRunner JSONL log; path=" + logPaths.running.stderrSrJsonl +
                    L" " + ErrorHelpers::FormatGle(gle)
                );
            }
        }
    }


    if (stdoutFinalLogAvailable) {
        DWORD gle = 0;
        if (prepared.stdoutLogWriter.OpenAppendFile(stdoutLogPathForHook, &gle)) {
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
        if (prepared.stderrLogWriter.OpenAppendFile(stderrLogPathForHook, &gle)) {
            lifecycleDiag.DebugLine(
                L"Reopened stderr log for append OK; path=" + stderrLogPathForHook
            );
        } else {
            SetInternalFailureExitCode_(exitCode);
            lifecycleDiag.ErrorLine(
                L"Failed to reopen stderr log for append; path=" +
                stderrLogPathForHook + L" " + ErrorHelpers::FormatGle(gle)
            );
            stderrLogPathForHook.clear();
        }
    }

    if (stderrChildFinalLogAvailable) {
        DWORD gle = 0;
        if (prepared.stderrChildLogWriter.OpenAppendFile(stderrChildLogPathForHook, &gle)) {
            lifecycleDiag.DebugLine(
                L"Reopened stderr child log for append OK; path=" + stderrChildLogPathForHook
            );
        } else {
            SetInternalFailureExitCode_(exitCode);
            lifecycleDiag.ErrorLine(
                L"Failed to reopen stderr child log for append; path=" +
                stderrChildLogPathForHook + L" " + ErrorHelpers::FormatGle(gle)
            );
            stderrChildLogPathForHook.clear();
            stderrChildFinalLogAvailable = false;
        }
    }

    if (stderrSrFinalLogAvailable) {
        DWORD gle = 0;
        if (prepared.stderrSrLogWriter.OpenAppendFile(stderrSrLogPathForHook, &gle)) {
            lifecycleDiag.DebugLine(
                L"Reopened stderr SilentRunner log for append OK; path=" + stderrSrLogPathForHook
            );
        } else {
            SetInternalFailureExitCode_(exitCode);
            lifecycleDiag.ErrorLine(
                L"Failed to reopen stderr SilentRunner log for append; path=" +
                stderrSrLogPathForHook + L" " + ErrorHelpers::FormatGle(gle)
            );
            stderrSrLogPathForHook.clear();
        }
    }
    if (stdoutJsonlFinalLogAvailable) {
        DWORD gle = 0;
        if (prepared.stdoutJsonlWriter.OpenAppendFile(stdoutJsonlLogPathForFinal, &gle)) {
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
        if (prepared.stderrJsonlWriter.OpenAppendFile(stderrJsonlLogPathForFinal, &gle)) {
            lifecycleDiag.DebugLine(
                L"Reopened stderr JSONL log for append OK; path=" + stderrJsonlLogPathForFinal
            );
        } else {
            SetInternalFailureExitCode_(exitCode);
            lifecycleDiag.ErrorLine(
                L"Failed to reopen stderr JSONL log for append; path=" +
                stderrJsonlLogPathForFinal + L" " + ErrorHelpers::FormatGle(gle)
            );
            stderrJsonlLogPathForFinal.clear();
            stderrJsonlFinalLogAvailable = false;
        }
    }

    if (stderrChildJsonlFinalLogAvailable) {
        DWORD gle = 0;
        if (prepared.stderrChildJsonlWriter.OpenAppendFile(stderrChildJsonlLogPathForFinal, &gle)) {
            lifecycleDiag.DebugLine(
                L"Reopened stderr child JSONL log for append OK; path=" + stderrChildJsonlLogPathForFinal
            );
        } else {
            SetInternalFailureExitCode_(exitCode);
            lifecycleDiag.ErrorLine(
                L"Failed to reopen stderr child JSONL log for append; path=" +
                stderrChildJsonlLogPathForFinal + L" " + ErrorHelpers::FormatGle(gle)
            );
            stderrChildJsonlLogPathForFinal.clear();
            stderrChildJsonlFinalLogAvailable = false;
        }
    }

    if (stderrSrJsonlFinalLogAvailable) {
        DWORD gle = 0;
        if (prepared.stderrSrJsonlWriter.OpenAppendFile(stderrSrJsonlLogPathForFinal, &gle)) {
            lifecycleDiag.DebugLine(
                L"Reopened stderr SilentRunner JSONL log for append OK; path=" + stderrSrJsonlLogPathForFinal
            );
        } else {
            SetInternalFailureExitCode_(exitCode);
            lifecycleDiag.ErrorLine(
                L"Failed to reopen stderr SilentRunner JSONL log for append; path=" +
                stderrSrJsonlLogPathForFinal + L" " + ErrorHelpers::FormatGle(gle)
            );
            stderrSrJsonlLogPathForFinal.clear();
            stderrSrJsonlFinalLogAvailable = false;
        }
    }


    if (fileSinkPausedForLogFinalization) {
        prepared.fileSinkWorker->AttachLogWriters(
            stdoutFinalLogAvailable && prepared.stdoutLogWriter.IsOpen(),
            prepared.stdoutLogWriter.IsOpen() ? &prepared.stdoutLogWriter : nullptr,
            stdoutLogPathForHook,
            stderrFinalLogAvailable && prepared.stderrLogWriter.IsOpen(),
            prepared.stderrLogWriter.IsOpen() ? &prepared.stderrLogWriter : nullptr,
            stderrLogPathForHook,
            stderrChildFinalLogAvailable && prepared.stderrChildLogWriter.IsOpen(),
            prepared.stderrChildLogWriter.IsOpen() ? &prepared.stderrChildLogWriter : nullptr,
            stderrChildLogPathForHook,
            stderrSrFinalLogAvailable && prepared.stderrSrLogWriter.IsOpen(),
            prepared.stderrSrLogWriter.IsOpen() ? &prepared.stderrSrLogWriter : nullptr,
            stderrSrLogPathForHook
        );
        prepared.fileSinkWorker->AttachJsonlWriters(
            stdoutJsonlFinalLogAvailable && prepared.stdoutJsonlWriter.IsOpen(),
            prepared.stdoutJsonlWriter.IsOpen() ? &prepared.stdoutJsonlWriter : nullptr,
            stdoutJsonlLogPathForFinal,
            stderrJsonlFinalLogAvailable && prepared.stderrJsonlWriter.IsOpen(),
            prepared.stderrJsonlWriter.IsOpen() ? &prepared.stderrJsonlWriter : nullptr,
            stderrJsonlLogPathForFinal,
            stderrChildJsonlFinalLogAvailable && prepared.stderrChildJsonlWriter.IsOpen(),
            prepared.stderrChildJsonlWriter.IsOpen() ? &prepared.stderrChildJsonlWriter : nullptr,
            stderrChildJsonlLogPathForFinal,
            stderrSrJsonlFinalLogAvailable && prepared.stderrSrJsonlWriter.IsOpen(),
            prepared.stderrSrJsonlWriter.IsOpen() ? &prepared.stderrSrJsonlWriter : nullptr,
            stderrSrJsonlLogPathForFinal
        );
        prepared.fileSinkWorker->Resume();
    }

    const bool hookSuccess = (exitCode == 0);
    const std::wstring& hookPath = hookSuccess ? opt.runOnSuccess : opt.runOnFailure;
    const wchar_t* hookType = hookSuccess ? L"success" : L"failure";

    const std::vector<SRRunHook::EnvironmentVariable> hookEnvironment{
        { L"SILENTRUNNER_EXIT_CODE", std::to_wstring(exitCode) },
        { L"SILENTRUNNER_EXECUTION_ID", prepared.executionId },
        { L"SILENTRUNNER_STDOUT_LOG", stdoutLogPathForHook },
        { L"SILENTRUNNER_STDOUT_JSONL_LOG", stdoutJsonlFinalLogAvailable ? stdoutJsonlLogPathForFinal : L"" },
        { L"SILENTRUNNER_STDERR_LOG", stderrLogPathForHook },
        { L"SILENTRUNNER_STDERR_JSONL_LOG", stderrJsonlFinalLogAvailable ? stderrJsonlLogPathForFinal : L"" },
        { L"SILENTRUNNER_STDERR_CHILD_LOG", stderrChildLogPathForHook },
        { L"SILENTRUNNER_STDERR_CHILD_JSONL_LOG", stderrChildJsonlFinalLogAvailable ? stderrChildJsonlLogPathForFinal : L"" },
        { L"SILENTRUNNER_STDERR_SR_LOG", stderrSrLogPathForHook },
        { L"SILENTRUNNER_STDERR_SR_JSONL_LOG", stderrSrJsonlFinalLogAvailable ? stderrSrJsonlLogPathForFinal : L"" }
    };
    if (!hookPath.empty()) {
        for (const SRRunHook::EnvironmentVariable& variable : hookEnvironment) {
            lifecycleDiag.DebugLine(
                std::wstring(L"Run-on-") + hookType +
                L" hook environment " + variable.name + L"=" + variable.value
            );
        }
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


    if (prepared.fileSinkWorker &&
        prepared.workerSupervisor &&
        prepared.workerSupervisor->IsWorkerAvailable(
            SR::JobTargetWorker::SRFileSinkWorker
        )) {
        prepared.fileSinkWorker->Drain();
    }
    if (prepared.parentEmitWorker &&
        prepared.workerSupervisor &&
        prepared.workerSupervisor->IsWorkerAvailable(
            SR::JobTargetWorker::SRParentEmitWorker
        )) {
        prepared.parentEmitWorker->Drain();
    }

    if (opt.verbose && !noDiagnosticChannel && executionTimelineOrNull && prepared.jobsExchange) {
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
            prepared.jobsExchange->EnqueuePendingJobs(finalHarvestJobs);

            if (prepared.fileSinkWorker &&
                prepared.workerSupervisor &&
                prepared.workerSupervisor->IsWorkerAvailable(
                    SR::JobTargetWorker::SRFileSinkWorker
                )) {
                prepared.fileSinkWorker->Drain();
            }
            if (prepared.parentEmitWorker &&
                prepared.workerSupervisor &&
                prepared.workerSupervisor->IsWorkerAvailable(
                    SR::JobTargetWorker::SRParentEmitWorker
                )) {
                prepared.parentEmitWorker->Drain();
            }
        }
    }

    if (prepared.fileSinkWorker) {
        prepared.fileSinkWorker->DrainAndStop();
    }
    if (prepared.parentEmitWorker) {
        prepared.parentEmitWorker->DrainAndStop();
    }
    ClosePreparedRuntimeFiles(prepared);
    if (!hookPath.empty()) {
        DWORD hookGle = 0;
        DWORD hookPid = 0;
    
        if (!SRRunHook::RunHookDetached(
                hookPath,
                opt.cwd,
                hookEnvironment,
                hookGle,
                hookPid
            )) {
            lifecycleDiag.ProbeLine(
                std::wstring(L"[RUN-HOOK] Run-on-") + hookType +
                L" hook start failed; path=" + hookPath +
                L" " + ErrorHelpers::FormatGle(hookGle)
            );
        } else {
            lifecycleDiag.ProbeLine(
                std::wstring(L"[RUN-HOOK] Run-on-") + hookType +
                L" hook started; pid=" + std::to_wstring(hookPid) +
                L" path=" + hookPath
            );
        }
    }
    return exitCode;
}
