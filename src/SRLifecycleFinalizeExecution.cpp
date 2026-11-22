
#include "SRLifecycleFinalizeExecution.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "ErrorHelpers.h"
#include "FileHelpers.h"
#include "TextHelpers.h"

#include "SRExecutionTimeline.h"
#include "SRExecutionTimelineDiagnostics.h"
#include "SRLifecycleDiagnostics.h"
#include "SRJobsExchange.h"
#include "SRParentEmitPolicy.h"
#include "SRParentReplayRouter.h"
#include "SRTargetLogFiles.h"
#include "SRPendingJobTypes.h"
#include "SRReplayJsonlToParent.h"
#include "SRReplayTxtToParent.h"
#include "SRRunHook.h"
#include "SRRuntime.h"
#include "SRTypes.h"
#include "SRWorkerSupervisor.h"
#include "SRWorkers.h"


static std::wstring FormatLogWriterFailure_(
    const wchar_t* operation,
    const LogWriterFailure& failure
) {
    return
        std::wstring(operation) +
        L"(target=" +
        SR::JobTargetNameToString(failure.target) +
        L") failed; " +
        ErrorHelpers::FormatGle(failure.gle);
}
static void SetInternalFailureExitCode_(int& exitCode) noexcept {
    exitCode = 255;
}

static bool IsSuccess_(int exitCode) noexcept {
    return exitCode == 0;
}
static bool HasWorkerOperationalFailure_(
    const SR::SRWorkerSupervisor& supervisor
) {
    const auto fileSinkFailure =
        supervisor.RetrieveWorkerOperationalFailure(
            SR::JobTargetWorker::SRFileSinkWorker
        );

    if (const auto* failure =
            std::get_if<SR::FileSinkWorkerFailureState>(
                &fileSinkFailure
            )) {
        if (std::any_of(
                failure->targets.begin(),
                failure->targets.end(),
                [](const auto& targetFailure) {
                    return targetFailure.suppressed;
                }
            )) {
            return true;
        }
    }

    const auto parentEmitFailure =
        supervisor.RetrieveWorkerOperationalFailure(
            SR::JobTargetWorker::SRParentEmitWorker
        );

    if (const auto* failure =
            std::get_if<SR::ParentEmitWorkerFailureState>(
                &parentEmitFailure
            )) {
        return
            failure->workerStdoutFailure.suppressed ||
            failure->workerStderrFailure.suppressed;
    }

    return false;
}

static void ApplyWorkerOperationalFailureExitCode_(
    const SR::SRWorkerSupervisor* supervisor,
    int& exitCode
) {
    if (supervisor &&
        HasWorkerOperationalFailure_(*supervisor)) {
        SetInternalFailureExitCode_(exitCode);
    }
}
static void ApplyWorkerFatalFailureExitCode_(
    const SR::SRWorkerSupervisor* supervisor,
    int& exitCode
) {
    if (!supervisor ||
        supervisor->RetrieveWorkerFailures().empty()) {
        return;
    }

    SetInternalFailureExitCode_(exitCode);
}

enum class WorkerWriteFailureMode {
    Diagnostics,
    HookEnvironment
};

static std::wstring ProcessWorkerWriteFailures_(
    const SR::SRWorkerSupervisor* supervisor,
    SRLifecycleDiagnostics& lifecycleDiag,
    WorkerWriteFailureMode mode
) {
    if (!supervisor) {
        return L"outputWriteFailures_0=[]";
    }

    std::wstring entries;
    uint32_t failureCount = 0;

    const auto processFailure = [&](
        const wchar_t* targetName,
        uint32_t gle,
        const std::wstring& reason
    ) {
        if (mode == WorkerWriteFailureMode::Diagnostics) {
            lifecycleDiag.ErrorLine(
                L"Output write failure: target=" +
                std::wstring(targetName) +
                L" reason=" + (reason.empty() ? L"(none)" : reason) +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            return;
        }

        if (!entries.empty()) {
            entries += L",";
        }
        entries += targetName;
        entries += L"_GLE=" + std::to_wstring(gle);
        ++failureCount;
    };

    const auto fileSinkFailure = supervisor->RetrieveWorkerOperationalFailure(
        SR::JobTargetWorker::SRFileSinkWorker
    );
    if (const auto* failure =
            std::get_if<SR::FileSinkWorkerFailureState>(&fileSinkFailure)) {
        for (const auto& targetFailure : failure->targets) {
            if (targetFailure.suppressed) {
                processFailure(
                    SR::JobTargetNameToString(targetFailure.target),
                    targetFailure.gle,
                    targetFailure.reason
                );
            }
        }
    }

    const auto parentEmitFailure = supervisor->RetrieveWorkerOperationalFailure(
        SR::JobTargetWorker::SRParentEmitWorker
    );
    if (const auto* failure =
            std::get_if<SR::ParentEmitWorkerFailureState>(&parentEmitFailure)) {
        if (failure->workerStdoutFailure.suppressed) {
            processFailure(
                L"ParentStdout",
                failure->workerStdoutFailure.gle,
                failure->workerStdoutFailure.reason
            );
        }
        if (failure->workerStderrFailure.suppressed) {
            processFailure(
                L"ParentStderr",
                failure->workerStderrFailure.gle,
                failure->workerStderrFailure.reason
            );
        }
    }

    if (mode == WorkerWriteFailureMode::Diagnostics) {
        return {};
    }
    return L"outputWriteFailures_" + std::to_wstring(failureCount) +
        L"=[" + entries + L"]";
}


// Best-effort finalization over a partially or fully prepared runtime state.
// Individual resources may be absent depending on earlier failures,
// replay mode, or logging configuration.
// The lifecycle phase is provided externally as contextual origin.
int FinalizeExecution(
    const SR::FinalizeExecutionConfig& config,
    SRWorkers& workers,
    SRTargetLogFiles& logFiles,
    const SR::WorkerTargetLayout<SR::JobTargetWorker::SRFileSinkWorker>& fileSinkTargetLayout,
    SRParentEmitPolicy& parentEmitPolicy,
    const std::string& parsingToken,
    int exitCode,
    SRLifecycleDiagnostics& lifecycleDiag,
    const SRRuntimeResult* runtimeResultOrNull,
    ExecutionTimeline* executionTimelineOrNull,
    std::optional<int> prepareExitCode,
    std::optional<int> runtimeExitCode
) {
    // Finalization is best-effort and must not short-circuit on controlled
    // cleanup/log failures. Such failures may downgrade exitCode to 255
    // and clear hook-visible log paths. The selected post-execution hook is
    // started only after routing, workers, and log file writers are finalized.
    
    lifecycleDiag.DebugLine(
        L"FinalizeExecution procedure starts"
    );
    const bool abortedOnRuntimeFailure =
        runtimeResultOrNull && runtimeResultOrNull->abortedOnRuntimeFailure;
    const std::wstring abortedOnRuntimeFailureValue =
        abortedOnRuntimeFailure ? L"true" : L"false";
    lifecycleDiag.InfoLine(
        L"SILENTRUNNER_ABORTED_ON_RUNTIME_FAILURE=" + abortedOnRuntimeFailureValue
    );

    bool allOutputWorkersFailed = false;
    const SR::JobTargetFilter allLogTargets;

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
                SetInternalFailureExitCode_(exitCode);

                allOutputWorkersFailed = true;

                if (executionTimelineOrNull) {
                    executionTimelineOrNull->StopRouting();
                }
            }
        }
    }
    // Include write failures recorded during Prepare or Runtime before
    // choosing the success/failure parent replay policy.
    ApplyWorkerOperationalFailureExitCode_(
        workers.supervisor.get(),
        exitCode
    );


    SR::ParentReplayPolicySnapshot replayPolicySnapshot;

    replayPolicySnapshot.stdoutParentTarget =
        parentEmitPolicy.StdoutParentTarget();
    replayPolicySnapshot.stderrParentTarget =
        parentEmitPolicy.StderrParentTarget();

    replayPolicySnapshot.stdoutEmitMode =
        parentEmitPolicy.RetrieveTargetEmitMode(
            replayPolicySnapshot.stdoutParentTarget
        );
    replayPolicySnapshot.stderrEmitMode =
        parentEmitPolicy.RetrieveTargetEmitMode(
            replayPolicySnapshot.stderrParentTarget
        );

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

    if (!allOutputWorkersFailed && parentReplayRequested) {
        bool fileSinkPausedForReplay = false;
        SR::JobTargetFilter replayLogFilter;
        for (const auto& source : SR::kParentReplaySourceLayout.entries) {
            if ((stdoutReplayRequested &&
                 source.parentTarget == replayPolicySnapshot.stdoutParentTarget) ||
                (stderrReplayRequested &&
                 source.parentTarget == replayPolicySnapshot.stderrParentTarget)) {
                replayLogFilter.targets.push_back(source.sourceTarget);
            }
        }

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

        if (persistentReplaySyncNeeded) {
            LogWriterFailure flushFailure;
            if (!logFiles.FlushRunningWriters(
                    replayLogFilter,
                    &flushFailure
                )) {
                SetInternalFailureExitCode_(exitCode);
                lifecycleDiag.ErrorLine(
                    FormatLogWriterFailure_(
                        L"FlushFileBuffers",
                        flushFailure
                    )
                );
            }
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
                config.stdoutTxtHeaderGranularity,
                config.stderrChildTxtHeaderGranularity,

                1u << 15
            ) &&

            replayJsonlToParent.Init(&lifecycleDiag) &&
            parentReplayRouter.Init(
                lifecycleDiag,
                SR::kParentReplaySourceLayout
            );

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

            const auto replayLogPaths =
                logFiles.BuildRunningPathBindings(replayLogFilter);
            if (!parentReplayRouter.ReplayToParent(
                    replayPolicySnapshot,
            executionSucceededBeforeReplay,
                    replayLogPaths
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

    LogWriterFailure flushFailure;
    if (!logFiles.FlushRunningWriters(
            allLogTargets,
            &flushFailure
        )) {
        SetInternalFailureExitCode_(exitCode);
        lifecycleDiag.ErrorLine(
            FormatLogWriterFailure_(
                L"FlushFileBuffers",
                flushFailure
            )
        );
    }

    // Include write failures observed during replay and running-log flush
    // before freezing the log retention and finalization decision.
    ApplyWorkerOperationalFailureExitCode_(
        workers.supervisor.get(),
        exitCode
    );
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

    bool fileSinkPausedForLogFinalization = false;

    if (workers.fileSink) {
        fileSinkPausedForLogFinalization =
            workers.fileSink->PauseAfterCurrentJob();
    }
    LogWriterFailure runningCloseFailure;
    if (!logFiles.CloseRunningWriters(
            allLogTargets,
            &runningCloseFailure
        )) {
        SetInternalFailureExitCode_(exitCode);
        lifecycleDiag.ErrorLine(
            FormatLogWriterFailure_(
                L"CloseHandle",
                runningCloseFailure
            )
        );
    }

    std::vector<TargetLogFinalizationResult> logFinalizationResults;
    if (!logFiles.FinalizeRunningLogs(
            logFinalizationSuccess,
            logFinalizationResults
        )) {
        SetInternalFailureExitCode_(exitCode);
    }
    for (const auto& result : logFinalizationResults) {
        const auto targetIndex = fileSinkTargetLayout.ConfigIndexOf(result.target);
        const SR::WorkerTargetLayoutEntry* targetLayoutEntry =
            targetIndex < fileSinkTargetLayout.targets.size()
                ? &fileSinkTargetLayout.targets[targetIndex]
                : nullptr;
        const std::wstring diagnosticText =
            targetLayoutEntry && targetLayoutEntry->logDiagnosticText
                ? targetLayoutEntry->logDiagnosticText
                : L"log";
        if (result.action ==
            TargetLogFinalizationAction::Rename) {
            if (!result.succeeded) {
                lifecycleDiag.ErrorLine(
                    L"Failed to rename " +
                    diagnosticText +
                    L"; from=" +
                    result.runningPath +
                    L" to=" +
                    result.finalPath +
                    L" " +
                    ErrorHelpers::FormatGle(result.gle)
                );
            }
        } else if (
            result.action ==
            TargetLogFinalizationAction::Delete
        ) {
            if (!result.succeeded) {
                lifecycleDiag.ErrorLine(
                    L"Failed to delete " +
                    diagnosticText +
                    L"; path=" +
                    result.runningPath +
                    L" " +
                    ErrorHelpers::FormatGle(result.gle)
                );
            }
        }
    }


    LogWriterFailure reopenFailure;
    if (!logFiles.ReopenFinalWriters(
            allLogTargets,
            logFinalizationSuccess,
            &reopenFailure
        )) {
        SetInternalFailureExitCode_(exitCode);
        lifecycleDiag.ErrorLine(
            FormatLogWriterFailure_(
                L"OpenAppendFile",
                reopenFailure
            )
        );
    }


    if (fileSinkPausedForLogFinalization) {
        SR::JobTargetFilter txtLogFilter;
        txtLogFilter.format = SR::JobTargetFormat::Txt;
        SR::JobTargetFilter jsonlLogFilter;
        jsonlLogFilter.format = SR::JobTargetFormat::Jsonl;
        workers.fileSink->AttachTxtLogWriters(
            logFiles.BuildFinalBindings(
                txtLogFilter,
                logFinalizationSuccess
            )
        );
        workers.fileSink->AttachJsonlLogWriters(
            logFiles.BuildFinalBindings(
                jsonlLogFilter,
                logFinalizationSuccess
            )
        );
        workers.fileSink->Resume();
    }

    const auto finalLogPaths = logFiles.GetFinalLogPaths();

    // Report retained final log paths after reopening the final writers.
    for (const TargetLogPathBinding& binding : finalLogPaths) {
        if (!binding.created || !binding.path) {
            continue;
        }

        const std::size_t targetIndex =
            fileSinkTargetLayout.ConfigIndexOf(binding.target);
        if (targetIndex >= fileSinkTargetLayout.targets.size()) {
            continue;
        }

        const auto& targetLayoutEntry =
            fileSinkTargetLayout.targets[targetIndex];
        if (!targetLayoutEntry.logFileKey) {
            continue;
        }

        lifecycleDiag.InfoLine(
            std::wstring(targetLayoutEntry.logFileKey) +
            L"=" + *binding.path
        );
    }

    if (executionTimelineOrNull) {
        executionTimelineOrNull->EndCurrentPhase();
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

    if (config.verbose && !allOutputWorkersFailed && executionTimelineOrNull && workers.jobsExchange) {

        SR::EventSummary finalHarvestEventSummary;
        if (executionTimelineOrNull->BuildFinalHarvestEventSummary(
                finalHarvestEventSummary
            )) {
            SR::PendingJob finalHarvestJob;
            finalHarvestJob.payloadType = SR::JobPayloadType::SrDiag;
            finalHarvestJob.key = finalHarvestEventSummary.eventKey;
            finalHarvestJob.srDiag.key = finalHarvestJob.key;
            finalHarvestJob.srDiag.timestampUtc =
                FileHelpers::MakeEventUtcTimestamp();
            finalHarvestJob.srDiag.severity =
                SR::DiagnosticSeverity::Verbose;
            finalHarvestJob.srDiag.message =
                SR::FormatFinalEventSummary(finalHarvestEventSummary);
            finalHarvestJob.srDiag.payloadByteCount =
                static_cast<uint64_t>(
                    TextHelpers::Utf16ToUtf8ByteCount(
                        finalHarvestJob.srDiag.message
                    )
                );

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
    ProcessWorkerWriteFailures_(
        workers.supervisor.get(),
        lifecycleDiag,
        WorkerWriteFailureMode::Diagnostics
    );
    lifecycleDiag.DebugLine(
        L"FinalizeExecution procedure ends"
    );

    // Complete all diagnostics emitted before the final result.
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

    ApplyWorkerOperationalFailureExitCode_(
        workers.supervisor.get(),
        exitCode
    );
    ApplyWorkerFatalFailureExitCode_(
        workers.supervisor.get(),
        exitCode
    );

    // The final INFO is the only ordinary diagnostic emitted after
    // the finalization procedure has completed.
    lifecycleDiag.InfoLine(
        L"SilentRunner ends; " +
            SR::ExecutionExitCodeKey() + L"=" + std::to_wstring(exitCode)
    );

    if (executionTimelineOrNull) {
        executionTimelineOrNull->StopRouting();
    }


    if (workers.fileSink) {
        workers.fileSink->DrainAndStop();
    }
    if (workers.parentEmit) {
        workers.parentEmit->DrainAndStop();
    }
    // Include failures caused by writing the final INFO itself.
    ApplyWorkerOperationalFailureExitCode_(
        workers.supervisor.get(),
        exitCode
    );
    ApplyWorkerFatalFailureExitCode_(
        workers.supervisor.get(),
        exitCode
    );
    LogWriterFailure finalCloseFailure;
    if (!logFiles.CloseFinalWriters(
            allLogTargets,
            logFinalizationSuccess,
            &finalCloseFailure
        )) {
        SetInternalFailureExitCode_(exitCode);
        lifecycleDiag.ProbeLine(
            FormatLogWriterFailure_(
                L"CloseHandle",
                finalCloseFailure
            )
        );
    }
    if (!config.comspecPath.empty() &&
        !(IsSuccess_(exitCode) ? config.runOnSuccessPath : config.runOnFailurePath).empty()) {

        std::vector<SRRunHook::EnvironmentVariable> hookEnvironment{
            { SR::ExecutionExitCodeKey(), std::to_wstring(exitCode) },
            { L"SILENTRUNNER_EXECUTION_ID", config.executionId },
            { L"SILENTRUNNER_ABORTED_ON_RUNTIME_FAILURE", abortedOnRuntimeFailureValue }
        };
        hookEnvironment.reserve(
            6 + fileSinkTargetLayout.targets.size()
        );

        hookEnvironment.push_back({
            L"SILENTRUNNER_OUTPUT_WRITE_FAILURES",
            ProcessWorkerWriteFailures_(
                workers.supervisor.get(),
                lifecycleDiag,
                WorkerWriteFailureMode::HookEnvironment
            )
        });
        if (prepareExitCode.has_value()) {
            hookEnvironment.push_back({
                SR::ExecutionExitCodeKey(SR::LifecyclePhase::Prepare),
                std::to_wstring(*prepareExitCode)
            });
        }

        if (runtimeExitCode.has_value()) {
            hookEnvironment.push_back({
                SR::ExecutionExitCodeKey(SR::LifecyclePhase::Runtime),
                std::to_wstring(*runtimeExitCode)
            });
        }
        for (const TargetLogPathBinding& binding : finalLogPaths) {
            const std::size_t targetIndex =
                fileSinkTargetLayout.ConfigIndexOf(binding.target);
            if (targetIndex >= fileSinkTargetLayout.targets.size()) {
                continue;
            }

            const auto& targetLayoutEntry =
                fileSinkTargetLayout.targets[targetIndex];
            if (!targetLayoutEntry.logFileKey) {
                continue;
            }

            hookEnvironment.push_back({
                targetLayoutEntry.logFileKey,
                binding.created && binding.path
                    ? *binding.path
                    : std::wstring{}
            });
        }
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
            config.comspecPath,
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
            exitCode = 253;
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
