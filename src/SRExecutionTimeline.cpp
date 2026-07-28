#include "SRExecutionTimeline.h"

#include "FileHelpers.h"
#include "SRLifecycleDiagnostics.h"
#include "SRReplayJobsBatch.h"


#include <algorithm>
#include <iterator>

#include <vector>
#include <type_traits>


bool ExecutionTimeline::Init() {
    std::lock_guard<std::mutex> lock(mutex_);

    prepareTimeline_.Reset(
        SR::LifecyclePhase::Prepare,
        static_cast<uint32_t>(SR::LifecyclePhase::Prepare),
        SR::LifecyclePhaseToString(SR::LifecyclePhase::Prepare)
    );

    runtimeTimeline_.Reset(
        SR::LifecyclePhase::Runtime,
        static_cast<uint32_t>(SR::LifecyclePhase::Runtime),
        SR::LifecyclePhaseToString(SR::LifecyclePhase::Runtime)
    );

    currentPhase_ = nullptr;
    jobQueue_.clear();
    parentEmitPolicy_ = nullptr;
    routingStopped_ = false;
    cachedBufferUsage_.Store(SR::BufferUsage{});
    return true;
}
    

PhaseContext ExecutionTimeline::PrepareContext() noexcept {
    return PhaseContext(&prepareTimeline_);
}

PhaseContext ExecutionTimeline::RuntimeContext() noexcept {
    return PhaseContext(&runtimeTimeline_);
}
SR::BufferUsage ExecutionTimeline::GetCachedBufferUsage() const noexcept {
    return cachedBufferUsage_.Load();
}

void ExecutionTimeline::RefreshCachedBufferUsageLocked_() noexcept {
    cachedBufferUsage_.Store(
        SR::SumBufferUsage(
            prepareTimeline_.bufferUsage,
            runtimeTimeline_.bufferUsage
        )
    );
}
void ExecutionTimeline::SetJobsExchange(SRJobsExchange& jobsExchange) {
    std::lock_guard<std::mutex> lock(mutex_);
    jobsExchange_ = &jobsExchange;
}
void ExecutionTimeline::EnqueuePendingJobs_(
    const SR::PendingJobs& pendingJobs,
    SR::EventSummary* eventSummaryOrNull
) {
    if (pendingJobs.empty()) {
        return;
    }

    if (!jobsExchange_) {
        if (eventSummaryOrNull) {
            for (const SR::PendingJob& job : pendingJobs) {
                eventSummaryOrNull->pendingJobsNotEnqueued.push_back(
                    SR::PendingJobNotEnqueuedItem{
                        job.key,
                        SR::PendingJobNotEnqueuedReason::NoJobsExchange
                    }
                );
            }
        }
        return;
    }

    const SR::PendingJobEnqueueResults enqueueResults =
        jobsExchange_->EnqueuePendingJobs(pendingJobs);

    if (eventSummaryOrNull) {
        for (const SR::PendingJobEnqueueResult& result : enqueueResults) {
            if (result.accepted) {
                eventSummaryOrNull->pendingJobsEnqueued.push_back(result.key);
            } else {
                eventSummaryOrNull->pendingJobsNotEnqueued.push_back(
                    SR::PendingJobNotEnqueuedItem{
                        result.key,
                        result.reason
                    }
                );
            }
        }
    }
}
void ExecutionTimeline::SetParentEmitPolicy(SRParentEmitPolicy& parentEmitPolicy) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    parentEmitPolicy_ = &parentEmitPolicy;
}
void ExecutionTimeline::SetVerboseEnabled(bool value) noexcept {
    verboseEnabled_.store(value, std::memory_order_relaxed);
}
void ExecutionTimeline::SetLifecycleDiagnostics(
    SRLifecycleDiagnostics& lifecycleDiag
) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    lifecycleDiag_ = &lifecycleDiag;
}
void ExecutionTimeline::ProbeLine_(const std::wstring& msg) const {
    if constexpr (!kExecutionTimelineProbeEnabled) return;
    if (!lifecycleDiag_) return;
    lifecycleDiag_->ProbeLine(msg);
}


bool ExecutionTimeline::StartPhase(PhaseContext context) {
    if (!context.phaseTimeline_) return false;

    std::lock_guard<std::mutex> lock(mutex_);

    PhaseTimeline& phaseTimeline = *context.phaseTimeline_;
    phaseTimeline.Start();
    currentPhase_ = &phaseTimeline;
    return true;
}

bool ExecutionTimeline::EndPhase(PhaseContext context) {
    if (!context.phaseTimeline_) return false;

    std::lock_guard<std::mutex> lock(mutex_);

    PhaseTimeline& phaseTimeline = *context.phaseTimeline_;
    phaseTimeline.End();

    return true;
}

void ExecutionTimeline::EndCurrentPhase() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!currentPhase_) return;

    currentPhase_->End();
}

void ExecutionTimeline::StopRouting() {
    std::lock_guard<std::mutex> lock(mutex_);
    routingStopped_ = true;
}

bool ExecutionTimeline::HarvestCompletedJobs() {
    return HarvestCompletedJobs_(nullptr);
}
bool ExecutionTimeline::BuildFinalHarvestEventSummary(
    SR::EventSummary& eventSummary
) {
    CollectEventSummaryDiagnostics_(eventSummary);

    const bool harvested = HarvestCompletedJobs_(&eventSummary);
    if (!harvested) {
        return false;
    }

    return true;
}


bool ExecutionTimeline::HarvestCompletedJobs_(
    SR::EventSummary* eventSummaryOrNull
) {
    SR::JobResults completedResults;
    SR::UnobtainableResults* unobtainableResults = nullptr;
    SR::UnobtainableResultItems unobtainableItems;
    if (jobsExchange_) {
        completedResults = jobsExchange_->TakeAllJobResults();
        if (eventSummaryOrNull) {
            for (const auto& result : completedResults) {
                eventSummaryOrNull->completedResultsTaken.push_back(
                    {result.key, result.target}
                );
            }
        }

        unobtainableResults =
            &jobsExchange_->GetUnobtainableResults();
        unobtainableItems = unobtainableResults->Retrieve();
    }

    bool timelineEntryLocationsResolved = true;

    {
        std::lock_guard<std::mutex> lock(mutex_);

        if (eventSummaryOrNull && currentPhase_) {
            eventSummaryOrNull->eventKey.phase = currentPhase_->phase;
            eventSummaryOrNull->eventKey.phaseOrderNo =
                currentPhase_->phaseOrderNo;
            eventSummaryOrNull->eventKey.eventOrderNo =
                currentPhase_->nextEventOrderNo;
        }
        SR::TimelineEntryLocationResolveBatch batch;
        GroupCompletedResults_(completedResults, batch);
        for (const SR::UnobtainableResult& result : unobtainableItems) {
            batch.AppendUnobtainableResult(result);
        }

        timelineEntryLocationsResolved =
            ResolveTimelineEntryLocationsLocked_(batch);

        if (timelineEntryLocationsResolved) {
            SR::TimelineEntryLocationResolveBatch::SplitResult resolvedItems =
                batch.Split();

            ApplyJobResultsLocked_(
                resolvedItems.completedResultsGroups,
                eventSummaryOrNull
            );

            if (unobtainableResults) {
                unobtainableResults->RemoveNotFound(
                    resolvedItems.unobtainableResults
                );
            }

            if (resolvedItems.unobtainableResults.empty()) {
                PruneCompletedLocked_(
                    resolvedItems.completedResultsGroups,
                    eventSummaryOrNull
                );
            } else {
                PruneUnobtainableLocked_(
                    resolvedItems.completedResultsGroups,
                    resolvedItems.unobtainableResults,
                    eventSummaryOrNull
                );
            }
        }
    }

    return timelineEntryLocationsResolved;
}


bool ExecutionTimeline::RouteSrDiag(
    SR::DiagnosticSeverity severity,
    const std::wstring& message
) {
    return RouteSrDiag_(severity, message, true);
}

bool ExecutionTimeline::RouteSrDiag_(
    SR::DiagnosticSeverity severity,
    const std::wstring& message,
    bool eventSummaryEnabled
) {
    if (message.empty()) return true;

    return RouteEvent_(
        [&](PhaseTimeline& phaseTimeline) {
            const uint64_t eventOrderNo = phaseTimeline.nextEventOrderNo;
            phaseTimeline.AppendSrDiag(
                severity,
                message
            );
            ProbeLine_(
                L"AppendSrDiag eventOrderNo=" +
                std::to_wstring(eventOrderNo) +
                L" entries size=" +
                std::to_wstring(phaseTimeline.entries.size())
            );
        },
        eventSummaryEnabled
    );
}
void ExecutionTimeline::CollectEventSummaryDiagnostics_(
    SR::EventSummary& eventSummary
) {
    if (!jobsExchange_) {
        return;
    }

    eventSummary.workerSummaries =
        jobsExchange_->TakeWorkerSummaries();

    eventSummary.unobtainablePruning.workerFailures =
        jobsExchange_->GetWorkerFailures();
}
bool ExecutionTimeline::RouteEventSummary_(
    SR::EventSummary& eventSummary
) {
    CollectEventSummaryDiagnostics_(eventSummary);
    SR::PendingJobs pendingJobs;
    bool timelineEntryLocationsResolved = true;

    {
        std::lock_guard<std::mutex> lock(mutex_);

        if (routingStopped_) {
            return false;
        }

        if (!currentPhase_) {
            return true;
        }

        const uint64_t eventOrderNo = currentPhase_->nextEventOrderNo;

        eventSummary.eventKey.phase = currentPhase_->phase;
        eventSummary.eventKey.phaseOrderNo = currentPhase_->phaseOrderNo;
        eventSummary.eventKey.eventOrderNo = eventOrderNo;

        currentPhase_->AppendSrDiag(
            SR::DiagnosticSeverity::Verbose,
            SR::FormatEventSummary(eventSummary)
        );
        RefreshCachedBufferUsageLocked_();
        ProbeLine_(
            L"AppendSrDiag eventOrderNo=" +
            std::to_wstring(eventOrderNo) +
            L" entries size=" +
            std::to_wstring(currentPhase_->entries.size())
        );

        SR::TimelineEntryLocationResolveBatch batch;
        SR::JobQueueItem item;
        item.key = eventSummary.eventKey;
        batch.AppendJobQueueItem(item);

        timelineEntryLocationsResolved =
            ResolveTimelineEntryLocationsLocked_(batch);

        if (timelineEntryLocationsResolved) {
            SR::TimelineEntryLocationResolveBatch::SplitResult resolvedItems =
                batch.Split();

            BuildPendingJobsLocked_(
                resolvedItems.jobQueueItems,
                pendingJobs,
                nullptr
            );
        }
    }

    if (!timelineEntryLocationsResolved) {
        return false;
    }

    if (!pendingJobs.empty()) {
        EnqueuePendingJobs_(pendingJobs, nullptr);
    }

    return true;
}

bool ExecutionTimeline::RouteChildStdout(
    const char* bytes,
    size_t byteCount,
    SR::ReplayPayloadStorage replayPayloadStorage
) {
    if (!bytes || byteCount == 0) return true;

    return RouteEvent_([&](PhaseTimeline& phaseTimeline) {
        phaseTimeline.AppendChildStdout(
            bytes,
            byteCount,
            replayPayloadStorage
        );
    });
}

bool ExecutionTimeline::RouteChildStderr(
    const char* bytes,
    size_t byteCount,
    SR::ReplayPayloadStorage replayPayloadStorage
) {
    if (!bytes || byteCount == 0) return true;

    return RouteEvent_([&](PhaseTimeline& phaseTimeline) {
        phaseTimeline.AppendChildStderr(
            bytes,
            byteCount,
            replayPayloadStorage
        );
    });
}

void ExecutionTimeline::AddToJobQueueLocked_(
    const PhaseTimeline& phaseTimeline,
    uint64_t eventOrderNo
) {
    TimelineEntryKey key;
    key.phase = phaseTimeline.phase;
    key.phaseOrderNo = phaseTimeline.phaseOrderNo;
    key.eventOrderNo = eventOrderNo;

    jobQueue_.push_back(key);
    ProbeLine_(
        std::wstring(L"ExecutionTimeline::AddToJobQueueLocked_ key=") +
        SR::LifecyclePhaseShortNameToString(key.phase) +
        L":" +
        std::to_wstring(key.phaseOrderNo) +
        L":" +
        std::to_wstring(key.eventOrderNo)
    );
    ProbeLine_(
        L"ExecutionTimeline::AddToJobQueueLocked_ jobQueueSize=" +
        std::to_wstring(jobQueue_.size())
    );
}
void ExecutionTimeline::RetrieveJobQueueLocked_(
    SR::TimelineEntryLocationResolveBatch& batch,
    SR::EventSummary* eventSummaryOrNull
) {
    ProbeLine_(
        L"ExecutionTimeline::RetrieveJobQueueLocked_ queueInitial=" +
        std::to_wstring(jobQueue_.size())
    );

    while (!jobQueue_.empty()) {
        SR::JobQueueItem item;
        item.key = jobQueue_.front();
        if (eventSummaryOrNull) {
            eventSummaryOrNull->jobQueueRetrieved.push_back(item.key);
        }

        batch.AppendJobQueueItem(item);
        jobQueue_.pop_front();
    }
}
PhaseTimeline* ExecutionTimeline::GetPhaseTimelineForLifecyclePhase_(
    SR::LifecyclePhase phase
) noexcept {
    switch (phase) {
        case SR::LifecyclePhase::Prepare:
            return &prepareTimeline_;

        case SR::LifecyclePhase::Runtime:
            return &runtimeTimeline_;

        default:
            return nullptr;
    }
}

bool ExecutionTimeline::ResolveTimelineEntryLocationsLocked_(
    SR::TimelineEntryLocationResolveBatch& batch
) {
    bool resolved = true;

    auto resolveInPhase = [&](
        PhaseTimeline& phaseTimeline
    ) {
        for (std::size_t index = 0; index < phaseTimeline.entries.size(); ++index) {
            std::visit(
                [&](const auto& entry) {
                    std::vector<std::size_t> itemIndexes;

                    if (phaseTimeline.phase == SR::LifecyclePhase::Prepare) {
                        itemIndexes = batch.TakeFromPrepareIndex(entry.key);
                    } else if (phaseTimeline.phase == SR::LifecyclePhase::Runtime) {
                        itemIndexes = batch.TakeFromRuntimeIndex(entry.key);
                    }

                    if (itemIndexes.empty()) {
                        return;
                    }

                    SR::TimelineEntryLocation location;
                    location.phaseTimeline = &phaseTimeline;
                    location.index = index;

                    for (std::size_t itemIndex : itemIndexes) {
                        if (!batch.UpdateTimelineEntryLocation(itemIndex, location)) {
                            resolved = false;
                        }
                    }
                },
                phaseTimeline.entries[index]
            );

            if (phaseTimeline.phase == SR::LifecyclePhase::Prepare &&
                !batch.HasPendingPrepareKeys()) {
                break;
            }

            if (phaseTimeline.phase == SR::LifecyclePhase::Runtime &&
                !batch.HasPendingRuntimeKeys()) {
                break;
            }
        }
    };

    if (batch.HasPrepare()) {
        resolveInPhase(prepareTimeline_);
    }

    if (batch.HasRuntime()) {
        resolveInPhase(runtimeTimeline_);
    }

    return resolved;
}

void ExecutionTimeline::GroupCompletedResults_(
    const SR::JobResults& completedResults,
    SR::TimelineEntryLocationResolveBatch& batch
) {
    SR::CompletedResultsGroups groups;

    for (const SR::JobResult& result : completedResults) {
        const TimelineEntryKey key = result.key;

        auto existingGroup = std::find_if(
            groups.begin(),
            groups.end(),
            [&](const SR::CompletedResultsGroup& group) {
                return
                    group.key.phase == key.phase &&
                    group.key.phaseOrderNo == key.phaseOrderNo &&
                    group.key.eventOrderNo == key.eventOrderNo;
            }
        );

        if (existingGroup == groups.end()) {
            SR::CompletedResultsGroup newGroup;
            newGroup.key = key;
            groups.push_back(std::move(newGroup));

            existingGroup = std::prev(groups.end());
        }

        existingGroup->results.push_back(result);
    }

    for (const SR::CompletedResultsGroup& group : groups) {
        batch.AppendCompletedResultsGroup(group);
    }
}


void ExecutionTimeline::BuildPendingJobsLocked_(
    const SR::JobQueueItems& jobQueueItems,
    SR::PendingJobs& out,
    SR::EventSummary* eventSummaryOrNull
) {
    out.clear();

    ProbeLine_(
        L"ExecutionTimeline::BuildPendingJobsLocked_ items=" +
        std::to_wstring(jobQueueItems.size())
    );

    for (const SR::JobQueueItem& item : jobQueueItems) {
        SR::PendingJob job;
        SR::PendingJobBuildFailedReason failedReason =
            SR::PendingJobBuildFailedReason::UnresolvedLocation;

        if (BuildPendingJobLocked_(item, job, &failedReason)) {
            if (eventSummaryOrNull) {
                eventSummaryOrNull->pendingJobsBuilt.push_back(item.key);
            }
            out.push_back(std::move(job));
        } else if (eventSummaryOrNull) {
            eventSummaryOrNull->pendingJobsBuildFailed.push_back(
                SR::PendingJobBuildFailedItem{item.key, failedReason}
            );
        }
    }

    ProbeLine_(
        L"ExecutionTimeline::BuildPendingJobsLocked_ outCount=" +
        std::to_wstring(out.size())
    );
}

bool ExecutionTimeline::BuildPendingJobLocked_(
    const SR::JobQueueItem& item,
    SR::PendingJob& out,
    SR::PendingJobBuildFailedReason* failedReasonOrNull
) const {
    if (item.location.phaseTimeline == nullptr) {
        if (failedReasonOrNull) {
            *failedReasonOrNull =
                SR::PendingJobBuildFailedReason::UnresolvedLocation;
        }
        return false;
    }

    if (item.location.index >= item.location.phaseTimeline->entries.size()) {
        if (failedReasonOrNull) {
            *failedReasonOrNull =
                SR::PendingJobBuildFailedReason::InvalidLocationIndex;
        }
        return false;
    }

    const SR::TimelineEntryVariant& timelineEntry =
        item.location.phaseTimeline->entries[item.location.index];

    return std::visit(
        [&](const auto& entry) -> bool {
            if (entry.key.phase != item.key.phase ||
                entry.key.phaseOrderNo != item.key.phaseOrderNo ||
                entry.key.eventOrderNo != item.key.eventOrderNo) {
                if (failedReasonOrNull) {
                    *failedReasonOrNull =
                        SR::PendingJobBuildFailedReason::LocationKeyMismatch;
                }
                return false;
            }

            out = SR::PendingJob{};
            out.key = item.key;
            out.payloadType = entry.payloadType;

            using Entry = std::decay_t<decltype(entry)>;

            if constexpr (std::is_same_v<Entry, SR::SrDiagEntry>) {
                out.srDiag = entry;
            } else if constexpr (std::is_same_v<Entry, SR::ChildStdoutEntry>) {
                out.childStdout = entry;
            } else if constexpr (std::is_same_v<Entry, SR::ChildStderrEntry>) {
                out.childStderr = entry;
            }

            return true;
        },
        timelineEntry
    );
}

void ExecutionTimeline::ApplyJobResultsLocked_(
    const SR::CompletedResultsGroups& completedResultsGroups,
    SR::EventSummary* eventSummaryOrNull
) {
    ProbeLine_(
        L"ExecutionTimeline::ApplyJobResultsLocked_ groups=" +
        std::to_wstring(completedResultsGroups.size())
    );

    for (const SR::CompletedResultsGroup& group : completedResultsGroups) {
        if (group.location.phaseTimeline == nullptr) {
            if (eventSummaryOrNull) {
                for (const SR::JobResult& result : group.results) {
                    const SR::CompletedResultNotAppliedReason reason =
                        SR::IsFileReplayJobOrigin(result.origin)
                            ? SR::CompletedResultNotAppliedReason::
                                ReplayWithoutTimelineEntry
                            : SR::CompletedResultNotAppliedReason::
                                UnresolvedLocation;

                    eventSummaryOrNull->completedResultsNotApplied.push_back(
                        SR::CompletedResultNotAppliedItem{
                            group.key,
                            result.target,
                            reason
                        }
                    );
                }
            }
            continue;
        }

        if (group.location.index >= group.location.phaseTimeline->entries.size()) {
            if (eventSummaryOrNull) {
                for (const SR::JobResult& result : group.results) {
                    eventSummaryOrNull->completedResultsNotApplied.push_back(
                        SR::CompletedResultNotAppliedItem{
                            group.key,
                            result.target,
                            SR::CompletedResultNotAppliedReason::InvalidLocationIndex
                        }
                    );
                }
            }
            continue;
        }

        SR::TimelineEntryVariant& timelineEntry =
            group.location.phaseTimeline->entries[group.location.index];

        for (const SR::JobResult& result : group.results) {
            bool applied = false;
            SR::CompletedResultNotAppliedReason notAppliedReason =
                SR::CompletedResultNotAppliedReason::InvalidStateTransition;

            std::visit(
                [&](auto& entry) {
                    SR::EventJobResult& jobResult =
                        entry.jobResults.At(result.target);

                    if (!SR::CanTransitionJobState(jobResult.state, result.state)) {
                        notAppliedReason =
                            SR::CompletedResultNotAppliedReason::InvalidStateTransition;
                        return;
                    }

                    jobResult.state = result.state;
                    jobResult.details = result.details;
                    applied = true;
                },
                timelineEntry
            );

            if (!eventSummaryOrNull) {
                continue;
            }

            if (applied) {
                eventSummaryOrNull->completedResultsApplied.push_back(
                    SR::CompletedResultAppliedItem{group.key, result.target}
                );
            } else {
                eventSummaryOrNull->completedResultsNotApplied.push_back(
                    SR::CompletedResultNotAppliedItem{
                        group.key,
                        result.target,
                        notAppliedReason
                    }
                );
            }
        }
    }
}

void ExecutionTimeline::PruneCompletedLocked_(
    const SR::CompletedResultsGroups& completedResultsGroups,
    SR::EventSummary* eventSummaryOrNull
) {
    auto recordSkipped = [&](
        const SR::CompletedResultsGroup& group,
        SR::PruneSkippedReason reason
    ) {
        if (!eventSummaryOrNull) {
            return;
        }

        eventSummaryOrNull->completedPruning.pruneSkipped.push_back(
            SR::PruneSkippedItem{group.key, reason}
        );
    };

    auto recordFailed = [&](
        const SR::CompletedResultsGroup& group,
        SR::PruneFailedReason reason
    ) {
        if (!eventSummaryOrNull) {
            return;
        }

        eventSummaryOrNull->completedPruning.pruneFailed.push_back(
            SR::PruneFailedItem{group.key, reason}
        );
    };

    if (!parentEmitPolicy_) {
        for (const SR::CompletedResultsGroup& group : completedResultsGroups) {
            recordSkipped(group, SR::PruneSkippedReason::NoParentEmitPolicy);
        }
        return;
    }

    if (parentEmitPolicy_->NeedsStdoutReplayBuffer()) {
        for (const SR::CompletedResultsGroup& group : completedResultsGroups) {
            recordSkipped(group, SR::PruneSkippedReason::StdoutReplayBufferNeeded);
        }
        return;
    }

    if (parentEmitPolicy_->NeedsStderrReplayBuffer()) {
        for (const SR::CompletedResultsGroup& group : completedResultsGroups) {
            recordSkipped(group, SR::PruneSkippedReason::StderrReplayBufferNeeded);
        }
        return;
    }

    std::vector<std::size_t> preparePruneIndexes;
    std::vector<std::size_t> runtimePruneIndexes;

    for (const SR::CompletedResultsGroup& group : completedResultsGroups) {
        if (group.location.phaseTimeline == nullptr) {
            recordSkipped(group, SR::PruneSkippedReason::UnresolvedLocation);
            continue;
        }

        if (group.location.index >= group.location.phaseTimeline->entries.size()) {
            recordSkipped(group, SR::PruneSkippedReason::InvalidLocationIndex);
            continue;
        }

        SR::TimelineEntryVariant& timelineEntry =
            group.location.phaseTimeline->entries[group.location.index];

        bool pruneable = false;
        std::visit(
            [&](const auto& entry) {
                pruneable = SR::AreAllJobResultsPruneable(
                    entry.payloadType,
                    entry.jobResults
                );
            },
            timelineEntry
        );

        if (!pruneable) {
            recordSkipped(group, SR::PruneSkippedReason::NotPruneable);
            continue;
        }

        if (group.location.phaseTimeline == &prepareTimeline_) {
            preparePruneIndexes.push_back(group.location.index);
        } else if (group.location.phaseTimeline == &runtimeTimeline_) {
            runtimePruneIndexes.push_back(group.location.index);
        } else {
            recordFailed(group, SR::PruneFailedReason::UnknownPhaseTimeline);
        }
    }

    auto erasePruneableIndexes = [](
        PhaseTimeline& phaseTimeline,
        std::vector<std::size_t>& indexes
    ) {
        std::sort(indexes.begin(), indexes.end());
        indexes.erase(
            std::unique(indexes.begin(), indexes.end()),
            indexes.end()
        );

        for (auto it = indexes.rbegin(); it != indexes.rend(); ++it) {
            if (*it < phaseTimeline.entries.size()) {
                phaseTimeline.entries.erase(phaseTimeline.entries.begin() + *it);
            }
        }
    };

    if (eventSummaryOrNull) {
        for (const SR::CompletedResultsGroup& group : completedResultsGroups) {
            if (group.location.phaseTimeline == &prepareTimeline_) {
                if (std::find(
                        preparePruneIndexes.begin(),
                        preparePruneIndexes.end(),
                        group.location.index
                    ) != preparePruneIndexes.end()) {
                    eventSummaryOrNull->completedPruning.pruned.push_back(
                        group.key
                    );
                }
            } else if (group.location.phaseTimeline == &runtimeTimeline_) {
                if (std::find(
                        runtimePruneIndexes.begin(),
                        runtimePruneIndexes.end(),
                        group.location.index
                    ) != runtimePruneIndexes.end()) {
                    eventSummaryOrNull->completedPruning.pruned.push_back(
                        group.key
                    );
                }
            }
        }
    }

    erasePruneableIndexes(prepareTimeline_, preparePruneIndexes);
    erasePruneableIndexes(runtimeTimeline_, runtimePruneIndexes);
}
//
// Performs fallback pruning for TimelineEntries blocked by
// permanently unavailable workers.
//
// The algorithm never modifies the actual TimelineEntry.
// Instead it creates a temporary copy of the entry JobResults,
// virtually projects eligible unobtainable targets to a
// pruneable state, and evaluates the existing
// AreAllJobResultsPruneable() logic on that copy.
//
void ExecutionTimeline::PruneUnobtainableLocked_(
    const SR::CompletedResultsGroups& completedResultsGroups,
    const SR::ResolvedUnobtainableResultItems& unobtainableResults,
    SR::EventSummary* eventSummaryOrNull
) {
    struct PruneCandidate {
        SR::TimelineEntryKey key;
        SR::TimelineEntryLocation location;
        std::vector<SR::JobTarget> virtualSuppressedTargets;
    };

    std::vector<PruneCandidate> candidates;

    auto findOrAddCandidate = [&](
        const SR::TimelineEntryKey& key,
        const SR::TimelineEntryLocation& location
    ) -> PruneCandidate& {
        for (PruneCandidate& candidate : candidates) {
            if (candidate.location.phaseTimeline == location.phaseTimeline &&
                candidate.location.index == location.index) {
                return candidate;
            }
        }

        candidates.push_back(PruneCandidate{key, location, {}});
        return candidates.back();
    };

    for (const SR::CompletedResultsGroup& group : completedResultsGroups) {
        if (group.resolveStatus !=
            SR::TimelineEntryKeyLocationPairResolveStatus::Resolved) {
            continue;
        }

        findOrAddCandidate(group.key, group.location);
    }

    for (const SR::ResolvedUnobtainableResult& resolved : unobtainableResults) {
        if (resolved.resolveStatus !=
            SR::TimelineEntryKeyLocationPairResolveStatus::Resolved) {
            continue;
        }
        if (eventSummaryOrNull) {
            eventSummaryOrNull
                ->unobtainablePruning
                .unobtainableTargets
                .push_back(resolved.result);
        }

        PruneCandidate& candidate =
            findOrAddCandidate(resolved.result.key, resolved.location);

        if (std::find(
                candidate.virtualSuppressedTargets.begin(),
                candidate.virtualSuppressedTargets.end(),
                resolved.result.target
            ) == candidate.virtualSuppressedTargets.end()) {
            candidate.virtualSuppressedTargets.push_back(
                resolved.result.target
            );
        }
    }

    auto recordSkipped = [&](
        const PruneCandidate& candidate,
        SR::PruneSkippedReason reason
    ) {
        if (!eventSummaryOrNull) {
            return;
        }

        eventSummaryOrNull
            ->unobtainablePruning
            .pruning
            .pruneSkipped
            .push_back(
            SR::PruneSkippedItem{candidate.key, reason}
        );
    };

    auto recordFailed = [&](
        const PruneCandidate& candidate,
        SR::PruneFailedReason reason
    ) {
        if (!eventSummaryOrNull) {
            return;
        }

        eventSummaryOrNull
            ->unobtainablePruning
            .pruning
            .pruneFailed
            .push_back(
            SR::PruneFailedItem{candidate.key, reason}
        );
    };

    if (!parentEmitPolicy_) {
        for (const PruneCandidate& candidate : candidates) {
            recordSkipped(
                candidate,
                SR::PruneSkippedReason::NoParentEmitPolicy
            );
        }
        return;
    }

    if (parentEmitPolicy_->NeedsStdoutReplayBuffer()) {
        for (const PruneCandidate& candidate : candidates) {
            recordSkipped(
                candidate,
                SR::PruneSkippedReason::StdoutReplayBufferNeeded
            );
        }
        return;
    }

    if (parentEmitPolicy_->NeedsStderrReplayBuffer()) {
        for (const PruneCandidate& candidate : candidates) {
            recordSkipped(
                candidate,
                SR::PruneSkippedReason::StderrReplayBufferNeeded
            );
        }
        return;
    }

    std::vector<std::size_t> preparePruneIndexes;
    std::vector<std::size_t> runtimePruneIndexes;

    for (const PruneCandidate& candidate : candidates) {
        if (candidate.location.phaseTimeline == nullptr) {
            recordSkipped(
                candidate,
                SR::PruneSkippedReason::UnresolvedLocation
            );
            continue;
        }

        if (candidate.location.index >=
            candidate.location.phaseTimeline->entries.size()) {
            recordSkipped(
                candidate,
                SR::PruneSkippedReason::InvalidLocationIndex
            );
            continue;
        }

        SR::TimelineEntryVariant& timelineEntry =
            candidate.location.phaseTimeline->entries[
                candidate.location.index
            ];

        bool pruneable = false;
        std::visit(
            [&](const auto& entry) {
                SR::UnobtainableJobResults virtualJobResults =
                    entry.jobResults;

                for (SR::JobTarget target :
                    candidate.virtualSuppressedTargets) {
                    SR::EventJobResult& virtualResult =
                        virtualJobResults.At(target);

                    if (SR::CanTransitionJobState(
                            virtualResult.state,
                            SR::JobState::Suppressed
                        )) {
                        virtualResult.state =
                            SR::JobState::Suppressed;
                    }
                }

                pruneable = SR::AreAllJobResultsPruneable(
                    entry.payloadType,
                    virtualJobResults
                );
            },
            timelineEntry
        );

        if (!pruneable) {
            recordSkipped(
                candidate,
                SR::PruneSkippedReason::NotPruneable
            );
            continue;
        }

        if (candidate.location.phaseTimeline == &prepareTimeline_) {
            preparePruneIndexes.push_back(candidate.location.index);
        } else if (candidate.location.phaseTimeline == &runtimeTimeline_) {
            runtimePruneIndexes.push_back(candidate.location.index);
        } else {
            recordFailed(
                candidate,
                SR::PruneFailedReason::UnknownPhaseTimeline
            );
        }
    }

    auto erasePruneableIndexes =[](
        PhaseTimeline& phaseTimeline,
        std::vector<std::size_t>& indexes
    ) {
        std::sort(indexes.begin(), indexes.end());
        indexes.erase(
            std::unique(indexes.begin(), indexes.end()),
            indexes.end()
        );

        for (auto it = indexes.rbegin(); it != indexes.rend(); ++it) {
            if (*it < phaseTimeline.entries.size()) {
                phaseTimeline.entries.erase(
                    phaseTimeline.entries.begin() + *it
                );
            }
        }
    };

    if (eventSummaryOrNull) {
        for (const PruneCandidate& candidate : candidates) {
            const std::vector<std::size_t>* pruneIndexes = nullptr;

            if (candidate.location.phaseTimeline == &prepareTimeline_) {
                pruneIndexes = &preparePruneIndexes;
            } else if (
                candidate.location.phaseTimeline == &runtimeTimeline_
            ) {
                pruneIndexes = &runtimePruneIndexes;
            }

            if (pruneIndexes &&
                std::find(
                    pruneIndexes->begin(),
                    pruneIndexes->end(),
                    candidate.location.index
                ) != pruneIndexes->end()) {
                eventSummaryOrNull
                    ->unobtainablePruning
                    .pruning
                    .pruned
                    .push_back(candidate.key);
            }
        }
    }

    erasePruneableIndexes(prepareTimeline_, preparePruneIndexes);
    erasePruneableIndexes(runtimeTimeline_, runtimePruneIndexes);
}

bool ExecutionTimeline::ReplayToParent(
    const SR::ParentReplayParameters& parameters
) {
    bool succeeded = true;

    if (parameters.stdoutParentReplayParameters.source ==
        SR::ParentReplaySource::Timeline) {
        if (parameters.stdoutParentReplayParameters.target !=
            SR::JobTarget::StdoutParent) {
            return false;
        }
        SR::GetAllDelayedFilter filter;
        filter.stdoutParent = true;

        succeeded =
            ReplayDelayedToParent_(
                filter,
                parameters.stdoutParentReplayParameters.target
            ) &&
            succeeded;
    }

    if (parameters.stderrParentReplayParameters.source ==
        SR::ParentReplaySource::Timeline) {
        SR::GetAllDelayedFilter filter;

        switch (parameters.stderrParentReplayParameters.target) {
            case SR::JobTarget::StderrMixedParent:
                filter.stderrMixedParent = true;
                break;

            case SR::JobTarget::StderrChildParent:
                filter.stderrChildParent = true;
                break;

            case SR::JobTarget::StderrSrParent:
                filter.stderrSrParent = true;
                break;

            default:
                return false;
        }

        succeeded =
            ReplayDelayedToParent_(
                filter,
                parameters.stderrParentReplayParameters.target
            ) &&
            succeeded;
    }

    return succeeded;
}

bool ExecutionTimeline::ReplayDelayedToParent_(
    const SR::GetAllDelayedFilter& filter,
    SR::JobTarget target
) {
    SR::JobQueueItems delayedItems;
    SR::PendingJobs delayedPendingJobs;
    SRJobsExchange* jobsExchange = nullptr;

    {
        std::lock_guard<std::mutex> lock(mutex_);

        if (!jobsExchange_) {
            return false;
        }

        jobsExchange = jobsExchange_;

        prepareTimeline_.GetAllDelayed(filter, delayedItems);
        runtimeTimeline_.GetAllDelayed(filter, delayedItems);

        for (const SR::JobQueueItem& item : delayedItems) {
            SR::PendingJob pendingJob;

            if (!BuildPendingJobLocked_(item, pendingJob, nullptr)) {
                return false;
            }

            delayedPendingJobs.push_back(std::move(pendingJob));
        }
    }

    SRReplayJobsBatch replayBatch;

    if (!replayBatch.Init(*jobsExchange, target)) {
        return false;
    }

    for (SR::PendingJob& pendingJob : delayedPendingJobs) {
        if (!replayBatch.Add(std::move(pendingJob))) {
            return false;
        }
    }

    return replayBatch.Flush();
}
