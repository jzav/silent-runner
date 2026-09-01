#pragma once

#include <cstddef>
#include <deque>
#include <mutex>
#include <string>
#include <utility>

#include "SRPhaseTimeline.h"
#include "SRTypes.h"
#include "SRPendingJobTypes.h"
#include "SRJobsExchange.h"
#include "SRParentEmitPolicy.h"
#include "SRParentReplayTypes.h"

#include "SRExecutionTimelineDiagnostics.h"

class SRLifecycleDiagnostics;
// Opaque phase handle used by execution-level APIs.
//
// The pointed-to PhaseTimeline remains owned by ExecutionTimeline.
class PhaseContext {
public:
    PhaseContext() noexcept = default;
    PhaseContext(const PhaseContext&) = default;
    PhaseContext& operator=(const PhaseContext&) = default;

private:
    explicit PhaseContext(PhaseTimeline* phaseTimeline) noexcept
        : phaseTimeline_(phaseTimeline) {}

    PhaseTimeline* phaseTimeline_ = nullptr;

    friend class ExecutionTimeline;
};

// Top-level execution timeline owner.
//
// Owns the prepare/runtime phase timelines and exposes the public routing,
// snapshot, and replay entry points used by runtime and diagnostics layers.
//
// Per-phase event ordering, phaseOrderNo, payload storage, and buffered/dropped
// accounting belong to PhaseTimeline.
class ExecutionTimeline {
public:
    ExecutionTimeline() = default;

    ExecutionTimeline(const ExecutionTimeline&) = delete;
    ExecutionTimeline& operator=(const ExecutionTimeline&) = delete;

    bool Init();

    PhaseContext PrepareContext() noexcept;
    PhaseContext RuntimeContext() noexcept;
    void SetJobsExchange(SRJobsExchange& jobsExchange);
    void SetParentEmitPolicy(SRParentEmitPolicy& parentEmitPolicy) noexcept;
    void SetVerboseEnabled(bool value) noexcept;
    void SetLifecycleDiagnostics(SRLifecycleDiagnostics& lifecycleDiag) noexcept;

    bool StartPhase(PhaseContext context);
    bool EndPhase(PhaseContext context);
    void EndCurrentPhase();
    void StopRouting();
    bool HarvestCompletedJobs();
    bool BuildFinalHarvestEventSummary(
        SR::EventSummary& eventSummary
    );

    bool RouteSrDiag(
        SR::DiagnosticSeverity severity,
        const std::wstring& message,
        SR::ReplayPayloadStorage replayPayloadStorage,
        uint64_t payloadByteCount,
        bool eventSummaryEnabled
    );

    bool RouteChildStdout(
        const char* bytes,
        size_t byteCount,
        SR::ReplayPayloadStorage replayPayloadStorage,
        bool eventSummaryEnabled
    );

    bool RouteChildStderr(
        const char* bytes,
        size_t byteCount,
        SR::ReplayPayloadStorage replayPayloadStorage,
        bool eventSummaryEnabled
    );


    const PhaseTimeline& Prepare() const noexcept { return prepareTimeline_; }
    const PhaseTimeline& Runtime() const noexcept { return runtimeTimeline_; }
    SR::BufferUsage GetCachedBufferUsage() const noexcept;
    void ProbeLine(const std::wstring& msg) const;



    bool ReplayToParent(
        const SR::ParentReplayParameters& parameters
    );

private:

    static constexpr bool kExecutionTimelineProbeEnabled = true;
    void ProbeLine_(const std::wstring& msg) const;
    void ProbeBufferAccounting_(
        const wchar_t* origin,
        const SR::BufferUsage& beforeUsage,
        const SR::BufferUsage& afterUsage,
        SR::ReplayPayloadStorage replayPayloadStorage,
        uint64_t payloadByteCount
    ) const;


    void RefreshCachedBufferUsageLocked_() noexcept;
    using TimelineEntryKey = SR::TimelineEntryKey;
    void CollectEventSummaryDiagnostics_(
        SR::EventSummary& eventSummary
    );
    bool RouteEventSummary_(
        SR::EventSummary& eventSummary
    );

    template <typename AppendFn>
    bool RouteEvent_(
        const AppendFn& appendFn,
        bool eventSummaryEnabled
    ) {

        SR::EventSummary eventSummary;
        struct RouteEventSummarizer {
            ExecutionTimeline* owner = nullptr;
            SR::EventSummary* eventSummary = nullptr;
            bool enabled = false;
            ~RouteEventSummarizer() {
                if (!enabled || !owner || !eventSummary) {
                    return;
                }
                try {
                    owner->RouteEventSummary_(*eventSummary);
                } catch (...) {
                }
            }
        } routeEventSummarizer{this, &eventSummary, eventSummaryEnabled && verboseEnabled_.load(std::memory_order_relaxed)};
        eventSummary.result = SR::EventResult::Failed;
        eventSummary.failedStep = L"routeEventIncomplete";

        SR::JobResults completedResults;
        SR::UnobtainableResults* unobtainableResults = nullptr;
        SR::UnobtainableResultItems unobtainableItems;
        if (jobsExchange_) {
            completedResults = jobsExchange_->TakeAllJobResults();
            for (const auto& result : completedResults) {
                eventSummary.completedResultsTaken.push_back({result.key, result.target});
            }

            unobtainableResults =
                &jobsExchange_->GetUnobtainableResults();
            unobtainableItems = unobtainableResults->Retrieve();
        }

        SR::PendingJobs pendingJobs;
        bool timelineEntryLocationsResolved = true;

        {
            // Serializes all Route... calls for this ExecutionTimeline.
            // The lock protects currentPhase_ and the phase-local eventOrderNo counter,
            // so Stamp()/Append operations assign a single monotonic order across
            // stdout, stderr, and SilentRunner diagnostic events.
            std::lock_guard<std::mutex> lock(mutex_);

            if (routingStopped_) {
                eventSummary.result = SR::EventResult::Failed;
                eventSummary.failedStep = L"routingStopped";
                return false;
            }

            SR::TimelineEntryLocationResolveBatch batch;
            GroupCompletedResults_(completedResults, batch);
            for (const SR::UnobtainableResult& result : unobtainableItems) {
                batch.AppendUnobtainableResult(result);
            }
            if (currentPhase_) {
                const uint64_t eventOrderNo = currentPhase_->nextEventOrderNo;
                appendFn(*currentPhase_);
                RefreshCachedBufferUsageLocked_();

                eventSummary.eventKey.phase = currentPhase_->phase;
                eventSummary.eventKey.phaseOrderNo = currentPhase_->phaseOrderNo;
                eventSummary.eventKey.eventOrderNo = eventOrderNo;

                AddToJobQueueLocked_(*currentPhase_, eventOrderNo);
            }

            if (jobsExchange_) {
                RetrieveJobQueueLocked_(batch, &eventSummary);
                timelineEntryLocationsResolved =
                    ResolveTimelineEntryLocationsLocked_(batch);

                if (timelineEntryLocationsResolved) {
                    SR::TimelineEntryLocationResolveBatch::SplitResult resolvedItems =
                        batch.Split();

                    ApplyJobResultsLocked_(resolvedItems.completedResultsGroups, &eventSummary);
                    BuildPendingJobsLocked_(
                        resolvedItems.jobQueueItems,
                        pendingJobs,
                        &eventSummary
                    );

                    if (unobtainableResults) {
                        unobtainableResults->RemoveNotFound(
                            resolvedItems.unobtainableResults
                        );
                    }

                    if (resolvedItems.unobtainableResults.empty()) {
                        PruneCompletedLocked_(
                            resolvedItems.completedResultsGroups,
                            &eventSummary
                        );
                    } else {
                        PruneUnobtainableLocked_(
                            resolvedItems.completedResultsGroups,
                            resolvedItems.unobtainableResults,
                            &eventSummary
                        );
                    }
                }
            }
        }

        if (!timelineEntryLocationsResolved) {
            eventSummary.result = SR::EventResult::Failed;
            eventSummary.failedStep = L"resolveTimelineEntryLocations";
            return false;
        }

        if (!pendingJobs.empty()) {
            EnqueuePendingJobs_(pendingJobs, &eventSummary);
        }

        eventSummary.result = SR::EventResult::Ok;
        eventSummary.failedStep = nullptr;
        return true;
    }


    bool ReplayDelayedToParent_(
        const SR::GetAllDelayedFilter& filter,
        SR::JobTarget target
    );


    bool HarvestCompletedJobs_(
        SR::EventSummary* eventSummaryOrNull
    );
    void ApplyJobResultsLocked_(
        const SR::CompletedResultsGroups& completedResultsGroups,
        SR::EventSummary* eventSummaryOrNull
    );
    PhaseTimeline* GetPhaseTimelineForLifecyclePhase_(
        SR::LifecyclePhase phase
    ) noexcept;
    bool ResolveTimelineEntryLocationsLocked_(
        SR::TimelineEntryLocationResolveBatch& batch
    );
    void GroupCompletedResults_(
        const SR::JobResults& completedResults,
        SR::TimelineEntryLocationResolveBatch& batch
    );


    void AddToJobQueueLocked_(
        const PhaseTimeline& phaseTimeline,
        uint64_t eventOrderNo
    );
    void RetrieveJobQueueLocked_(
        SR::TimelineEntryLocationResolveBatch& batch,
        SR::EventSummary* eventSummaryOrNull
    );
    void BuildPendingJobsLocked_(
        const SR::JobQueueItems& jobQueueItems,
        SR::PendingJobs& out,
        SR::EventSummary* eventSummaryOrNull
    );
    bool BuildPendingJobLocked_(
        const SR::JobQueueItem& item,
        SR::PendingJob& out,
        SR::PendingJobBuildFailedReason* failedReasonOrNull
    ) const;
    void EnqueuePendingJobs_(
        const SR::PendingJobs& pendingJobs,
        SR::EventSummary* eventSummaryOrNull
    );
    void PruneCompletedLocked_(
        const SR::CompletedResultsGroups& completedResultsGroups,
        SR::EventSummary* eventSummaryOrNull
    );
    void PruneUnobtainableLocked_(
        const SR::CompletedResultsGroups& completedResultsGroups,
        const SR::ResolvedUnobtainableResultItems& unobtainableResults,
        SR::EventSummary* eventSummaryOrNull
    );

private:
    // Coordinates currentPhase_ and cross-phase snapshots.
    // Per-phase event ordering is stored in PhaseTimeline::nextEventOrderNo.
    mutable std::mutex mutex_;

    PhaseTimeline prepareTimeline_;
    PhaseTimeline runtimeTimeline_;
    SR::AtomicBufferUsageCache cachedBufferUsage_;

    PhaseTimeline* currentPhase_ = nullptr;
    SRJobsExchange* jobsExchange_ = nullptr; // non-owning
    SRParentEmitPolicy* parentEmitPolicy_ = nullptr; // non-owning
    SRLifecycleDiagnostics* lifecycleDiag_ = nullptr; // non-owning, probe sink only
    std::atomic<bool> verboseEnabled_{false};
    bool routingStopped_ = false;
    std::deque<TimelineEntryKey> jobQueue_;
};
