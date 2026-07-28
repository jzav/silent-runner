#pragma once

#include <string>
#include <vector>

#include "SRTypes.h"
#include "SRJobTypes.h"
#include "SRPendingJobTypes.h"
#include "SRUnobtainableResults.h"
#include "SRWorkerSupervisor.h"

namespace SR {

#define SR_EVENT_RESULT_TABLE(X) \
    X(Ok, L"ok") \
    X(Failed, L"failed")

enum class EventResult {
#define SR_X_EVENT_RESULT(name, text) name,
    SR_EVENT_RESULT_TABLE(SR_X_EVENT_RESULT)
#undef SR_X_EVENT_RESULT
};

inline constexpr const wchar_t* EventResultToString(
    EventResult result
) noexcept {
    switch (result) {
#define SR_X_EVENT_RESULT(name, text) \
        case EventResult::name: return text;
        SR_EVENT_RESULT_TABLE(SR_X_EVENT_RESULT)
#undef SR_X_EVENT_RESULT
    default:
        return L"unknown";
    }
}

#define SR_COMPLETED_RESULT_NOT_APPLIED_REASON_TABLE(X) \
    X(UnresolvedLocation, L"unresolvedLocation") \
    X(ReplayWithoutTimelineEntry, L"replayWithoutTimelineEntry") \
    X(InvalidLocationIndex, L"invalidLocationIndex") \
    X(InvalidStateTransition, L"invalidStateTransition")

enum class CompletedResultNotAppliedReason {
#define SR_X_COMPLETED_RESULT_NOT_APPLIED_REASON(name, text) name,
    SR_COMPLETED_RESULT_NOT_APPLIED_REASON_TABLE(SR_X_COMPLETED_RESULT_NOT_APPLIED_REASON)
#undef SR_X_COMPLETED_RESULT_NOT_APPLIED_REASON
};

inline constexpr const wchar_t* CompletedResultNotAppliedReasonToString(
    CompletedResultNotAppliedReason reason
) noexcept {
    switch (reason) {
#define SR_X_COMPLETED_RESULT_NOT_APPLIED_REASON(name, text) \
        case CompletedResultNotAppliedReason::name: return text;
        SR_COMPLETED_RESULT_NOT_APPLIED_REASON_TABLE(SR_X_COMPLETED_RESULT_NOT_APPLIED_REASON)
#undef SR_X_COMPLETED_RESULT_NOT_APPLIED_REASON
    default:
        return L"unknown";
    }
}

#define SR_PENDING_JOB_BUILD_FAILED_REASON_TABLE(X) \
    X(UnresolvedLocation, L"unresolvedLocation") \
    X(InvalidLocationIndex, L"invalidLocationIndex") \
    X(LocationKeyMismatch, L"locationKeyMismatch")

enum class PendingJobBuildFailedReason {
#define SR_X_PENDING_JOB_BUILD_FAILED_REASON(name, text) name,
    SR_PENDING_JOB_BUILD_FAILED_REASON_TABLE(SR_X_PENDING_JOB_BUILD_FAILED_REASON)
#undef SR_X_PENDING_JOB_BUILD_FAILED_REASON
};

inline constexpr const wchar_t* PendingJobBuildFailedReasonToString(
    PendingJobBuildFailedReason reason
) noexcept {
    switch (reason) {
#define SR_X_PENDING_JOB_BUILD_FAILED_REASON(name, text) \
        case PendingJobBuildFailedReason::name: return text;
        SR_PENDING_JOB_BUILD_FAILED_REASON_TABLE(SR_X_PENDING_JOB_BUILD_FAILED_REASON)
#undef SR_X_PENDING_JOB_BUILD_FAILED_REASON
    default:
        return L"unknown";
    }
}


#define SR_PRUNE_SKIPPED_REASON_TABLE(X) \
    X(NoParentEmitPolicy, L"noParentEmitPolicy") \
    X(StdoutReplayBufferNeeded, L"stdoutReplayBufferNeeded") \
    X(StderrReplayBufferNeeded, L"stderrReplayBufferNeeded") \
    X(UnresolvedLocation, L"unresolvedLocation") \
    X(InvalidLocationIndex, L"invalidLocationIndex") \
    X(NotPruneable, L"notPruneable")

enum class PruneSkippedReason {
#define SR_X_PRUNE_SKIPPED_REASON(name, text) name,
    SR_PRUNE_SKIPPED_REASON_TABLE(SR_X_PRUNE_SKIPPED_REASON)
#undef SR_X_PRUNE_SKIPPED_REASON
};

inline constexpr const wchar_t* PruneSkippedReasonToString(
    PruneSkippedReason reason
) noexcept {
    switch (reason) {
#define SR_X_PRUNE_SKIPPED_REASON(name, text) \
        case PruneSkippedReason::name: return text;
        SR_PRUNE_SKIPPED_REASON_TABLE(SR_X_PRUNE_SKIPPED_REASON)
#undef SR_X_PRUNE_SKIPPED_REASON
    default:
        return L"unknown";
    }
}

#define SR_PRUNE_FAILED_REASON_TABLE(X) \
    X(UnknownPhaseTimeline, L"unknownPhaseTimeline")

enum class PruneFailedReason {
#define SR_X_PRUNE_FAILED_REASON(name, text) name,
    SR_PRUNE_FAILED_REASON_TABLE(SR_X_PRUNE_FAILED_REASON)
#undef SR_X_PRUNE_FAILED_REASON
};

inline constexpr const wchar_t* PruneFailedReasonToString(
    PruneFailedReason reason
) noexcept {
    switch (reason) {
#define SR_X_PRUNE_FAILED_REASON(name, text) \
        case PruneFailedReason::name: return text;
        SR_PRUNE_FAILED_REASON_TABLE(SR_X_PRUNE_FAILED_REASON)
#undef SR_X_PRUNE_FAILED_REASON
    default:
        return L"unknown";
    }
}

struct CompletedResultTakenItem {
    TimelineEntryKey key{};
    JobTarget target = JobTarget::StdoutParent;
};

struct CompletedResultAppliedItem {
    TimelineEntryKey key{};
    JobTarget target = JobTarget::StdoutParent;
};

struct CompletedResultNotAppliedItem {
    TimelineEntryKey key{};
    JobTarget target = JobTarget::StdoutParent;
    CompletedResultNotAppliedReason reason =
        CompletedResultNotAppliedReason::UnresolvedLocation;
};

struct PendingJobBuildFailedItem {
    TimelineEntryKey key{};
    PendingJobBuildFailedReason reason =
        PendingJobBuildFailedReason::UnresolvedLocation;
};

struct PendingJobNotEnqueuedItem {
    TimelineEntryKey key{};
    PendingJobNotEnqueuedReason reason =
        PendingJobNotEnqueuedReason::NoJobsExchange;
};

struct PruneSkippedItem {
    TimelineEntryKey key{};
    PruneSkippedReason reason =
        PruneSkippedReason::NotPruneable;
};

struct PruneFailedItem {
    TimelineEntryKey key{};
    PruneFailedReason reason =
        PruneFailedReason::UnknownPhaseTimeline;
};
struct PruningSummary {
    std::vector<TimelineEntryKey> pruned;
    std::vector<PruneSkippedItem> pruneSkipped;
    std::vector<PruneFailedItem> pruneFailed;
};

struct UnobtainablePruningSummary {
    WorkerFailureRecords workerFailures;
    UnobtainableResultItems unobtainableTargets;
    PruningSummary pruning;
};

struct EventSummary {
    EventResult result = EventResult::Ok;
    const wchar_t* failedStep = nullptr;

    TimelineEntryKey eventKey{};

    std::vector<CompletedResultTakenItem> completedResultsTaken;
    std::vector<CompletedResultAppliedItem> completedResultsApplied;
    std::vector<CompletedResultNotAppliedItem> completedResultsNotApplied;

    std::vector<TimelineEntryKey> jobQueueRetrieved;
    std::vector<TimelineEntryKey> pendingJobsBuilt;
    std::vector<PendingJobBuildFailedItem> pendingJobsBuildFailed;
    std::vector<TimelineEntryKey> pendingJobsEnqueued;
    std::vector<PendingJobNotEnqueuedItem> pendingJobsNotEnqueued;
    SR::WorkerSummaries workerSummaries;

    PruningSummary completedPruning;
    UnobtainablePruningSummary unobtainablePruning;
};

std::wstring FormatEventSummary(
    const EventSummary& eventSummary
);
std::wstring FormatFinalEventSummary(
    const EventSummary& eventSummary
);

} // namespace SR
