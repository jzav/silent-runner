#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <deque>
#include <vector>
#include <string>

#include "SRJobTypes.h"
#include "SRPhaseTimelineEntry.h"

// Pending-job snapshot contract.
//
// SRJobTypes.h contains the job/result state model.
// SRPhaseTimelineEntry.h contains the timeline entry payload models.
// PendingJob combines both layers and is therefore kept separate to avoid
// a header cycle between SRJobTypes.h and SRPhaseTimelineEntry.h.

namespace SR {

struct PendingJob {
    TimelineEntryKey key{};
    JobOrigin origin = JobOrigin::Timeline;
    JobPayloadType payloadType = JobPayloadType::ChildStdout;

    SrDiagEntry srDiag;
    ChildStdoutEntry childStdout;
    ChildStderrEntry childStderr;
};

using PendingJobs = std::deque<PendingJob>;

#define SR_PENDING_JOB_NOT_ENQUEUED_REASON_TABLE(X) \
    X(NoJobsExchange, L"noJobsExchange") \
    X(NoWorker, L"noWorker") \
    X(NoFileSinkWorker, L"noFileSinkWorker") \
    X(NoParentEmitWorker, L"noParentEmitWorker") \
    X(FileSinkWorkerUnavailable, L"fileSinkWorkerUnavailable") \
    X(ParentEmitWorkerUnavailable, L"parentEmitWorkerUnavailable") \
    X(FileSinkWorkerRejected, L"fileSinkWorkerRejected") \
    X(ParentEmitWorkerRejected, L"parentEmitWorkerRejected")

enum class PendingJobNotEnqueuedReason {
#define SR_X_PENDING_JOB_NOT_ENQUEUED_REASON(name, text) name,
    SR_PENDING_JOB_NOT_ENQUEUED_REASON_TABLE(SR_X_PENDING_JOB_NOT_ENQUEUED_REASON)
#undef SR_X_PENDING_JOB_NOT_ENQUEUED_REASON
};

inline constexpr const wchar_t* PendingJobNotEnqueuedReasonToString(
    PendingJobNotEnqueuedReason reason
) noexcept {
    switch (reason) {
#define SR_X_PENDING_JOB_NOT_ENQUEUED_REASON(name, text) \
        case PendingJobNotEnqueuedReason::name: return text;
        SR_PENDING_JOB_NOT_ENQUEUED_REASON_TABLE(SR_X_PENDING_JOB_NOT_ENQUEUED_REASON)
#undef SR_X_PENDING_JOB_NOT_ENQUEUED_REASON
    default:
        return L"unknown";
    }
}

struct PendingJobEnqueueResult {
    TimelineEntryKey key{};
    bool accepted = false;
    PendingJobNotEnqueuedReason reason =
        PendingJobNotEnqueuedReason::NoJobsExchange;
};

using PendingJobEnqueueResults =
    std::vector<PendingJobEnqueueResult>;

#define SR_WORKER_JOB_REJECTED_REASON_TABLE(X) \
    X(PendingJobsInsertFailed, L"PendingJobsInsertFailed")

enum class WorkerJobRejectedReason {
#define SR_X_WORKER_JOB_REJECTED_REASON(name, text) name,
    SR_WORKER_JOB_REJECTED_REASON_TABLE(SR_X_WORKER_JOB_REJECTED_REASON)
#undef SR_X_WORKER_JOB_REJECTED_REASON
};

inline constexpr const wchar_t* WorkerJobRejectedReasonToString(
    WorkerJobRejectedReason reason
) noexcept {
    switch (reason) {
#define SR_X_WORKER_JOB_REJECTED_REASON(name, text) \
        case WorkerJobRejectedReason::name: return text;
        SR_WORKER_JOB_REJECTED_REASON_TABLE(SR_X_WORKER_JOB_REJECTED_REASON)
#undef SR_X_WORKER_JOB_REJECTED_REASON
    default:
        return L"unknown";
    }
}

struct WorkerJobRejectedSummary {
    PendingJob pendingJob;
    WorkerJobRejectedReason reason =
        WorkerJobRejectedReason::PendingJobsInsertFailed;
};

struct WorkerPendingJobsEnqueueSummary {
    JobTargetWorker worker = JobTargetWorker::SRFileSinkWorker;
    PendingJobs jobsReceived;
    PendingJobs jobsAccepted;
    std::vector<WorkerJobRejectedSummary> jobsRejected;
};

using WorkerPendingJobsEnqueueSummaries =
    std::vector<WorkerPendingJobsEnqueueSummary>;


struct WorkerTargetResultSummary {
    JobTarget target = JobTarget::StdoutTxt;
    JobState state = JobState::Pending;
    DWORD failedReasonGle = 0;
    std::wstring failedReasonText;
};

inline WorkerTargetResultSummary MakeWorkerTargetResultSummary(
    const JobResult& result
) {
    WorkerTargetResultSummary summary;
    summary.target = result.target;
    summary.state = result.state;
    summary.failedReasonGle = result.details.failedReasonGle;
    summary.failedReasonText = result.details.failedReasonText;
    return summary;
}

struct WorkerPendingJobSummary {
    JobTargetWorker worker = JobTargetWorker::SRFileSinkWorker;
    PendingJob pendingJob;
    std::vector<WorkerTargetResultSummary> targets;
};

using WorkerPendingJobSummaries = std::vector<WorkerPendingJobSummary>;
struct WorkerSummaries {
    WorkerPendingJobsEnqueueSummaries pendingJobsEnqueueSummaries;
    WorkerPendingJobSummaries pendingJobSummaries;
};


} // namespace SR
