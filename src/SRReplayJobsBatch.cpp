#include "SRReplayJobsBatch.h"

#include <limits>
#include <utility>

#include "SRJobsExchange.h"

namespace {

constexpr std::size_t kReplayBatchMaxJobs = 32;
constexpr uint64_t kReplayBatchMaxPayloadBytes = 1u << 20;

bool AllAccepted_(
    const SR::PendingJobEnqueueResults& results
) noexcept {
    for (const SR::PendingJobEnqueueResult& result : results) {
        if (!result.accepted) {
            return false;
        }
    }

    return true;
}

} // namespace

bool SRReplayJobsBatch::Init(
    SRJobsExchange& jobsExchange,
    SR::JobTarget target
) noexcept {
    jobsExchange_ = &jobsExchange;
    target_ = target;
    pendingJobs_.clear();
    pendingJobPayloadBytes_ = 0;
    return true;
}

bool SRReplayJobsBatch::Add(SR::PendingJob job) {
    if (!jobsExchange_) {
        return false;
    }
    const uint64_t payloadByteCount =
        RetrievePayloadByteCount_(job);

    if (pendingJobPayloadBytes_ >
        std::numeric_limits<uint64_t>::max() - payloadByteCount) {
        pendingJobPayloadBytes_ =
            std::numeric_limits<uint64_t>::max();
    } else {
        pendingJobPayloadBytes_ += payloadByteCount;
    }

    pendingJobs_.push_back(std::move(job));

    if (pendingJobs_.size() >= kReplayBatchMaxJobs ||
        pendingJobPayloadBytes_ >= kReplayBatchMaxPayloadBytes) {
        return Flush();
    }

    return true;
}

bool SRReplayJobsBatch::Flush() {
    if (!jobsExchange_) {
        return false;
    }

    if (pendingJobs_.empty()) {
        return true;
    }

    const std::size_t expectedResultCount =
        pendingJobs_.size();

    const SR::PendingJobEnqueueResults results =
        jobsExchange_->EnqueueParentEmitJobs(
            pendingJobs_,
            target_
        );

    const bool accepted =
        results.size() == expectedResultCount &&
        AllAccepted_(results);

    pendingJobs_.clear();
    pendingJobPayloadBytes_ = 0;

    return accepted;
}

uint64_t SRReplayJobsBatch::RetrievePayloadByteCount_(
    const SR::PendingJob& job
) noexcept {
    switch (job.payloadType) {
        case SR::JobPayloadType::SrDiag:
            return job.srDiag.payloadByteCount;

        case SR::JobPayloadType::ChildStdout:
            return job.childStdout.payloadByteCount;

        case SR::JobPayloadType::ChildStderr:
            return job.childStderr.payloadByteCount;
    }

    return 0;
}
