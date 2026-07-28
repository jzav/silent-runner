#pragma once

#include <cstddef>
#include <cstdint>

#include "SRPendingJobTypes.h"

class SRJobsExchange;

class SRReplayJobsBatch {
public:
    SRReplayJobsBatch() = default;

    bool Init(
        SRJobsExchange& jobsExchange,
        SR::JobTarget target
    ) noexcept;

    SRReplayJobsBatch(const SRReplayJobsBatch&) = delete;
    SRReplayJobsBatch& operator=(const SRReplayJobsBatch&) = delete;

    SRReplayJobsBatch(SRReplayJobsBatch&&) = delete;
    SRReplayJobsBatch& operator=(SRReplayJobsBatch&&) = delete;

    bool Add(SR::PendingJob job);
    bool Flush();

private:
    static uint64_t RetrievePayloadByteCount_(
        const SR::PendingJob& job
    ) noexcept;

    SRJobsExchange* jobsExchange_ = nullptr;
    SR::JobTarget target_;

    SR::PendingJobs pendingJobs_;
    uint64_t pendingJobPayloadBytes_ = 0;
};
