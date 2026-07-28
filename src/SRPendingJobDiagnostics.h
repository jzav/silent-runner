#pragma once

#include <string>
#include <vector>

#include "SRPendingJobTypes.h"

namespace SR {


std::wstring FormatWorkerPendingJobsEnqueueSummary(
    const WorkerPendingJobsEnqueueSummary& summary
);

std::wstring FormatPendingJobId(const PendingJob& pendingJob);
std::wstring FormatWorkerTargetResultSummary(
    const PendingJob& pendingJob,
    const WorkerTargetResultSummary& target
);
std::wstring FormatWorkerPendingJobSummary(
    const WorkerPendingJobSummary& summary
);

} // namespace SR
