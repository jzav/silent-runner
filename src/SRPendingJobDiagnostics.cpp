#include "SRPendingJobDiagnostics.h"
#include "ErrorHelpers.h"

namespace SR {
namespace {

void AppendTimelineEntryKey_(
    std::wstring& out,
    const TimelineEntryKey& key
) {
    out += LifecyclePhaseShortNameToString(key.phase);
    out += L":";
    out += std::to_wstring(key.phaseOrderNo);
    out += L":";
    out += std::to_wstring(key.eventOrderNo);
}

std::wstring FormatTimelineEntryKey_(
    const TimelineEntryKey& key
) {
    std::wstring out;
    AppendTimelineEntryKey_(out, key);
    return out;
}

void AppendWorkerTargetFailureDetails_(
    std::wstring& out,
    const WorkerTargetResultSummary& target
) {
    if (target.failedReasonText.empty() &&
        target.failedReasonGle == 0) {
        return;
    }

    out += L"(";

    if (!target.failedReasonText.empty()) {
        out += target.failedReasonText;
    }

    if (target.failedReasonGle != 0) {
        if (!target.failedReasonText.empty()) {
            out += L"_";
        }

        out += ErrorHelpers::FormatGle(target.failedReasonGle);
    }

    out += L")";
}

} // namespace
void AppendPendingJobKeyListLine_(
    std::wstring& out,
    const wchar_t* label,
    const PendingJobs& jobs
) {
    out += label;
    out += L"_";
    out += std::to_wstring(jobs.size());
    out += L"=[";

    for (std::size_t i = 0; i < jobs.size(); ++i) {
        if (i != 0) {
            out += L",";
        }

        AppendTimelineEntryKey_(out, jobs[i].key);
    }

    out += L"]\n";
}

void AppendWorkerRejectedJobListLine_(
    std::wstring& out,
    const wchar_t* label,
    const std::vector<WorkerJobRejectedSummary>& jobs
) {
    out += label;
    out += L"_";
    out += std::to_wstring(jobs.size());
    out += L"=[";

    for (std::size_t i = 0; i < jobs.size(); ++i) {
        if (i != 0) {
            out += L",";
        }

        AppendTimelineEntryKey_(out, jobs[i].pendingJob.key);
        out += L"_";
        out += WorkerJobRejectedReasonToString(jobs[i].reason);
    }

    out += L"]\n";
}



std::wstring FormatWorkerPendingJobsEnqueueSummary(
    const WorkerPendingJobsEnqueueSummary& summary
) {
    std::wstring out;

    AppendPendingJobKeyListLine_(
        out,
        L"jobsReceived",
        summary.jobsReceived
    );
    AppendPendingJobKeyListLine_(
        out,
        L"jobsAccepted",
        summary.jobsAccepted
    );
    AppendWorkerRejectedJobListLine_(
        out,
        L"jobsRejected",
        summary.jobsRejected
    );

    return out;
}

std::wstring FormatPendingJobId(const PendingJob& pendingJob) {
    return L"[" + FormatTimelineEntryKey_(pendingJob.key) + L"]";
}

std::wstring FormatWorkerTargetResultSummary(
    const PendingJob& pendingJob,
    const WorkerTargetResultSummary& target
) {
    std::wstring out;

    AppendTimelineEntryKey_(out, pendingJob.key);
    out += L":";
    out += JobTargetNameToString(target.target);
    out += L"_";
    out += JobStateNameToString(target.state);

    AppendWorkerTargetFailureDetails_(out, target);

    return out;
}

std::wstring FormatWorkerPendingJobSummary(
    const WorkerPendingJobSummary& summary
) {
    std::wstring out;

    out += L"PendingJob=";
    out += FormatPendingJobId(summary.pendingJob);
    out += L" payloadType=";
    out += JobPayloadTypeNameToString(summary.pendingJob.payloadType);
    out += L" targets_";
    out += std::to_wstring(summary.targets.size());
    out += L"=[\n";

    for (std::size_t i = 0; i < summary.targets.size(); ++i) {
        out += L"  ";
        out += FormatWorkerTargetResultSummary(
            summary.pendingJob,
            summary.targets[i]
        );

        if (i + 1 < summary.targets.size()) {
            out += L",";
        }

        out += L"\n";
    }

    out += L"]";

    return out;
}

} // namespace SR
