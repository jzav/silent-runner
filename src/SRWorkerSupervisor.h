// SRWorkerSupervisor.h
#pragma once

#include <mutex>
#include <string>
#include <vector>

#include "SRPendingJobTypes.h"

namespace SR {

struct WorkerFailureRecord {
    JobTargetWorker worker = JobTargetWorker::SRParentEmitWorker;
    std::wstring failureText;
};

using WorkerFailureRecords = std::vector<WorkerFailureRecord>;

//
// Tracks permanent worker availability.
//
// Once a worker becomes unavailable, new jobs are no longer
// scheduled to that worker.
//
// The goal is not to recover in-flight jobs, but to prevent
// future TimelineEntry retention and unbounded Timeline buffer
// growth caused by workers that can no longer produce results.
//
class SRWorkerSupervisor {
public:
    SRWorkerSupervisor() = default;

    SRWorkerSupervisor(const SRWorkerSupervisor&) = delete;
    SRWorkerSupervisor& operator=(const SRWorkerSupervisor&) = delete;

    void SetWorkerAvailable(JobTargetWorker worker, bool available);
    void ReportWorkerFailure(
        JobTargetWorker worker,
        const std::wstring& failureText
    );

    bool IsWorkerAvailable(JobTargetWorker worker) const;
    bool IsAnyWorkerAvailable() const;
    bool HasWorkerFailure(JobTargetWorker worker) const;

    WorkerFailureRecords RetrieveWorkerFailures() const;
    std::wstring FormatWorkerFailureDiagnostics() const;

private:
    struct WorkerState {
        bool available = false;
        bool failed = false;
        std::wstring failureText;
    };
    WorkerState& WorkerStateOf_(JobTargetWorker worker);
    const WorkerState& WorkerStateOf_(JobTargetWorker worker) const;

    mutable std::mutex mutex_;

    WorkerState parentEmitWorker_;
    WorkerState fileSinkWorker_;
};

} // namespace SR
