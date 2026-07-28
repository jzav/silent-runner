#pragma once

#include <string>
#include "SRPendingJobTypes.h"
#include "SRUnobtainableResults.h"
#include "SRWorkerSupervisor.h"

class SRFileSinkWorker;
class SRParentEmitWorker;
class SRLifecycleDiagnostics;

class SRJobsExchange {
public:
    SRJobsExchange() = default;

    SRJobsExchange(const SRJobsExchange&) = delete;
    SRJobsExchange& operator=(const SRJobsExchange&) = delete;

    void SetFileSinkWorker(SRFileSinkWorker& worker) noexcept;
    void SetParentEmitWorker(SRParentEmitWorker& worker) noexcept;
    void SetWorkerSupervisor(SR::SRWorkerSupervisor& supervisor) noexcept;
    bool Init(SRLifecycleDiagnostics* diagnostics) noexcept;

    SR::PendingJobEnqueueResults EnqueuePendingJobs(const SR::PendingJobs& jobs);
    SR::PendingJobEnqueueResults EnqueueParentEmitJobs(
        const SR::PendingJobs& jobs,
        SR::JobTarget target
    );

    SR::JobResults TakeAllJobResults();
    SR::WorkerSummaries TakeWorkerSummaries();
    SR::UnobtainableResults& GetUnobtainableResults() noexcept;
    const SR::UnobtainableResults& GetUnobtainableResults() const noexcept;
    SR::WorkerFailureRecords GetWorkerFailures() const;

private:
    static constexpr bool kJobsExchangeProbeEnabled = true;
    void ProbeLine_(const std::wstring& msg);
    bool IsWorkerAvailable_(SR::JobTargetWorker worker) const;
    void AddUnobtainableTargets_(
        const SR::PendingJob& job,
        SR::JobTargetWorker worker
    );
    SR::SRWorkerSupervisor* workerSupervisor_ = nullptr; // non-owning
    SR::UnobtainableResults unobtainableResults_;
    SRFileSinkWorker* fileSinkWorker_ = nullptr; // non-owning
    SRParentEmitWorker* parentEmitWorker_ = nullptr; // non-owning
    SRLifecycleDiagnostics* diagnostics_ = nullptr; // non-owning
};
