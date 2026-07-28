#include "SRJobsExchange.h"

#include <iterator>

#include "SRFileSinkWorker.h"
#include "SRParentEmitWorker.h"
#include "SRLifecycleDiagnostics.h"
#include "SRWorkerSupervisor.h"

bool SRJobsExchange::Init(
    SRLifecycleDiagnostics* diagnostics
) noexcept {
    diagnostics_ = diagnostics;
    return true;
}

void SRJobsExchange::ProbeLine_(const std::wstring& msg) {
    if constexpr (!kJobsExchangeProbeEnabled) return;
    if (!diagnostics_) return;
    diagnostics_->ProbeLine(msg);
}
bool SRJobsExchange::IsWorkerAvailable_(
    SR::JobTargetWorker worker
) const {
    if (!workerSupervisor_) {
        return false;
    }

    return workerSupervisor_->IsWorkerAvailable(worker);
}
void SRJobsExchange::AddUnobtainableTargets_(
    const SR::PendingJob& job,
    SR::JobTargetWorker worker
) {
    const std::vector<SR::JobTarget> targets =
        SR::RetrieveTargetsForPayloadType(job.payloadType, worker);

    for (SR::JobTarget target : targets) {
        unobtainableResults_.Add(
            SR::UnobtainableResult{
                job.key,
                target
            }
        );
    }
}



void SRJobsExchange::SetFileSinkWorker(SRFileSinkWorker& worker) noexcept {
    fileSinkWorker_ = &worker;
    ProbeLine_(L"SRJobsExchange::SetFileSinkWorker");
}
void SRJobsExchange::SetParentEmitWorker(SRParentEmitWorker& worker) noexcept {
    parentEmitWorker_ = &worker;
    ProbeLine_(L"SRJobsExchange::SetParentEmitWorker");
}
void SRJobsExchange::SetWorkerSupervisor(
    SR::SRWorkerSupervisor& supervisor
) noexcept {
    workerSupervisor_ = &supervisor;
    ProbeLine_(L"SRJobsExchange::SetWorkerSupervisor");
}
SR::UnobtainableResults& SRJobsExchange::GetUnobtainableResults() noexcept {
    return unobtainableResults_;
}

const SR::UnobtainableResults& SRJobsExchange::GetUnobtainableResults() const noexcept {
    return unobtainableResults_;
}
SR::WorkerFailureRecords SRJobsExchange::GetWorkerFailures() const {
    if (!workerSupervisor_) {
        return {};
    }

    return workerSupervisor_->RetrieveWorkerFailures();
}


SR::PendingJobEnqueueResults SRJobsExchange::EnqueuePendingJobs(const SR::PendingJobs& jobs) {
    SR::PendingJobEnqueueResults results;
    results.reserve(jobs.size());

    ProbeLine_(
        L"SRJobsExchange::EnqueuePendingJobs count=" +
        std::to_wstring(jobs.size())
    );
    if (jobs.empty()) {
        ProbeLine_(L"SRJobsExchange::EnqueuePendingJobs skip:empty");
        return results;
    }

    const bool hasFileSinkWorkerObject = fileSinkWorker_ != nullptr;
    const bool hasParentEmitWorkerObject = parentEmitWorker_ != nullptr;

    const bool canUseFileSinkWorker =
        hasFileSinkWorkerObject &&
        IsWorkerAvailable_(SR::JobTargetWorker::SRFileSinkWorker);
    const bool canUseParentEmitWorker =
        hasParentEmitWorkerObject &&
        IsWorkerAvailable_(SR::JobTargetWorker::SRParentEmitWorker);

    SR::PendingJobs fileSinkJobs;
    SR::PendingJobs parentEmitJobs;

    for (const SR::PendingJob& job : jobs) {
        if (canUseFileSinkWorker) {
            fileSinkJobs.push_back(job);
        } else {
            AddUnobtainableTargets_(
                job,
                SR::JobTargetWorker::SRFileSinkWorker
            );
        }

        if (canUseParentEmitWorker) {
            parentEmitJobs.push_back(job);
        } else {
            AddUnobtainableTargets_(
                job,
                SR::JobTargetWorker::SRParentEmitWorker
            );
        }
    }

    bool fileSinkAccepted = true;
    bool parentEmitAccepted = true;

    if (!fileSinkJobs.empty()) {
        ProbeLine_(L"SRJobsExchange::EnqueuePendingJobs forward to FileSinkWorker");
        fileSinkAccepted = fileSinkWorker_->EnqueuePendingJobs(fileSinkJobs);
    }

    if (!parentEmitJobs.empty()) {
        ProbeLine_(L"SRJobsExchange::EnqueuePendingJobs forward to ParentEmitWorker");
        parentEmitAccepted = parentEmitWorker_->EnqueuePendingJobs(parentEmitJobs);
    }

    for (const SR::PendingJob& job : jobs) {
        SR::PendingJobEnqueueResult result;
        result.key = job.key;
        result.accepted = true;

        if (!hasFileSinkWorkerObject && !hasParentEmitWorkerObject) {
            result.accepted = false;
            result.reason = SR::PendingJobNotEnqueuedReason::NoWorker;
        } else if (!hasFileSinkWorkerObject) {
            result.accepted = false;
            result.reason =
                SR::PendingJobNotEnqueuedReason::NoFileSinkWorker;
        } else if (!hasParentEmitWorkerObject) {
            result.accepted = false;
            result.reason =
                SR::PendingJobNotEnqueuedReason::NoParentEmitWorker;
        } else if (!canUseFileSinkWorker) {
            result.accepted = false;
            result.reason =
                SR::PendingJobNotEnqueuedReason::
                    FileSinkWorkerUnavailable;
        } else if (!canUseParentEmitWorker) {
            result.accepted = false;
            result.reason =
                SR::PendingJobNotEnqueuedReason::
                    ParentEmitWorkerUnavailable;
        } else if (!fileSinkAccepted) {
            result.accepted = false;
            result.reason =
                SR::PendingJobNotEnqueuedReason::
                    FileSinkWorkerRejected;
        } else if (!parentEmitAccepted) {
            result.accepted = false;
            result.reason =
                SR::PendingJobNotEnqueuedReason::
                    ParentEmitWorkerRejected;
        }


        results.push_back(result);
    }

    return results;
}
SR::PendingJobEnqueueResults SRJobsExchange::EnqueueParentEmitJobs(
    const SR::PendingJobs& jobs,
    SR::JobTarget target
) {
    SR::PendingJobEnqueueResults results;
    results.reserve(jobs.size());

    ProbeLine_(
        L"SRJobsExchange::EnqueueParentEmitJobs count=" +
        std::to_wstring(jobs.size()) +
        L" target=" +
        SR::JobTargetNameToString(target)
    );

    if (jobs.empty()) {
        ProbeLine_(
            L"SRJobsExchange::EnqueueParentEmitJobs skip:empty"
        );
        return results;
    }

    const bool hasParentEmitWorkerObject =
        parentEmitWorker_ != nullptr;

    const bool canUseParentEmitWorker =
        hasParentEmitWorkerObject &&
        IsWorkerAvailable_(
            SR::JobTargetWorker::SRParentEmitWorker
        );

    bool parentEmitAccepted = true;

    if (canUseParentEmitWorker) {
        ProbeLine_(
            L"SRJobsExchange::EnqueueParentEmitJobs "
            L"forward to ParentEmitWorker"
        );

        parentEmitAccepted =
            parentEmitWorker_->EnqueuePendingJobs(jobs);
    } else {
        for (const SR::PendingJob& job : jobs) {
            if (SR::IsFileReplayJobOrigin(job.origin)) {
                continue;
            }

            unobtainableResults_.Add(
                SR::UnobtainableResult{
                    job.key,
                    target
                }
            );
        }
    }

    for (const SR::PendingJob& job : jobs) {
        SR::PendingJobEnqueueResult result;
        result.key = job.key;
        result.accepted = true;

        if (!hasParentEmitWorkerObject) {
            result.accepted = false;
            result.reason =
                SR::PendingJobNotEnqueuedReason::
                    NoParentEmitWorker;
        } else if (!canUseParentEmitWorker) {
            result.accepted = false;
            result.reason =
                SR::PendingJobNotEnqueuedReason::
                    ParentEmitWorkerUnavailable;
        } else if (!parentEmitAccepted) {
            result.accepted = false;
            result.reason =
                SR::PendingJobNotEnqueuedReason::
                    ParentEmitWorkerRejected;
        }

        results.push_back(result);
    }

    return results;
}

SR::JobResults SRJobsExchange::TakeAllJobResults() {
    SR::JobResults allResults;
    ProbeLine_(L"SRJobsExchange::TakeAllJobResults begin");

    if (fileSinkWorker_) {
        SR::JobResults fileSinkResults = fileSinkWorker_->TakeJobResults();
        ProbeLine_(
            L"SRJobsExchange::TakeAllJobResults fileSinkResults=" +
            std::to_wstring(fileSinkResults.size())
        );

        allResults.insert(
            allResults.end(),
            std::make_move_iterator(fileSinkResults.begin()),
            std::make_move_iterator(fileSinkResults.end())
        );
    }

    if (parentEmitWorker_) {
        SR::JobResults parentEmitResults = parentEmitWorker_->TakeJobResults();
        ProbeLine_(
            L"SRJobsExchange::TakeAllJobResults parentEmitResults=" +
            std::to_wstring(parentEmitResults.size())
        );

        allResults.insert(
            allResults.end(),
            std::make_move_iterator(parentEmitResults.begin()),
            std::make_move_iterator(parentEmitResults.end())
        );
    }

    ProbeLine_(
        L"SRJobsExchange::TakeAllJobResults allResults=" +
        std::to_wstring(allResults.size())
    );
    return allResults;
}


SR::WorkerSummaries SRJobsExchange::TakeWorkerSummaries() {
    SR::WorkerSummaries summaries;
    ProbeLine_(L"SRJobsExchange::TakeWorkerSummaries begin");

    if (fileSinkWorker_) {
        SR::WorkerSummaries fileSinkSummaries =
            fileSinkWorker_->TakeWorkerSummaries();
        ProbeLine_(
            L"SRJobsExchange::TakeWorkerSummaries fileSinkEnqueueSummaries=" +
            std::to_wstring(
                fileSinkSummaries.pendingJobsEnqueueSummaries.size()
            )
        );
        ProbeLine_(
            L"SRJobsExchange::TakeWorkerSummaries fileSinkPendingJobSummaries=" +
            std::to_wstring(
                fileSinkSummaries.pendingJobSummaries.size()
            )
        );

        summaries.pendingJobsEnqueueSummaries.insert(
            summaries.pendingJobsEnqueueSummaries.end(),
            std::make_move_iterator(
                fileSinkSummaries.pendingJobsEnqueueSummaries.begin()
            ),
            std::make_move_iterator(
                fileSinkSummaries.pendingJobsEnqueueSummaries.end()
            )
        );
        summaries.pendingJobSummaries.insert(
            summaries.pendingJobSummaries.end(),
            std::make_move_iterator(
                fileSinkSummaries.pendingJobSummaries.begin()
            ),
            std::make_move_iterator(
                fileSinkSummaries.pendingJobSummaries.end()
            )
        );
    }

    if (parentEmitWorker_) {
        SR::WorkerSummaries parentEmitSummaries =
            parentEmitWorker_->TakeWorkerSummaries();
        ProbeLine_(
            L"SRJobsExchange::TakeWorkerSummaries parentEmitEnqueueSummaries=" +
            std::to_wstring(
                parentEmitSummaries.pendingJobsEnqueueSummaries.size()
            )
        );
        ProbeLine_(
            L"SRJobsExchange::TakeWorkerSummaries parentEmitPendingJobSummaries=" +
            std::to_wstring(
                parentEmitSummaries.pendingJobSummaries.size()
            )
        );

        summaries.pendingJobsEnqueueSummaries.insert(
            summaries.pendingJobsEnqueueSummaries.end(),
            std::make_move_iterator(
                parentEmitSummaries.pendingJobsEnqueueSummaries.begin()
            ),
            std::make_move_iterator(
                parentEmitSummaries.pendingJobsEnqueueSummaries.end()
            )
        );
        summaries.pendingJobSummaries.insert(
            summaries.pendingJobSummaries.end(),
            std::make_move_iterator(
                parentEmitSummaries.pendingJobSummaries.begin()
            ),
            std::make_move_iterator(
                parentEmitSummaries.pendingJobSummaries.end()
            )
        );
    }
    ProbeLine_(
        L"SRJobsExchange::TakeWorkerSummaries enqueueSummaries=" +
        std::to_wstring(summaries.pendingJobsEnqueueSummaries.size())
    );
    ProbeLine_(
        L"SRJobsExchange::TakeWorkerSummaries pendingJobSummaries=" +
        std::to_wstring(summaries.pendingJobSummaries.size())
    );
    return summaries;
}
