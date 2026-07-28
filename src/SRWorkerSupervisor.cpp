// SRWorkerSupervisor.cpp
#include "SRWorkerSupervisor.h"

namespace SR {

SRWorkerSupervisor::WorkerState& SRWorkerSupervisor::WorkerStateOf_(
    JobTargetWorker worker
) {
    switch (worker) {
        case JobTargetWorker::SRParentEmitWorker:
            return parentEmitWorker_;
        case JobTargetWorker::SRFileSinkWorker:
            return fileSinkWorker_;
    }

    return parentEmitWorker_;
}

const SRWorkerSupervisor::WorkerState& SRWorkerSupervisor::WorkerStateOf_(
    JobTargetWorker worker
) const {
    switch (worker) {
        case JobTargetWorker::SRParentEmitWorker:
            return parentEmitWorker_;
        case JobTargetWorker::SRFileSinkWorker:
            return fileSinkWorker_;
    }

    return parentEmitWorker_;
}

void SRWorkerSupervisor::SetWorkerAvailable(
    JobTargetWorker worker,
    bool available
) {
    std::lock_guard<std::mutex> lock(mutex_);

    WorkerState& state = WorkerStateOf_(worker);

    if (state.failed) {
        state.available = false;
        return;
    }

    state.available = available;
}

void SRWorkerSupervisor::ReportWorkerFailure(
    JobTargetWorker worker,
    const std::wstring& failureText
) {
    std::lock_guard<std::mutex> lock(mutex_);

    WorkerState& state = WorkerStateOf_(worker);

    state.available = false;
    state.failed = true;
    state.failureText = failureText;
}

bool SRWorkerSupervisor::IsWorkerAvailable(
    JobTargetWorker worker
) const {
    std::lock_guard<std::mutex> lock(mutex_);

    const WorkerState& state = WorkerStateOf_(worker);

    return state.available && !state.failed;
}
bool SRWorkerSupervisor::IsAnyWorkerAvailable() const {
    std::lock_guard<std::mutex> lock(mutex_);

    return
        (parentEmitWorker_.available && !parentEmitWorker_.failed) ||
        (fileSinkWorker_.available && !fileSinkWorker_.failed);
}

bool SRWorkerSupervisor::HasWorkerFailure(
    JobTargetWorker worker
) const {
    std::lock_guard<std::mutex> lock(mutex_);

    const WorkerState& state = WorkerStateOf_(worker);

    return state.failed;
}

WorkerFailureRecords SRWorkerSupervisor::RetrieveWorkerFailures() const {
    std::lock_guard<std::mutex> lock(mutex_);

    WorkerFailureRecords records;

    if (parentEmitWorker_.failed) {
        records.push_back(
            WorkerFailureRecord{
                JobTargetWorker::SRParentEmitWorker,
                parentEmitWorker_.failureText
            }
        );
    }

    if (fileSinkWorker_.failed) {
        records.push_back(
            WorkerFailureRecord{
                JobTargetWorker::SRFileSinkWorker,
                fileSinkWorker_.failureText
            }
        );
    }

    return records;
}

std::wstring SRWorkerSupervisor::FormatWorkerFailureDiagnostics() const {
    const WorkerFailureRecords records = RetrieveWorkerFailures();

    std::wstring out;

    for (const WorkerFailureRecord& record : records) {
        if (!out.empty()) {
            out += L"\n";
        }

        out += L"Worker failure: worker=";
        out += JobTargetWorkerNameToString(record.worker);
        out += L" reason=";

        if (!record.failureText.empty()) {
            out += record.failureText;
        } else {
            out += L"(none)";
        }
    }

    return out;
}

} // namespace SR
