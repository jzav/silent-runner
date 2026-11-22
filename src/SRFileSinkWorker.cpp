// SRFileSinkWorker.cpp

#include "SRFileSinkWorker.h"

#include <algorithm>
#include <stdexcept>
#include <utility>

#include "FileHelpers.h"
#include "LogWriter.h"
#include "SRTargetLogFiles.h"

#include "SRPhaseTimelineEntry.h"
#include "SRPhaseTimelineEntryFormatter.h"

#include "SRLifecycleDiagnostics.h"
#include "SRJobDiagnostics.h"

#include "SRPendingJobDiagnostics.h"
#include "SRThreading.h"
#include "SRWorkerSupervisor.h"
#include "SRWorkerCommonPolicy.h"

namespace {

static constexpr char kLf = '\n';
const SR::FileSinkWorkerFailureState::TargetFailure* FindFileTargetFailure_(
    const SR::FileSinkWorkerFailureState& failure,
    SR::JobTarget target
) noexcept {
    for (const auto& targetFailure : failure.targets) {
        if (targetFailure.target == target) {
            return &targetFailure;
        }
    }
    return nullptr;
}





} // namespace

// -----------------------------------------------------------------------------
// Public API: configure file targets, enqueue pending jobs, collect job results.
// -----------------------------------------------------------------------------

SRFileSinkWorker::~SRFileSinkWorker() {
    DrainAndStop();
}

void SRFileSinkWorker::ProbeLine_(const std::wstring& msg) const {
    if constexpr (!kFileSinkWorkerProbeEnabled) return;
    if (!diagnostics_) return;
    diagnostics_->ProbeLine(msg);
}
void SRFileSinkWorker::SetWorkerSupervisor(
    SR::SRWorkerSupervisor* supervisor
) noexcept {
    workerSupervisor_ = supervisor;
}




bool SRFileSinkWorker::Init(
    SRLifecycleDiagnostics* diagnostics,
    const SR::FileSinkWorkerTargetLayout& targetLayout,
    SR::JsonlPayloadRepresentation jsonlPayloadRepresentation,
    const SRWorkerCommonPolicy& workerCommonPolicy
) {

    diagnostics_ = diagnostics;
    ProbeLine_(L"SRFileSinkWorker::Init");

    {
        std::scoped_lock lock(domainMutex_, failureMutex_);
        domain_ = WorkerDomain{};
        domain_.config.parsingToken =
            workerCommonPolicy.ParsingToken();
        domain_.config.executionId = workerCommonPolicy.ExecutionId();
        domain_.config.stdoutTxtHeaderGranularity =
            workerCommonPolicy.StdoutTxtHeaderGranularity();
        domain_.config.stderrChildTxtHeaderGranularity =
            workerCommonPolicy.StderrChildTxtHeaderGranularity();
        domain_.config.jsonlPayloadRepresentation =
            jsonlPayloadRepresentation;



        domain_.config.failure.targets.reserve(domain_.targetConfigs.size());
        for (std::size_t workerConfigIndex = 0;
             workerConfigIndex < domain_.targetConfigs.size();
             ++workerConfigIndex) {
            const SR::WorkerTargetLayoutEntry& targetLayoutEntry =
                targetLayout.targets[workerConfigIndex];

            FileTargetConfig& targetConfig =
                domain_.targetConfigs[
                    workerConfigIndex
                ];

            targetConfig.target =
                targetLayoutEntry.target;
            targetConfig.format =
                targetLayoutEntry.format;
            targetConfig.headerEnabled =
                targetLayoutEntry.headerEnabled;
            domain_.config.failure.targets.push_back({
                targetLayoutEntry.target,
                false,
                0,
                {}
            });
        }
    }

    
    stdoutTxtLastWrittenPayloadType_.reset();
    stdoutTxtAtLineStart_ = true;
    stderrSrAndChildTxtLastWrittenPayloadType_.reset();
    stderrSrAndChildTxtAtLineStart_ = true;
    stderrChildTxtLastWrittenPayloadType_.reset();
    stderrChildTxtAtLineStart_ = true;
    stderrSrAndChildInclStdoutTxtLastWrittenPayloadType_.reset();
    stderrSrAndChildInclStdoutTxtAtLineStart_ = true;

    
    return true;
}

void SRFileSinkWorker::AttachTxtLogWriters(
    const std::vector<TargetLogBinding>& bindings
) {
    std::lock_guard<std::mutex> lock(domainMutex_);
    AttachLogWritersLocked_(
        bindings,
        SR::JobTargetFormat::Txt
    );
}
void SRFileSinkWorker::AttachJsonlLogWriters(
    const std::vector<TargetLogBinding>& bindings
) {
    std::lock_guard<std::mutex> lock(domainMutex_);
    AttachLogWritersLocked_(
        bindings,
        SR::JobTargetFormat::Jsonl
    );
}
void SRFileSinkWorker::AttachLogWritersLocked_(
    const std::vector<TargetLogBinding>& bindings,
    SR::JobTargetFormat expectedFormat
) {
    for (const auto& binding : bindings) {
        FileTargetConfig* targetConfigPtr = nullptr;
        for (auto& candidate : domain_.targetConfigs) {
            if (candidate.target == binding.target) {
                targetConfigPtr = &candidate;
                break;
            }
        }
        if (!targetConfigPtr) {
            continue;
        }
        FileTargetConfig& targetConfig = *targetConfigPtr;

        if (targetConfig.format != expectedFormat) {
            continue;
        }
        targetConfig.enabled = binding.enabled;
        targetConfig.writer = binding.writer;
    }
}

bool SRFileSinkWorker::StartPaused(
    std::shared_ptr<ExecutionTimeline> executionTimeline
) {
    ProbeLine_(L"SRFileSinkWorker::StartPaused begin");
    (void)executionTimeline;

    std::lock_guard<std::mutex> lock(controlMutex_);
    if (started_) {
        ProbeLine_(L"SRFileSinkWorker::StartPaused already started");
        return true;
    }

    stopMode_ = StopMode::KeepRunning;
    paused_ = true;
    processingActive_ = false;

    try {
        workerThread_ = std::thread([this]() {
            SRThreading::RunGuardedThreadEntry(
                [this]() {
                    ThreadMain_();
                },
                [this](const SRThreading::ThreadExceptionInfo& ex) {
                    ProbeLine_(
                        L"SRFileSinkWorker::ThreadMain_ exception: " +
                        ex.text
                    );

                    if (workerSupervisor_) {
                        workerSupervisor_->ReportWorkerFailure(
                            SR::JobTargetWorker::SRFileSinkWorker,
                            ex.text
                        );
                    }

                    {
                        std::lock_guard<std::mutex> lock(controlMutex_);
                        processingActive_ = false;
                        stopMode_ = StopMode::DrainAndStop;
                    }

                    cv_.notify_all();
                    drainCv_.notify_all();
                }
            );
        });
    } catch (...) {
        return false;
    }

    started_ = true;
    if (workerSupervisor_) {
        workerSupervisor_->SetWorkerAvailable(
            SR::JobTargetWorker::SRFileSinkWorker,
            true
        );
    }
    ProbeLine_(L"SRFileSinkWorker::StartPaused started");
    return true;
}

void SRFileSinkWorker::Resume() {
    {
        std::lock_guard<std::mutex> lock(controlMutex_);
        paused_ = false;
    }

    cv_.notify_one();
}

void SRFileSinkWorker::Pause() {
    std::lock_guard<std::mutex> lock(controlMutex_);
    paused_ = true;
}

bool SRFileSinkWorker::Drain() {
    {
        std::unique_lock<std::mutex> lock(controlMutex_);
        if (workerSupervisor_ &&
            !workerSupervisor_->IsWorkerAvailable(
                SR::JobTargetWorker::SRFileSinkWorker
            )) {
            return false;
        }

        paused_ = false;
        cv_.notify_one();

        drainCv_.wait(lock, [this]() {
            std::lock_guard<std::mutex> pendingLock(pendingJobsMutex_);
            return
                (pendingJobs_.empty() && !processingActive_) ||
                (workerSupervisor_ &&
                 !workerSupervisor_->IsWorkerAvailable(
                     SR::JobTargetWorker::SRFileSinkWorker
                 ));
        });
    }

    return
        !workerSupervisor_ ||
        workerSupervisor_->IsWorkerAvailable(
            SR::JobTargetWorker::SRFileSinkWorker
        );
}

bool SRFileSinkWorker::PauseAfterCurrentJob() {
    if (workerSupervisor_ &&
        !workerSupervisor_->IsWorkerAvailable(
            SR::JobTargetWorker::SRFileSinkWorker
        )) {
        return false;
    }

    Pause();

    std::unique_lock<std::mutex> lock(controlMutex_);
    drainCv_.wait(lock, [this]() {
        return
            !processingActive_ ||
            (workerSupervisor_ &&
             !workerSupervisor_->IsWorkerAvailable(
                 SR::JobTargetWorker::SRFileSinkWorker
             ));
    });

    return
        !workerSupervisor_ ||
        workerSupervisor_->IsWorkerAvailable(
            SR::JobTargetWorker::SRFileSinkWorker
        );
}

void SRFileSinkWorker::DrainAndStop() {
    ProbeLine_(L"SRFileSinkWorker::DrainAndStop begin");
    {
        std::lock_guard<std::mutex> lock(controlMutex_);
        if (!started_) {
            ProbeLine_(L"SRFileSinkWorker::DrainAndStop skip:not started");
            return;
        }

        stopMode_ = StopMode::DrainAndStop;
    }

    cv_.notify_one();

    if (workerThread_.joinable()) {
        workerThread_.join();
    }
    ProbeLine_(L"SRFileSinkWorker::DrainAndStop joined");

    {
        std::lock_guard<std::mutex> lock(controlMutex_);
        started_ = false;
        paused_ = false;
        processingActive_ = false;
    }
    drainCv_.notify_all();
}

bool SRFileSinkWorker::EnqueuePendingJobs(const SR::PendingJobs& jobs) {
    ProbeLine_(
        L"SRFileSinkWorker::EnqueuePendingJobs count=" +
        std::to_wstring(jobs.size())
    );
    if (jobs.empty()) {
        ProbeLine_(L"SRFileSinkWorker::EnqueuePendingJobs skip:empty");
        return true;
    }

    SR::WorkerPendingJobsEnqueueSummary summary;
    summary.worker = SR::JobTargetWorker::SRFileSinkWorker;
    summary.jobsReceived = jobs;

    try {
        {
            std::lock_guard<std::mutex> lock(pendingJobsMutex_);
            for (const auto& job : jobs) {
                pendingJobs_.push_back(job);
            }
            ProbeLine_(
                L"SRFileSinkWorker::EnqueuePendingJobs pendingJobs total=" +
                std::to_wstring(pendingJobs_.size())
            );
        }

        for (const auto& job : jobs) {
            summary.jobsAccepted.push_back(job);
        }
    } catch (...) {
        summary.jobsRejected.reserve(jobs.size());
        for (const auto& job : jobs) {
            SR::WorkerJobRejectedSummary rejected;
            rejected.pendingJob = job;
            rejected.reason =
                SR::WorkerJobRejectedReason::PendingJobsInsertFailed;
            summary.jobsRejected.push_back(std::move(rejected));
        }

        {
            std::lock_guard<std::mutex> lock(workerSummariesMutex_);
            workerSummaries_.pendingJobsEnqueueSummaries.push_back(std::move(summary));
        }

        return false;
    }

    {
        std::lock_guard<std::mutex> lock(workerSummariesMutex_);
        workerSummaries_.pendingJobsEnqueueSummaries.push_back(std::move(summary));
    }

    cv_.notify_one();
    return true;
}

// -----------------------------------------------------------------------------
// File target mapping: the target tables live in SRJobTypes.h.
// -----------------------------------------------------------------------------




// -----------------------------------------------------------------------------
// Worker loop: dequeue and execute PendingJobs in FIFO order.
// -----------------------------------------------------------------------------

void SRFileSinkWorker::ThreadMain_() {
    ProbeLine_(L"SRFileSinkWorker::ThreadMain_ begin");
    std::size_t dequeuedJobCount = 0;
    for (;;) {
        SR::PendingJob job;

        {
            std::unique_lock<std::mutex> controlLock(controlMutex_);
            cv_.wait(controlLock, [this]() {
                if (stopMode_ == StopMode::DrainAndStop) {
                    return true;
                }

                if (paused_) {
                    return false;
                }

                std::lock_guard<std::mutex> jobsLock(pendingJobsMutex_);
                return !pendingJobs_.empty();
            });

            {
                std::lock_guard<std::mutex> jobsLock(pendingJobsMutex_);

                if (pendingJobs_.empty()) {
                    processingActive_ = false;

                    if (stopMode_ == StopMode::DrainAndStop) {
                        return;
                    }

                    continue;
                }

                job = std::move(pendingJobs_.front());
                pendingJobs_.pop_front();
                processingActive_ = true;
            }
        }

        ++dequeuedJobCount;
        if (kFileSinkWorkerInjectFailure &&
            dequeuedJobCount == kFileSinkWorkerFailOnDequeuedJob) {
            throw std::runtime_error(
                "Injected SRFileSinkWorker failure"
            );
        }

        ProbeLine_(
            std::wstring(L"SRFileSinkWorker::ThreadMain_ execute payloadType=") +
            SR::JobPayloadTypeNameToString(job.payloadType)
        );
        ExecutePendingJob_(job);

        {
            std::lock_guard<std::mutex> controlLock(controlMutex_);
            processingActive_ = false;
        }
        drainCv_.notify_all();

        if (ShouldStopAfterDrain_()) {
            ProbeLine_(L"SRFileSinkWorker::ThreadMain_ stop after drain");
            break;
        }
    }
}

bool SRFileSinkWorker::ShouldStopAfterDrain_() const noexcept {
    {
        std::lock_guard<std::mutex> controlLock(controlMutex_);
        if (stopMode_ != StopMode::DrainAndStop) {
            return false;
        }
    }

    std::lock_guard<std::mutex> jobsLock(pendingJobsMutex_);
    return pendingJobs_.empty();
}

// -----------------------------------------------------------------------------
// Job execution: one PendingJob fans out to file targets; each target returns
// exactly one JobResult.
// -----------------------------------------------------------------------------

void SRFileSinkWorker::ExecutePendingJob_(const SR::PendingJob& job) {
    std::wstring probePrefix =
        std::wstring(L"SRFileSinkWorker::ExecutePendingJob_ ") +
        SR::FormatPendingJobId(job) +
        L" payloadType=" +
        SR::JobPayloadTypeNameToString(job.payloadType);
    if (job.payloadType == SR::JobPayloadType::SrDiag) {
        probePrefix += L" severity=";
        probePrefix += SR::DiagnosticSeverityToToken(job.srDiag.severity);
    }
    ProbeLine_(probePrefix);
    const std::vector<SR::JobTarget> targets =
        SR::RetrieveTargetsForPayloadType(
            job.payloadType,
            SR::JobTargetWorker::SRFileSinkWorker
        );

    ProbeLine_(
        std::wstring(L"SRFileSinkWorker::ExecutePendingJob_ ") +
        SR::FormatPendingJobId(job) +
        L" targetCount=" +
        std::to_wstring(targets.size())
    );

    SR::WorkerPendingJobSummary summary;
    summary.worker = SR::JobTargetWorker::SRFileSinkWorker;
    summary.pendingJob = job;
    summary.targets.reserve(targets.size());

    for (SR::JobTarget target : targets) {
        SR::JobResult result = ExecuteFileTarget_(job, target);
        const std::wstring resultProbeLabel =
            std::wstring(L"SRFileSinkWorker::ExecutePendingJob_ result ") +
            SR::FormatPendingJobId(job);
        ProbeLine_(
            SR::FormatJobTargetState(
                resultProbeLabel.c_str(),
                target,
                result.state
            )
        );

        summary.targets.push_back(
            SR::MakeWorkerTargetResultSummary(result)
        );

        AppendJobResult_(std::move(result));
    }

    {
        std::lock_guard<std::mutex> lock(workerSummariesMutex_);
        workerSummaries_.pendingJobSummaries.push_back(std::move(summary));
    ProbeLine_(
        std::wstring(L"SRFileSinkWorker::ExecutePendingJob_ summary stored ") +
        SR::FormatPendingJobId(job) +
        L" targets=" +
        std::to_wstring(targets.size())
    );
    }
}

SR::JobResult SRFileSinkWorker::ExecuteFileTarget_(
    const SR::PendingJob& job,
    SR::JobTarget target
) {
    SR::JobResult result = MakeJobResult_(job, target);
    ProbeLine_(
        SR::FormatJobTargetState(
            L"SRFileSinkWorker::ExecuteFileTarget_ begin",
            target,
            result.state
        )
    );
    const WriteConfigSnapshot writeConfig = RetrieveWriteConfig_(target);
    const FileTargetConfig& targetConfig = writeConfig.targetConfig;
    const SR::JobTargetFormat targetFormat =
        targetConfig.format;



    if (targetFormat == SR::JobTargetFormat::Txt) {
        if (!IsValidTxtTarget_(targetConfig, result)) {

            ProbeLine_(
                SR::FormatJobTargetState(
                    L"SRFileSinkWorker::ExecuteFileTarget_ txt invalid",
                    target,
                    result.state
                )
            );
            return result;
        }

        DWORD gle = 0;
        if (!TryWriteTxtTarget_(job, writeConfig, &gle)) {

            ProbeLine_(
                SR::FormatJobTargetState(
                    L"SRFileSinkWorker::ExecuteFileTarget_ txt write failed",
                    target,
                    SR::JobState::Failed
                )
            );
            const DWORD failureGle = (gle != 0) ? gle : ERROR_WRITE_FAULT;
            const std::wstring failureText = L"TXT file sink write or flush failed";
            SuppressFileTargetAfterWriteFailure_(target, failureGle, failureText);

            result.state = SR::JobState::Failed;
            result.details.failedReasonGle = failureGle;
            result.details.failedReasonText = failureText;
            return result;
        }

        ProbeLine_(
            SR::FormatJobTargetState(
                L"SRFileSinkWorker::ExecuteFileTarget_ txt ok",
                target,
                SR::JobState::Ok
            )
        );
        result.state = SR::JobState::Ok;
        return result;
    }

    if (targetFormat == SR::JobTargetFormat::Jsonl) {
        if (!IsValidJsonlTarget_(targetConfig, result)) {

            ProbeLine_(
                SR::FormatJobTargetState(
                    L"SRFileSinkWorker::ExecuteFileTarget_ jsonl invalid",
                    target,
                    result.state
                )
            );
            return result;
        }

        DWORD gle = 0;
        if (!TryWriteJsonlTarget_(job, writeConfig, &gle)) {


            ProbeLine_(
                SR::FormatJobTargetState(
                    L"SRFileSinkWorker::ExecuteFileTarget_ jsonl write failed",
                    target,
                    SR::JobState::Failed
                )
            );
            const DWORD failureGle = (gle != 0) ? gle : ERROR_WRITE_FAULT;
            const std::wstring failureText = L"JSONL file sink write or flush failed";
            SuppressFileTargetAfterWriteFailure_(target, failureGle, failureText);

            result.state = SR::JobState::Failed;
            result.details.failedReasonGle = failureGle;
            result.details.failedReasonText = failureText;
            return result;
        }

        ProbeLine_(
            SR::FormatJobTargetState(
                L"SRFileSinkWorker::ExecuteFileTarget_ jsonl ok",
                target,
                SR::JobState::Ok
            )
        );
        result.state = SR::JobState::Ok;
        return result;
    }

    ProbeLine_(
        SR::FormatJobTargetState(
            L"SRFileSinkWorker::ExecuteFileTarget_ outside domain",
            target,
            SR::JobState::Ignored
        )
    );
    result.state = SR::JobState::Ignored;
    result.details.ignoredReasonText = L"Target is outside the FileSinkWorker domain";
    return result;
}

SR::JobResult SRFileSinkWorker::MakeJobResult_(
    const SR::PendingJob& job,
    SR::JobTarget target
) const {
    SR::JobResult result;
    result.key = job.key;

    result.origin = job.origin;
    result.target = target;
    result.state = SR::JobState::Pending;
    return result;
}

// -----------------------------------------------------------------------------
// Target configuration and validation.
// -----------------------------------------------------------------------------

SRFileSinkWorker::WriteConfigSnapshot SRFileSinkWorker::RetrieveWriteConfig_(
    SR::JobTarget target
) const {
    std::lock_guard<std::mutex> lock(domainMutex_);

    WriteConfigSnapshot snapshot;

    snapshot.targetConfig = FileTargetConfig{target};
    for (const auto& candidate : domain_.targetConfigs) {
        if (candidate.target == target) {
            snapshot.targetConfig = candidate;
            break;
        }
    }

    if (snapshot.targetConfig.headerEnabled) {
        snapshot.parsingToken = domain_.config.parsingToken;
    }
    snapshot.executionId = domain_.config.executionId;
    snapshot.stdoutTxtHeaderGranularity =
        domain_.config.stdoutTxtHeaderGranularity;
    snapshot.stderrChildTxtHeaderGranularity =
        domain_.config.stderrChildTxtHeaderGranularity;
    snapshot.jsonlPayloadRepresentation =
        domain_.config.jsonlPayloadRepresentation;



    return snapshot;
}


bool SRFileSinkWorker::IsValidTxtTarget_(
    const FileTargetConfig& targetConfig,

    SR::JobResult& result
) const {
    if (!targetConfig.enabled) {

        ProbeLine_(
            SR::FormatJobTargetState(
                L"SRFileSinkWorker::IsValidTxtTarget_ disabled",
                targetConfig.target,

                SR::JobState::Ignored
            )
        );
        result.state = SR::JobState::Ignored;
        result.details.ignoredReasonText = L"TXT file sink target is not enabled";
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(failureMutex_);

        const SR::FileSinkWorkerFailureState& failure = domain_.config.failure;
        const auto* targetFailure =
            FindFileTargetFailure_(failure, targetConfig.target);
        if (targetFailure && targetFailure->suppressed) {
            ProbeLine_(
                SR::FormatJobTargetState(
                    L"SRFileSinkWorker::IsValidTxtTarget_ suppressed",
                    targetConfig.target,
                    SR::JobState::Suppressed
                )
            );
            result.state = SR::JobState::Suppressed;
            result.details.failedReasonGle = targetFailure->gle;
            result.details.failedReasonText =
                targetFailure->reason.empty()
                    ? L"TXT file sink target is suppressed after previous write failure"
                    : targetFailure->reason;
            return false;
        }
    }

    return true;
}

bool SRFileSinkWorker::IsValidJsonlTarget_(
    const FileTargetConfig& targetConfig,

    SR::JobResult& result
) const {
    if (!targetConfig.enabled) {

        ProbeLine_(
            SR::FormatJobTargetState(
                L"SRFileSinkWorker::IsValidJsonlTarget_ disabled",
                targetConfig.target,

                SR::JobState::Ignored
            )
        );
        result.state = SR::JobState::Ignored;
        result.details.ignoredReasonText = L"JSONL file sink target is not enabled";
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(failureMutex_);

        const SR::FileSinkWorkerFailureState& failure = domain_.config.failure;
        const auto* targetFailure =
            FindFileTargetFailure_(failure, targetConfig.target);
        if (targetFailure && targetFailure->suppressed) {
            ProbeLine_(
                SR::FormatJobTargetState(
                    L"SRFileSinkWorker::IsValidJsonlTarget_ suppressed",
                    targetConfig.target,
                    SR::JobState::Suppressed
                )
            );
            result.state = SR::JobState::Suppressed;
            result.details.failedReasonGle = targetFailure->gle;
            result.details.failedReasonText =
                targetFailure->reason.empty()
                    ? L"JSONL file sink target is suppressed after previous write failure"
                    : targetFailure->reason;
            return false;
        }
    }

    return true;
}

void SRFileSinkWorker::SuppressFileTargetAfterWriteFailure_(
    SR::JobTarget target,
    DWORD gle,
    const std::wstring& reason
) {

    const DWORD failureGle = (gle != 0) ? gle : ERROR_WRITE_FAULT;

    std::lock_guard<std::mutex> lock(failureMutex_);


    SR::FileSinkWorkerFailureState& failure = domain_.config.failure;
    const auto it = std::find_if(
        failure.targets.begin(),
        failure.targets.end(),
        [target](const auto& candidate) { return candidate.target == target; }
    );
    if (it == failure.targets.end() || it->suppressed) {
        return;
    }

    it->suppressed = true;
    it->gle = failureGle;
    it->reason = reason;

    if (workerSupervisor_) {
        workerSupervisor_->ReportFileSinkWorkerFailure(failure);
    }
}

// -----------------------------------------------------------------------------
// TXT/JSONL writers. Failed is produced only by these TryWrite* functions.
// -----------------------------------------------------------------------------

// Serializes and writes one pending job to a TXT file target.
//
    // For parseable TXT targets, this method owns the block framing:
    // - determines whether a payload header is required,
    // - formats the header through SRPhaseTimelineEntryFormatter,
    // - inserts an LF before a header when the preceding child payload did not end
    //   at a line boundary,
    // - writes the entry payload,
    // - updates TXT block and line-boundary state.
    //
    // For non-parseable TXT targets, child stdout/stderr payloads remain raw bytes.
    //
    // The formatter defines header and line contents; this method defines their
    // placement, framing, writing, and flushing.
    //
    // Keep TXT header selection, LF separation, and payload ordering aligned
    // with SRParentEmitWorker::BuildPayloadBytes_().
bool SRFileSinkWorker::TryWriteTxtTarget_(
    const SR::PendingJob& job,
    const WriteConfigSnapshot& writeConfig,
    DWORD* outGle
) {
    const FileTargetConfig& targetConfig = writeConfig.targetConfig;


    if (outGle) {
        *outGle = 0;
    }
    ProbeLine_(
        SR::FormatJobTargetState(
            L"SRFileSinkWorker::TryWriteTxtTarget_ begin",
            targetConfig.target,

            SR::JobState::Pending
        )
    );

    if (!targetConfig.writer || !targetConfig.writer->IsOpen()) {

        ProbeLine_(
            SR::FormatJobTargetState(
                L"SRFileSinkWorker::TryWriteTxtTarget_ invalid writer",
                targetConfig.target,

                SR::JobState::Failed
            )
        );
        if (outGle) {
            *outGle = ERROR_INVALID_HANDLE;
        }
        return false;
    }

    if (targetConfig.headerEnabled) {

        const std::string& parsingToken = writeConfig.parsingToken;

        bool headerRequired = false;
        std::string header;
        std::optional<SR::JobPayloadType>* lastWrittenPayloadType = nullptr;
        bool* atLineStart = nullptr;
        switch (targetConfig.target) {
            case SR::JobTarget::StdoutTxt:
                lastWrittenPayloadType =
                    &stdoutTxtLastWrittenPayloadType_;
                atLineStart =
                    &stdoutTxtAtLineStart_;
                break;
            case SR::JobTarget::StderrSrAndChildTxt:
                lastWrittenPayloadType =
                    &stderrSrAndChildTxtLastWrittenPayloadType_;
                atLineStart =
                    &stderrSrAndChildTxtAtLineStart_;
                break;
            case SR::JobTarget::StderrChildTxt:
                lastWrittenPayloadType =
                    &stderrChildTxtLastWrittenPayloadType_;
                atLineStart =
                    &stderrChildTxtAtLineStart_;
                break;
            case SR::JobTarget::StderrSrAndChildInclStdoutTxt:
                lastWrittenPayloadType =
                    &stderrSrAndChildInclStdoutTxtLastWrittenPayloadType_;
                atLineStart =
                    &stderrSrAndChildInclStdoutTxtAtLineStart_;
                break;
            default:
                break;
        }
        const bool startsNewBlock =
            lastWrittenPayloadType &&
            (
                !*lastWrittenPayloadType ||
                **lastWrittenPayloadType != job.payloadType
            );


        // Determine whether this payload starts a new TXT block and build the
        // corresponding block header when required.
        switch (job.payloadType) {
            case SR::JobPayloadType::SrDiag:
                headerRequired = true;
                header =
                    SR::SRPhaseTimelineEntryFormatter::FormatSrDiagTxtHeader(
                        job.srDiag,
                        parsingToken,
                        writeConfig.executionId
                    );
                break;

            case SR::JobPayloadType::ChildStderr:
                headerRequired =
                    writeConfig.stderrChildTxtHeaderGranularity ==
                        SR::ChildTxtHeaderGranularity::Event ||
                    startsNewBlock;

                if (headerRequired) {
                    header =
                        SR::SRPhaseTimelineEntryFormatter::FormatChildStderrTxtHeader(
                            job.childStderr,
                            parsingToken,
                            writeConfig.executionId
                        );
                }
                break;
            case SR::JobPayloadType::ChildStdout:
                headerRequired =
                    writeConfig.stdoutTxtHeaderGranularity ==

                        SR::ChildTxtHeaderGranularity::Event ||
                    startsNewBlock;

                if (headerRequired) {
                    header =
                        SR::SRPhaseTimelineEntryFormatter::FormatChildStdoutTxtHeader(
                            job.childStdout,
                            parsingToken,
                            writeConfig.executionId
                        );
                }
                break;

        }

        if (headerRequired) {
            if (atLineStart && !*atLineStart) {
                if (!targetConfig.writer->WriteRaw(&kLf, 1, outGle)) {
                    return false;
                }
                *atLineStart = true;
            }


            if (!targetConfig.writer->WriteLine(

                    header.data(),
                    header.size(),
                    outGle
                )) {
                return false;
            }
        }

        // Write the payload representation that follows the parseable TXT header.
        switch (job.payloadType) {
            case SR::JobPayloadType::SrDiag: {
                const std::vector<char> utf8Bytes =

                    FileHelpers::WideToUtf8(job.srDiag.message);

                if (!utf8Bytes.empty() &&

                    !targetConfig.writer->WriteRaw(

                        utf8Bytes.data(),

                        utf8Bytes.size(),

                        outGle
                    )) {
                    return false;
                }

                if (!targetConfig.writer->WriteRaw(&kLf, 1, outGle)) {

                    return false;
                }
                break;
            }

            case SR::JobPayloadType::ChildStderr:
                if (!job.childStderr.bytes.empty() &&
                    !targetConfig.writer->WriteRaw(

                        job.childStderr.bytes.data(),
                        job.childStderr.bytes.size(),
                        outGle
                    )) {
                    return false;
                }
                break;

            case SR::JobPayloadType::ChildStdout:
                if (!job.childStdout.bytes.empty() &&
                    !targetConfig.writer->WriteRaw(
                        job.childStdout.bytes.data(),
                        job.childStdout.bytes.size(),
                        outGle
                    )) {
                    return false;
                }
                break;

        }

        if (!targetConfig.writer->Flush(outGle)) {

            return false;
        }

        if (lastWrittenPayloadType && atLineStart) {
            *lastWrittenPayloadType = job.payloadType;
            // Update the framed TXT line-boundary state after the payload has
            // been written successfully.
            switch (job.payloadType) {
                case SR::JobPayloadType::SrDiag:
                    *atLineStart = true;
                    break;
                case SR::JobPayloadType::ChildStderr:
                    *atLineStart =
                        job.childStderr.bytes.empty() ||
                        job.childStderr.bytes.back() == kLf;
                    break;
                case SR::JobPayloadType::ChildStdout:
                    *atLineStart =
                        job.childStdout.bytes.empty() ||
                        job.childStdout.bytes.back() == kLf;
                    break;
            }
        }

        return true;
    } else {
        const std::vector<char>* payloadBytes = nullptr;
        // Non-parseable TXT targets write child output as raw bytes without block framing.

        switch (job.payloadType) {
            case SR::JobPayloadType::ChildStdout:
                payloadBytes = &job.childStdout.bytes;
                break;

            case SR::JobPayloadType::ChildStderr:
                payloadBytes = &job.childStderr.bytes;
                break;

            case SR::JobPayloadType::SrDiag:
                break;
        }

        ProbeLine_(
            L"SRFileSinkWorker::TryWriteTxtTarget_ payloadBytes=" +
            std::to_wstring(payloadBytes ? payloadBytes->size() : 0)
        );

        if (payloadBytes && !payloadBytes->empty()) {
            if (!targetConfig.writer->WriteRaw(payloadBytes->data(), payloadBytes->size(), outGle)) {

                ProbeLine_(
                    SR::FormatJobTargetState(
                        L"SRFileSinkWorker::TryWriteTxtTarget_ WriteRaw failed",
                        targetConfig.target,

                        SR::JobState::Failed
                    )
                );
                return false;
            }
        }

        ProbeLine_(
            SR::FormatJobTargetState(
                L"SRFileSinkWorker::TryWriteTxtTarget_ flush",
                targetConfig.target,

                SR::JobState::Pending
            )
        );
        return targetConfig.writer->Flush(outGle);
    }
}

bool SRFileSinkWorker::TryWriteJsonlTarget_(
    const SR::PendingJob& job,
    const WriteConfigSnapshot& writeConfig,
    DWORD* outGle
) {
    const FileTargetConfig& targetConfig =
        writeConfig.targetConfig;

    if (outGle) {
        *outGle = 0;
    }

    ProbeLine_(
        SR::FormatJobTargetState(
            L"SRFileSinkWorker::TryWriteJsonlTarget_ begin",
            targetConfig.target,

            SR::JobState::Pending
        )
    );

    if (!targetConfig.writer || !targetConfig.writer->IsOpen()) {

        ProbeLine_(
            SR::FormatJobTargetState(
                L"SRFileSinkWorker::TryWriteJsonlTarget_ invalid writer",
                targetConfig.target,

                SR::JobState::Failed
            )
        );
        if (outGle) {
            *outGle = ERROR_INVALID_HANDLE;
        }
        return false;
    }

    std::string line;
    switch (job.payloadType) {
        case SR::JobPayloadType::SrDiag:
            line = SR::SRPhaseTimelineEntryFormatter::FormatJsonLine(
                job.srDiag,
                writeConfig.jsonlPayloadRepresentation,
                writeConfig.executionId
            );
            break;

        case SR::JobPayloadType::ChildStdout:
            line = SR::SRPhaseTimelineEntryFormatter::FormatJsonLine(
                job.childStdout,
                writeConfig.jsonlPayloadRepresentation,
                writeConfig.executionId
            );
            break;

        case SR::JobPayloadType::ChildStderr:
            line = SR::SRPhaseTimelineEntryFormatter::FormatJsonLine(
                job.childStderr,
                writeConfig.jsonlPayloadRepresentation,
                writeConfig.executionId
            );
            break;
    }



    if (!targetConfig.writer->WriteLine(line.data(), line.size(), outGle)) {

        ProbeLine_(
            SR::FormatJobTargetState(
                L"SRFileSinkWorker::TryWriteJsonlTarget_ WriteLine failed",
                targetConfig.target,

                SR::JobState::Failed
            )
        );
        return false;
    }

    ProbeLine_(
        SR::FormatJobTargetState(
            L"SRFileSinkWorker::TryWriteJsonlTarget_ flush",
            targetConfig.target,

            SR::JobState::Pending
        )
    );

    return targetConfig.writer->Flush(outGle);

}

// -----------------------------------------------------------------------------
// Outbox.
// -----------------------------------------------------------------------------

SR::JobResults SRFileSinkWorker::TakeJobResults() {
    SR::JobResults results;

    {
        std::lock_guard<std::mutex> lock(jobResultsMutex_);
        results.swap(jobResults_);
        ProbeLine_(
            L"SRFileSinkWorker::TakeJobResults count=" +
            std::to_wstring(results.size())
        );
    }

    return results;
}

SR::WorkerSummaries SRFileSinkWorker::TakeWorkerSummaries() {
    SR::WorkerSummaries summaries;

    {
        std::lock_guard<std::mutex> lock(workerSummariesMutex_);
        std::swap(summaries, workerSummaries_);
    }

    return summaries;
}

void SRFileSinkWorker::AppendJobResult_(SR::JobResult result) {
    ProbeLine_(
        SR::FormatJobTargetState(
            L"SRFileSinkWorker::AppendJobResult_",
            result.target,
            result.state
        )
    );
    std::lock_guard<std::mutex> lock(jobResultsMutex_);
    jobResults_.push_back(std::move(result));
}
