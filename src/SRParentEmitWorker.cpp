// SRParentEmitWorker.cpp
#include "SRParentEmitWorker.h"

#include <iterator>
#include <stdexcept>
#include <utility>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "ParentStdEmitter.h"
#include "SRJobDiagnostics.h"
#include "SRPhaseTimelineEntry.h"
#include "SRPhaseTimelineEntryFormatter.h"

#include "TextHelpers.h"
#include "SRLifecycleDiagnostics.h"
#include "SRThreading.h"
#include "SRWorkerSupervisor.h"

SRParentEmitWorker::~SRParentEmitWorker() {
    DrainAndStop();
}
void SRParentEmitWorker::ProbeLine_(const std::wstring& msg) const {
    if constexpr (!kParentEmitWorkerProbeEnabled) return;
    if (!diagnostics_) return;
    diagnostics_->ProbeLine(msg);
}
void SRParentEmitWorker::SetWorkerSupervisor(
    SR::SRWorkerSupervisor* supervisor
) noexcept {
    workerSupervisor_ = supervisor;
}
void SRParentEmitWorker::SetParsingTokenPolicy(
    const std::string& parsingToken,
    const std::vector<SR::JobTarget>& enabledTargets
) {
    std::lock_guard<std::mutex> lock(domainMutex_);

    domain_.config.parsingToken = parsingToken;

    for (auto& targetConfig : domain_.targetConfigs) {
        targetConfig.headerParsingTokenEnabled = false;
    }

    for (const SR::JobTarget target : enabledTargets) {
        if (SR::JobTargetWorkerOf(target) !=
            SR::JobTargetWorker::SRParentEmitWorker) {
            continue;
        }

        const std::size_t workerConfigIndex =
            SR::JobTargetWorkerConfigIndexOf(target);

        if (workerConfigIndex >= domain_.targetConfigs.size()) {
            continue;
        }

        domain_.targetConfigs[
            workerConfigIndex
        ].headerParsingTokenEnabled = true;
    }

}



bool SRParentEmitWorker::Init(
    SRLifecycleDiagnostics* diagnostics,
    SRParentEmitPolicy* parentEmitPolicyOrNull
) noexcept {
    diagnostics_ = diagnostics;
    ProbeLine_(L"SRParentEmitWorker::Init");

    {
        std::scoped_lock lock(domainMutex_, failureLatchMutex_);
        domain_ = WorkerDomain{};
    }

    stderrMixedParentLastWrittenPayloadType_.reset();
    stderrMixedParentAtLineStart_ = true;

    {
        std::lock_guard<std::mutex> lock(parentEmitPolicyMutex_);
        parentEmitPolicy_ = parentEmitPolicyOrNull;
    }

    return true;
}

bool SRParentEmitWorker::Start() {
    std::lock_guard<std::mutex> lock(controlMutex_);

    if (started_) {
        return true;
    }

    stopMode_ = StopMode::KeepRunning;
    processingActive_ = false;

    try {
        workerThread_ = std::thread([this]() {
            SRThreading::RunGuardedThreadEntry(
                [this]() {
                    WorkerLoop_();
                },
                [this](const SRThreading::ThreadExceptionInfo& ex) {
                    ProbeLine_(
                        L"SRParentEmitWorker::WorkerLoop_ exception: " +
                        ex.text
                    );

                    if (workerSupervisor_) {
                        workerSupervisor_->ReportWorkerFailure(
                            SR::JobTargetWorker::SRParentEmitWorker,
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
            SR::JobTargetWorker::SRParentEmitWorker,
            true
        );
    }
    return true;
}

void SRParentEmitWorker::DrainAndStop() {
    {
        std::lock_guard<std::mutex> lock(controlMutex_);

        if (!started_) {
            return;
        }

        stopMode_ = StopMode::DrainAndStop;
    }

    cv_.notify_all();

    if (workerThread_.joinable()) {
        workerThread_.join();
    }

    {
        std::lock_guard<std::mutex> lock(controlMutex_);
        started_ = false;
        processingActive_ = false;
    }
}
void SRParentEmitWorker::Drain() {
    {
        std::unique_lock<std::mutex> lock(controlMutex_);
        cv_.notify_all();

        drainCv_.wait(lock, [this]() {
            std::lock_guard<std::mutex> pendingLock(pendingJobsMutex_);
            return
                (pendingJobs_.empty() && !processingActive_) ||
                (workerSupervisor_ &&
                 !workerSupervisor_->IsWorkerAvailable(
                     SR::JobTargetWorker::SRParentEmitWorker
                 ));
        });
    }
}


bool SRParentEmitWorker::EnqueuePendingJobs(const SR::PendingJobs& jobs) {
    if (jobs.empty()) {
        return true;
    }

    SR::WorkerPendingJobsEnqueueSummary summary;
    summary.worker = SR::JobTargetWorker::SRParentEmitWorker;
    summary.jobsReceived = jobs;

    try {
        {
            std::lock_guard<std::mutex> lock(pendingJobsMutex_);
            for (const auto& job : jobs) {
                pendingJobs_.push_back(job);
            }
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
            workerSummaries_.pendingJobsEnqueueSummaries.push_back(
                std::move(summary)
            );
        }

        return false;
    }

    {
        std::lock_guard<std::mutex> lock(workerSummariesMutex_);
        workerSummaries_.pendingJobsEnqueueSummaries.push_back(
            std::move(summary)
        );
    }

    cv_.notify_all();
    return true;
}

SR::JobResults SRParentEmitWorker::TakeJobResults() {
    std::lock_guard<std::mutex> lock(jobResultsMutex_);

    SR::JobResults results;
    results.insert(
        results.end(),
        std::make_move_iterator(jobResults_.begin()),
        std::make_move_iterator(jobResults_.end())
    );

    jobResults_.clear();
    return results;
}

void SRParentEmitWorker::WorkerLoop_() {
    ProbeLine_(L"SRParentEmitWorker::WorkerLoop_ begin");
    std::size_t dequeuedJobCount = 0;
    for (;;) {
        SR::PendingJob job;

        {
            std::unique_lock<std::mutex> controlLock(controlMutex_);

            cv_.wait(controlLock, [this]() {
                if (stopMode_ == StopMode::DrainAndStop) {
                    return true;
                }

                std::lock_guard<std::mutex> pendingLock(pendingJobsMutex_);
                return !pendingJobs_.empty();
            });

            {
                std::lock_guard<std::mutex> pendingLock(pendingJobsMutex_);

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
        if (kParentEmitWorkerInjectFailure &&
            dequeuedJobCount == kParentEmitWorkerFailOnDequeuedJob) {
            throw std::runtime_error(
                "Injected SRParentEmitWorker failure"
            );
        }
        ProbeLine_(
            std::wstring(L"SRParentEmitWorker::WorkerLoop_ execute payloadType=") +
            SR::JobPayloadTypeNameToString(job.payloadType)
        );

        ExecutePendingJob_(job);

        {
            std::lock_guard<std::mutex> controlLock(controlMutex_);
            std::lock_guard<std::mutex> pendingLock(pendingJobsMutex_);

            processingActive_ = false;
            drainCv_.notify_all();


            if (stopMode_ == StopMode::DrainAndStop &&
                pendingJobs_.empty()) {
                return;
            }
        }
    }
}

void SRParentEmitWorker::ExecutePendingJob_(const SR::PendingJob& job) {
    ProbeLine_(
        std::wstring(L"SRParentEmitWorker::ExecutePendingJob_ payloadType=") +
        SR::JobPayloadTypeNameToString(job.payloadType)
    );
    const std::vector<SR::JobTarget> targets =
        SR::RetrieveTargetsForPayloadType(
            job.payloadType,
            SR::JobTargetWorker::SRParentEmitWorker
        );
    ProbeLine_(
        L"SRParentEmitWorker::ExecutePendingJob_ targetCount=" +
        std::to_wstring(targets.size())
    );

    SR::WorkerPendingJobSummary summary;
    summary.worker = SR::JobTargetWorker::SRParentEmitWorker;
    summary.pendingJob = job;
    summary.targets.reserve(targets.size());

    for (SR::JobTarget target : targets) {
        SR::JobResult result = ExecuteParentTarget_(job, target);
        ProbeLine_(
            SR::FormatJobTargetState(
                L"SRParentEmitWorker::ExecutePendingJob_ result",
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
    }

    ProbeLine_(L"SRParentEmitWorker::ExecutePendingJob_ summary stored");
}

SR::JobResult SRParentEmitWorker::ExecuteParentTarget_(
    const SR::PendingJob& job,
    SR::JobTarget target
) {
    SR::JobResult result = MakeJobResult_(job, target);
    const WriteConfigSnapshot writeConfig = RetrieveWriteConfig_(target);
    const ParentTargetConfig& targetConfig = writeConfig.targetConfig;


    if (!IsValidStdoutParentTarget_(targetConfig) &&

        !IsValidStderrParentTarget_(targetConfig)) {

        result.state = SR::JobState::Ignored;
        result.details.ignoredReasonText =
            L"Target is outside the ParentEmitWorker domain";
        return result;
    }

    if (IsParentTargetSuppressed_(targetConfig, result)) {

        return result;
    }


    SRParentEmitPolicy* parentEmitPolicy = nullptr;
    {
        std::lock_guard<std::mutex> lock(parentEmitPolicyMutex_);
        parentEmitPolicy = parentEmitPolicy_;
    }

    if (!parentEmitPolicy) {
        result.state = SR::JobState::Ignored;
        result.details.ignoredReasonText =
            L"Parent emit policy is not attached";
        return result;
    }

    const auto jobStateDecision =
        parentEmitPolicy->RetrieveParentTargetJobStateDecision(
            target
        );

    if (jobStateDecision.state) {
        result.state = *jobStateDecision.state;
        result.details.ignoredReasonText =
            jobStateDecision.ignoredReasonText;
        return result;
    }

    DWORD gle = 0;
    if (!TryEmitParentTarget_(job, writeConfig, &gle)) {
        const DWORD failureGle = (gle != 0) ? gle : ERROR_WRITE_FAULT;
        const std::wstring failureText = IsValidStdoutParentTarget_(targetConfig)

            ? L"Parent stdout emit failed"
            : L"Parent stderr emit failed";

        SuppressParentTargetAfterWriteFailure_(
            targetConfig,

            failureGle,
            failureText
        );

        result.state = SR::JobState::Failed;
        result.details.failedReasonGle = failureGle;
        result.details.failedReasonText = failureText;
        return result;
    }
    result.state = SR::JobState::Ok;
    return result;
}
SRParentEmitWorker::WriteConfigSnapshot
SRParentEmitWorker::RetrieveWriteConfig_(
    SR::JobTarget target
) const {
    std::lock_guard<std::mutex> lock(domainMutex_);
    WriteConfigSnapshot snapshot;

    if (SR::JobTargetWorkerOf(target) ==
        SR::JobTargetWorker::SRParentEmitWorker) {
        const std::size_t workerConfigIndex =
            SR::JobTargetWorkerConfigIndexOf(target);

        if (workerConfigIndex < domain_.targetConfigs.size()) {
            snapshot.targetConfig = domain_.targetConfigs[
                workerConfigIndex
            ];
        }
    }
    if (snapshot.targetConfig.headerParsingTokenEnabled) {
        snapshot.parsingToken = domain_.config.parsingToken;
    }
    return snapshot;
}
bool SRParentEmitWorker::IsValidStdoutParentTarget_(
    const ParentTargetConfig& targetConfig

) noexcept {
    return
        targetConfig.enabled &&

        SR::JobTargetStreamOf(targetConfig.target) ==
            ParentStreamType::Stdout;

}
bool SRParentEmitWorker::IsValidStderrParentTarget_(
    const ParentTargetConfig& targetConfig

) noexcept {
    return
        targetConfig.enabled &&

        SR::JobTargetStreamOf(targetConfig.target) ==
            ParentStreamType::Stderr;

}
bool SRParentEmitWorker::IsParentTargetSuppressed_(
    const ParentTargetConfig& targetConfig,

    SR::JobResult& result
) const {
    std::lock_guard<std::mutex> lock(failureLatchMutex_);
    if (!targetConfig.enabled) {

        return false;
    }
    const ParentEmitFailureLatch& latch =
        FailureLatchForStream_(
            SR::JobTargetStreamOf(targetConfig.target)
        );

    if (!latch.suppressed) {
        return false;
    }
    result.state = SR::JobState::Suppressed;
    result.details.failedReasonGle = latch.gle;
    result.details.failedReasonText = latch.reason;
    return true;
}

SR::JobResult SRParentEmitWorker::MakeJobResult_(
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



void SRParentEmitWorker::SuppressParentTargetAfterWriteFailure_(
    const ParentTargetConfig& targetConfig,

    DWORD gle,
    const std::wstring& reason
) {
    std::lock_guard<std::mutex> lock(failureLatchMutex_);

    if (!targetConfig.enabled) {

        return;
    }

    ParentEmitFailureLatch& latch =
        FailureLatchForStream_(
            SR::JobTargetStreamOf(targetConfig.target)
        );


    if (latch.suppressed) {
        return;
    }

    latch.suppressed = true;
    latch.gle = gle;
    latch.reason = reason;
}


SRParentEmitWorker::ParentEmitFailureLatch&
SRParentEmitWorker::FailureLatchForStream_(
    ParentStreamType streamType
) noexcept {
    if (streamType == ParentStreamType::Stdout) {
        return domain_.config.workerStdoutFailure;
    }

    return domain_.config.workerStderrFailure;
}

const SRParentEmitWorker::ParentEmitFailureLatch&
SRParentEmitWorker::FailureLatchForStream_(
    ParentStreamType streamType
) const noexcept {
    if (streamType == ParentStreamType::Stdout) {
        return domain_.config.workerStdoutFailure;
    }

    return domain_.config.workerStderrFailure;
}

bool SRParentEmitWorker::TryEmitParentTarget_(
    const SR::PendingJob& job,
    const WriteConfigSnapshot& writeConfig,
    DWORD* outGle
) {
    if (outGle) {
        *outGle = 0;
    }

    const ParentTargetConfig& targetConfig = writeConfig.targetConfig;


    std::vector<char> bytes;
    if (!BuildPayloadBytes_(job, writeConfig, bytes)) {

        if (outGle) {
            *outGle = ERROR_INVALID_DATA;
        }
        return false;
    }

    if (bytes.empty()) {
        return true;
    }

    bool emitted = false;

    if (IsValidStdoutParentTarget_(targetConfig)) {

        emitted = ParentStdEmitter::TryEmitStdoutBytes(
            bytes.data(),
            bytes.size(),
            outGle
        );
    } else if (IsValidStderrParentTarget_(targetConfig)) {


        emitted = ParentStdEmitter::TryEmitStderrBytes(
            bytes.data(),
            bytes.size(),
            outGle
        );
    } else {
        if (outGle) {
            *outGle = ERROR_INVALID_PARAMETER;
        }
        return false;
    }

    if (!emitted) {
        return false;
    }

    if (targetConfig.headerParsingTokenEnabled &&

        targetConfig.target == SR::JobTarget::StderrMixedParent) {

        stderrMixedParentLastWrittenPayloadType_ = job.payloadType;

        // Update the mixed-parent line-boundary state after the payload has been
        // emitted successfully.
        switch (job.payloadType) {
            case SR::JobPayloadType::SrDiag:
                stderrMixedParentAtLineStart_ = true;
                break;

            case SR::JobPayloadType::ChildStderr:
                stderrMixedParentAtLineStart_ =
                    job.childStderr.bytes.empty() ||
                    job.childStderr.bytes.back() == '\n';
                break;

            case SR::JobPayloadType::ChildStdout:
                break;
        }
    }

    return true;
}

// Builds the complete byte sequence for one parent-target emission.
//
// For parseable mixed-stderr output, this method applies the same segment
// framing contract as the file-sink TXT path:
// - decides whether a segment header is required,
// - obtains the header text from SRPhaseTimelineEntryFormatter,
// - inserts a separating LF when the previous child payload did not end at a
//   line boundary,
// - appends the original diagnostic or child payload bytes.
//
// For non-parseable parent targets, child payload bytes are forwarded unchanged.
//
// This method only constructs bytes. The caller performs the actual parent
// handle write and updates framing state after a successful emission.
//
// Keep mixed-TXT header selection, LF separation, and payload ordering aligned
// with SRFileSinkWorker::TryWriteTxtTarget_().
bool SRParentEmitWorker::BuildPayloadBytes_(
    const SR::PendingJob& job,
    const WriteConfigSnapshot& writeConfig,
    std::vector<char>& bytesOut
) {
    bytesOut.clear();

    const ParentTargetConfig& targetConfig = writeConfig.targetConfig;


    if (targetConfig.headerParsingTokenEnabled) {

        const std::string& parsingToken = writeConfig.parsingToken;
        bool headerRequired = false;
        std::string header;

        // Determine whether this payload starts a new TXT segment and build the
        // corresponding segment header when required.
        switch (job.payloadType) {
            case SR::JobPayloadType::SrDiag:
                headerRequired = true;
                header =
                    SR::SRPhaseTimelineEntryFormatter::FormatSrDiagTxtHeader(
                        job.srDiag,
                        parsingToken
                    );
                break;

            case SR::JobPayloadType::ChildStderr:
                headerRequired =
                    targetConfig.target == SR::JobTarget::StderrMixedParent &&

                    (
                        !stderrMixedParentLastWrittenPayloadType_ ||
                        *stderrMixedParentLastWrittenPayloadType_ !=
                            SR::JobPayloadType::ChildStderr
                    );

                if (headerRequired) {
                    header =
                        SR::SRPhaseTimelineEntryFormatter::FormatChildStderrTxtHeader(
                            job.childStderr,
                            parsingToken
                        );
                }
                break;

            case SR::JobPayloadType::ChildStdout:
                break;
        }

        if (headerRequired) {
            if (targetConfig.target == SR::JobTarget::StderrMixedParent &&

                !stderrMixedParentAtLineStart_) {
                bytesOut.push_back('\n');
            }

            bytesOut.insert(
                bytesOut.end(),
                header.begin(),
                header.end()
            );
            bytesOut.push_back('\n');
        }

        // Append the payload representation that follows the parseable TXT header.
        switch (job.payloadType) {
            case SR::JobPayloadType::SrDiag: {
                const std::string utf8Bytes =

                    TextHelpers::Utf16ToUtf8(job.srDiag.message);

                bytesOut.insert(
                    bytesOut.end(),
                    utf8Bytes.begin(),

                    utf8Bytes.end()

                );
                bytesOut.push_back('\n');
                return true;
            }

            case SR::JobPayloadType::ChildStderr:
                bytesOut.insert(
                    bytesOut.end(),
                    job.childStderr.bytes.begin(),
                    job.childStderr.bytes.end()
                );
                return true;

            case SR::JobPayloadType::ChildStdout:
                return true;
        }

        return false;
    } else {
        // Build the raw byte representation for parent targets without TXT segment
        // framing.
        switch (job.payloadType) {

            case SR::JobPayloadType::ChildStdout:
                bytesOut = job.childStdout.bytes;
                return true;

            case SR::JobPayloadType::ChildStderr:
                bytesOut = job.childStderr.bytes;
                return true;

            default:
                return false;
        }
    }
}

SR::WorkerSummaries SRParentEmitWorker::TakeWorkerSummaries() {
    SR::WorkerSummaries summaries;

    {
        std::lock_guard<std::mutex> lock(workerSummariesMutex_);
        std::swap(summaries, workerSummaries_);
    }

    return summaries;
}
void SRParentEmitWorker::AppendJobResult_(SR::JobResult result) {
    std::lock_guard<std::mutex> lock(jobResultsMutex_);
    jobResults_.push_back(std::move(result));
}
