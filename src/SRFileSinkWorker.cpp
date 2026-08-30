// SRFileSinkWorker.cpp

#include "SRFileSinkWorker.h"

#include <stdexcept>
#include <utility>

#include "FileHelpers.h"
#include "SRPhaseTimelineEntry.h"
#include "SRPhaseTimelineEntryFormatter.h"

#include "SRLifecycleDiagnostics.h"
#include "SRJobDiagnostics.h"

#include "SRPendingJobDiagnostics.h"
#include "SRThreading.h"
#include "SRWorkerSupervisor.h"

namespace {

static constexpr char kLf = '\n';





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
void SRFileSinkWorker::SetParsingTokenPolicy(
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
            SR::JobTargetWorker::SRFileSinkWorker) {
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




bool SRFileSinkWorker::Init(SRLifecycleDiagnostics* diagnostics) {
    diagnostics_ = diagnostics;
    ProbeLine_(L"SRFileSinkWorker::Init");

    {
        std::scoped_lock lock(domainMutex_, failureMutex_);
        domain_ = WorkerDomain{};
    }
    
    stderrSrAndChildTxtLastWrittenPayloadType_.reset();
    stderrSrAndChildTxtAtLineStart_ = true;
    stderrSrAndChildInclStdoutTxtLastWrittenPayloadType_.reset();
    stderrSrAndChildInclStdoutTxtAtLineStart_ = true;

    
    return true;
}

void SRFileSinkWorker::AttachLogWriters(
    bool stdoutTxtEnabled,
    LogWriter::FileWriter* stdoutTxtWriter,
    const std::wstring& stdoutTxtRunningPath,
    bool stderrSrAndChildTxtEnabled,
    LogWriter::FileWriter* stderrSrAndChildTxtWriter,
    const std::wstring& stderrSrAndChildTxtRunningPath,
    bool stderrChildTxtEnabled,
    LogWriter::FileWriter* stderrChildTxtWriter,
    const std::wstring& stderrChildTxtRunningPath,
    bool stderrSrTxtEnabled,
    LogWriter::FileWriter* stderrSrTxtWriter,
    const std::wstring& stderrSrTxtRunningPath,
    bool stderrSrAndChildInclStdoutTxtEnabled,
    LogWriter::FileWriter* stderrSrAndChildInclStdoutTxtWriter,
    const std::wstring& stderrSrAndChildInclStdoutTxtRunningPath
) {
    std::lock_guard<std::mutex> lock(domainMutex_);
    AttachLogWritersLocked_(
        stdoutTxtEnabled,
        stdoutTxtWriter,
        stdoutTxtRunningPath,
        stderrSrAndChildTxtEnabled,
        stderrSrAndChildTxtWriter,
        stderrSrAndChildTxtRunningPath,
        stderrChildTxtEnabled,
        stderrChildTxtWriter,
        stderrChildTxtRunningPath,
        stderrSrTxtEnabled,
        stderrSrTxtWriter,
        stderrSrTxtRunningPath,
        stderrSrAndChildInclStdoutTxtEnabled,
        stderrSrAndChildInclStdoutTxtWriter,
        stderrSrAndChildInclStdoutTxtRunningPath
    );
}
void SRFileSinkWorker::AttachJsonlWriters(
    bool stdoutJsonlEnabled,
    LogWriter::FileWriter* stdoutJsonlWriter,
    const std::wstring& stdoutJsonlRunningPath,
    bool stderrSrAndChildJsonlEnabled,
    LogWriter::FileWriter* stderrSrAndChildJsonlWriter,
    const std::wstring& stderrSrAndChildJsonlRunningPath,
    bool stderrChildJsonlEnabled,
    LogWriter::FileWriter* stderrChildJsonlWriter,
    const std::wstring& stderrChildJsonlRunningPath,
    bool stderrSrJsonlEnabled,
    LogWriter::FileWriter* stderrSrJsonlWriter,
    const std::wstring& stderrSrJsonlRunningPath,
    bool stderrSrAndChildInclStdoutJsonlEnabled,
    LogWriter::FileWriter* stderrSrAndChildInclStdoutJsonlWriter,
    const std::wstring& stderrSrAndChildInclStdoutJsonlRunningPath
) {
    std::lock_guard<std::mutex> lock(domainMutex_);
    AttachJsonlWritersLocked_(
        stdoutJsonlEnabled,
        stdoutJsonlWriter,
        stdoutJsonlRunningPath,
        stderrSrAndChildJsonlEnabled,
        stderrSrAndChildJsonlWriter,
        stderrSrAndChildJsonlRunningPath,
        stderrChildJsonlEnabled,
        stderrChildJsonlWriter,
        stderrChildJsonlRunningPath,
        stderrSrJsonlEnabled,
        stderrSrJsonlWriter,
        stderrSrJsonlRunningPath,
        stderrSrAndChildInclStdoutJsonlEnabled,
        stderrSrAndChildInclStdoutJsonlWriter,
        stderrSrAndChildInclStdoutJsonlRunningPath
    );
}

void SRFileSinkWorker::AttachLogWritersLocked_(
    bool stdoutTxtEnabled,
    LogWriter::FileWriter* stdoutTxtWriter,
    const std::wstring& stdoutTxtRunningPath,
    bool stderrSrAndChildTxtEnabled,
    LogWriter::FileWriter* stderrSrAndChildTxtWriter,
    const std::wstring& stderrSrAndChildTxtRunningPath,
    bool stderrChildTxtEnabled,
    LogWriter::FileWriter* stderrChildTxtWriter,
    const std::wstring& stderrChildTxtRunningPath,
    bool stderrSrTxtEnabled,
    LogWriter::FileWriter* stderrSrTxtWriter,
    const std::wstring& stderrSrTxtRunningPath,
    bool stderrSrAndChildInclStdoutTxtEnabled,
    LogWriter::FileWriter* stderrSrAndChildInclStdoutTxtWriter,
    const std::wstring& stderrSrAndChildInclStdoutTxtRunningPath
) {
    FileTargetConfig& stdoutTxtConfig =
        domain_.targetConfigs[
            SR::JobTargetWorkerConfigIndexOf(
                SR::JobTarget::StdoutTxt
            )
        ];
    stdoutTxtConfig.enabled = stdoutTxtEnabled;
    stdoutTxtConfig.writer = stdoutTxtWriter;
    stdoutTxtConfig.runningPath = stdoutTxtRunningPath;

    FileTargetConfig& stderrSrAndChildTxtConfig =
        domain_.targetConfigs[
            SR::JobTargetWorkerConfigIndexOf(
                SR::JobTarget::StderrSrAndChildTxt
            )
        ];
    stderrSrAndChildTxtConfig.enabled = stderrSrAndChildTxtEnabled;
    stderrSrAndChildTxtConfig.writer = stderrSrAndChildTxtWriter;
    stderrSrAndChildTxtConfig.runningPath = stderrSrAndChildTxtRunningPath;

    FileTargetConfig& stderrChildTxtConfig =
        domain_.targetConfigs[
            SR::JobTargetWorkerConfigIndexOf(
                SR::JobTarget::StderrChildTxt
            )
        ];
    stderrChildTxtConfig.enabled = stderrChildTxtEnabled;
    stderrChildTxtConfig.writer = stderrChildTxtWriter;
    stderrChildTxtConfig.runningPath = stderrChildTxtRunningPath;

    FileTargetConfig& stderrSrTxtConfig =
        domain_.targetConfigs[
            SR::JobTargetWorkerConfigIndexOf(
                SR::JobTarget::StderrSrTxt
            )
        ];
    stderrSrTxtConfig.enabled = stderrSrTxtEnabled;
    stderrSrTxtConfig.writer = stderrSrTxtWriter;
    stderrSrTxtConfig.runningPath = stderrSrTxtRunningPath;
    FileTargetConfig& stderrSrAndChildInclStdoutTxtConfig =
        domain_.targetConfigs[
            SR::JobTargetWorkerConfigIndexOf(
                SR::JobTarget::StderrSrAndChildInclStdoutTxt
            )
        ];
    stderrSrAndChildInclStdoutTxtConfig.enabled = stderrSrAndChildInclStdoutTxtEnabled;
    stderrSrAndChildInclStdoutTxtConfig.writer = stderrSrAndChildInclStdoutTxtWriter;
    stderrSrAndChildInclStdoutTxtConfig.runningPath = stderrSrAndChildInclStdoutTxtRunningPath;


}
void SRFileSinkWorker::AttachJsonlWritersLocked_(
    bool stdoutJsonlEnabled,
    LogWriter::FileWriter* stdoutJsonlWriter,
    const std::wstring& stdoutJsonlRunningPath,
    bool stderrSrAndChildJsonlEnabled,
    LogWriter::FileWriter* stderrSrAndChildJsonlWriter,
    const std::wstring& stderrSrAndChildJsonlRunningPath,
    bool stderrChildJsonlEnabled,
    LogWriter::FileWriter* stderrChildJsonlWriter,
    const std::wstring& stderrChildJsonlRunningPath,
    bool stderrSrJsonlEnabled,
    LogWriter::FileWriter* stderrSrJsonlWriter,
    const std::wstring& stderrSrJsonlRunningPath,
    bool stderrSrAndChildInclStdoutJsonlEnabled,
    LogWriter::FileWriter* stderrSrAndChildInclStdoutJsonlWriter,
    const std::wstring& stderrSrAndChildInclStdoutJsonlRunningPath
) {
    FileTargetConfig& stdoutJsonlConfig =
        domain_.targetConfigs[
            SR::JobTargetWorkerConfigIndexOf(
                SR::JobTarget::StdoutJsonl
            )
        ];
    stdoutJsonlConfig.enabled = stdoutJsonlEnabled;
    stdoutJsonlConfig.writer = stdoutJsonlWriter;
    stdoutJsonlConfig.runningPath = stdoutJsonlRunningPath;

    FileTargetConfig& stderrSrAndChildJsonlConfig =
        domain_.targetConfigs[
            SR::JobTargetWorkerConfigIndexOf(
                SR::JobTarget::StderrSrAndChildJsonl
            )
        ];
    stderrSrAndChildJsonlConfig.enabled = stderrSrAndChildJsonlEnabled;
    stderrSrAndChildJsonlConfig.writer = stderrSrAndChildJsonlWriter;
    stderrSrAndChildJsonlConfig.runningPath = stderrSrAndChildJsonlRunningPath;

    FileTargetConfig& stderrChildJsonlConfig =
        domain_.targetConfigs[
            SR::JobTargetWorkerConfigIndexOf(
                SR::JobTarget::StderrChildJsonl
            )
        ];
    stderrChildJsonlConfig.enabled = stderrChildJsonlEnabled;
    stderrChildJsonlConfig.writer = stderrChildJsonlWriter;
    stderrChildJsonlConfig.runningPath = stderrChildJsonlRunningPath;

    FileTargetConfig& stderrSrJsonlConfig =
        domain_.targetConfigs[
            SR::JobTargetWorkerConfigIndexOf(
                SR::JobTarget::StderrSrJsonl
            )
        ];
    stderrSrJsonlConfig.enabled = stderrSrJsonlEnabled;
    stderrSrJsonlConfig.writer = stderrSrJsonlWriter;
    stderrSrJsonlConfig.runningPath = stderrSrJsonlRunningPath;
    FileTargetConfig& stderrSrAndChildInclStdoutJsonlConfig =
        domain_.targetConfigs[
            SR::JobTargetWorkerConfigIndexOf(
                SR::JobTarget::StderrSrAndChildInclStdoutJsonl
            )
        ];
    stderrSrAndChildInclStdoutJsonlConfig.enabled = stderrSrAndChildInclStdoutJsonlEnabled;
    stderrSrAndChildInclStdoutJsonlConfig.writer = stderrSrAndChildInclStdoutJsonlWriter;
    stderrSrAndChildInclStdoutJsonlConfig.runningPath = stderrSrAndChildInclStdoutJsonlRunningPath;

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
        SR::JobTargetFormatOf(target);


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
        if (!TryWriteJsonlTarget_(job, targetConfig, &gle)) {

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

    if (SR::JobTargetWorkerOf(target) ==
        SR::JobTargetWorker::SRFileSinkWorker) {
        const std::size_t workerConfigIndex =
            SR::JobTargetWorkerConfigIndexOf(target);

        if (workerConfigIndex < domain_.targetConfigs.size()) {
            snapshot.targetConfig =
                domain_.targetConfigs[
                    workerConfigIndex
                ];
        } else {
            snapshot.targetConfig = FileTargetConfig{target};
        }
    } else {
        snapshot.targetConfig = FileTargetConfig{target};
    }

    if (snapshot.targetConfig.headerParsingTokenEnabled) {
        snapshot.parsingToken = domain_.config.parsingToken;
    }

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

        const WorkerFailureState& failure = domain_.config.failure;
        if (failure.suppressedAfterWriteFailure) {
            ProbeLine_(
                SR::FormatJobTargetState(
                    L"SRFileSinkWorker::IsValidTxtTarget_ suppressed",
                    targetConfig.target,
                    SR::JobState::Suppressed
                )
            );
            result.state = SR::JobState::Suppressed;
            result.details.failedReasonGle = failure.firstWriteFailureGle;
            result.details.failedReasonText =
                failure.firstWriteFailureText.empty()
                    ? L"TXT file sink worker domain is suppressed after previous write failure"
                    : failure.firstWriteFailureText;
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

        const WorkerFailureState& failure = domain_.config.failure;
        if (failure.suppressedAfterWriteFailure) {
            ProbeLine_(
                SR::FormatJobTargetState(
                    L"SRFileSinkWorker::IsValidJsonlTarget_ suppressed",
                    targetConfig.target,
                    SR::JobState::Suppressed
                )
            );
            result.state = SR::JobState::Suppressed;
            result.details.failedReasonGle = failure.firstWriteFailureGle;
            result.details.failedReasonText =
                failure.firstWriteFailureText.empty()
                    ? L"JSONL file sink worker domain is suppressed after previous write failure"
                    : failure.firstWriteFailureText;
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
    (void)target;

    const DWORD failureGle = (gle != 0) ? gle : ERROR_WRITE_FAULT;

    std::lock_guard<std::mutex> lock(failureMutex_);


    WorkerFailureState& failure = domain_.config.failure;
    if (failure.suppressedAfterWriteFailure) {
        return;
    }

    failure.suppressedAfterWriteFailure = true;
    failure.firstWriteFailureGle = failureGle;
    failure.firstWriteFailureText = reason;
}

// -----------------------------------------------------------------------------
// TXT/JSONL writers. Failed is produced only by these TryWrite* functions.
// -----------------------------------------------------------------------------

// Serializes and writes one pending job to a TXT file target.
//
// For parseable stderr-sr-and-child TXT targets, this method owns the segment framing:
// - determines whether a new SrDiag or ChildStderr header is required,
// - formats the header through SRPhaseTimelineEntryFormatter,
// - inserts an LF before a header when the preceding raw payload did not end
//   at a line boundary,
// - writes the entry payload,
// - updates stderr-sr-and-child TXT segment and line-boundary state.
//
// For ordinary TXT targets, child stdout/stderr payloads remain raw bytes.
//
// The formatter defines header and line contents; this method defines their
// placement, framing, writing, and flushing.
//
// Keep stderr-sr-and-child TXT header selection, LF separation, and payload ordering aligned
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

    if (targetConfig.headerParsingTokenEnabled) {

        const std::string& parsingToken = writeConfig.parsingToken;

        bool headerRequired = false;
        std::string header;
        std::optional<SR::JobPayloadType>* lastWrittenPayloadType = nullptr;
        bool* atLineStart = nullptr;
        switch (targetConfig.target) {
            case SR::JobTarget::StderrSrAndChildTxt:
                lastWrittenPayloadType =
                    &stderrSrAndChildTxtLastWrittenPayloadType_;
                atLineStart = &stderrSrAndChildTxtAtLineStart_;
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
        const bool startsNewSegment =
            lastWrittenPayloadType &&
            (
                !*lastWrittenPayloadType ||
                **lastWrittenPayloadType != job.payloadType
            );


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
                headerRequired = startsNewSegment;
                if (headerRequired) {
                    header =
                        SR::SRPhaseTimelineEntryFormatter::FormatChildStderrTxtHeader(
                            job.childStderr,
                            parsingToken
                        );
                }
                break;
            case SR::JobPayloadType::ChildStdout:
                headerRequired = startsNewSegment;
                if (headerRequired) {
                    header =
                        SR::SRPhaseTimelineEntryFormatter::FormatChildStdoutTxtHeader(
                            job.childStdout,
                            parsingToken
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
        // Ordinary TXT targets write child output as raw bytes without segment framing.
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
    const FileTargetConfig& targetConfig,

    DWORD* outGle
) {
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
                job.srDiag
            );

            break;

        case SR::JobPayloadType::ChildStdout:
            line = SR::SRPhaseTimelineEntryFormatter::FormatJsonLine(
                job.childStdout
            );

            break;

        case SR::JobPayloadType::ChildStderr:
            line = SR::SRPhaseTimelineEntryFormatter::FormatJsonLine(
                job.childStderr
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
