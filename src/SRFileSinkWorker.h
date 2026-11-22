// SRFileSinkWorker.h
#pragma once

#include <cstddef>
#include <array>

#include <condition_variable>
#include <memory>
#include <optional>

#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "SRPendingJobTypes.h"
#include "SRWorkerTypes.h"
namespace LogWriter { class FileWriter; }
struct TargetLogBinding;

class ExecutionTimeline;
class SRLifecycleDiagnostics;
class SRWorkerCommonPolicy;
namespace SR { class SRWorkerSupervisor; }


class SRFileSinkWorker {
public:
    SRFileSinkWorker() = default;
    ~SRFileSinkWorker();

    SRFileSinkWorker(const SRFileSinkWorker&) = delete;
    SRFileSinkWorker& operator=(const SRFileSinkWorker&) = delete;

    bool StartPaused(std::shared_ptr<ExecutionTimeline> executionTimeline = nullptr);
    void Resume();
    void Pause();
    bool Drain();
    bool PauseAfterCurrentJob();
    void DrainAndStop();
    void SetWorkerSupervisor(SR::SRWorkerSupervisor* supervisor) noexcept;


    SR::WorkerSummaries TakeWorkerSummaries();

    bool Init(
        SRLifecycleDiagnostics* diagnostics,
        const SR::FileSinkWorkerTargetLayout& targetLayout,
        SR::JsonlPayloadRepresentation jsonlPayloadRepresentation,
        const SRWorkerCommonPolicy& workerCommonPolicy
    );


    void AttachTxtLogWriters(
        const std::vector<TargetLogBinding>& bindings
    );
    void AttachJsonlLogWriters(
        const std::vector<TargetLogBinding>& bindings
    );

    bool EnqueuePendingJobs(const SR::PendingJobs& jobs);
    SR::JobResults TakeJobResults();

private:
    enum class StopMode {
        KeepRunning,
        DrainAndStop
    };

    struct FileTargetConfig {
        SR::JobTarget target = SR::JobTarget::StdoutTxt;
        SR::JobTargetFormat format = SR::JobTargetFormat::Txt;

        bool enabled = false;
        bool headerEnabled = false;

        LogWriter::FileWriter* writer = nullptr;
    };


    struct WorkerConfig {
        SR::FileSinkWorkerFailureState failure;
        std::string parsingToken;
        std::wstring executionId;
        SR::ChildTxtHeaderGranularity stdoutTxtHeaderGranularity =
            SR::ChildTxtHeaderGranularity::Block;
        SR::ChildTxtHeaderGranularity stderrChildTxtHeaderGranularity =
            SR::ChildTxtHeaderGranularity::Block;
        SR::JsonlPayloadRepresentation jsonlPayloadRepresentation =
            SR::JsonlPayloadRepresentation::Text;


    };

    struct WriteConfigSnapshot {
        FileTargetConfig targetConfig;
        std::string parsingToken;
        std::wstring executionId;
        SR::ChildTxtHeaderGranularity stdoutTxtHeaderGranularity =
            SR::ChildTxtHeaderGranularity::Block;
        SR::ChildTxtHeaderGranularity stderrChildTxtHeaderGranularity =

            SR::ChildTxtHeaderGranularity::Block;
        SR::JsonlPayloadRepresentation jsonlPayloadRepresentation =
            SR::JsonlPayloadRepresentation::Text;


    };



    struct WorkerDomain {
        std::array<
            FileTargetConfig,
            SR::kFileSinkTargetConfigCount
        > targetConfigs{};
        WorkerConfig config;
    };


    void AttachLogWritersLocked_(
        const std::vector<TargetLogBinding>& bindings,
        SR::JobTargetFormat expectedFormat
    );
    
    void ThreadMain_();
    void ExecutePendingJob_(const SR::PendingJob& job);
    SR::JobResult ExecuteFileTarget_(const SR::PendingJob& job, SR::JobTarget target);
    SR::JobResult MakeJobResult_(const SR::PendingJob& job, SR::JobTarget target) const;
    void AppendJobResult_(SR::JobResult result);
    bool ShouldStopAfterDrain_() const noexcept;

    WriteConfigSnapshot RetrieveWriteConfig_(SR::JobTarget target) const;
    bool IsValidTxtTarget_(const FileTargetConfig& targetConfig, SR::JobResult& result) const;

    bool IsValidJsonlTarget_(const FileTargetConfig& targetConfig, SR::JobResult& result) const;

    bool TryWriteTxtTarget_(const SR::PendingJob& job, const WriteConfigSnapshot& writeConfig, DWORD* outGle);
    bool TryWriteJsonlTarget_(const SR::PendingJob& job, const WriteConfigSnapshot& writeConfig, DWORD* outGle);


    void SuppressFileTargetAfterWriteFailure_(SR::JobTarget target, DWORD gle, const std::wstring& reason);

    
    static constexpr bool kFileSinkWorkerProbeEnabled = true;
    static constexpr bool kFileSinkWorkerInjectFailure = false;
    static constexpr std::size_t kFileSinkWorkerFailOnDequeuedJob = 2;
    void ProbeLine_(const std::wstring& msg) const;

private:
    mutable std::mutex controlMutex_;
    std::condition_variable cv_;
    std::condition_variable drainCv_;
    std::thread workerThread_;

    mutable std::mutex domainMutex_;
    mutable std::mutex failureMutex_;

    WorkerDomain domain_;

    std::optional<SR::JobPayloadType>
        stdoutTxtLastWrittenPayloadType_;
    bool stdoutTxtAtLineStart_ = true;
    std::optional<SR::JobPayloadType>
        stderrSrAndChildTxtLastWrittenPayloadType_;
    bool stderrSrAndChildTxtAtLineStart_ = true;
    std::optional<SR::JobPayloadType>
        stderrChildTxtLastWrittenPayloadType_;
    bool stderrChildTxtAtLineStart_ = true;
    std::optional<SR::JobPayloadType>
        stderrSrAndChildInclStdoutTxtLastWrittenPayloadType_;
    bool stderrSrAndChildInclStdoutTxtAtLineStart_ = true;


    mutable std::mutex pendingJobsMutex_;
    SR::PendingJobs pendingJobs_;

    mutable std::mutex jobResultsMutex_;
    SR::JobResults jobResults_;
    mutable std::mutex workerSummariesMutex_;
    SR::WorkerSummaries workerSummaries_;
    SRLifecycleDiagnostics* diagnostics_ = nullptr; // non-owning
    SR::SRWorkerSupervisor* workerSupervisor_ = nullptr; // non-owning


    StopMode stopMode_ = StopMode::KeepRunning;
    bool started_ = false;
    bool paused_ = false;
    bool processingActive_ = false;
};
