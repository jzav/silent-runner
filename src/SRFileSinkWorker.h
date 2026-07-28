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

#include "LogWriter.h"
#include "SRPendingJobTypes.h"

class ExecutionTimeline;
class SRLifecycleDiagnostics;
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
    void SetParsingTokenPolicy(
        const std::string& parsingToken,
        const std::vector<SR::JobTarget>& enabledTargets
    );


    SR::WorkerSummaries TakeWorkerSummaries();

    bool Init(SRLifecycleDiagnostics* diagnostics);
    void AttachLogWriters(
        bool stdoutTxtEnabled,
        LogWriter::FileWriter* stdoutTxtWriter,
        const std::wstring& stdoutTxtRunningPath,
        bool stderrMixedTxtEnabled,
        LogWriter::FileWriter* stderrMixedTxtWriter,
        const std::wstring& stderrMixedTxtRunningPath,
        bool stderrChildTxtEnabled,
        LogWriter::FileWriter* stderrChildTxtWriter,
        const std::wstring& stderrChildTxtRunningPath,
        bool stderrSrTxtEnabled,
        LogWriter::FileWriter* stderrSrTxtWriter,
        const std::wstring& stderrSrTxtRunningPath
    );
    void AttachJsonlWriters(
        bool stdoutJsonlEnabled,
        LogWriter::FileWriter* stdoutJsonlWriter,
        const std::wstring& stdoutJsonlRunningPath,
        bool stderrMixedJsonlEnabled,
        LogWriter::FileWriter* stderrMixedJsonlWriter,
        const std::wstring& stderrMixedJsonlRunningPath,
        bool stderrChildJsonlEnabled,
        LogWriter::FileWriter* stderrChildJsonlWriter,
        const std::wstring& stderrChildJsonlRunningPath,
        bool stderrSrJsonlEnabled,
        LogWriter::FileWriter* stderrSrJsonlWriter,
        const std::wstring& stderrSrJsonlRunningPath
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
        bool enabled = false;
        bool headerParsingTokenEnabled = false;

        LogWriter::FileWriter* writer = nullptr;
        std::wstring runningPath;
    };


    struct WorkerFailureState {
        bool suppressedAfterWriteFailure = false;
        DWORD firstWriteFailureGle = 0;
        std::wstring firstWriteFailureText;
    };

    struct WorkerConfig {
        WorkerFailureState failure;
        std::string parsingToken;
    };

    struct WriteConfigSnapshot {
        FileTargetConfig targetConfig;
        std::string parsingToken;
    };



    struct WorkerDomain {
        std::array<
            FileTargetConfig,
            SR::kFileSinkTargetConfigCount
        > targetConfigs{{
            FileTargetConfig{SR::JobTarget::StdoutTxt},
            FileTargetConfig{SR::JobTarget::StderrMixedTxt},
            FileTargetConfig{SR::JobTarget::StderrChildTxt},
            FileTargetConfig{SR::JobTarget::StderrSrTxt},
            FileTargetConfig{SR::JobTarget::StdoutJsonl},
            FileTargetConfig{SR::JobTarget::StderrMixedJsonl},
            FileTargetConfig{SR::JobTarget::StderrChildJsonl},
            FileTargetConfig{SR::JobTarget::StderrSrJsonl}
        }};

        WorkerConfig config;
    };


    void AttachLogWritersLocked_(
        bool stdoutTxtEnabled,
        LogWriter::FileWriter* stdoutTxtWriter,
        const std::wstring& stdoutTxtRunningPath,
        bool stderrMixedTxtEnabled,
        LogWriter::FileWriter* stderrMixedTxtWriter,
        const std::wstring& stderrMixedTxtRunningPath,
        bool stderrChildTxtEnabled,
        LogWriter::FileWriter* stderrChildTxtWriter,
        const std::wstring& stderrChildTxtRunningPath,
        bool stderrSrTxtEnabled,
        LogWriter::FileWriter* stderrSrTxtWriter,
        const std::wstring& stderrSrTxtRunningPath
    );
    void AttachJsonlWritersLocked_(
        bool stdoutJsonlEnabled,
        LogWriter::FileWriter* stdoutJsonlWriter,
        const std::wstring& stdoutJsonlRunningPath,
        bool stderrMixedJsonlEnabled,
        LogWriter::FileWriter* stderrMixedJsonlWriter,
        const std::wstring& stderrMixedJsonlRunningPath,
        bool stderrChildJsonlEnabled,
        LogWriter::FileWriter* stderrChildJsonlWriter,
        const std::wstring& stderrChildJsonlRunningPath,
        bool stderrSrJsonlEnabled,
        LogWriter::FileWriter* stderrSrJsonlWriter,
        const std::wstring& stderrSrJsonlRunningPath
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
    bool TryWriteJsonlTarget_(const SR::PendingJob& job, const FileTargetConfig& targetConfig, DWORD* outGle);
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
        stderrMixedTxtLastWrittenPayloadType_;
    bool stderrMixedTxtAtLineStart_ = true;

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
