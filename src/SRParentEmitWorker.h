// SRParentEmitWorker.h
#pragma once
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <array>

#include <string>
#include <condition_variable>
#include <mutex>
#include <optional>

#include <thread>
#include <vector>

#include "SRParentEmitPolicy.h"
#include "SRPendingJobTypes.h"

class SRLifecycleDiagnostics;
class SRWorkerCommonPolicy;
namespace SR { class SRWorkerSupervisor; }
class SRParentEmitWorker {
public:
    SRParentEmitWorker() = default;
    ~SRParentEmitWorker();

    SRParentEmitWorker(const SRParentEmitWorker&) = delete;
    SRParentEmitWorker& operator=(const SRParentEmitWorker&) = delete;

    bool Start();
    void SetWorkerSupervisor(SR::SRWorkerSupervisor* supervisor) noexcept;


    void DrainAndStop();
    void Drain();

    bool Init(
        SRLifecycleDiagnostics* diagnostics,
        SRParentEmitPolicy* parentEmitPolicyOrNull,
        const SR::ParentEmitWorkerTargetLayout& targetLayout,
        const SRWorkerCommonPolicy& workerCommonPolicy
    ) noexcept;


    bool EnqueuePendingJobs(const SR::PendingJobs& jobs);
    SR::JobResults TakeJobResults();
    SR::WorkerSummaries TakeWorkerSummaries();

private:
    enum class StopMode {
        KeepRunning,
        DrainAndStop
    };

    using ParentStreamType = SR::JobTargetStream;

    struct ParentTargetConfig {
        SR::JobTarget target{};
        ParentStreamType stream = ParentStreamType::Stdout;

        bool enabled = false;
        bool headerParsingTokenEnabled = false;

    };


    struct ParentEmitFailureLatch {
        bool suppressed = false;
        DWORD gle = 0;
        std::wstring reason;
    };

    struct WorkerConfig {
        ParentEmitFailureLatch workerStdoutFailure;
        ParentEmitFailureLatch workerStderrFailure;
        std::string parsingToken;
        SR::ChildOutputPresentation stdoutPresentation =
            SR::ChildOutputPresentation::Block;
        SR::ChildOutputPresentation stderrChildPresentation =
            SR::ChildOutputPresentation::Block;

    };

    struct WriteConfigSnapshot {
        ParentTargetConfig targetConfig;
        std::string parsingToken;
        SR::ChildOutputPresentation stdoutPresentation =
            SR::ChildOutputPresentation::Block;
        SR::ChildOutputPresentation stderrChildPresentation =
            SR::ChildOutputPresentation::Block;

    };



    struct WorkerDomain {
        SR::ParentEmitWorkerTargetLayout targetLayout;
        std::array<
            ParentTargetConfig,
            SR::kParentTargetConfigCount
        > targetConfigs{};
        WorkerConfig config;
    };


    void WorkerLoop_();

    void ExecutePendingJob_(const SR::PendingJob& job);
    SR::JobResult ExecuteParentTarget_(
        const SR::PendingJob& job,
        SR::JobTarget target
    );

    SR::JobResult MakeJobResult_(
        const SR::PendingJob& job,
        SR::JobTarget target
    ) const;


    WriteConfigSnapshot RetrieveWriteConfig_(
        SR::JobTarget target
    ) const;

    static bool IsValidStdoutParentTarget_(
        const ParentTargetConfig& targetConfig

    ) noexcept;
    static bool IsValidStderrParentTarget_(
        const ParentTargetConfig& targetConfig

    ) noexcept;

    bool IsParentTargetSuppressed_(
        const ParentTargetConfig& targetConfig,

        SR::JobResult& result
    ) const;

    void SuppressParentTargetAfterWriteFailure_(
        const ParentTargetConfig& targetConfig,

        DWORD gle,
        const std::wstring& reason
    );


    ParentEmitFailureLatch& FailureLatchForStream_(
        ParentStreamType streamType
    ) noexcept;

    const ParentEmitFailureLatch& FailureLatchForStream_(
        ParentStreamType streamType
    ) const noexcept;

    bool TryEmitParentTarget_(
        const SR::PendingJob& job,
        const WriteConfigSnapshot& writeConfig,
        DWORD* outGle
    );

    bool BuildPayloadBytes_(
        const SR::PendingJob& job,
        const WriteConfigSnapshot& writeConfig,
        std::vector<char>& bytesOut
    );



    void AppendJobResult_(SR::JobResult result);
    static constexpr bool kParentEmitWorkerProbeEnabled = true;
    static constexpr bool kParentEmitWorkerInjectFailure = false;
    static constexpr std::size_t kParentEmitWorkerFailOnDequeuedJob = 2;
    void ProbeLine_(const std::wstring& msg) const;


    mutable std::mutex controlMutex_;
    std::condition_variable cv_;
    std::condition_variable drainCv_;
    std::thread workerThread_;

    mutable std::mutex parentEmitPolicyMutex_;
    SRParentEmitPolicy* parentEmitPolicy_ = nullptr; // non-owning

    SRLifecycleDiagnostics* diagnostics_ = nullptr; // non-owning
    SR::SRWorkerSupervisor* workerSupervisor_ = nullptr; // non-owning


    mutable std::mutex domainMutex_;
    mutable std::mutex failureLatchMutex_;
    WorkerDomain domain_;
    std::optional<SR::JobPayloadType>
        stdoutParentLastWrittenPayloadType_;
    bool stdoutParentAtLineStart_ = true;
    std::optional<SR::JobPayloadType>
        stderrSrAndChildParentLastWrittenPayloadType_;
    bool stderrSrAndChildParentAtLineStart_ = true;
    std::optional<SR::JobPayloadType>
        stderrChildParentLastWrittenPayloadType_;
    bool stderrChildParentAtLineStart_ = true;
    std::optional<SR::JobPayloadType>
        stderrSrAndChildInclStdoutParentLastWrittenPayloadType_;
    bool stderrSrAndChildInclStdoutParentAtLineStart_ = true;



    mutable std::mutex pendingJobsMutex_;
    SR::PendingJobs pendingJobs_;

    mutable std::mutex jobResultsMutex_;
    SR::JobResults jobResults_;
    mutable std::mutex workerSummariesMutex_;
    SR::WorkerSummaries workerSummaries_;

    StopMode stopMode_ = StopMode::KeepRunning;
    bool started_ = false;
    bool processingActive_ = false;
};
