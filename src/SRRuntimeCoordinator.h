#pragma once

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <optional>

#include "SRRuntimeStopReason.h"

class SRWindowsJobObjectController;
// SRRuntimeCoordinator - runtime decision policy
// ----------------------------------------------
// Reports update facts; EvaluatePolicyLocked_ is the only place that decides
// whether to abort or finish.
// The coordinator owns no thread or process handle. SRRuntime executes actions.
//
// Policy:
// - The first accepted abort request (buffer limit, timeout or configured runtime
//   failure) wins. Timeout and buffer limits remain active while output
//   is being drained after process-tree completion.
// - Explicit stops take precedence over normal completion.
// - Completion requires the main child, process tree and both readers to finish.
// - Child-supervision failures (e.g. process-tree monitoring or child exit-code
//   retrieval) are recorded as state. SRRuntime maps them to Runtime exit code
//   255. They request an abort only when --abort-on-runtime-failure is enabled.

// - If the main child has finished but Job zero is not yet reported, timeout
//   is verified against current Job accounting before it is accepted.
// - The execution timeout covers process-tree execution and reader completion.
class SRRuntimeCoordinator {
public:
    enum class Action {
        Abort,
        Completed
    };

    enum class RuntimeFailureCause {
        None,
        UnexpectedChildWaitTimeout,
        GetChildExitCodeFailed,
        ProcessTreeCompletionCheckUnavailable,
        ChildWatcherCallbackException,
        JobAccountingQueryFailed,
        JobMonitorThreadException,
        TimeoutCallbackException
    };

    SRRuntimeCoordinator() = default;
    void Init(bool abortOnRuntimeFailure) noexcept { abortOnRuntimeFailure_ = abortOnRuntimeFailure; }
    SRRuntimeCoordinator(const SRRuntimeCoordinator&) = delete;
    SRRuntimeCoordinator& operator=(const SRRuntimeCoordinator&) = delete;

    void ReportMainChildFinished();
    void ReportProcessTreeFinished();
    void ReportStdoutReaderFinished();
    void ReportStderrReaderFinished();
    void ReportTimeout();
    void ReportBufferLimitExceeded();
    void ReportRuntimeFailure(RuntimeFailureCause cause);

    // Blocks until the decision policy produces an action.
    // Timeout is reported by SRTimeLimiter through ReportTimeout().
    Action WaitForActionSync(
        SRWindowsJobObjectController& jobController,
        DWORD& outTimeoutJobQueryGle
    );

    // After a timeout or requested runtime-failure abort, give both readers
    // one shared grace period to finish naturally before cancellation.
    void WaitForReadersAfterAbort();
    SRRuntimeStopReason::StopReason StopReason() const;
    bool RuntimeFailureDetected() const;
    RuntimeFailureCause FirstRuntimeFailureCause() const;
    static const wchar_t* RuntimeFailureCauseToString(RuntimeFailureCause cause) noexcept;

private:
    static constexpr std::chrono::milliseconds kReaderDrainGracePeriod{2000};
    // Both helpers are called only with mutex_ held.
    bool IsCompleted_() const noexcept;
    std::optional<Action> EvaluatePolicyLocked_(bool timeoutJobChecked = false) noexcept;

    mutable std::mutex mutex_;
    std::condition_variable actionCv_;

    bool mainChildFinished_ = false;
    bool processTreeFinished_ = false;
    bool stdoutReaderFinished_ = false;
    bool stderrReaderFinished_ = false;
    bool timeoutReported_ = false;
    bool bufferLimitExceeded_ = false;
    bool abortActionPending_ = false;
    bool runtimeFailureDetected_ = false;
    RuntimeFailureCause firstRuntimeFailureCause_ = RuntimeFailureCause::None;
    bool abortOnRuntimeFailure_ = false;
    SRRuntimeStopReason::StopReason stopReason_ = SRRuntimeStopReason::StopReason::None;
};
