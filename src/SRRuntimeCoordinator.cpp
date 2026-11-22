#include "SRRuntimeCoordinator.h"
#include "SRWindowsJobObjectController.h"

void SRRuntimeCoordinator::ReportMainChildFinished() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        mainChildFinished_ = true;
        EvaluatePolicyLocked_();
    }
    actionCv_.notify_one();
}

void SRRuntimeCoordinator::ReportProcessTreeFinished() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        processTreeFinished_ = true;
        EvaluatePolicyLocked_();
    }
    actionCv_.notify_one();
}

void SRRuntimeCoordinator::ReportStdoutReaderFinished() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stdoutReaderFinished_ = true;
        EvaluatePolicyLocked_();
    }
    actionCv_.notify_one();
}

void SRRuntimeCoordinator::ReportStderrReaderFinished() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stderrReaderFinished_ = true;
        EvaluatePolicyLocked_();
    }
    actionCv_.notify_one();
}

void SRRuntimeCoordinator::ReportTimeout() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        timeoutReported_ = true;
        EvaluatePolicyLocked_();
    }
    actionCv_.notify_one();
}

void SRRuntimeCoordinator::ReportBufferLimitExceeded() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        bufferLimitExceeded_ = true;
        EvaluatePolicyLocked_();
    }
    actionCv_.notify_one();
}

void SRRuntimeCoordinator::ReportRuntimeFailure(RuntimeFailureCause cause) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!runtimeFailureDetected_) {
            firstRuntimeFailureCause_ = cause;
        }
        runtimeFailureDetected_ = true;
        EvaluatePolicyLocked_();
    }
    actionCv_.notify_one();
}

bool SRRuntimeCoordinator::IsCompleted_() const noexcept {
    return mainChildFinished_ && processTreeFinished_ &&
           stdoutReaderFinished_ && stderrReaderFinished_;
}

std::optional<SRRuntimeCoordinator::Action>
SRRuntimeCoordinator::EvaluatePolicyLocked_(bool timeoutJobChecked) noexcept {
    // Stop policy: retain the first accepted reason, including reports that
    // arrived before WaitForActionSync() started (e.g. during Prepare).
    if (stopReason_ == SRRuntimeStopReason::StopReason::None) {
        if (bufferLimitExceeded_) {
            stopReason_ = SRRuntimeStopReason::StopReason::BufferLimit;
            abortActionPending_ = true;
        } else if (timeoutReported_ && !IsCompleted_() &&
                   (!mainChildFinished_ || processTreeFinished_ || timeoutJobChecked)) {
            stopReason_ = SRRuntimeStopReason::StopReason::Timeout;
            abortActionPending_ = true;
        } else if (abortOnRuntimeFailure_ && runtimeFailureDetected_) {
            stopReason_ = SRRuntimeStopReason::StopReason::RuntimeFailure;
            abortActionPending_ = true;
        } else if (IsCompleted_()) {
            stopReason_ = SRRuntimeStopReason::StopReason::NormalExit;
        }
    }

    // An explicit stop must be delivered before completion.
    if (abortActionPending_) return Action::Abort;
    if (IsCompleted_()) return Action::Completed;

    return std::nullopt;
}

SRRuntimeCoordinator::Action SRRuntimeCoordinator::WaitForActionSync(
    SRWindowsJobObjectController& jobController,
    DWORD& outTimeoutJobQueryGle
) {

    std::unique_lock<std::mutex> lock(mutex_);
    outTimeoutJobQueryGle = ERROR_SUCCESS;
    bool timeoutJobChecked = false;

    for (;;) {
        if (auto action = EvaluatePolicyLocked_(timeoutJobChecked)) {
            if (*action == Action::Abort) {
                abortActionPending_ = false;
            }
            return *action;
        }
        // The main child has finished, but the periodic Job zero check may
        // still be pending. Refresh Job accounting before the timeout decision.
        // Query the controller outside the coordinator mutex.
        if (stopReason_ == SRRuntimeStopReason::StopReason::None &&
            timeoutReported_ && mainChildFinished_ &&
            !processTreeFinished_ && !timeoutJobChecked) {
            lock.unlock();

            DWORD activeProcesses = 0;
            DWORD queryGle = ERROR_SUCCESS;
            const bool queryOk =
                jobController.TryGetActiveProcessCount(activeProcesses, queryGle);

            lock.lock();

            // State may have changed while the Job Object query was running.
            if (stopReason_ == SRRuntimeStopReason::StopReason::None &&
                timeoutReported_ && mainChildFinished_ &&
                !processTreeFinished_) {
                if (queryOk && activeProcesses == 0) {
                    processTreeFinished_ = true;
                } else {
                    timeoutJobChecked = true;
                    if (!queryOk) {
                        outTimeoutJobQueryGle =
                            queryGle != ERROR_SUCCESS ? queryGle : ERROR_GEN_FAILURE;
                    }
                }
            }
            continue;
        }
        // Report*() signals the condition variable when runtime state changes.
        actionCv_.wait(lock);

    }
}

void SRRuntimeCoordinator::WaitForReadersAfterAbort() {
    std::unique_lock<std::mutex> lock(mutex_);
    actionCv_.wait_for(lock, kReaderDrainGracePeriod, [this] {
        return stdoutReaderFinished_ && stderrReaderFinished_;
    });
}
SRRuntimeStopReason::StopReason SRRuntimeCoordinator::StopReason() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stopReason_;
}

bool SRRuntimeCoordinator::RuntimeFailureDetected() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return runtimeFailureDetected_;
}

SRRuntimeCoordinator::RuntimeFailureCause SRRuntimeCoordinator::FirstRuntimeFailureCause() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return firstRuntimeFailureCause_;
}

const wchar_t* SRRuntimeCoordinator::RuntimeFailureCauseToString(RuntimeFailureCause cause) noexcept {
    switch (cause) {
        case RuntimeFailureCause::UnexpectedChildWaitTimeout: return L"CHILD_WAIT_UNEXPECTED_TIMEOUT";
        case RuntimeFailureCause::GetChildExitCodeFailed: return L"GET_EXIT_CODE_PROCESS_FAILED";
        case RuntimeFailureCause::ProcessTreeCompletionCheckUnavailable: return L"PROCESS_TREE_COMPLETION_CHECK_UNAVAILABLE";
        case RuntimeFailureCause::ChildWatcherCallbackException: return L"CHILD_WATCHER_CALLBACK_EXCEPTION";
        case RuntimeFailureCause::JobAccountingQueryFailed: return L"QUERY_ACTIVE_PROCESSES_FAILED";
        case RuntimeFailureCause::JobMonitorThreadException: return L"JOB_MONITOR_THREAD_EXCEPTION";
        case RuntimeFailureCause::TimeoutCallbackException: return L"TIMEOUT_CALLBACK_EXCEPTION";
        case RuntimeFailureCause::None:
        default: return L"UNKNOWN";
    }
}
