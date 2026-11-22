#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <atomic>
#include <thread>

#include "CoreHelpers.h"

class SRLifecycleDiagnostics;
class SRRuntimeCoordinator;

// Owns the Windows Job Object and its monitoring thread.
// Reports process-tree completion, but does not decide Runtime completion.
// SRRuntimeCoordinator decides policy actions; SRRuntime executes termination.
class SRWindowsJobObjectController {
public:
    enum class InitFailureReason {
        None,
        AlreadyInitialized,
        CreateJobObject,
        SetKillOnJobClose,
        CreateIocp,
        AssociateIocp,
        StartMonitorThread
    };

    struct InitFailure {
        InitFailureReason reason = InitFailureReason::None;
        DWORD gle = 0;
    };


    explicit SRWindowsJobObjectController(SRLifecycleDiagnostics& diag) noexcept
        : diag_(diag) {}

    ~SRWindowsJobObjectController() noexcept;

    SRWindowsJobObjectController(const SRWindowsJobObjectController&) = delete;
    SRWindowsJobObjectController& operator=(const SRWindowsJobObjectController&) = delete;
    SRWindowsJobObjectController(SRWindowsJobObjectController&&) = delete;
    SRWindowsJobObjectController& operator=(SRWindowsJobObjectController&&) = delete;

    // One initialization attempt per instance. Job Object and monitoring thread
    // are required. IOCP is required for DEBUG diagnostics, optional otherwise.

    bool Init(SRRuntimeCoordinator& coordinator, InitFailure& failure);


    bool IsValid() const noexcept { return job_.valid(); }
    bool AssignProcess(HANDLE process, DWORD& outGle) const noexcept;
    bool Abort(DWORD exitCode, DWORD& outGle) noexcept;

    // Enable authoritative process-tree completion checks in the monitoring thread.
    // Safe to request repeatedly; completion is reported only once.
    bool RequestProcessTreeCompletionCheck() noexcept;

    // Job accounting is authoritative; completion-port notifications are hints.
    bool TryGetActiveProcessCount(DWORD& count, DWORD& outGle) const noexcept;
    bool NotificationsFailed() const noexcept {
        return notificationFailed_.load(std::memory_order_acquire);
    }

    // Shutdown joins the monitor and closes the KILL_ON_JOB_CLOSE Job Object.
    // Normally call only after tree completion or a deliberate abort.
    // The destructor is a fallback, not a non-destructive detach.
    void Shutdown() noexcept;

private:
    enum class CompletionCheckState {
        NotRequested,
        Requested,
        Finished
    };
    bool StartMonitor_(InitFailure& failure);
    void StopMonitor_() noexcept;

    SRLifecycleDiagnostics& diag_; // Must outlive the controller and its monitoring thread.
    SRRuntimeCoordinator* coordinator_ = nullptr; // Bound by Init(), outlives the monitoring thread.

    CoreHelpers::UniqueHandle job_;
    CoreHelpers::UniqueHandle iocp_;
    std::thread monitorThread_;

    std::atomic<CompletionCheckState> completionCheckState_{
        CompletionCheckState::NotRequested
    };
    std::atomic<bool> notificationFailed_{false};
    std::atomic<bool> stopping_{false};
    bool iocpAssociated_ = false;
    bool initAttempted_ = false;
};
