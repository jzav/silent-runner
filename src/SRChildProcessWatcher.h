#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <optional>

#include "CoreHelpers.h"

class SRLifecycleDiagnostics;
class SRRuntimeCoordinator;
class SRWindowsJobObjectController;

// Watches the main child, captures its exit code, and reports completion
// to the coordinator. It requests process-tree completion checking from
// the Job Object controller; it does not own the monitoring thread.
// Stop() synchronizes with the callback; the destructor is a fallback.
class SRChildProcessWatcher {
public:
    SRChildProcessWatcher() = default;
    ~SRChildProcessWatcher() noexcept;

    SRChildProcessWatcher(const SRChildProcessWatcher&) = delete;
    SRChildProcessWatcher& operator=(const SRChildProcessWatcher&) = delete;

    void Init(
        SRRuntimeCoordinator& coordinator,
        SRWindowsJobObjectController& jobController,
        SRLifecycleDiagnostics& diag
    ) noexcept;

    // Registers once, without blocking until the process exits.
    // SRRuntime owns the original handle; the watcher retains its own
    // duplicate until Stop() completes.
    bool WaitForExitAsync(HANDLE childProcess, DWORD& outGle) noexcept;
    void Stop() noexcept;

    // Read only after Stop(), which synchronizes with the callback.
    std::optional<DWORD> childExitCode;
    DWORD childExitCodeError = ERROR_SUCCESS;

private:
    static VOID CALLBACK OnChildCompleted_(
        PTP_CALLBACK_INSTANCE instance,
        PVOID context,
        PTP_WAIT wait,
        TP_WAIT_RESULT waitResult
    ) noexcept;
    void HandleChildCompleted_() noexcept;
    void LogExitCodeFailure_(DWORD gle) noexcept;

    SRRuntimeCoordinator* coordinator_ = nullptr;
    SRWindowsJobObjectController* jobController_ = nullptr;
    SRLifecycleDiagnostics* diag_ = nullptr;
    CoreHelpers::UniqueHandle childProcess_;
    PTP_WAIT wait_ = nullptr; // CloseThreadpoolWait, not CloseHandle.
    bool startAttempted_ = false;
};
