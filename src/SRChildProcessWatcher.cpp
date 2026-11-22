#include "SRChildProcessWatcher.h"

#include "ErrorHelpers.h"
#include "SRLifecycleDiagnostics.h"

#include "SRRuntimeCoordinator.h"
#include "SRWindowsJobObjectController.h"

SRChildProcessWatcher::~SRChildProcessWatcher() noexcept {
    Stop();
}

void SRChildProcessWatcher::Init(
    SRRuntimeCoordinator& coordinator,
    SRWindowsJobObjectController& jobController,
    SRLifecycleDiagnostics& diag
) noexcept {
    coordinator_ = &coordinator;
    jobController_ = &jobController;
    diag_ = &diag;
}

bool SRChildProcessWatcher::WaitForExitAsync(
    HANDLE childProcess,
    DWORD& outGle
) noexcept {
    outGle = ERROR_SUCCESS;
    if (startAttempted_) {
        outGle = ERROR_ALREADY_EXISTS;
        return false;
    }
    startAttempted_ = true;

    if (!coordinator_ || !jobController_ || !childProcess ||
        childProcess == INVALID_HANDLE_VALUE) {
        outGle = ERROR_INVALID_HANDLE;
        return false;
    }

    // The wait and callback must retain a valid process handle even if the
    // owner releases its original handle during an exceptional exit.
    HANDLE duplicate = nullptr;
    if (!DuplicateHandle(
            GetCurrentProcess(), childProcess,
            GetCurrentProcess(), &duplicate,
            0, FALSE, DUPLICATE_SAME_ACCESS)) {
        outGle = GetLastError();
        return false;
    }
    childProcess_.reset(duplicate);

    wait_ = CreateThreadpoolWait(
        &SRChildProcessWatcher::OnChildCompleted_, this, nullptr);
    if (!wait_) {
        outGle = GetLastError();
        childProcess_.reset();
        return false;
    }
    SetThreadpoolWait(wait_, childProcess_.get(), nullptr);
    if (diag_ && diag_->IsDebugEnabled()) {
        try {
            diag_->DebugLine(L"Main child completion wait registered");
        } catch (...) {
            // Diagnostics must not change registration success.
        }
    }
    return true;
}

VOID CALLBACK SRChildProcessWatcher::OnChildCompleted_(
    PTP_CALLBACK_INSTANCE,
    PVOID context,
    PTP_WAIT,
    TP_WAIT_RESULT waitResult
) noexcept {
    auto* watcher = static_cast<SRChildProcessWatcher*>(context);
    if (!watcher) return;
    if (waitResult != WAIT_OBJECT_0) {
        try {
            watcher->coordinator_->ReportRuntimeFailure(
                SRRuntimeCoordinator::RuntimeFailureCause::UnexpectedChildWaitTimeout);
        } catch (...) {
        }
        try {
            if (watcher->diag_) {
                watcher->diag_->ErrorLine(
                    L"Main child completion wait returned unexpectedly; result=" +
                    std::to_wstring(waitResult)
                );
            }
        } catch (...) {
        }
        return;
    }
    watcher->HandleChildCompleted_();
}

void SRChildProcessWatcher::HandleChildCompleted_() noexcept {
    try {
        DWORD exitCode = 0;
        if (GetExitCodeProcess(childProcess_.get(), &exitCode)) {
            childExitCode = exitCode;
        } else {
            childExitCodeError = GetLastError();
            coordinator_->ReportRuntimeFailure(
                SRRuntimeCoordinator::RuntimeFailureCause::GetChildExitCodeFailed);
            LogExitCodeFailure_(childExitCodeError);
        }

        coordinator_->ReportMainChildFinished();
        if (!jobController_->RequestProcessTreeCompletionCheck()) {
            coordinator_->ReportRuntimeFailure(
                SRRuntimeCoordinator::RuntimeFailureCause::ProcessTreeCompletionCheckUnavailable);
            try {
                if (diag_) diag_->ErrorLine(L"Process-tree completion check unavailable");
            } catch (...) {
            }
        }
        if (childExitCode && diag_ && diag_->IsDebugEnabled()) {
            try {
                diag_->DebugLine(
                    L"Child exitCode=" +
                    std::to_wstring(*childExitCode)
                );
            } catch (...) {
            }
        }
    } catch (...) {
        // No exception may escape a Windows threadpool callback.
        try {
            coordinator_->ReportRuntimeFailure(
                SRRuntimeCoordinator::RuntimeFailureCause::ChildWatcherCallbackException);
        } catch (...) {
        }
        try {
            if (diag_) diag_->ErrorLine(L"Main child watcher callback failed");
        } catch (...) {
        }
    }
}

void SRChildProcessWatcher::LogExitCodeFailure_(DWORD gle) noexcept {
    try {
        if (diag_) {
            diag_->ErrorLine(
                L"GetExitCodeProcess failed; " + ErrorHelpers::FormatGle(gle)
            );
        }
    } catch (...) {
        // Optional diagnostics must not interrupt watcher shutdown.
    }
}

void SRChildProcessWatcher::Stop() noexcept {
    if (wait_) {
        SetThreadpoolWait(wait_, nullptr, nullptr);
        // Cancel pending callbacks and wait for any running callback.
        WaitForThreadpoolWaitCallbacks(wait_, TRUE);
        CloseThreadpoolWait(wait_);
        wait_ = nullptr;
    }
    // A synchronous Stop may cancel the callback just before its dispatch.
    // Recover the final exit code directly if the process is already signaled.
    if (!childExitCode && childExitCodeError == ERROR_SUCCESS &&
        childProcess_.valid() &&
        WaitForSingleObject(childProcess_.get(), 0) == WAIT_OBJECT_0) {
        DWORD exitCode = 0;
        if (GetExitCodeProcess(childProcess_.get(), &exitCode)) {
            childExitCode = exitCode;
            if (diag_ && diag_->IsDebugEnabled()) {
                try {
                    diag_->DebugLine(
                        L"Main child exit code recovered during watcher Stop; exit_code=" +
                        std::to_wstring(exitCode)
                    );
                } catch (...) {
                }
            }
        } else {
            childExitCodeError = GetLastError();
            LogExitCodeFailure_(childExitCodeError);
        }
    }
    childProcess_.reset();
}
