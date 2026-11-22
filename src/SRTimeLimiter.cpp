#include "SRTimeLimiter.h"

#include "SRRuntimeCoordinator.h"

SRTimeLimiter::~SRTimeLimiter() noexcept {
    Stop();
}

void SRTimeLimiter::Init(
    SRRuntimeCoordinator& coordinator,
    const SR::SRTimeLimiterConfig& config
) noexcept {
    coordinator_ = &coordinator;
    timeoutMs_ = config.timeoutMs;

}

bool SRTimeLimiter::Start(DWORD& outGle) noexcept {
    outGle = ERROR_SUCCESS;
    if (startAttempted_) {
        outGle = ERROR_ALREADY_EXISTS;
        return false;
    }
    startAttempted_ = true;

    if (!coordinator_) {
        outGle = ERROR_INVALID_PARAMETER;
        return false;
    }
    if (timeoutMs_ == 0) return true;

    timer_ = CreateThreadpoolTimer(&SRTimeLimiter::OnTimeout_, this, nullptr);
    if (!timer_) {
        outGle = GetLastError();
        return false;
    }

    // Negative FILETIME values are relative intervals in 100 ns units.
    LARGE_INTEGER dueTimeTicks{};
    dueTimeTicks.QuadPart = -static_cast<LONGLONG>(timeoutMs_) * 10000LL;
    FILETIME dueTime{dueTimeTicks.LowPart, static_cast<DWORD>(dueTimeTicks.HighPart)};
    SetThreadpoolTimer(timer_, &dueTime, 0, 0);
    return true;
}

VOID CALLBACK SRTimeLimiter::OnTimeout_(
    PTP_CALLBACK_INSTANCE,
    PVOID context,
    PTP_TIMER
) noexcept {
    auto* limiter = static_cast<SRTimeLimiter*>(context);
    if (!limiter || !limiter->coordinator_) return;
    try {
        limiter->coordinator_->ReportTimeout();
    } catch (...) {
        // No exception may escape a Windows threadpool callback.
        try {
            limiter->coordinator_->ReportRuntimeFailure(
                SRRuntimeCoordinator::RuntimeFailureCause::TimeoutCallbackException);
        } catch (...) {
        }
    }
}

void SRTimeLimiter::Stop() noexcept {
    if (!timer_) return;
    SetThreadpoolTimer(timer_, nullptr, 0, 0);
    // Complete or cancel any pending callback before releasing the timer.
    WaitForThreadpoolTimerCallbacks(timer_, TRUE);
    CloseThreadpoolTimer(timer_);
    timer_ = nullptr;
}
