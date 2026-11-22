#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>

#include "SRTypes.h"

class SRRuntimeCoordinator;

// Reports a one-shot execution timeout through the runtime coordinator.
// Stop() synchronizes with the callback; the destructor is a fallback.
class SRTimeLimiter {
public:
    SRTimeLimiter() = default;
    ~SRTimeLimiter() noexcept;

    SRTimeLimiter(const SRTimeLimiter&) = delete;
    SRTimeLimiter& operator=(const SRTimeLimiter&) = delete;

    void Init(SRRuntimeCoordinator& coordinator, const SR::SRTimeLimiterConfig& config) noexcept;

    // Starts once, without blocking. A zero timeout disables the timer.
    bool Start(DWORD& outGle) noexcept;
    void Stop() noexcept;

    uint32_t TimeoutMs() const noexcept { return timeoutMs_; }


private:
    static VOID CALLBACK OnTimeout_(
        PTP_CALLBACK_INSTANCE instance,
        PVOID context,
        PTP_TIMER timer
    ) noexcept;

    SRRuntimeCoordinator* coordinator_ = nullptr;
    uint32_t timeoutMs_ = 0;
    PTP_TIMER timer_ = nullptr; // CloseThreadpoolTimer, not CloseHandle.
    bool startAttempted_ = false;
};
