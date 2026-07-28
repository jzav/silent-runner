#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>

#include "CoreHelpers.h"
#include "SRTypes.h"

class SRBufferLimiter {
public:
    enum class StreamType {
        None   = 0,
        Stdout = 1,
        Stderr = 2
    };
    enum class EventOperation {
        None   = 0,
        Create = 1,
        Reset  = 2,
        Set    = 3
    };


    SRBufferLimiter() = default;
    SRBufferLimiter(const SRBufferLimiter&) = delete;
    SRBufferLimiter& operator=(const SRBufferLimiter&) = delete;

    void Init(const SR::Options& opt) noexcept;
    void ResetRuntimeState() noexcept;

    bool TryReserveStdout(
        size_t bytes,
        const SR::BufferUsage& usage
    ) noexcept;

    bool TryReserveStderr(
        size_t bytes,
        const SR::BufferUsage& usage
    ) noexcept;

    bool LimitHit() const noexcept;
    StreamType FirstHitStream() const noexcept;

    HANDLE LimitEventHandle() const noexcept;
    bool EventFailureDetected() const noexcept;
    EventOperation FirstEventFailureOperation() const noexcept;
    const wchar_t* FirstEventFailureOperationName() const noexcept;
    DWORD FirstEventFailureGle() const noexcept;


private:
    bool TryReserve_(
        StreamType stream,
        size_t bytes,
        uint64_t streamBufferedBytes,
        uint64_t totalBufferedBytes
    ) noexcept;
    void SignalLimitHit_(StreamType stream) noexcept;
    void RecordEventFailure_(EventOperation operation, DWORD gle) noexcept;


private:
    uint64_t stdoutMax_ = 0;
    uint64_t stderrMax_ = 0;
    uint64_t totalMax_  = 0;


    CoreHelpers::UniqueHandle limitEvent_;

    std::atomic_bool limitSignaled_{false};
    std::atomic<int> firstHitStream_{static_cast<int>(StreamType::None)};
    std::atomic_bool eventFailureDetected_{false};
    std::atomic<int> firstEventFailureOperation_{static_cast<int>(EventOperation::None)};
    std::atomic<DWORD> firstEventFailureGle_{0};

};
