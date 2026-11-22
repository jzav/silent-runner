#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>

#include "SRTypes.h"


class SRLifecycleDiagnostics;
class SRRuntimeCoordinator;

// Tracks in-memory replay-buffer reservations and reports limit violations
// to SRRuntimeCoordinator. It neither decides stop actions nor terminates
// child processes.
class SRBufferLimiter {
public:
    enum class StreamType {
        None   = 0,
        Stdout = 1,
        Stderr = 2
    };


    explicit SRBufferLimiter(SRRuntimeCoordinator& coordinator) noexcept
        : coordinator_(coordinator) {}
    SRBufferLimiter(const SRBufferLimiter&) = delete;
    SRBufferLimiter& operator=(const SRBufferLimiter&) = delete;

    void Init(
        const SR::SRBufferLimiterConfig& config,
        SRLifecycleDiagnostics* diagnosticsOrNull
    ) noexcept;



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
    bool StdoutLimitReached() const noexcept;
    bool StderrLimitReached() const noexcept;
    bool TotalLimitReached() const noexcept;


    uint64_t StdoutMaxBytes() const noexcept { return stdoutMax_; }
    uint64_t StderrMaxBytes() const noexcept { return stderrMax_; }
    uint64_t TotalMaxBytes() const noexcept { return totalMax_; }
    
    uint64_t stdoutMax_ = 0;
    uint64_t stderrMax_ = 0;
    uint64_t totalMax_  = 0;


private:
    bool TryReserve_(
        StreamType stream,
        size_t bytes,
        uint64_t streamBufferedBytes,
        uint64_t totalBufferedBytes
    ) noexcept;
    void SignalLimitHit_(StreamType stream) noexcept;


private:
    SRLifecycleDiagnostics* diagnostics_ = nullptr;
    SRRuntimeCoordinator& coordinator_;

    std::atomic_bool limitSignaled_{false};
    std::atomic<int> firstHitStream_{static_cast<int>(StreamType::None)};

    std::atomic_bool stdoutLimitReached_{false};
    std::atomic_bool stderrLimitReached_{false};
    std::atomic_bool totalLimitReached_{false};


};
