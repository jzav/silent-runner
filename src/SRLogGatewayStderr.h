// SRLogGatewayStderr.h
// Routes child stderr bytes into ExecutionTimeline.
// SilentRunner diagnostics use SRLifecycleDiagnostics directly.

#pragma once

#include <cstddef>
#include <memory>
#include <mutex>

class SRBufferLimiter;
class SRParentEmitPolicy;
class ExecutionTimeline;

class SRLogGatewayStderr {
public:
    SRLogGatewayStderr() = default;
    SRLogGatewayStderr(const SRLogGatewayStderr&) = delete;
    SRLogGatewayStderr& operator=(const SRLogGatewayStderr&) = delete;

    // Borrowed dependencies must outlive the gateway.
    void Init(
        const SRParentEmitPolicy& parentEmitPolicy,
        SRBufferLimiter* bufferLimitOrNull,
        ExecutionTimeline* executionTimelineOrNull
    ) noexcept;

    void RouteChildBytes(const char* p, size_t n);

private:
    void EnsureMutex_();
    void RouteChildBytesLocked_(const char* p, size_t n);

    std::unique_ptr<std::mutex> mutex_;
    const SRParentEmitPolicy* parentEmitPolicy_ = nullptr;
    SRBufferLimiter* bufferLimit_ = nullptr;
    ExecutionTimeline* executionTimeline_ = nullptr;
};
