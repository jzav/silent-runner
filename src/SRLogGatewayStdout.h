// SRLogGatewayStdout.h
// -------------------
// Responsibility:
// - Accept child stdout bytes and determine their replay-storage needs.
// - Request replay-buffer reservations through SRBufferLimiter.
// - Route events into ExecutionTimeline.
//
// Non-responsibility:
// - Reading child pipes (SRChildStreamReader).
// - Event ordering and worker dispatch (ExecutionTimeline / JobsExchange).
// - Parent emission and persistent file output (output workers).
// - Buffer-limit policy and accounting (SRBufferLimiter).

#pragma once

#include <cstddef>   // size_t

class SRBufferLimiter;
class SRParentEmitPolicy;
class ExecutionTimeline;

class SRLogGatewayStdout {
public:
    SRLogGatewayStdout() = default;
    SRLogGatewayStdout(const SRLogGatewayStdout&) = delete;
    SRLogGatewayStdout& operator=(const SRLogGatewayStdout&) = delete;

    void Init(
        const SRParentEmitPolicy& parentEmitPolicy,
        SRBufferLimiter* bufferLimitOrNull,
        ExecutionTimeline* executionTimelineOrNull
    ) noexcept;



    void RouteChildBytes(
        const char* p,
        size_t n
    );
    

private:
    const SRParentEmitPolicy* parentEmitPolicy_ = nullptr;
    SRBufferLimiter* bufferLimit_ = nullptr;
    ExecutionTimeline* executionTimeline_ = nullptr;


};
