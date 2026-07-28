// SRLogGatewayStdout.h
// -------------------
 // Responsibility:
 // - Serialize and route child STDOUT bytes:
 //   - optional ExecutionTimeline RAM replay storage (for end/success/failure modes without dirs)
 //   - optional buffer-limit reservation via SRBufferLimiter
 //   - emit to parent stdout in Stream mode only

//
// Non-responsibility:
// - child pipe reading (belongs to ChildStdReader)
// - buffering policy / total-per-stream enforcement details
//   (belongs to SRBufferLimiter)

#pragma once

#include <cstddef>   // size_t

#include "SRTypes.h"
#include "SRExecutionTimeline.h"

class SRBufferLimiter;
class SRParentEmitPolicy;

class SRLogGatewayStdout {
public:
    SRLogGatewayStdout() = default;
    SRLogGatewayStdout(const SRLogGatewayStdout&) = delete;
    SRLogGatewayStdout& operator=(const SRLogGatewayStdout&) = delete;

    void Init(
        SR::EmitMode emitMode,
        const SRParentEmitPolicy* parentEmitPolicyOrNull,
        SRBufferLimiter* bufferLimitOrNull,
        ExecutionTimeline* executionTimelineOrNull
    ) noexcept;



    void RouteChildBytes(
        const char* p,
        size_t n
    );
    

private:
    SR::EmitMode emitMode_ = SR::EmitMode::Stream;
    const SRParentEmitPolicy* parentEmitPolicy_ = nullptr;
    SRBufferLimiter* bufferLimit_ = nullptr;
    ExecutionTimeline* executionTimeline_ = nullptr;


};
