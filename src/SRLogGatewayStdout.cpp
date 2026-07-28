// SRLogGatewayStdout.cpp

#include "SRLogGatewayStdout.h"

#include "SRBufferLimiter.h"
#include "SRParentEmitPolicy.h"

void SRLogGatewayStdout::Init(
    SR::EmitMode emitMode,
    const SRParentEmitPolicy* parentEmitPolicyOrNull,
    SRBufferLimiter* bufferLimitOrNull,
    ExecutionTimeline* executionTimelineOrNull
) noexcept {

    emitMode_ = emitMode;
    parentEmitPolicy_ = parentEmitPolicyOrNull;
    bufferLimit_ = bufferLimitOrNull;
    executionTimeline_ = executionTimelineOrNull;

}

void SRLogGatewayStdout::RouteChildBytes(const char* p, size_t n) {
    if (!p || n == 0) return;



    // Route canonical ExecutionTimeline event with gateway-level replay storage decision.
    if (executionTimeline_) {
        SR::ReplayPayloadStorage replayPayloadStorage =
            SR::ReplayPayloadStorage::NotNeeded;

        if (parentEmitPolicy_ && parentEmitPolicy_->NeedsStdoutReplayBuffer()) {
            const SR::BufferUsage usage =
                executionTimeline_->GetCachedBufferUsage();

            const bool reserved =
                !bufferLimit_ ||
                bufferLimit_->TryReserveStdout(n, usage);

            replayPayloadStorage =
                reserved
                    ? SR::ReplayPayloadStorage::Store
                    : SR::ReplayPayloadStorage::DroppedByBufferLimit;
        }

        executionTimeline_->RouteChildStdout(
            p,
            n,
            replayPayloadStorage
        );
    }
    
}
