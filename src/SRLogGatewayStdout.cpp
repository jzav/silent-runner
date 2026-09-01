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

        const SR::BufferUsage usage =
            executionTimeline_->GetCachedBufferUsage();


        if (parentEmitPolicy_ &&
            (parentEmitPolicy_->NeedsStdoutReplayBuffer() ||
             parentEmitPolicy_->NeedsStderrInclStdoutReplayBuffer())) {

            const bool reserved =
                !bufferLimit_ ||
                bufferLimit_->TryReserveStdout(n, usage);

            replayPayloadStorage =
                reserved
                    ? SR::ReplayPayloadStorage::Store
                    : SR::ReplayPayloadStorage::DroppedByBufferLimit;
        }

        const bool eventSummaryEnabled =
            !bufferLimit_ ||
            (!bufferLimit_->StderrLimitReached() &&
             !bufferLimit_->TotalLimitReached() &&
             !(bufferLimit_->stderrMax_ != 0 &&
               usage.stderrBufferedBytes > bufferLimit_->stderrMax_));


        executionTimeline_->ProbeLine(
            std::wstring(L"[BUFFER][DECISION] origin=CHILD_STDOUT") +
            L" bytes=" +
            std::to_wstring(static_cast<uint64_t>(n)) +
            L" parentEmitPolicy=" +
            (parentEmitPolicy_ ? L"SET" : L"NULL") +
            L" needsStdoutReplayBuffer=" +
            ((parentEmitPolicy_ &&
              parentEmitPolicy_->NeedsStdoutReplayBuffer())
                ? L"TRUE"
                : L"FALSE") +
            L" needsStderrInclStdoutReplayBuffer=" +
            ((parentEmitPolicy_ &&
              parentEmitPolicy_->NeedsStderrInclStdoutReplayBuffer())
                ? L"TRUE"
                : L"FALSE") +
            L" bufferLimiter=" +
            (bufferLimit_ ? L"SET" : L"NULL") +
            L" storage=" +
            (replayPayloadStorage == SR::ReplayPayloadStorage::Store
                ? L"STORE"
                : replayPayloadStorage ==
                    SR::ReplayPayloadStorage::DroppedByBufferLimit
                    ? L"DROPPED_BY_BUFFER_LIMIT"
                    : L"NOT_NEEDED")
        );


        executionTimeline_->RouteChildStdout(
            p,
            n,
            replayPayloadStorage,
            eventSummaryEnabled
        );

    }
    
}
