// SRLogGatewayStderr.cpp

#include "SRLogGatewayStderr.h"

#include "SRBufferLimiter.h"
#include "SRParentEmitPolicy.h"
#include "SRExecutionTimeline.h"
#include "SRTypes.h"

#include <cstdint>
#include <string>

void SRLogGatewayStderr::Init(
    const SRParentEmitPolicy& parentEmitPolicy,
    SRBufferLimiter* bufferLimitOrNull,
    ExecutionTimeline* executionTimelineOrNull
) noexcept {
    parentEmitPolicy_ = &parentEmitPolicy;
    bufferLimit_ = bufferLimitOrNull;
    executionTimeline_ = executionTimelineOrNull;
}

void SRLogGatewayStderr::EnsureMutex_() {
    if (!mutex_) mutex_ = std::make_unique<std::mutex>();
}

void SRLogGatewayStderr::RouteChildBytes(const char* p, size_t n) {
    if (!p || n == 0) return;

    EnsureMutex_();
    std::lock_guard<std::mutex> lk(*mutex_);
    RouteChildBytesLocked_(p, n);
}

void SRLogGatewayStderr::RouteChildBytesLocked_(const char* p, size_t n) {
    if (!executionTimeline_) return;

    const SR::JobTarget target =
        parentEmitPolicy_
            ? parentEmitPolicy_->StderrParentTarget()
            : SR::JobTarget::StderrSrAndChildParent;
    const SR::JobTargetChannel channel = SR::JobTargetChannelOf(target);
    const bool routeToActiveView =
        channel == SR::JobTargetChannel::SrAndChild ||
        channel == SR::JobTargetChannel::SrAndChildInclStdout ||
        channel == SR::JobTargetChannel::Child;

    SR::ReplayPayloadStorage replayPayloadStorage =
        SR::ReplayPayloadStorage::NotNeeded;
    if (routeToActiveView &&
        parentEmitPolicy_ &&
        parentEmitPolicy_->NeedsStderrReplayBuffer()) {
        const SR::BufferUsage usage = executionTimeline_->GetCachedBufferUsage();
        const bool reserved =
            !bufferLimit_ || bufferLimit_->TryReserveStderr(n, usage);
        replayPayloadStorage = reserved
            ? SR::ReplayPayloadStorage::Store
            : SR::ReplayPayloadStorage::DroppedByBufferLimit;
    }

    const bool eventSummaryEnabled =
        !bufferLimit_ ||
        (!bufferLimit_->StderrLimitReached() &&
         !bufferLimit_->TotalLimitReached());

    executionTimeline_->ProbeLine(
        std::wstring(L"[BUFFER][DECISION] origin=STDERR_GATEWAY") +
        L" source=stderr-child" +
        L" bytes=" + std::to_wstring(static_cast<uint64_t>(n)) +
        L" replayPayloadByteCount=" + std::to_wstring(static_cast<uint64_t>(n)) +
        L" routeToActiveView=" + (routeToActiveView ? L"TRUE" : L"FALSE") +
        L" needsStderrReplayBuffer=" +
        ((parentEmitPolicy_ && parentEmitPolicy_->NeedsStderrReplayBuffer())
            ? L"TRUE" : L"FALSE") +
        L" runtimeDiagMessage=NULL" +
        L" bufferLimiter=" + (bufferLimit_ ? L"SET" : L"NULL") +
        L" storage=" +
        (replayPayloadStorage == SR::ReplayPayloadStorage::Store
            ? L"STORE"
            : replayPayloadStorage == SR::ReplayPayloadStorage::DroppedByBufferLimit
                ? L"DROPPED_BY_BUFFER_LIMIT"
                : L"NOT_NEEDED")
    );

    executionTimeline_->RouteChildStderr(
        p,
        n,
        replayPayloadStorage,
        eventSummaryEnabled
    );
}
