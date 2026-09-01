// SRLogGatewayStderr.cpp

#include "SRLogGatewayStderr.h"

#include "FileHelpers.h"
#include "TextHelpers.h"
#include "SRBufferLimiter.h"
#include "SRParentEmitPolicy.h"
#include "SRTypes.h"
#include <utility>


namespace {

std::wstring FormatDiagnosticLine_(
    const std::wstring& timestampUtc,
    SR::DiagnosticSeverity severity,
    const std::wstring& msg
) {
    std::wstring line;
    line += L"[";
    line += timestampUtc;
    line += L"] ";
    line += SR::DiagnosticSeverityToPrefix(severity);
    line += msg;
    return line;
}

} // namespace

void SRLogGatewayStderr::Init(
    SR::EmitMode emitMode,
    SR::StderrEmitSource emitSource,
    const SRParentEmitPolicy* parentEmitPolicyOrNull,
    SRBufferLimiter* bufferLimitOrNull,
    ExecutionTimeline* executionTimelineOrNull
) noexcept {


    emitMode_ = emitMode;
    emitSource_ = emitSource;
    parentEmitPolicy_ = parentEmitPolicyOrNull;
    executionTimeline_ = executionTimelineOrNull;


    bufferLimit_ = bufferLimitOrNull;
}



void SRLogGatewayStderr::EnsureMutex_() {
    if (!mutex_) mutex_ = std::make_unique<std::mutex>();
}

void SRLogGatewayStderr::RouteChildBytes(const char* p, size_t n) {
    if (!p || n == 0) return;

    EnsureMutex_();
    std::lock_guard<std::mutex> lk(*mutex_);
    RouteBytesLocked_(SR::StderrEmitSource::Child, p, n);
}

void SRLogGatewayStderr::RouteDiagnosticLineUtf16(
    SR::DiagnosticSeverity severity,
    const std::wstring& msg
) {
    if (msg.empty()) return;

    const std::wstring timestampUtc = FileHelpers::MakeRunUtcTimestamp();
    std::vector<char> utf8 =
        FileHelpers::WideToUtf8(FormatDiagnosticLine_(timestampUtc, severity, msg) + L"\n");
    if (utf8.empty()) return;

    EnsureMutex_();
    std::lock_guard<std::mutex> lk(*mutex_);
    RouteBytesLocked_(
        SR::StderrEmitSource::Sr,
        utf8.data(),
        utf8.size(),
        &severity,
        &msg
    );
}


bool SRLogGatewayStderr::ShouldRouteToActiveStderrView_(
    SR::StderrEmitSource source
) const noexcept {
    if (emitSource_ == SR::StderrEmitSource::SrAndChild ||
        emitSource_ == SR::StderrEmitSource::SrAndChildInclStdout) return true;

    return emitSource_ == source;
}


void SRLogGatewayStderr::RouteBytesLocked_(
    SR::StderrEmitSource source,
    const char* p,
    size_t n,
    const SR::DiagnosticSeverity* runtimeDiagSeverityOrNull,
    const std::wstring* runtimeDiagMessageOrNull
) {
    if (!p || n == 0) return;


    const bool routeToActiveView = ShouldRouteToActiveStderrView_(source);



    // Route canonical ExecutionTimeline event with gateway-level replay storage decision.
    if (executionTimeline_) {
        SR::ReplayPayloadStorage replayPayloadStorage =
            SR::ReplayPayloadStorage::NotNeeded;
        const size_t srDiagPayloadByteCount =
            source == SR::StderrEmitSource::Sr &&
            runtimeDiagMessageOrNull
                ? TextHelpers::Utf16ToUtf8ByteCount(
                    *runtimeDiagMessageOrNull
                )
                : 0;
        if (routeToActiveView &&
            parentEmitPolicy_ &&
            parentEmitPolicy_->NeedsStderrReplayBuffer()) {
            const SR::BufferUsage usage =
                executionTimeline_->GetCachedBufferUsage();

            if (source == SR::StderrEmitSource::Child) {
                const bool reserved =
                    !bufferLimit_ ||
                    bufferLimit_->TryReserveStderr(n, usage);

                replayPayloadStorage =
                    reserved
                        ? SR::ReplayPayloadStorage::Store
                        : SR::ReplayPayloadStorage::DroppedByBufferLimit;
            } else if (source == SR::StderrEmitSource::Sr &&
                       runtimeDiagMessageOrNull) {
                const bool reserved =
                    !bufferLimit_ ||
                    bufferLimit_->TryReserveStderr(
                        srDiagPayloadByteCount,
                        usage
                    );

                replayPayloadStorage =
                    reserved
                        ? SR::ReplayPayloadStorage::Store
                        : SR::ReplayPayloadStorage::DroppedByBufferLimit;
            }
        }

        const bool eventSummaryEnabled =
            !bufferLimit_ ||
            (!bufferLimit_->StderrLimitReached() &&
             !bufferLimit_->TotalLimitReached());


        executionTimeline_->ProbeLine(
            std::wstring(L"[BUFFER][DECISION] origin=STDERR_GATEWAY") +
            L" source=" +
            SR::StderrEmitSourceToString(source) +
            L" bytes=" +
            std::to_wstring(static_cast<uint64_t>(n)) +
            L" replayPayloadByteCount=" +
            std::to_wstring(
                source == SR::StderrEmitSource::Sr
                    ? static_cast<uint64_t>(srDiagPayloadByteCount)
                    : static_cast<uint64_t>(n)
            ) +
            L" routeToActiveView=" +
            (routeToActiveView ? L"TRUE" : L"FALSE") +
            L" needsStderrReplayBuffer=" +
            ((parentEmitPolicy_ &&
              parentEmitPolicy_->NeedsStderrReplayBuffer())
                ? L"TRUE"
                : L"FALSE") +
            L" runtimeDiagMessage=" +
            (runtimeDiagMessageOrNull ? L"SET" : L"NULL") +
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


        if (source == SR::StderrEmitSource::Child) {
            executionTimeline_->RouteChildStderr(
                p,
                n,
                replayPayloadStorage,
                eventSummaryEnabled
            );
        } else if (source == SR::StderrEmitSource::Sr &&
                   runtimeDiagSeverityOrNull &&
                   runtimeDiagMessageOrNull) {
            executionTimeline_->RouteSrDiag(
                *runtimeDiagSeverityOrNull,
                *runtimeDiagMessageOrNull,
                replayPayloadStorage,
                static_cast<uint64_t>(srDiagPayloadByteCount),
                eventSummaryEnabled
            );

        }
    }
}
