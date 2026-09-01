#include "SRLifecycleDiagnostics.h"
#include <fstream>
#include <mutex>

#include "FileHelpers.h"
#include "ParentStdEmitter.h"
#include "TextHelpers.h"
#include "SRBufferLimiter.h"
#include "SRParentEmitPolicy.h"

namespace {

std::mutex& ProbeLogMutex_() noexcept {
    static std::mutex mutex;
    return mutex;
}

bool TouchProbeLogFile_(const std::wstring& path) {
    const auto pathBytes = FileHelpers::WideToUtf8(path);
    if (pathBytes.empty()) return false;

    const std::string narrowPath(pathBytes.begin(), pathBytes.end());
    std::ofstream out(
        narrowPath,
        std::ios::out | std::ios::app | std::ios::binary
    );

    return static_cast<bool>(out);
}

bool AppendProbeLogBytes_(
    const std::wstring& path,
    const std::vector<char>& bytes
) {
    if (bytes.empty()) return true;

    const auto pathBytes = FileHelpers::WideToUtf8(path);
    if (pathBytes.empty()) return false;

    const std::string narrowPath(pathBytes.begin(), pathBytes.end());
    std::ofstream out(
        narrowPath,
        std::ios::out | std::ios::app | std::ios::binary
    );
    if (!out) return false;

    out.write(
        bytes.data(),
        static_cast<std::streamsize>(bytes.size())
    );
    out.put('\n');

    return static_cast<bool>(out);
}


} // namespace





// Builds the final prefixed diagnostic line without a trailing newline.
// Format: [timestampUtc] [SILENTRUNNER-...] [TYPE=FATAL] [PHASE=...] message
// TYPE=FATAL is part of the central DiagnosticSeverity::Fatal prefix.
static std::wstring FormatPrefixedLine_(
    const std::wstring& timestampUtc,
    SR::DiagnosticSeverity severity,
    SR::LifecyclePhase phase,
    const std::wstring& msg
) {
    std::wstring line;

    line += L"[";
    line += timestampUtc;
    line += L"] ";

    line += SR::DiagnosticSeverityToPrefix(severity);

    line += L"[PHASE=";
    line += TextHelpers::ToUpperAsciiCopy(std::wstring(SR::LifecyclePhaseToString(phase)));
    line += L"] ";

    line += msg;
    return line;
}

 // Initializes the lifecycle diagnostics collector for a new run.
 // This sets the parent-emit mode and execution timeline.


bool SRLifecycleDiagnostics::Init(
    SR::EmitMode emitMode,
    ExecutionTimeline* executionTimelineOrNull
) noexcept {


    emitMode_ = emitMode;
    executionTimeline_ = executionTimelineOrNull;


    return true;
}

// Updates whether DebugLine() should emit/store debug entries.
void SRLifecycleDiagnostics::SetDebugEnabled(bool value) noexcept {
    debugEnabled_ = value;
}
  
// Updates whether VerboseLine() should emit/store verbose entries.
void SRLifecycleDiagnostics::SetVerboseEnabled(bool value) noexcept {
    verboseEnabled_ = value;
}

// Updates the current lifecycle parent-emit mode.
// This does not modify runtime suppression latches.
void SRLifecycleDiagnostics::SetEmitMode(SR::EmitMode value) noexcept {
    emitMode_ = value;
}
void SRLifecycleDiagnostics::SetStderrEmitSource(SR::StderrEmitSource value) noexcept {
    stderrEmitSource_ = value;
}
void SRLifecycleDiagnostics::SetBufferLimiter(
    SRBufferLimiter* bufferLimitOrNull
) noexcept {
    bufferLimit_ = bufferLimitOrNull;
}
void SRLifecycleDiagnostics::SetParentEmitPolicy(
    const SRParentEmitPolicy* parentEmitPolicyOrNull
) noexcept {
    parentEmitPolicy_ = parentEmitPolicyOrNull;
}



bool SRLifecycleDiagnostics::TrySetProbeLogPath(
    const std::wstring& value
) noexcept {
    probeLogPath_.clear();

    if (value.empty()) {
        return true;
    }

    try {
        std::lock_guard<std::mutex> lock(ProbeLogMutex_());

        if (!TouchProbeLogFile_(value)) {
            return false;
        }

        probeLogPath_ = value;
        return true;
    } catch (...) {
        probeLogPath_.clear();
        return false;
    }
}









// Reports/stores an INFO lifecycle entry.
void SRLifecycleDiagnostics::InfoLine(const std::wstring& msg) {
    EmitLineWithSeverity_(SR::DiagnosticSeverity::Info, msg);
}


// Reports/stores a DEBUG lifecycle entry.
// If debug is disabled, the entry is ignored.
void SRLifecycleDiagnostics::DebugLine(const std::wstring& msg) {
    if (!debugEnabled_) return;
    EmitLineWithSeverity_(SR::DiagnosticSeverity::Debug, msg);
}


// Reports/stores a VERBOSE lifecycle entry.
// If verbose is disabled, the entry is ignored.
void SRLifecycleDiagnostics::VerboseLine(const std::wstring& msg) {
    if (!verboseEnabled_) return;
    EmitLineWithSeverity_(SR::DiagnosticSeverity::Verbose, msg);
}


// Reports/stores an ERROR lifecycle entry.
void SRLifecycleDiagnostics::ErrorLine(const std::wstring& msg) {
    EmitLineWithSeverity_(SR::DiagnosticSeverity::Error, msg);
}


// Reports/stores a FATAL lifecycle entry.
void SRLifecycleDiagnostics::FatalErrorLine(const std::wstring& msg) {
    EmitLineWithSeverity_(SR::DiagnosticSeverity::Fatal, msg);
}


void SRLifecycleDiagnostics::ProbeLine(const std::wstring& msg) {
    if (msg.empty() || probeLogPath_.empty()) return;

    try {
        const std::wstring line =
            L"[" +
            FileHelpers::MakeRunUtcTimestamp() +
            L"] " +
            msg;
        const auto bytes = FileHelpers::WideToUtf8(line);
        if (bytes.empty()) return;

        std::lock_guard<std::mutex> lock(ProbeLogMutex_());

        AppendProbeLogBytes_(probeLogPath_, bytes);
    } catch (...) {
    }
}


// Shared formatter + best-effort parent STDERR emit helper.
// Intended for internal lifecycle use and std::terminate best-effort reporting.
void SRLifecycleDiagnostics::BestEffortEmitFormattedToParentStderr(
    const std::wstring& timestampUtc,
    SR::DiagnosticSeverity severity,
    SR::LifecyclePhase phase,
    const std::wstring& msg
) noexcept {
    const std::wstring lineWithNewline =
        FormatPrefixedLine_(
            timestampUtc,
            severity,
            phase,
            msg
        ) + L"\n";

    ParentStdEmitter::EmitStderrUtf16(lineWithNewline);
}

// Shared formatter + last-resort parent STDERR emit helper.
// Intended for internal lifecycle use and std::terminate fallback reporting.
void SRLifecycleDiagnostics::LastResortEmitFormattedToParentStderr(
    const std::wstring& timestampUtc,
    SR::DiagnosticSeverity severity,
    SR::LifecyclePhase phase,
    const std::wstring& msg
) noexcept {
    const std::wstring lineWithNewline =
        FormatPrefixedLine_(
            timestampUtc,
            severity,
            phase,
            msg
        ) + L"\n";

    const std::vector<char> utf8 = FileHelpers::WideToUtf8(lineWithNewline);
    if (utf8.empty()) return;
    ParentStdEmitter::EmitStderrLastResort(utf8.data(), utf8.size());
}









// Core lifecycle reporting primitive.
// Structured event ordering/stamping/storage is owned by ExecutionTimeline::RouteSrDiag.
void SRLifecycleDiagnostics::EmitLineWithSeverity_(
    SR::DiagnosticSeverity severity,
    const std::wstring& msg
) {
    if (msg.empty()) return;

    if (executionTimeline_) {
        const uint64_t payloadByteCount =
            static_cast<uint64_t>(
                TextHelpers::Utf16ToUtf8ByteCount(msg)
            );

        SR::ReplayPayloadStorage replayPayloadStorage =
            SR::ReplayPayloadStorage::NotNeeded;

        const bool routeToActiveView =
            stderrEmitSource_ == SR::StderrEmitSource::SrAndChild ||
            stderrEmitSource_ == SR::StderrEmitSource::Sr ||
            stderrEmitSource_ == SR::StderrEmitSource::SrAndChildInclStdout;

        if (routeToActiveView &&
            parentEmitPolicy_ &&
            parentEmitPolicy_->NeedsStderrReplayBuffer()) {

            const SR::BufferUsage usage =
                executionTimeline_->GetCachedBufferUsage();

            const bool reserved =
                !bufferLimit_ ||
                bufferLimit_->TryReserveStderr(
                    static_cast<size_t>(payloadByteCount),
                    usage
                );

            replayPayloadStorage =
                reserved
                    ? SR::ReplayPayloadStorage::Store
                    : SR::ReplayPayloadStorage::DroppedByBufferLimit;
        }

        const bool eventSummaryEnabled =
            !bufferLimit_ ||
            (!bufferLimit_->StderrLimitReached() &&
             !bufferLimit_->TotalLimitReached());


        ProbeLine(
            std::wstring(L"[BUFFER][DECISION] origin=LIFECYCLE_SR") +
            L" payloadByteCount=" +
            std::to_wstring(payloadByteCount) +
            L" routeToActiveView=" +
            (routeToActiveView ? L"TRUE" : L"FALSE") +
            L" needsStderrReplayBuffer=" +
            ((parentEmitPolicy_ &&
              parentEmitPolicy_->NeedsStderrReplayBuffer())
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


        executionTimeline_->RouteSrDiag(
            severity,
            msg,
            replayPayloadStorage,
            payloadByteCount,
            eventSummaryEnabled
        );
    }
}
