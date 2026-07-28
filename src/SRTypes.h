#pragma once

// SRTypes.h - SilentRunner shared domain types
// -------------------------------------------
// Goals:
// - Single source of truth for enum <-> text helpers and parsing
// - Provides enum-to-text conversion, parsing, and help text generation.
// Notes:
// - Uses std::wstring_view (C++17+).

#include <cstddef>
#include <atomic>



#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace SR {

// =====================================================================================
// Common helpers
// =====================================================================================

// Helper macro: build a std::wstring_view from a wide literal without "sv" literals.
#define SR_WSV(lit) std::wstring_view(lit)

// =====================================================================================
// EmitMode (single source of truth)
// =====================================================================================

enum EmitStreamMask : uint8_t {
    STDOUT  = 1,
    STDERR  = 2,
    BOTH = (STDOUT | STDERR)
};

enum class ParentTargetAction {
    Emit,
    Delay,
    Ignore
};

// Table columns:
//   (EnumName, WideLiteralPtr, WideView, StreamMask, HelpTextWideLiteralPtr,
//    ActionWithoutPersistentReplaySource, ActionWithPersistentReplaySource)
#define SR_EMITMODE_TABLE(X) \
    X(Never,   L"never",   SR_WSV(L"never"),   BOTH,    L"never emit to parent",          Ignore, Ignore) \
    X(Stream,  L"stream",  SR_WSV(L"stream"),  BOTH,    L"emit while running (default)",  Emit,   Emit) \
    X(End,     L"end",     SR_WSV(L"end"),     BOTH,    L"emit at end of process",      Delay,  Ignore) \
    X(Success, L"success", SR_WSV(L"success"), BOTH,    L"emit only on success",        Delay,  Ignore) \
    X(Failure, L"failure", SR_WSV(L"failure"), BOTH,    L"emit on failure or timeout",  Delay,  Ignore)

enum class EmitMode {
#define SR_X_ENUM(name, wptr, wview, mask, help, withoutPersistentSource, withPersistentSource) name,
    SR_EMITMODE_TABLE(SR_X_ENUM)
#undef SR_X_ENUM
};

inline constexpr const wchar_t* EmitModeToString(EmitMode m) noexcept {
    switch (m) {
#define SR_X_CASE(name, wptr, wview, mask, help, withoutPersistentSource, withPersistentSource) case EmitMode::name: return wptr;
        SR_EMITMODE_TABLE(SR_X_CASE)
#undef SR_X_CASE
    default:
        return L"<invalid>";
    }
}

inline constexpr std::wstring_view EmitModeToView(EmitMode m) noexcept {
    switch (m) {
#define SR_X_CASE(name, wptr, wview, mask, help, withoutPersistentSource, withPersistentSource) case EmitMode::name: return wview;
        SR_EMITMODE_TABLE(SR_X_CASE)
#undef SR_X_CASE
    default:
        return {};
    }
}

inline constexpr uint8_t EmitModeStreamMask(EmitMode m) noexcept {
    switch (m) {
#define SR_X_CASE(name, wptr, wview, mask, help, withoutPersistentSource, withPersistentSource) case EmitMode::name: return (uint8_t)(mask);
        SR_EMITMODE_TABLE(SR_X_CASE)
#undef SR_X_CASE
    default:
        return 0;
    }
}

inline constexpr ParentTargetAction RetrieveParentTargetAction(
    EmitMode mode,
    bool hasPersistentReplaySource
) noexcept {
    switch (mode) {
#define SR_X_PARENT_TARGET_ACTION(name, wptr, wview, mask, help, withoutPersistentSource, withPersistentSource) \
        case EmitMode::name: \
            return hasPersistentReplaySource \
                ? ParentTargetAction::withPersistentSource \
                : ParentTargetAction::withoutPersistentSource;
        SR_EMITMODE_TABLE(SR_X_PARENT_TARGET_ACTION)
#undef SR_X_PARENT_TARGET_ACTION
    }

    return ParentTargetAction::Ignore;
}

// Strict parse: expects the input to already be normalized (e.g., lowercased) if desired.
inline constexpr bool TryParseEmitMode(std::wstring_view s, EmitMode& out) noexcept {
#define SR_X_IF(name, wptr, wview, mask, help, withoutPersistentSource, withPersistentSource) if (s == wview) { out = EmitMode::name; return true; }
    SR_EMITMODE_TABLE(SR_X_IF)
#undef SR_X_IF
    return false;
}

// Help generator: formats one item per line: "  <token>  - <help>"
inline void AppendEmitModeHelp(std::wstring& out) {
#define SR_X_HELP(name, wptr, wview, mask, help, withoutPersistentSource, withPersistentSource) \
    out += L"  "; out += wptr; out += L"  - "; out += help; out += L"\n";
    SR_EMITMODE_TABLE(SR_X_HELP)
#undef SR_X_HELP
}

// (Optional convenience) Help generator filtered by stream.
inline void AppendEmitModeHelpForStdout(std::wstring& out) {
#define SR_X_HELP(name, wptr, wview, mask, help, withoutPersistentSource, withPersistentSource) \
    do { if (((uint8_t)(mask) & (uint8_t)STDOUT) != 0) { \
        out += L"  "; out += wptr; out += L"  - "; out += help; out += L"\n"; \
    } } while (0);
    SR_EMITMODE_TABLE(SR_X_HELP)
#undef SR_X_HELP
}

inline void AppendEmitModeHelpForStderr(std::wstring& out) {
#define SR_X_HELP(name, wptr, wview, mask, help, withoutPersistentSource, withPersistentSource) \
    do { if (((uint8_t)(mask) & (uint8_t)STDERR) != 0) { \
        out += L"  "; out += wptr; out += L"  - "; out += help; out += L"\n"; \
    } } while (0);
    SR_EMITMODE_TABLE(SR_X_HELP)
#undef SR_X_HELP
}

inline void AppendEmitModeHelpForBoth(std::wstring& out) {
#define SR_X_HELP(name, wptr, wview, mask, help, withoutPersistentSource, withPersistentSource) \
    do { if ((uint8_t)(mask) == (uint8_t)BOTH) { \
        out += L"  "; out += wptr; out += L"  - "; out += help; out += L"\n"; \
    } } while (0);
    SR_EMITMODE_TABLE(SR_X_HELP)
#undef SR_X_HELP
}

// =====================================================================================
// StderrEmitSource
// =====================================================================================
//
// Selects which logical stderr view is emitted to the parent and replayed.
// File logs can fan out to multiple stderr views, but parent stderr emit is
// intentionally exclusive.

#define SR_STDERR_EMIT_SOURCE_TABLE(X) \
    X(Mixed,        L"mixed", L"mixed child + SilentRunner stderr", StderrMixedParent) \
    X(Child,        L"child", L"child stderr only",                 StderrChildParent) \
    X(SilentRunner, L"sr",    L"SilentRunner stderr only",          StderrSrParent)

enum class StderrEmitSource {
#define SR_X_ENUM_STDERR_SOURCE(name, wptr, help, target) name,
    SR_STDERR_EMIT_SOURCE_TABLE(SR_X_ENUM_STDERR_SOURCE)
#undef SR_X_ENUM_STDERR_SOURCE
};

inline constexpr const wchar_t* StderrEmitSourceToString(
    StderrEmitSource source
) noexcept {
    switch (source) {
#define SR_X_CASE_STDERR_SOURCE(name, wptr, help, target) case StderrEmitSource::name: return wptr;
        SR_STDERR_EMIT_SOURCE_TABLE(SR_X_CASE_STDERR_SOURCE)
#undef SR_X_CASE_STDERR_SOURCE
    default:
        return L"<invalid>";
    }
}

// =====================================================================================
// KeepLogMode (single source of truth)
// =====================================================================================

#define SR_KEEPLOGMODE_TABLE(X) \
    X(Always,  L"always",  SR_WSV(L"always"),  L"always keep the log file (default)") \
    X(Success, L"success", SR_WSV(L"success"), L"keep the log file only on success (exit code 0)") \
    X(Failure, L"failure", SR_WSV(L"failure"), L"keep the log file only on failure (non-zero exit, timeout, etc.)")

enum class KeepLogMode {
#define SR_X_ENUM(name, wptr, wview, help) name,
    SR_KEEPLOGMODE_TABLE(SR_X_ENUM)
#undef SR_X_ENUM
};

inline constexpr std::wstring_view KeepLogModeToView(KeepLogMode m) noexcept {
    switch (m) {
#define SR_X_CASE(name, wptr, wview, help) case KeepLogMode::name: return wview;
        SR_KEEPLOGMODE_TABLE(SR_X_CASE)
#undef SR_X_CASE
    default:
        return {};
    }
}

// Strict parse: expects the input to already be normalized (e.g., lowercased) if desired.
inline constexpr bool TryParseKeepLogMode(std::wstring_view s, KeepLogMode& out) noexcept {
#define SR_X_IF(name, wptr, wview, help) if (s == wview) { out = KeepLogMode::name; return true; }
    SR_KEEPLOGMODE_TABLE(SR_X_IF)
#undef SR_X_IF
    return false;
}

inline void AppendKeepLogModeHelp(std::wstring& out) {
#define SR_X_HELP(name, wptr, wview, help) \
    out += L"  "; out += wptr; out += L"  - "; out += help; out += L"\n";
    SR_KEEPLOGMODE_TABLE(SR_X_HELP)
#undef SR_X_HELP
}

// =====================================================================================
// IdSuffixMode
// =====================================================================================

#define SR_ID_SUFFIX_MODE_TABLE(X) \
    X(None,         0, L"none",          false) \
    X(Timestamp,    1, L"timestamp",      true) \
    X(Pid,          2, L"pid",            true) \
    X(TimestampPid, 3, L"timestamp+pid",  true) \
    X(PidTimestamp, 4, L"pid+timestamp",  true)

enum class IdSuffixMode {
#define SR_X_ENUM_ID_SUFFIX_MODE(name, value, text, cliAllowed) name = value,
    SR_ID_SUFFIX_MODE_TABLE(SR_X_ENUM_ID_SUFFIX_MODE)
#undef SR_X_ENUM_ID_SUFFIX_MODE
};

struct IdSuffixModeInfo {
    IdSuffixMode mode = IdSuffixMode::None;
    const wchar_t* text = L"";
    bool cliAllowed = false;
};

inline constexpr IdSuffixModeInfo kIdSuffixModeInfos[] = {
#define SR_X_INFO_ID_SUFFIX_MODE(name, value, text, cliAllowed) \
    { IdSuffixMode::name, text, cliAllowed },
    SR_ID_SUFFIX_MODE_TABLE(SR_X_INFO_ID_SUFFIX_MODE)
#undef SR_X_INFO_ID_SUFFIX_MODE
};

inline constexpr const IdSuffixModeInfo* IdSuffixModeInfos() noexcept {
    return kIdSuffixModeInfos;
}

inline constexpr std::size_t IdSuffixModeInfoCount() noexcept {
    return sizeof(kIdSuffixModeInfos) / sizeof(kIdSuffixModeInfos[0]);
}

inline constexpr const wchar_t* IdSuffixModeToString(IdSuffixMode m) noexcept {
    switch (m) {
#define SR_X_CASE_ID_SUFFIX_MODE(name, value, text, cliAllowed) case IdSuffixMode::name: return text;
        SR_ID_SUFFIX_MODE_TABLE(SR_X_CASE_ID_SUFFIX_MODE)
#undef SR_X_CASE_ID_SUFFIX_MODE
        default:
            return L"<invalid>";
    }
}







// =====================================================================================
// ExecutionMode
// =====================================================================================

#define SR_EXECUTION_MODE_TABLE(X) \
    X(ScriptOrExe, 0, L"script-or-exe") \
    X(RawCommand,  1, L"raw-command (-c)")

enum class ExecutionMode {
#define SR_X_ENUM_EXECUTION_MODE(name, value, text) name = value,
    SR_EXECUTION_MODE_TABLE(SR_X_ENUM_EXECUTION_MODE)
#undef SR_X_ENUM_EXECUTION_MODE
};

inline constexpr const wchar_t* ExecutionModeToString(ExecutionMode m) noexcept {
    switch (m) {
#define SR_X_CASE_EXECUTION_MODE(name, value, text) case ExecutionMode::name: return text;
        SR_EXECUTION_MODE_TABLE(SR_X_CASE_EXECUTION_MODE)
#undef SR_X_CASE_EXECUTION_MODE
        default:
            return L"<invalid>";
    }
}



// =====================================================================================
// DiagnosticSeverity (single source of truth)
// =====================================================================================
//
// Table columns:
//   (EnumName, TokenWideLiteralPtr, UppercaseTokenWideLiteralPtr, PrefixWideLiteralPtr)
#define SR_DIAGNOSTIC_SEVERITY_LIST(X) \
    X(Verbose, L"verbose", L"VERBOSE", L"[SILENTRUNNER-VERBOSE] ") \
    X(Debug,   L"debug",   L"DEBUG",   L"[SILENTRUNNER-DEBUG] ") \
    X(Info,    L"info",    L"INFO",    L"[SILENTRUNNER-INFO] ") \
    X(Error,   L"error",   L"ERROR",   L"[SILENTRUNNER-ERRORS] ") \
    X(Fatal,   L"fatal",   L"FATAL",   L"[SILENTRUNNER-ERRORS] [TYPE=FATAL] ")

enum class DiagnosticSeverity {
#define SR_X_ENUM_DIAGNOSTIC_SEVERITY(name, token, uppercaseToken, prefix) name,
    SR_DIAGNOSTIC_SEVERITY_LIST(SR_X_ENUM_DIAGNOSTIC_SEVERITY)
#undef SR_X_ENUM_DIAGNOSTIC_SEVERITY
};

inline constexpr const wchar_t* DiagnosticSeverityToToken(
    DiagnosticSeverity severity
) noexcept {
    switch (severity) {
#define SR_X_CASE_DIAGNOSTIC_SEVERITY(name, token, uppercaseToken, prefix) case DiagnosticSeverity::name: return token;
        SR_DIAGNOSTIC_SEVERITY_LIST(SR_X_CASE_DIAGNOSTIC_SEVERITY)
#undef SR_X_CASE_DIAGNOSTIC_SEVERITY
    default:
        return L"<invalid>";
    }
}

inline constexpr const wchar_t* DiagnosticSeverityToPrefix(
    DiagnosticSeverity severity
) noexcept {
    switch (severity) {
#define SR_X_CASE_DIAGNOSTIC_SEVERITY(name, token, uppercaseToken, prefix) case DiagnosticSeverity::name: return prefix;
        SR_DIAGNOSTIC_SEVERITY_LIST(SR_X_CASE_DIAGNOSTIC_SEVERITY)
#undef SR_X_CASE_DIAGNOSTIC_SEVERITY
    default:
        return L"[SILENTRUNNER-ERRORS] ";
    }
}
inline constexpr bool TryParseDiagnosticSeverity(
    std::wstring_view value,
    DiagnosticSeverity& severity
) noexcept {
#define SR_X_IF_DIAGNOSTIC_SEVERITY(name, token, uppercaseToken, prefix) \
    if (value == token) { severity = DiagnosticSeverity::name; return true; }
    SR_DIAGNOSTIC_SEVERITY_LIST(SR_X_IF_DIAGNOSTIC_SEVERITY)
#undef SR_X_IF_DIAGNOSTIC_SEVERITY

    return false;
}

inline constexpr bool TryParseDiagnosticSeverityUppercase(
    std::wstring_view value,
    DiagnosticSeverity& severity
) noexcept {
#define SR_X_IF_DIAGNOSTIC_SEVERITY_UPPERCASE(name, token, uppercaseToken, prefix) \
    if (value == uppercaseToken) { severity = DiagnosticSeverity::name; return true; }
    SR_DIAGNOSTIC_SEVERITY_LIST(SR_X_IF_DIAGNOSTIC_SEVERITY_UPPERCASE)
#undef SR_X_IF_DIAGNOSTIC_SEVERITY_UPPERCASE

    return false;
}


inline DiagnosticSeverity DiagnosticSeverityFromToken(
    const std::wstring& severity
) noexcept {
    DiagnosticSeverity parsedSeverity;

    if (TryParseDiagnosticSeverity(
            severity,
            parsedSeverity
        )) {
        return parsedSeverity;
    }

    return DiagnosticSeverity::Error;
}


// =====================================================================================
// LifecyclePhase (single source of truth)
// =====================================================================================
//

#define SR_LIFECYCLE_PHASE_TABLE(X) \
    X(Prepare, 1, L"prepare", SR_WSV(L"prepare"), L"PREPARE", L"P") \
    X(Runtime, 2, L"runtime", SR_WSV(L"runtime"), L"RUNTIME", L"R")

enum class LifecyclePhase : uint8_t {
#define SR_X_ENUM_LIFECYCLE_PHASE(name, value, text, textView, uppercaseText, shortText) \
    name = value,
    SR_LIFECYCLE_PHASE_TABLE(SR_X_ENUM_LIFECYCLE_PHASE)
#undef SR_X_ENUM_LIFECYCLE_PHASE
};

inline constexpr const wchar_t* LifecyclePhaseToString(
    LifecyclePhase phase
) noexcept {
    switch (phase) {
#define SR_X_CASE_LIFECYCLE_PHASE(name, value, text, textView, uppercaseText, shortText) \
        case LifecyclePhase::name: return text;
        SR_LIFECYCLE_PHASE_TABLE(SR_X_CASE_LIFECYCLE_PHASE)
#undef SR_X_CASE_LIFECYCLE_PHASE
        default:
            return L"<invalid>";
    }
}

inline constexpr const wchar_t* LifecyclePhaseShortNameToString(
    LifecyclePhase phase
) noexcept {
    switch (phase) {
#define SR_X_CASE_LIFECYCLE_PHASE(name, value, text, textView, uppercaseText, shortText) \
        case LifecyclePhase::name: return shortText;
        SR_LIFECYCLE_PHASE_TABLE(SR_X_CASE_LIFECYCLE_PHASE)
#undef SR_X_CASE_LIFECYCLE_PHASE
        default:
            return L"?";
    }
}

inline constexpr bool TryParseLifecyclePhase(
    std::wstring_view value,
    LifecyclePhase& phase
) noexcept {
#define SR_X_IF_LIFECYCLE_PHASE(name, phaseValue, text, textView, uppercaseText, shortText) \
    if (value == textView) { phase = LifecyclePhase::name; return true; }
    SR_LIFECYCLE_PHASE_TABLE(SR_X_IF_LIFECYCLE_PHASE)
#undef SR_X_IF_LIFECYCLE_PHASE

    return false;
}

inline constexpr bool TryParseLifecyclePhaseUppercase(
    std::wstring_view value,
    LifecyclePhase& phase
) noexcept {
#define SR_X_IF_LIFECYCLE_PHASE_UPPERCASE(name, phaseValue, text, textView, uppercaseText, shortText) \
    if (value == uppercaseText) { phase = LifecyclePhase::name; return true; }
    SR_LIFECYCLE_PHASE_TABLE(SR_X_IF_LIFECYCLE_PHASE_UPPERCASE)
#undef SR_X_IF_LIFECYCLE_PHASE_UPPERCASE

    return false;
}




// =====================================================================================
// Buffering
// =====================================================================================

enum class ReplayPayloadStorage : uint8_t {
    Store,
    NotNeeded,
    DroppedByBufferLimit
};

#define SR_BUFFER_USAGE_FIELD_TABLE(X) \
    X(stdoutBufferedBytes) \
    X(stderrBufferedBytes) \
    X(totalBufferedBytes) \
    X(stdoutDroppedBytes) \
    X(stderrDroppedBytes) \
    X(totalDroppedBytes) \
    X(stdoutDroppedEvents) \
    X(stderrDroppedEvents) \
    X(totalDroppedEvents)

struct BufferUsage {
#define SR_X_BUFFER_USAGE_FIELD(name) uint64_t name = 0;
    SR_BUFFER_USAGE_FIELD_TABLE(SR_X_BUFFER_USAGE_FIELD)
#undef SR_X_BUFFER_USAGE_FIELD
};

static inline BufferUsage SumBufferUsage(
    const BufferUsage& lhs,
    const BufferUsage& rhs
) noexcept {
    BufferUsage usage;

#define SR_X_BUFFER_USAGE_SUM_FIELD(name) \
    usage.name = lhs.name + rhs.name;
    SR_BUFFER_USAGE_FIELD_TABLE(SR_X_BUFFER_USAGE_SUM_FIELD)
#undef SR_X_BUFFER_USAGE_SUM_FIELD

    return usage;
}

struct AtomicBufferUsageCache {
    void Store(const BufferUsage& usage) noexcept {
#define SR_X_BUFFER_USAGE_STORE(name) \
        name.store(usage.name, std::memory_order_relaxed);
        SR_BUFFER_USAGE_FIELD_TABLE(SR_X_BUFFER_USAGE_STORE)
#undef SR_X_BUFFER_USAGE_STORE
    }

    BufferUsage Load() const noexcept {
        BufferUsage usage;

#define SR_X_BUFFER_USAGE_LOAD(name) \
        usage.name = name.load(std::memory_order_relaxed);
        SR_BUFFER_USAGE_FIELD_TABLE(SR_X_BUFFER_USAGE_LOAD)
#undef SR_X_BUFFER_USAGE_LOAD

        return usage;
    }

#define SR_X_BUFFER_USAGE_ATOMIC_FIELD(name) std::atomic<uint64_t> name{0};
    SR_BUFFER_USAGE_FIELD_TABLE(SR_X_BUFFER_USAGE_ATOMIC_FIELD)
#undef SR_X_BUFFER_USAGE_ATOMIC_FIELD
};


// =====================================================================================
// LogPaths
// =====================================================================================


struct LogPathSet {
    std::wstring stdoutTxt;
    std::wstring stdoutJsonl;

    std::wstring stderrMixedTxt;
    std::wstring stderrMixedJsonl;

    std::wstring stderrChildTxt;
    std::wstring stderrChildJsonl;

    std::wstring stderrSrTxt;
    std::wstring stderrSrJsonl;
};

struct LogPaths {
    LogPathSet running;
    LogPathSet success;
    LogPathSet failure;
};



// =====================================================================================
// Shared options (domain config)
// =====================================================================================

struct Options {
    bool showHelp = false;
    bool debug = false;
    bool verbose = false;

    bool inheritStdin = false;
    bool utf8 = false;        // prefixes inner with: chcp 65001>nul &
    uint32_t timeoutMs = 0;   // 0 = infinite
    std::wstring cwd;

    ExecutionMode executionMode = ExecutionMode::ScriptOrExe;

    std::wstring stdoutDir;
    std::wstring stderrDir;
    std::wstring stderrChildDir;
    std::wstring stderrSrDir;
    std::wstring stdoutJsonlDir;
    std::wstring stderrJsonlDir;
    std::wstring stderrChildJsonlDir;
    std::wstring stderrSrJsonlDir;
    std::wstring probeDir;


    std::wstring runOnSuccess;
    std::wstring runOnFailure;
    std::wstring idPrefix;    // optional ID prefix
    std::wstring idBase;      // optional ID base
    IdSuffixMode idSuffix = IdSuffixMode::None;

    EmitMode stdoutEmit = EmitMode::Stream;  // default
    EmitMode stderrEmit = EmitMode::Stream;  // default
    StderrEmitSource stderrEmitSource = StderrEmitSource::Mixed;

    KeepLogMode stdoutDirKeepLog = KeepLogMode::Always; // default
    KeepLogMode stderrDirKeepLog = KeepLogMode::Always; // default
    KeepLogMode stderrChildDirKeepLog = KeepLogMode::Always;
    KeepLogMode stderrSrDirKeepLog = KeepLogMode::Always;

    uint64_t stdoutMaxBufferBytes = 0; // 0 = unlimited (RAM only)
    uint64_t stderrMaxBufferBytes = 0; // 0 = unlimited (RAM only)
    uint64_t maxTotalBufferBytes  = 0; // 0 = unlimited (RAM only)
    bool hasReplayablePersistentStdoutTxtSource = false;
    bool hasReplayablePersistentStdoutJsonlSource = false;
    bool hasReplayablePersistentStderrMixedTxtSource = false;
    bool hasReplayablePersistentStderrMixedJsonlSource = false;
    bool hasReplayablePersistentStderrChildTxtSource = false;
    bool hasReplayablePersistentStderrChildJsonlSource = false;
    bool hasReplayablePersistentStderrSrTxtSource = false;
    bool hasReplayablePersistentStderrSrJsonlSource = false;

    std::wstring inner; // inner command passed to cmd.exe /d /s /c "...".
    std::vector<std::wstring> parserDebugMessages;
};

#undef SR_EXECUTION_MODE_TABLE
#undef SR_ID_SUFFIX_MODE_TABLE
#undef SR_DIAGNOSTIC_SEVERITY_LIST
#undef SR_KEEPLOGMODE_TABLE
#undef SR_EMITMODE_TABLE
#undef SR_WSV
#undef SR_LIFECYCLE_PHASE_TABLE

} // namespace SR
