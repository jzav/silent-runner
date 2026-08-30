#include "ArgumentParser.h"

#include <cwchar>   // wcstoull
#include <cwctype>  // iswspace

#include "CmdBuilder.h"
#include "FileHelpers.h"
#include "TextHelpers.h"


namespace ArgumentParser {


static bool SplitKeyValue(const std::wstring& arg, std::wstring& keyOut, std::wstring& valOut) {
    size_t eq = arg.find(L'=');
    if (eq == std::wstring::npos) return false;
    keyOut = arg.substr(0, eq);
    valOut = arg.substr(eq + 1);
    return true;
}

static bool IsValidId(const std::wstring& id) {
    if (id.empty()) return false;
    for (wchar_t c : id) {
        if ((c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') ||
            (c >= L'0' && c <= L'9') || c == L'.' || c == L'_' || c == L'-') {
            continue;
        }
        return false;
    }
    return true;
}

static void TrimTrailingNewlines(std::wstring& s) {
    while (!s.empty() && (s.back() == L'\n' || s.back() == L'\r')) {
        s.pop_back();
    }
}

static std::wstring Trimmed(const std::wstring& s) {
    size_t start = 0;
    while (start < s.size() && iswspace(s[start])) {
        ++start;
    }

    size_t end = s.size();
    while (end > start && iswspace(s[end - 1])) {
        --end;
    }

    return s.substr(start, end - start);
}

static constexpr const wchar_t* kUnsupportedScriptOrExeMetacharacters = L"&|><()^%!";

static bool DetectSpecialScriptOrExeCmdChars(
    const std::wstring& rawArg,
    std::wstring& debugInfo
) {
    std::wstring detected;

    for (const wchar_t* p = kUnsupportedScriptOrExeMetacharacters; *p; ++p) {
        if (rawArg.find(*p) != std::wstring::npos) {
            if (!detected.empty()) {
                detected += L" ";
            }
            detected.push_back(*p);
        }
    }

    if (detected.empty()) {
        debugInfo.clear();
        return false;
    }

    debugInfo =
        L"Script-or-exe argument contains characters that may trigger cmd.exe shell operations or affect interpretation:\n"
        L"  ARGUMENT=\"" + rawArg + L"\"\n"
        L"  CHARS=" + detected + L"\n"
        L"  EFFECTS=chaining (&, &&, ||), output piping (|), redirection (>, <), grouping ( ), escaping (^), variable expansion (%...%, !...!)\n"
        L"\n"
        L"For complex command logic, use a .cmd or other script file (multi-line supported).\n"
        L"For raw command strings, use -c \"<command>\".\n"
        L"For examples and detailed usage, see documentation.";
    return true;
}

static bool ValidateSROptionPathArgument(
    const std::wstring& rawPath,
    const wchar_t* argumentName,
    std::wstring& err
) {
    if (rawPath.empty()) {
        err = std::wstring(L"Invalid value for ") + argumentName +
              L": path must not be empty";
        return false;
    }

    if (rawPath != Trimmed(rawPath)) {
        err = std::wstring(L"Invalid value for ") + argumentName +
              L": paths containing leading or trailing whitespace are not supported";
        return false;
    }

    if (rawPath.find(L'"') != std::wstring::npos) {
        err = std::wstring(L"Invalid value for ") + argumentName +
              L": paths containing double quotes are not supported";
        return false;
    }

    if (rawPath.find(L'<') != std::wstring::npos ||
        rawPath.find(L'>') != std::wstring::npos ||
        rawPath.find(L'|') != std::wstring::npos ||
        rawPath.find(L'?') != std::wstring::npos ||
        rawPath.find(L'*') != std::wstring::npos) {
        err = std::wstring(L"Invalid value for ") + argumentName +
              L": paths containing invalid characters (< > | ? *) are not supported";
        return false;
    }

    return true;
}

// Validates --cwd as a child/hook working directory option.
//
// Important:
// - This validates that the requested directory exists and is created if not.
// - Relative --cwd values are resolved by EnsureDirExists() / WinAPI against
//   SilentRunner's current process working directory at parse time.
// - The value is stored as provided and later passed to CreateProcessW as
//   lpCurrentDirectory.
// - This does NOT call SetCurrentDirectoryW and does NOT change where
//   SilentRunner resolves its own option paths (for example --std*-dir).
static bool ValidateCwdArgument(
    const std::wstring& rawPath,
    const wchar_t* argumentName,
    std::wstring& err
) {
    if (!ValidateSROptionPathArgument(rawPath, argumentName, err)) return false;

    DWORD cwdGle = 0;
    if (!FileHelpers::EnsureDirExists(rawPath, &cwdGle)) {
        err = std::wstring(L"Invalid value for ") + argumentName +
              L": path must point to an existing or creatable directory";
        return false;
    }

    return true;
}

// Resolves an SR option path to an absolute path using GetFullPathNameW.
//
// Important:
// - Relative paths are resolved against SilentRunner's inherited current working
//   directory (from parent process) at parse time.
// - This does NOT use --cwd. The --cwd option is only the child/hook current working
//   directory, not SilentRunner's own path-resolution base.
// - Used for run hooks so later hook execution is independent of the runtime
//   child working directory.
static bool TryResolveAbsolutePathArgument(
    const std::wstring& rawPath,
    const wchar_t* argumentName,
    std::wstring& resolvedPathOut,
    std::wstring& err
) {
    resolvedPathOut.clear();

    const DWORD required = GetFullPathNameW(rawPath.c_str(), 0, nullptr, nullptr);
    if (required == 0) {
        err = std::wstring(L"Invalid value for ") + argumentName +
              L": failed to resolve path";
        return false;
    }

    std::wstring buffer(required, L'\0');
    const DWORD written = GetFullPathNameW(
        rawPath.c_str(),
        required,
        buffer.data(),
        nullptr
    );
    if (written == 0 || written >= required) {
        err = std::wstring(L"Invalid value for ") + argumentName +
              L": failed to resolve path";
        return false;
    }

    buffer.resize(written);
    resolvedPathOut = buffer;
    return true;
}

static bool ValidateRunHookPathArgument(
    const std::wstring& rawPath,
    const wchar_t* argumentName,
    std::wstring& resolvedPathOut,
    std::wstring& err
) {
    if (!ValidateSROptionPathArgument(rawPath, argumentName, err)) return false;
    if (!TryResolveAbsolutePathArgument(rawPath, argumentName, resolvedPathOut, err)) return false;

    if (!FileHelpers::FileExists(resolvedPathOut)) {
        err = std::wstring(L"Invalid value for ") + argumentName +
              L": path must point to an existing hook file";
        return false;
    }

    return true;
}

static bool ParseU64(const std::wstring& s, uint64_t& out) {
    if (s.empty()) return false;
    wchar_t* end = nullptr;
    unsigned long long v = wcstoull(s.c_str(), &end, 10);
    if (!end || *end != L'\0') return false;
    out = (uint64_t)v;
    return true;
}

static bool IsBufferedEmitMode(SR::EmitMode mode) noexcept {
    return
        mode == SR::EmitMode::End ||
        mode == SR::EmitMode::Success ||
        mode == SR::EmitMode::Failure;
}

static void FinalizeReplayPolicyOptions(SR::Options& opt) {
    // Must be called only after all SilentRunner options are parsed.
    // This stores only concrete replayable persistent source availability.
    // Aggregate and need*ReplayBuffer values are derived on demand by
    // SRParentEmitPolicy or local diagnostic helpers.
    opt.hasReplayablePersistentStdoutTxtSource =
        !opt.stdoutDir.empty();
    opt.hasReplayablePersistentStdoutJsonlSource =
        !opt.stdoutJsonlDir.empty();

    opt.hasReplayablePersistentStderrSrAndChildTxtSource =
        !opt.stderrDir.empty();
    opt.hasReplayablePersistentStderrSrAndChildJsonlSource =
        !opt.stderrJsonlDir.empty();

    opt.hasReplayablePersistentStderrChildTxtSource =
        !opt.stderrChildDir.empty();
    opt.hasReplayablePersistentStderrChildJsonlSource =
        !opt.stderrChildJsonlDir.empty();

    opt.hasReplayablePersistentStderrSrTxtSource =
        !opt.stderrSrDir.empty();
    opt.hasReplayablePersistentStderrSrJsonlSource =
        !opt.stderrSrJsonlDir.empty();
    opt.hasReplayablePersistentStderrSrAndChildInclStdoutTxtSource =
        !opt.stderrSrAndChildInclStdoutDir.empty();
    opt.hasReplayablePersistentStderrSrAndChildInclStdoutJsonlSource =
        !opt.stderrSrAndChildInclStdoutJsonlDir.empty();
}

static bool HasReplayablePersistentStdoutSource_(const SR::Options& opt) noexcept {
    return
        opt.hasReplayablePersistentStdoutTxtSource ||
        opt.hasReplayablePersistentStdoutJsonlSource;
}

static bool HasReplayablePersistentStderrSource_(const SR::Options& opt) noexcept {
    return
        (opt.stderrEmitSource == SR::StderrEmitSource::SrAndChild &&
         (opt.hasReplayablePersistentStderrSrAndChildTxtSource ||
          opt.hasReplayablePersistentStderrSrAndChildJsonlSource)) ||
        (opt.stderrEmitSource == SR::StderrEmitSource::Child &&
         (opt.hasReplayablePersistentStderrChildTxtSource ||
          opt.hasReplayablePersistentStderrChildJsonlSource)) ||
        (opt.stderrEmitSource == SR::StderrEmitSource::Sr &&
         (opt.hasReplayablePersistentStderrSrTxtSource ||
          opt.hasReplayablePersistentStderrSrJsonlSource)) ||
        (opt.stderrEmitSource == SR::StderrEmitSource::SrAndChildInclStdout &&
         (opt.hasReplayablePersistentStderrSrAndChildInclStdoutTxtSource ||
          opt.hasReplayablePersistentStderrSrAndChildInclStdoutJsonlSource));
}

static bool NeedsStdoutReplayBuffer_(const SR::Options& opt) noexcept {
    return
        IsBufferedEmitMode(opt.stdoutEmit) &&
        !HasReplayablePersistentStdoutSource_(opt);
}

static bool NeedsStderrReplayBuffer_(const SR::Options& opt) noexcept {
    return
        IsBufferedEmitMode(opt.stderrEmit) &&
        !HasReplayablePersistentStderrSource_(opt);
}

static void AppendUnboundedBufferedReplayDebugMessages(SR::Options& opt) {
    const bool hasTotalLimit = opt.maxTotalBufferBytes != 0;
    const bool needStdoutReplayBuffer = NeedsStdoutReplayBuffer_(opt);
    const bool needStderrReplayBuffer = NeedsStderrReplayBuffer_(opt);

    if (needStdoutReplayBuffer &&
        opt.stdoutMaxBufferBytes == 0 &&
        !hasTotalLimit) {
        opt.parserDebugMessages.push_back(
            L"Stdout buffering is enabled without a replayable stdout log file and without a buffer limit.\n"
            L"  EMIT_MODE=end/success/failure may buffer stdout in RAM until replay.\n"
            L"  For replayable stdout logging, consider using --stdout-dir or --stdout-dir-jsonl.\n"
            L"  Otherwise, consider using --stdout-max-buffer-bytes or --std-total-max-buffer-bytes."
        );
    }

    if (needStderrReplayBuffer &&
        opt.stderrMaxBufferBytes == 0 &&
        !hasTotalLimit) {
        const wchar_t* sourceName = SR::StderrEmitSourceToString(opt.stderrEmitSource);
        const wchar_t* dirArg =
            (opt.stderrEmitSource == SR::StderrEmitSource::SrAndChild) ? L"--stderr-dir or --stderr-dir-jsonl" :
            (opt.stderrEmitSource == SR::StderrEmitSource::Child) ? L"--stderr-dir-child or --stderr-dir-child-jsonl" :
            (opt.stderrEmitSource == SR::StderrEmitSource::Sr) ? L"--stderr-dir-sr or --stderr-dir-sr-jsonl" :
            (opt.stderrEmitSource == SR::StderrEmitSource::SrAndChildInclStdout) ? L"--stderr-dir-incl-stdout or --stderr-dir-incl-stdout-jsonl" :
            L"<unknown stderr emit source>";

        opt.parserDebugMessages.push_back(
            std::wstring(L"Stderr buffering is enabled for ") + sourceName +
            L" without a matching stderr log file and without a buffer limit.\n"
            L"  EMIT_MODE=end/success/failure may buffer stderr in RAM until replay.\n"
            L"  Consider using " + dirArg +
            L", --stderr-max-buffer-bytes, or --std-total-max-buffer-bytes."
        );
    }
}

std::wstring BuildUsageText() {
    std::wstring err =
        L"Usage:\n"
        L"  SilentRunner.exe [options] <script-or-exe> [args...]\n"
        L"      Execute script or executable via cmd.exe /d /s /c.\n"
        L"      The file must be executable in the user's Windows environment.\n"
        L"      Some characters may trigger cmd.exe shell operations or affect interpretation:\n"
        L"      chaining (&, &&, ||), output piping (|), redirection (>, <),\n"
        L"      grouping ( ), escaping (^), or variable expansion (%...%, !...!)\n"
        L"      Their presence may be logged for debugging.\n"
        L"      For complex command logic, use a .cmd or other script file (multi-line supported).\n"
        L"  SilentRunner.exe [options] -c \"<command>\"\n"
        L"      Execute raw command string via cmd.exe /d /s /c.\n"
        L"      The command must be passed as a single \"<command>\" argument.\n"
        L"\n"
        L"Paths:\n"
        L"      Paths containing spaces must be quoted.\n"
        L"      Relative paths are resolved against SilentRunner's current working directory (inherited from parent process),\n"
        L"      not against --cwd.\n"
        L"\n"
        L"Common options:\n"
        L"  --help\n"
        L"      Show this help message and exit.\n"
        L"  --debug\n"
        L"      Enable debug diagnostics.\n"
        L"  --verbose\n"
        L"      Enable verbose diagnostics (implies --debug).\n"
        L"  --probe-dir <dir>\n"
        L"      Enables detailed internal probe logging. Intended for development and advanced diagnostics.\n"
        L"      Output format may change between versions.\n"
        L"      Probe logs bypass the ExecutionTimeline and are written directly to the probe log file.\n"
        L"  --inherit-stdin\n"
        L"      Inherit parent stdin instead of using NUL.\n"
        L"  --utf8 or --utf-8\n"
        L"      Force UTF-8 code page (chcp 65001) for the child process.\n"
        L"  --timeout-ms <ms>\n"
        L"      Terminate the child process after the specified timeout (milliseconds).\n"
        L"  --cwd <dir>\n"
        L"      Set the working directory for the main child process and run-on-* hooks.\n"
        L"      If omitted, SilentRunner uses its inherited working directory.\n"
        L"\n"
        L"Run hooks:\n"
        L"  --run-on-success <path>\n"
        L"  --run-on-failure <path>\n"
        L"      Execute hook file via cmd.exe /d /s /c.\n"
        L"      The file must exist and be directly executable by cmd.exe.\n"
        L"      No arguments are supported; execution context is provided via environment variables only:\n"
        L"      SILENTRUNNER_EXIT_CODE, SILENTRUNNER_EXECUTION_ID,\n"
        L"      SILENTRUNNER_STDOUT_LOG, SILENTRUNNER_STDOUT_JSONL_LOG,\n"
        L"      SILENTRUNNER_STDERR_LOG, SILENTRUNNER_STDERR_JSONL_LOG,\n"
        L"      SILENTRUNNER_STDERR_CHILD_LOG, SILENTRUNNER_STDERR_CHILD_JSONL_LOG,\n"
        L"      SILENTRUNNER_STDERR_SR_LOG, SILENTRUNNER_STDERR_SR_JSONL_LOG,\n"
        L"      SILENTRUNNER_STDERR_INCL_STDOUT_LOG, SILENTRUNNER_STDERR_INCL_STDOUT_JSONL_LOG.\n"
        L"      Log environment variables are empty if the corresponding log is not kept after execution\n"
        L"      (see --stdout-dir-keep-log, --stderr-dir-keep-log,\n"
        L"      --stderr-dir-child-keep-log, --stderr-dir-sr-keep-log,\n"
        L"      --stderr-dir-incl-stdout-keep-log).\n"
        L"      The success hook runs only when the child exit code is 0.\n"
        L"      The failure hook runs only when the child exit code is non-zero.\n"
        L"      Run hooks are started detached. SilentRunner logs only whether the hook process\n"
        L"      was started successfully; hook output is not captured.\n"
        L"\n"
        L"Execution ID:\n"
        L"  --id-prefix <value>\n"
        L"  --id-base <value>\n"
        L"  --id-suffix <timestamp|pid|timestamp+pid|pid+timestamp>\n"
        L"      All three components are optional and may be used independently.\n"
        L"      The execution ID is formed from the specified components in this order:\n"
        L"      id-prefix + id-base + id-suffix.\n"
        L"      If none is specified, the execution ID defaults to timestamp+pid (UTC).\n"
        L"\n"
        L"Output routing options:\n"
        L"  --stdout-emit <mode>\n"
        L"      Control how stdout is emitted to the parent.\n"
        L"  --stderr-emit <mode>\n"
        L"      Emit stderr-sr-and-child to the parent (SilentRunner diagnostics plus child stderr).\n"
        L"  --stderr-emit-child <mode>\n"
        L"      Emit stderr-child to the parent (child stderr only).\n"
        L"  --stderr-emit-sr <mode>\n"
        L"      Emit stderr-sr to the parent (SilentRunner diagnostics only).\n"
        L"  --stderr-emit-incl-stdout <mode>\n"
        L"      Emit stderr-sr-and-child-incl-stdout to the parent (SilentRunner diagnostics plus child stderr and stdout).\n"
        L"      The four stderr emit options are mutually exclusive.\n"
        L"\n"
        L"  --stdout-max-buffer-bytes <bytes>\n"
        L"  --stderr-max-buffer-bytes <bytes>\n"
        L"  --std-total-max-buffer-bytes <bytes>\n"
        L"      Limit RAM used when buffering stdout/stderr for End/Success/Failure replay.\n"
        L"      stdout/stderr limits are per-stream; std-total-max-buffer-bytes is the total limit.\n"
        L"      Recommended especially when no log file is configured.\n"
        L"\n"
        L"  --stdout-dir <dir>\n"
        L"  --stderr-dir <dir>\n"
        L"      Write stdout and stderr-sr-and-child to log files.\n"
        L"      stderr-sr-and-child contains SilentRunner diagnostics plus child stderr.\n"
        L"      The directory is created automatically if it does not exist.\n"
        L"      Buffering is not needed for End/Success/Failure emit modes when log files are used.\n"
        L"  --stderr-dir-child <dir>\n"
        L"      Write stderr-child to log files (child stderr only).\n"
        L"  --stderr-dir-sr <dir>\n"
        L"      Write stderr-sr to log files (SilentRunner diagnostics only).\n"
        L"  --stderr-dir-incl-stdout <dir>\n"
        L"      Write stderr-sr-and-child-incl-stdout to log files.\n"
        L"  --stdout-dir-jsonl <dir>\n"
        L"  --stderr-dir-jsonl <dir>\n"
        L"  --stderr-dir-child-jsonl <dir>\n"
        L"  --stderr-dir-sr-jsonl <dir>\n"
        L"  --stderr-dir-incl-stdout-jsonl <dir>\n"
        L"      Write structured JSONL output events to log files.\n"
        L"  --stdout-dir-keep-log <mode>\n"
        L"  --stderr-dir-keep-log <mode>\n"
        L"  --stderr-dir-child-keep-log <mode>\n"
        L"  --stderr-dir-sr-keep-log <mode>\n"
        L"  --stderr-dir-incl-stdout-keep-log <mode>\n"
        L"      Control when log files are kept or deleted.\n"
        L"      JSONL outputs share the same keep-log policy as the corresponding TXT stream.\n"
        L"\n"
        L"Emit modes:\n";
    SR::AppendEmitModeHelpForBoth(err);

    err += L"\nKeep-log modes:\n";
    SR::AppendKeepLogModeHelp(err);

    err += L"\nFor examples and detailed usage, see documentation.";
    return err;
}

bool ParseArgs(int argc, wchar_t** argv, SR::Options& opt, std::wstring& err) {
    int i = 1;

    bool idPrefixSeen = false;
    bool idBaseSeen = false;
    bool idSuffixSeen = false;

    bool debugSeen = false;
    bool verboseSeen = false;
    bool probeDirSeen = false;

    bool inheritStdinSeen = false;
    bool utf8Seen = false;
    bool timeoutMsSeen = false;
    bool cwdSeen = false;
    bool runOnSuccessSeen = false;
    bool runOnFailureSeen = false;
    bool rawCommandSeen = false;

    bool stdoutDirSeen = false;
    bool stderrDirSeen = false;
    bool stderrChildDirSeen = false;
    bool stderrSrDirSeen = false;
    bool stderrSrAndChildInclStdoutDirSeen = false;
    bool stdoutJsonlDirSeen = false;
    bool stderrJsonlDirSeen = false;
    bool stderrChildJsonlDirSeen = false;
    bool stderrSrJsonlDirSeen = false;
    bool stderrSrAndChildInclStdoutJsonlDirSeen = false;

    bool stdoutEmitSeen = false;
    bool stderrEmitSeen = false;
    bool stderrChildEmitSeen = false;
    bool stderrSrEmitSeen = false;
    bool stderrSrAndChildInclStdoutEmitSeen = false;

    bool stdoutMaxBufferBytesSeen = false;
    bool stderrMaxBufferBytesSeen = false;
    bool stdTotalMaxBufferBytesSeen = false;

    bool stdoutDirKeepLogSeen = false;
    bool stderrDirKeepLogSeen = false;
    bool stderrChildDirKeepLogSeen = false;
    bool stderrSrDirKeepLogSeen = false;
    bool stderrSrAndChildInclStdoutDirKeepLogSeen = false;

    auto need_value = [&](const std::wstring& key) -> bool {
        if (i + 1 >= argc) {
            err = L"Missing value for " + key;
            return false;
        }
        return true;
    };

    auto set_id_error = [&]() -> bool {
        err =
            L"The argument '--id' is not supported.\n\n"
            L"Use the identity model:\n"
            L"  --id-prefix <value>\n"
            L"  --id-base <value>\n"
            L"  --id-suffix <mode>\n\n"
            L"Example:\n"
            L"  --id-prefix myapp --id-base worker --id-suffix pid\n\n"
            L"Run with --help for more details.";
        return false;
    };


    // Phase 0: Detect --help option first
    for (int i = 1; i < argc; i++) {
        std::wstring arg = argv[i];

        if (TextHelpers::EqualsOrdinalIgnoreCase(arg, L"--help")) {
            opt.showHelp = true;
            return true;
        }
    }

    // -----------------------------------------------------------------------------
    // Phase 1: Parse SilentRunner options (configuration layer)
    //
    // This loop processes CLI options that configure SilentRunner itself
    // (e.g. --stdout-dir, --stderr-dir, --timeout-ms, --emit, -c, etc.).
    //
    // Key properties:
    // - Options are consumed here and are NOT part of the child command.
    // - Option values (e.g. paths) are validated using SR-specific rules
    //   (e.g. ValidateSROptionPathArgument).
    // - Parsing stops at the first non-option token, which is interpreted as
    //   the beginning of the child command (script-or-exe mode).
    // - The "-c" option switches executionMode to RawCommand and consumes
    //   the entire command string directly.
    //
    // Special case: "-c" / "/c":
    // - Consumes the next argument as a full raw command string.
    // - Sets executionMode = RawCommand.
    // - Terminates option parsing immediately (remaining argv is not processed here).
    //
    // This phase operates on the "SR options layer" only and does NOT attempt
    // to interpret the semantics of the child command.
    // -----------------------------------------------------------------------------
    for (; i < argc; i++) {
        std::wstring arg = argv[i];
        std::wstring key, val;

        key = arg;

        if (TextHelpers::StartsWith(arg, L"--")) {

            SplitKeyValue(arg, key, val);
        }


        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--debug")) {
            if (debugSeen) {
                err = L"Duplicate --debug";
                return false;
            }
            debugSeen = true;
            opt.debug = true;
            continue;
        }

        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--verbose")) {
            if (verboseSeen) {
                err = L"Duplicate --verbose";
                return false;
            }
            verboseSeen = true;
            opt.debug = true;
            opt.verbose = true;
            continue;
        }

        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--probe-dir")) {
            if (probeDirSeen) {
                err = L"Duplicate --probe-dir";
                return false;
            }
            probeDirSeen = true;
            if (val.empty()) {
                if (!need_value(L"--probe-dir")) return false;
                val = argv[++i];
            }
            if (!ValidateSROptionPathArgument(val, L"--probe-dir", err)) return false;
            opt.probeDir = val;
            continue;
        }

        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--inherit-stdin")) {
            if (inheritStdinSeen) {
                err = L"Duplicate --inherit-stdin";
                return false;
            }
            inheritStdinSeen = true;
            opt.inheritStdin = true;
            continue;
        }

        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--utf8") || TextHelpers::EqualsOrdinalIgnoreCase(key, L"--utf-8")) {
            if (utf8Seen) {
                err = L"Duplicate --utf8 or --utf-8";
                return false;
            }
            utf8Seen = true;
            opt.utf8 = true;
            continue;
        }

        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--timeout-ms")) {
            if (timeoutMsSeen) {
                err = L"Duplicate --timeout-ms";
                return false;
            }
            timeoutMsSeen = true;
            if (val.empty()) {
                if (!need_value(L"--timeout-ms")) return false;
                val = argv[++i];
            }
            uint64_t x = 0;
            if (!ParseU64(val, x) || x > 0xffffffffULL) {
                err = L"Invalid value for --timeout-ms";
                return false;
            }
            opt.timeoutMs = (uint32_t)x;
            continue;
        }

        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--cwd")) {
            if (cwdSeen) {
                err = L"Duplicate --cwd";
                return false;
            }
            cwdSeen = true;
            if (val.empty()) {
                if (!need_value(L"--cwd")) return false;
                val = argv[++i];
            }
            if (!ValidateCwdArgument(val, L"--cwd", err)) return false;
            opt.cwd = val;
            continue;
        }

        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--run-on-success")) {
            if (runOnSuccessSeen) {
                err = L"Duplicate --run-on-success";
                return false;
            }
            runOnSuccessSeen = true;
            if (val.empty()) {
                if (!need_value(L"--run-on-success")) return false;
                val = argv[++i];
            }
            std::wstring resolvedHookPath;
            if (!ValidateRunHookPathArgument(val, L"--run-on-success", resolvedHookPath, err)) return false;
            opt.runOnSuccess = resolvedHookPath;
            continue;
        }

        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--run-on-failure")) {
            if (runOnFailureSeen) {
                err = L"Duplicate --run-on-failure";
                return false;
            }
            runOnFailureSeen = true;
            if (val.empty()) {
                if (!need_value(L"--run-on-failure")) return false;
                val = argv[++i];
            }
            std::wstring resolvedHookPath;
            if (!ValidateRunHookPathArgument(val, L"--run-on-failure", resolvedHookPath, err)) return false;
            opt.runOnFailure = resolvedHookPath;
            continue;
        }

        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--stdout-dir")) {
            if (stdoutDirSeen) {
                err = L"Duplicate --stdout-dir";
                return false;
            }
            stdoutDirSeen = true;
            if (val.empty()) {
                if (!need_value(L"--stdout-dir")) return false;
                val = argv[++i];
            }
            if (!ValidateSROptionPathArgument(val, L"--stdout-dir", err)) return false;
            opt.stdoutDir = val;
            continue;
        }

        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--stderr-dir")) {
            if (stderrDirSeen) {
                err = L"Duplicate --stderr-dir";
                return false;
            }
            stderrDirSeen = true;
            if (val.empty()) {
                if (!need_value(L"--stderr-dir")) return false;
                val = argv[++i];
            }
            if (!ValidateSROptionPathArgument(val, L"--stderr-dir", err)) return false;
            opt.stderrDir = val;
            continue;
        }

        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--stderr-dir-child")) {
            if (stderrChildDirSeen) {
                err = L"Duplicate --stderr-dir-child";
                return false;
            }
            stderrChildDirSeen = true;
            if (val.empty()) {
                if (!need_value(L"--stderr-dir-child")) return false;
                val = argv[++i];
            }
            if (!ValidateSROptionPathArgument(val, L"--stderr-dir-child", err)) return false;
            opt.stderrChildDir = val;
            continue;
        }
        
        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--stderr-dir-sr")) {
            if (stderrSrDirSeen) {
                err = L"Duplicate --stderr-dir-sr";
                return false;
            }
            stderrSrDirSeen = true;
            if (val.empty()) {
                if (!need_value(L"--stderr-dir-sr")) return false;
                val = argv[++i];
            }
            if (!ValidateSROptionPathArgument(val, L"--stderr-dir-sr", err)) return false;
            opt.stderrSrDir = val;
            continue;
        }

        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--stderr-dir-incl-stdout")) {
            if (stderrSrAndChildInclStdoutDirSeen) {
                err = L"Duplicate --stderr-dir-incl-stdout";
                return false;
            }
            stderrSrAndChildInclStdoutDirSeen = true;
            if (val.empty()) {
                if (!need_value(L"--stderr-dir-incl-stdout")) return false;
                val = argv[++i];
            }
            if (!ValidateSROptionPathArgument(val, L"--stderr-dir-incl-stdout", err)) return false;
            opt.stderrSrAndChildInclStdoutDir = val;
            continue;
        }

        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--stdout-dir-jsonl")) {
            if (stdoutJsonlDirSeen) {
                err = L"Duplicate --stdout-dir-jsonl";
                return false;
            }
            stdoutJsonlDirSeen = true;
            if (val.empty()) {
                if (!need_value(L"--stdout-dir-jsonl")) return false;
                val = argv[++i];
            }
            if (!ValidateSROptionPathArgument(val, L"--stdout-dir-jsonl", err)) return false;
            opt.stdoutJsonlDir = val;
            continue;
        }
        
        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--stderr-dir-jsonl")) {
            if (stderrJsonlDirSeen) {
                err = L"Duplicate --stderr-dir-jsonl";
                return false;
            }
            stderrJsonlDirSeen = true;
            if (val.empty()) {
                if (!need_value(L"--stderr-dir-jsonl")) return false;
                val = argv[++i];
            }
            if (!ValidateSROptionPathArgument(val, L"--stderr-dir-jsonl", err)) return false;
            opt.stderrJsonlDir = val;
            continue;
        }
        
        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--stderr-dir-child-jsonl")) {
            if (stderrChildJsonlDirSeen) {
                err = L"Duplicate --stderr-dir-child-jsonl";
                return false;
            }
            stderrChildJsonlDirSeen = true;
            if (val.empty()) {
                if (!need_value(L"--stderr-dir-child-jsonl")) return false;
                val = argv[++i];
            }
            if (!ValidateSROptionPathArgument(val, L"--stderr-dir-child-jsonl", err)) return false;
            opt.stderrChildJsonlDir = val;
            continue;
        }
        
        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--stderr-dir-sr-jsonl")) {
            if (stderrSrJsonlDirSeen) {
                err = L"Duplicate --stderr-dir-sr-jsonl";
                return false;
            }
            stderrSrJsonlDirSeen = true;
            if (val.empty()) {
                if (!need_value(L"--stderr-dir-sr-jsonl")) return false;
                val = argv[++i];
            }
            if (!ValidateSROptionPathArgument(val, L"--stderr-dir-sr-jsonl", err)) return false;
            opt.stderrSrJsonlDir = val;
            continue;
        }

        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--stderr-dir-incl-stdout-jsonl")) {
            if (stderrSrAndChildInclStdoutJsonlDirSeen) {
                err = L"Duplicate --stderr-dir-incl-stdout-jsonl";
                return false;
            }
            stderrSrAndChildInclStdoutJsonlDirSeen = true;
            if (val.empty()) {
                if (!need_value(L"--stderr-dir-incl-stdout-jsonl")) return false;
                val = argv[++i];
            }
            if (!ValidateSROptionPathArgument(val, L"--stderr-dir-incl-stdout-jsonl", err)) return false;
            opt.stderrSrAndChildInclStdoutJsonlDir = val;
            continue;
        }
        
        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--id")) {
            return set_id_error();
        }

        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--id-prefix")) {
            if (idPrefixSeen) {
                err = L"Duplicate --id-prefix";
                return false;
            }
            idPrefixSeen = true;
            if (val.empty()) {
                if (!need_value(L"--id-prefix")) return false;
                val = argv[++i];
            }
            opt.idPrefix = val;
            continue;
        }

        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--id-base")) {
            if (idBaseSeen) {
                err = L"Duplicate --id-base";
                return false;
            }
            idBaseSeen = true;
            if (val.empty()) {
                if (!need_value(L"--id-base")) return false;
                val = argv[++i];
            }
            opt.idBase = val;
            continue;
        }

        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--id-suffix")) {
            if (idSuffixSeen) {
                err = L"Duplicate --id-suffix";
                return false;
            }
            idSuffixSeen = true;
            if (val.empty()) {
                if (!need_value(L"--id-suffix")) return false;
                val = argv[++i];
            }
            if (val.empty()) {
                err = L"Missing value for --id-suffix";
                return false;
            }

            SR::IdSuffixMode suffixMode = SR::IdSuffixMode::None;
            if (!SR::TryParseIdSuffixModeIgnoreCase(val, suffixMode)) {
                err =
                    L"Invalid value for --id-suffix. Allowed values:\n"
                    L"  timestamp\n"
                    L"  pid\n"
                    L"  timestamp+pid\n"
                    L"  pid+timestamp";
                return false;
            }
            opt.idSuffix = suffixMode;
            continue;
        }

        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--stdout-max-buffer-bytes")) {
            if (stdoutMaxBufferBytesSeen) {
                err = L"Duplicate --stdout-max-buffer-bytes";
                return false;
            }
            stdoutMaxBufferBytesSeen = true;
            if (val.empty()) {
                if (!need_value(L"--stdout-max-buffer-bytes")) return false;
                val = argv[++i];
            }
            uint64_t x = 0;
            if (!ParseU64(val, x)) {
                err = L"Invalid value for --stdout-max-buffer-bytes";
                return false;
            }
            opt.stdoutMaxBufferBytes = x;
            continue;
        }

        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--stderr-max-buffer-bytes")) {
            if (stderrMaxBufferBytesSeen) {
                err = L"Duplicate --stderr-max-buffer-bytes";
                return false;
            }
            stderrMaxBufferBytesSeen = true;
            if (val.empty()) {
                if (!need_value(L"--stderr-max-buffer-bytes")) return false;
                val = argv[++i];
            }
            uint64_t x = 0;
            if (!ParseU64(val, x)) {
                err = L"Invalid value for --stderr-max-buffer-bytes";
                return false;
            }
            opt.stderrMaxBufferBytes = x;
            continue;
        }

        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--std-total-max-buffer-bytes")) {
            if (stdTotalMaxBufferBytesSeen) {
                err = L"Duplicate --std-total-max-buffer-bytes";
                return false;
            }
            stdTotalMaxBufferBytesSeen = true;
            if (val.empty()) {
                if (!need_value(L"--std-total-max-buffer-bytes")) return false;
                val = argv[++i];
            }
            uint64_t x = 0;
            if (!ParseU64(val, x)) {
                err = L"Invalid value for --std-total-max-buffer-bytes";
                return false;
            }
            opt.maxTotalBufferBytes = x;
            continue;
        }

        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--stdout-emit")) {
            if (stdoutEmitSeen) { err = L"Duplicate --stdout-emit"; return false; }
            stdoutEmitSeen = true;
            if (val.empty()) { if (!need_value(L"--stdout-emit")) return false; val = argv[++i]; }
            if (val.empty()) { err = L"Missing value for --stdout-emit"; return false; }
            SR::EmitMode m;
            if (!SR::TryParseEmitModeIgnoreCase(val, m) || !(SR::EmitModeStreamMask(m) & SR::STDOUT)) {
                err = L"Invalid value for --stdout-emit. Allowed values:\n";
                SR::AppendEmitModeHelpForStdout(err);
                TrimTrailingNewlines(err);
                return false;
            }
            opt.stdoutEmit = m;
            continue;
        }

        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--stderr-emit")) {
            if (stderrEmitSeen) { err = L"Duplicate --stderr-emit"; return false; }
            if (stderrChildEmitSeen || stderrSrEmitSeen || stderrSrAndChildInclStdoutEmitSeen) {
                err = L"--stderr-emit must not be combined with --stderr-emit-child, --stderr-emit-sr, or --stderr-emit-incl-stdout";
                return false;

            }
            stderrEmitSeen = true;
            if (val.empty()) { if (!need_value(L"--stderr-emit")) return false; val = argv[++i]; }
            if (val.empty()) { err = L"Missing value for --stderr-emit"; return false; }
            SR::EmitMode m;
            if (!SR::TryParseEmitModeIgnoreCase(val, m) || !(SR::EmitModeStreamMask(m) & SR::STDERR)) {
                err = L"Invalid value for --stderr-emit. Allowed values:\n";
                SR::AppendEmitModeHelpForStderr(err);
                TrimTrailingNewlines(err);
                return false;
            }
            opt.stderrEmit = m;
            opt.stderrEmitSource = SR::StderrEmitSource::SrAndChild;
            continue;
        }
        
        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--stderr-emit-child")) {
            if (stderrChildEmitSeen) { err = L"Duplicate --stderr-emit-child"; return false; }
            if (stderrEmitSeen || stderrSrEmitSeen || stderrSrAndChildInclStdoutEmitSeen) {
                err = L"--stderr-emit-child must not be combined with --stderr-emit, --stderr-emit-sr, or --stderr-emit-incl-stdout";
                return false;

            }
            stderrChildEmitSeen = true;
            if (val.empty()) { if (!need_value(L"--stderr-emit-child")) return false; val = argv[++i]; }
            if (val.empty()) { err = L"Missing value for --stderr-emit-child"; return false; }
            SR::EmitMode m;
            if (!SR::TryParseEmitModeIgnoreCase(val, m) || !(SR::EmitModeStreamMask(m) & SR::STDERR)) {
                err = L"Invalid value for --stderr-emit-child. Allowed values:\n";
                SR::AppendEmitModeHelpForStderr(err);
                TrimTrailingNewlines(err);
                return false;
            }
            opt.stderrEmit = m;
            opt.stderrEmitSource = SR::StderrEmitSource::Child;
            continue;
        }
        
        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--stderr-emit-sr")) {
            if (stderrSrEmitSeen) { err = L"Duplicate --stderr-emit-sr"; return false; }
            if (stderrEmitSeen || stderrChildEmitSeen || stderrSrAndChildInclStdoutEmitSeen) {
                err = L"--stderr-emit-sr must not be combined with --stderr-emit, --stderr-emit-child, or --stderr-emit-incl-stdout";
                return false;

            }
            stderrSrEmitSeen = true;
            if (val.empty()) { if (!need_value(L"--stderr-emit-sr")) return false; val = argv[++i]; }
            if (val.empty()) { err = L"Missing value for --stderr-emit-sr"; return false; }
            SR::EmitMode m;
            if (!SR::TryParseEmitModeIgnoreCase(val, m) || !(SR::EmitModeStreamMask(m) & SR::STDERR)) {
                err = L"Invalid value for --stderr-emit-sr. Allowed values:\n";
                SR::AppendEmitModeHelpForStderr(err);
                TrimTrailingNewlines(err);
                return false;
            }
            opt.stderrEmit = m;
            opt.stderrEmitSource = SR::StderrEmitSource::Sr;
            continue;
        }

        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--stderr-emit-incl-stdout")) {
            if (stderrSrAndChildInclStdoutEmitSeen) { err = L"Duplicate --stderr-emit-incl-stdout"; return false; }
            if (stderrEmitSeen || stderrChildEmitSeen || stderrSrEmitSeen) {
                err = L"--stderr-emit-incl-stdout must not be combined with --stderr-emit, --stderr-emit-child, or --stderr-emit-sr";
                return false;
            }
            stderrSrAndChildInclStdoutEmitSeen = true;
            if (val.empty()) { if (!need_value(L"--stderr-emit-incl-stdout")) return false; val = argv[++i]; }
            if (val.empty()) { err = L"Missing value for --stderr-emit-incl-stdout"; return false; }
            SR::EmitMode m;
            if (!SR::TryParseEmitModeIgnoreCase(val, m) || !(SR::EmitModeStreamMask(m) & SR::STDERR)) {
                err = L"Invalid value for --stderr-emit-incl-stdout. Allowed values:\n";
                SR::AppendEmitModeHelpForStderr(err);
                TrimTrailingNewlines(err);
                return false;
            }
            opt.stderrEmit = m;
            opt.stderrEmitSource = SR::StderrEmitSource::SrAndChildInclStdout;
            continue;
        }

        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--stdout-dir-keep-log")) {
            if (stdoutDirKeepLogSeen) { err = L"Duplicate --stdout-dir-keep-log"; return false; }
            stdoutDirKeepLogSeen = true;
            if (val.empty()) { if (!need_value(L"--stdout-dir-keep-log")) return false; val = argv[++i]; }
            if (val.empty()) { err = L"Missing value for --stdout-dir-keep-log"; return false; }
            SR::KeepLogMode m;
            if (!SR::TryParseKeepLogModeIgnoreCase(val, m)) {
                err = L"Invalid value for --stdout-dir-keep-log. Allowed values:\n";
                SR::AppendKeepLogModeHelp(err);
                TrimTrailingNewlines(err);
                return false;
            }
            opt.stdoutDirKeepLog = m;
            continue;
        }

        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--stderr-dir-keep-log")) {
            if (stderrDirKeepLogSeen) { err = L"Duplicate --stderr-dir-keep-log"; return false; }
            stderrDirKeepLogSeen = true;
            if (val.empty()) { if (!need_value(L"--stderr-dir-keep-log")) return false; val = argv[++i]; }
            if (val.empty()) { err = L"Missing value for --stderr-dir-keep-log"; return false; }
            SR::KeepLogMode m;
            if (!SR::TryParseKeepLogModeIgnoreCase(val, m)) {
                err = L"Invalid value for --stderr-dir-keep-log. Allowed values:\n";
                SR::AppendKeepLogModeHelp(err);
                TrimTrailingNewlines(err);
                return false;
            }
            opt.stderrDirKeepLog = m;
            continue;
        }
        
        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--stderr-dir-child-keep-log")) {
            if (stderrChildDirKeepLogSeen) { err = L"Duplicate --stderr-dir-child-keep-log"; return false; }
            stderrChildDirKeepLogSeen = true;
            if (val.empty()) { if (!need_value(L"--stderr-dir-child-keep-log")) return false; val = argv[++i]; }
            if (val.empty()) { err = L"Missing value for --stderr-dir-child-keep-log"; return false; }
            SR::KeepLogMode m;
            if (!SR::TryParseKeepLogModeIgnoreCase(val, m)) {
                err = L"Invalid value for --stderr-dir-child-keep-log. Allowed values:\n";
                SR::AppendKeepLogModeHelp(err);
                TrimTrailingNewlines(err);
                return false;
            }
            opt.stderrChildDirKeepLog = m;
            continue;
        }
        
        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--stderr-dir-sr-keep-log")) {
            if (stderrSrDirKeepLogSeen) { err = L"Duplicate --stderr-dir-sr-keep-log"; return false; }
            stderrSrDirKeepLogSeen = true;
            if (val.empty()) { if (!need_value(L"--stderr-dir-sr-keep-log")) return false; val = argv[++i]; }
            if (val.empty()) { err = L"Missing value for --stderr-dir-sr-keep-log"; return false; }
            SR::KeepLogMode m;
            if (!SR::TryParseKeepLogModeIgnoreCase(val, m)) {
                err = L"Invalid value for --stderr-dir-sr-keep-log. Allowed values:\n";
                SR::AppendKeepLogModeHelp(err);
                TrimTrailingNewlines(err);
                return false;
            }
            opt.stderrSrDirKeepLog = m;
            continue;
        }

        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"--stderr-dir-incl-stdout-keep-log")) {
            if (stderrSrAndChildInclStdoutDirKeepLogSeen) { err = L"Duplicate --stderr-dir-incl-stdout-keep-log"; return false; }
            stderrSrAndChildInclStdoutDirKeepLogSeen = true;
            if (val.empty()) { if (!need_value(L"--stderr-dir-incl-stdout-keep-log")) return false; val = argv[++i]; }
            if (val.empty()) { err = L"Missing value for --stderr-dir-incl-stdout-keep-log"; return false; }
            SR::KeepLogMode m;
            if (!SR::TryParseKeepLogModeIgnoreCase(val, m)) {
                err = L"Invalid value for --stderr-dir-incl-stdout-keep-log. Allowed values:\n";
                SR::AppendKeepLogModeHelp(err);
                TrimTrailingNewlines(err);
                return false;
            }
            opt.stderrSrAndChildInclStdoutDirKeepLog = m;
            continue;
        }
        
        if (TextHelpers::EqualsOrdinalIgnoreCase(key, L"-c") || TextHelpers::EqualsOrdinalIgnoreCase(key, L"/c")) {
            if (rawCommandSeen) {
                err = L"Duplicate -c or /c";
                return false;
            }
            rawCommandSeen = true;
            if (!need_value(L"-c")) return false;
            opt.inner = argv[++i];
            opt.executionMode = SR::ExecutionMode::RawCommand;
            break;
        }

        if (TextHelpers::StartsWith(key, L"--")) {

            err = L"Unknown argument: " + key;
            return false;
        }

        break;
    }

    if (i >= argc) {
        err =   
            L"Missing command or executable target.\n\n" +
            BuildUsageText();
        return false;
    }

    if (!opt.idPrefix.empty() && !IsValidId(opt.idPrefix)) {
        err = L"Invalid --id-prefix (allowed: A-Za-z0-9._-)";
        return false;
    }

    if (!opt.idBase.empty() && !IsValidId(opt.idBase)) {
        err = L"Invalid --id-base (allowed: A-Za-z0-9._-)";
        return false;
    }
    
    FinalizeReplayPolicyOptions(opt);
    AppendUnboundedBufferedReplayDebugMessages(opt);

    // -----------------------------------------------------------------------------
    // Phase 2: Process child command arguments (execution payload layer)
    //
    // At this point, all SilentRunner options have been parsed.
    // The remaining argv tokens represent the child command to be executed.
    //
    // Behavior depends on executionMode that is determined during Phase 1 (notably by "-c" option):
    //
    // 1) ScriptOrExe mode:
    //    - argv[i..argc) are treated as individual tokens (script/exe + args).
    //    - Each token is scanned for cmd.exe special characters (e.g. &, |, >, etc.).
    //      Findings are recorded for debugging purposes only; arguments are not rejected.
    //    - Tokens are then safely combined into a command string using
    //      CmdBuilder::QuoteIfNeeded and passed to cmd.exe /d /s /c.
    //
    // 2) RawCommand mode (-c):
    //    - opt.inner already contains the full command string (set in Phase 1).
    //    - No token-level validation is performed, as the user explicitly opted
    //      into raw shell semantics.
    //
    // Important:
    // - This phase does NOT interpret argument meaning (e.g. whether something
    //   is a path, flag, or value). All semantics belong to the child process.
    // -----------------------------------------------------------------------------
    if (opt.executionMode == SR::ExecutionMode::RawCommand && i + 1 < argc) {
        err = L"-c expects a single command string argument (use quotes if needed)";
        return false;
    }

    if (opt.executionMode == SR::ExecutionMode::ScriptOrExe) {
        for (int k = i; k < argc; k++) {
            std::wstring debugInfo;
            if (DetectSpecialScriptOrExeCmdChars(argv[k], debugInfo)) {
                opt.parserDebugMessages.push_back(debugInfo);
            }
        }

        std::wstring path = argv[i];

        std::wstring inner = CmdBuilder::QuoteIfNeeded(path);
        for (int k = i + 1; k < argc; k++) {
            inner.push_back(L' ');
            inner.append(CmdBuilder::QuoteIfNeeded(argv[k]));
        }

        opt.inner = inner;
    }

    return true;
}

} // namespace ArgumentParser
