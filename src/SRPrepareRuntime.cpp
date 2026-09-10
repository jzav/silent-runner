#include "SRPrepareRuntime.h"

#include "SRChildCmdBuilder.h"
#include "ErrorHelpers.h"
#include "FileHelpers.h"
#include "LogWriter.h"
#include "SRLifecycleDiagnostics.h"
#include "SRParentEmitPolicy.h"
#include "SRFileSinkWorker.h"

static void AppendUnboundedBufferedReplayDebugMessages(
    const SR::PrepareRuntimeConfig& config,
    const SRParentEmitPolicy& parentEmitPolicy,
    std::vector<std::wstring>& messages
) {
    const bool hasTotalLimit =
        config.stdTotalMaxBufferBytes != 0;
    const bool needStdoutReplayBuffer =
        parentEmitPolicy.NeedsStdoutReplayBuffer();
    const bool needStderrReplayBuffer =
        parentEmitPolicy.NeedsStderrReplayBuffer();

    if (needStdoutReplayBuffer &&
        config.stdoutMaxBufferBytes == 0 &&
        !hasTotalLimit) {
        messages.push_back(
            L"Stdout buffering is enabled without a replayable stdout log file and without a buffer limit.\n"
            L"  EMIT_MODE=end/success/failure may buffer stdout in RAM until replay.\n"
            L"  For replayable stdout logging, consider using --stdout-dir or --stdout-dir-jsonl.\n"
            L"  Otherwise, consider using --stdout-max-buffer-bytes or --std-total-max-buffer-bytes."
        );
    }

    if (needStderrReplayBuffer &&
        config.stderrMaxBufferBytes == 0 &&
        !hasTotalLimit) {
        const SR::StderrEmitSource stderrEmitSource =
            parentEmitPolicy.StderrEmitSource();
        const wchar_t* sourceName =
            SR::StderrEmitSourceToString(stderrEmitSource);
        const wchar_t* dirArg =
            (stderrEmitSource == SR::StderrEmitSource::SrAndChild) ? L"--stderr-dir or --stderr-dir-jsonl" :
            (stderrEmitSource == SR::StderrEmitSource::Child) ? L"--stderr-dir-child or --stderr-dir-child-jsonl" :
            (stderrEmitSource == SR::StderrEmitSource::Sr) ? L"--stderr-dir-sr or --stderr-dir-sr-jsonl" :
            (stderrEmitSource == SR::StderrEmitSource::SrAndChildInclStdout) ? L"--stderr-dir-incl-stdout or --stderr-dir-incl-stdout-jsonl" :
            L"<unknown stderr emit source>";

        messages.push_back(
            std::wstring(L"Stderr buffering is enabled for ") + sourceName +
            L" without a matching stderr log file and without a buffer limit.\n"
            L"  EMIT_MODE=end/success/failure may buffer stderr in RAM until replay.\n"
            L"  Consider using " + dirArg +
            L", --stderr-max-buffer-bytes, or --std-total-max-buffer-bytes."
        );
    }
}

static bool EnsureConfiguredCwdExists(
    const std::wstring& cwd,
    std::wstring& err
) {
    if (cwd.empty()) {
        return true;
    }

    DWORD cwdGle = 0;
    if (!FileHelpers::EnsureDirExists(cwd, &cwdGle)) {
        err =
            L"Invalid value for --cwd: "
            L"path must point to an existing or creatable directory";
        return false;
    }

    return true;
}

static bool TryResolveExistingRunHookPath(
    const std::wstring& rawPath,
    const wchar_t* argumentName,
    std::wstring& resolvedPathOut,
    std::wstring& err
) {
    resolvedPathOut.clear();

    if (rawPath.empty()) {
        return true;
    }

    const DWORD required =
        GetFullPathNameW(rawPath.c_str(), 0, nullptr, nullptr);

    if (required == 0) {
        err =
            std::wstring(L"Invalid value for ") +
            argumentName +
            L": failed to resolve path";
        return false;
    }

    std::wstring resolvedPath(required, L'\0');

    const DWORD written =
        GetFullPathNameW(
            rawPath.c_str(),
            required,
            resolvedPath.data(),
            nullptr
        );

    if (written == 0 || written >= required) {
        err =
            std::wstring(L"Invalid value for ") +
            argumentName +
            L": failed to resolve path";
        return false;
    }

    resolvedPath.resize(written);

    if (!FileHelpers::FileExists(resolvedPath)) {
        err =
            std::wstring(L"Invalid value for ") +
            argumentName +
            L": path must point to an existing hook file";
        return false;
    }

    resolvedPathOut = resolvedPath;
    return true;
}

void PrepareRuntime(
    SR::SRConfigs& configs,
    SRFileSinkWorker& fileSinkWorker,
    const SRParentEmitPolicy& parentEmitPolicy,
    SRLifecycleDiagnostics& lifecycleDiag,
    SRPrepareResult& result
) {
    auto& config = configs.prepareRuntime;
    SRLogFiles& logFiles = result.logFiles;
    SR::LogPaths& logPaths = logFiles.paths;
    SR::LogFileCreationResults& creationResults = logFiles.creationResults;
    SRLogFileWriters& writers = logFiles.writers;
    AppendUnboundedBufferedReplayDebugMessages(
        config,
        parentEmitPolicy,
        result.unboundedReplayBufferDebugMessages
    );

    result.stdoutStdHandleProbe =
        HandleHelpers::ProbeStdHandleForWrite(GetStdHandle(STD_OUTPUT_HANDLE));
    result.stderrStdHandleProbe =
        HandleHelpers::ProbeStdHandleForWrite(GetStdHandle(STD_ERROR_HANDLE));

    const bool srDiagFileRequested =
        !config.stderrDir.empty() ||
        !config.stderrDirSr.empty() ||
        !config.stderrDirInclStdout.empty() ||
        !config.stderrDirJsonl.empty() ||
        !config.stderrDirSrJsonl.empty() ||
        !config.stderrDirInclStdoutJsonl.empty();

    const bool srDiagParentRequested =
        parentEmitPolicy.StderrEmitMode() != SR::EmitMode::Never &&
        parentEmitPolicy.StderrEmitSource() != SR::StderrEmitSource::Child;

    const bool srDiagParentAvailable =
        srDiagParentRequested &&
        result.stderrStdHandleProbe.probablyWritable;

    if (!srDiagFileRequested && !srDiagParentAvailable) {
        result.earlyExitCode = 254;
        return;
    }
    std::wstring preparePathError;

    if (!EnsureConfiguredCwdExists(
            config.cwd,
            preparePathError
        )) {
        lifecycleDiag.FatalErrorLine(preparePathError);
        result.earlyExitCode = 2;
        return;
    }

    std::wstring resolvedRunOnSuccessPath;
    if (!TryResolveExistingRunHookPath(
            config.runOnSuccessPath,
            L"--run-on-success",
            resolvedRunOnSuccessPath,
            preparePathError
        )) {
        lifecycleDiag.FatalErrorLine(preparePathError);
        result.earlyExitCode = 2;
        return;
    }

    std::wstring resolvedRunOnFailurePath;
    if (!TryResolveExistingRunHookPath(
            config.runOnFailurePath,
            L"--run-on-failure",
            resolvedRunOnFailurePath,
            preparePathError
        )) {
        lifecycleDiag.FatalErrorLine(preparePathError);
        result.earlyExitCode = 2;
        return;
    }

    configs.finalizeExecution.runOnSuccessPath =
        resolvedRunOnSuccessPath;
    configs.finalizeExecution.runOnFailurePath =
        resolvedRunOnFailurePath;

    const bool userEnteredAnyIdPart =
        !config.idPrefix.empty() ||
        !config.idBase.empty() ||
        (config.idSuffix != SR::IdSuffixMode::None);

    config.useDefaultSuffixMode = !userEnteredAnyIdPart;

    config.effectiveIdSuffixMode =
        config.useDefaultSuffixMode ? SR::IdSuffixMode::TimestampPid : config.idSuffix;

    if (config.effectiveIdSuffixMode != SR::IdSuffixMode::None) {
        config.generatedSuffix =
            FileHelpers::BuildIdSuffix(config.effectiveIdSuffixMode);
    }

    config.executionId = FileHelpers::BuildExecutionId(
        config.idPrefix,
        config.idBase,
        config.generatedSuffix
    );

    configs.runHiddenWithRouting.generatedSuffix =
        config.generatedSuffix;
    configs.runHiddenWithRouting.effectiveIdSuffixMode =
        config.effectiveIdSuffixMode;
    configs.runHiddenWithRouting.useDefaultSuffixMode =
        config.useDefaultSuffixMode;
    configs.runHiddenWithRouting.executionId =
        config.executionId;

    configs.finalizeExecution.executionId =
        config.executionId;




    // Build the candidate log paths before opening any log files.
    //
    // Important:
    // - config.stdoutDir / config.stderrDir may be relative paths.
    // - Relative log directories are resolved later by WinAPI calls against
    //   SilentRunner's inherited current working directory (from parent process), not against --cwd.
    // - --cwd affects the child process and run-on-* hook working directory only.
    // - Preflight checks include running/success/failure names so SilentRunner does
    //   not overwrite an existing log from a previous execution ID.
    if (!config.probeDir.empty()) {
        logPaths.probe =
            FileHelpers::JoinPath(
                config.probeDir,
                config.executionId + L"_probe.log"
            );

        if (FileHelpers::FileExists(logPaths.probe)) {
            lifecycleDiag.FatalErrorLine(
                L"Refusing to start: probe log file already exists\n"
                L"  EXECUTION_ID=" + config.executionId + L"\n"
                L"  DIR=" + config.probeDir + L"\n"
                L"  EXISTING PATH:\n"
                L"    " + logPaths.probe
            );
            result.earlyExitCode = 255;
            return;
        }
    }


    if (!config.stderrDir.empty()) {
        logPaths.running.stderrSrAndChildTxt =
            FileHelpers::JoinPath(
                config.stderrDir,
                config.executionId + L"_stderr_running.log"
            );
        logPaths.success.stderrSrAndChildTxt =
            FileHelpers::JoinPath(
                config.stderrDir,
                config.executionId + L"_stderr_success.log"
            );
        logPaths.failure.stderrSrAndChildTxt =
            FileHelpers::JoinPath(
                config.stderrDir,
                config.executionId + L"_stderr_failure.log"
            );

        if (FileHelpers::FileExists(logPaths.running.stderrSrAndChildTxt) ||
            FileHelpers::FileExists(logPaths.success.stderrSrAndChildTxt) ||
            FileHelpers::FileExists(logPaths.failure.stderrSrAndChildTxt)) {
            lifecycleDiag.FatalErrorLine(
                L"Refusing to start: stderr-sr-and-child log files already exist\n"
                L"  EXECUTION_ID=" + config.executionId + L"\n"
                L"  DIR=" + config.stderrDir + L"\n"
                L"  EXISTING PATHS:\n"
                L"    " + logPaths.running.stderrSrAndChildTxt + L"\n"
                L"    " + logPaths.success.stderrSrAndChildTxt + L"\n"
                L"    " + logPaths.failure.stderrSrAndChildTxt
            );
            result.earlyExitCode = 255;
            return;
        }
    }

    if (!config.stderrDirSr.empty()) {
        logPaths.running.stderrSrTxt =
            FileHelpers::JoinPath(
                config.stderrDirSr,
                config.executionId + L"_stderr_sr_running.log"
            );
        logPaths.success.stderrSrTxt =
            FileHelpers::JoinPath(
                config.stderrDirSr,
                config.executionId + L"_stderr_sr_success.log"
            );
        logPaths.failure.stderrSrTxt =
            FileHelpers::JoinPath(
                config.stderrDirSr,
                config.executionId + L"_stderr_sr_failure.log"
            );

        if (FileHelpers::FileExists(logPaths.running.stderrSrTxt) ||
            FileHelpers::FileExists(logPaths.success.stderrSrTxt) ||
            FileHelpers::FileExists(logPaths.failure.stderrSrTxt)) {
            lifecycleDiag.FatalErrorLine(
                L"Refusing to start: stderr-sr log files already exist\n"
                L"  EXECUTION_ID=" + config.executionId + L"\n"
                L"  DIR=" + config.stderrDirSr + L"\n"
                L"  EXISTING PATHS:\n"
                L"    " + logPaths.running.stderrSrTxt + L"\n"
                L"    " + logPaths.success.stderrSrTxt + L"\n"
                L"    " + logPaths.failure.stderrSrTxt
            );
            result.earlyExitCode = 255;
            return;
        }
    }

    if (!config.stderrDirChild.empty()) {
        logPaths.running.stderrChildTxt =
            FileHelpers::JoinPath(
                config.stderrDirChild,
                config.executionId + L"_stderr_child_running.log"
            );
        logPaths.success.stderrChildTxt =
            FileHelpers::JoinPath(
                config.stderrDirChild,
                config.executionId + L"_stderr_child_success.log"
            );
        logPaths.failure.stderrChildTxt =
            FileHelpers::JoinPath(
                config.stderrDirChild,
                config.executionId + L"_stderr_child_failure.log"
            );

        if (FileHelpers::FileExists(logPaths.running.stderrChildTxt) ||
            FileHelpers::FileExists(logPaths.success.stderrChildTxt) ||
            FileHelpers::FileExists(logPaths.failure.stderrChildTxt)) {
            lifecycleDiag.FatalErrorLine(
                L"Refusing to start: stderr-child log files already exist\n"
                L"  EXECUTION_ID=" + config.executionId + L"\n"
                L"  DIR=" + config.stderrDirChild + L"\n"
                L"  EXISTING PATHS:\n"
                L"    " + logPaths.running.stderrChildTxt + L"\n"
                L"    " + logPaths.success.stderrChildTxt + L"\n"
                L"    " + logPaths.failure.stderrChildTxt
            );
            result.earlyExitCode = 255;
            return;
        }
    }

    if (!config.stdoutDir.empty()) {
        logPaths.running.stdoutTxt =
            FileHelpers::JoinPath(
                config.stdoutDir,
                config.executionId + L"_stdout_running.log"
            );
        logPaths.success.stdoutTxt =
            FileHelpers::JoinPath(
                config.stdoutDir,
                config.executionId + L"_stdout_success.log"
            );
        logPaths.failure.stdoutTxt =
            FileHelpers::JoinPath(
                config.stdoutDir,
                config.executionId + L"_stdout_failure.log"
            );

        if (FileHelpers::FileExists(logPaths.running.stdoutTxt) ||
            FileHelpers::FileExists(logPaths.success.stdoutTxt) ||
            FileHelpers::FileExists(logPaths.failure.stdoutTxt)) {
            lifecycleDiag.FatalErrorLine(
                L"Refusing to start: stdout log files already exist\n"
                L"  EXECUTION_ID=" + config.executionId + L"\n"
                L"  DIR=" + config.stdoutDir + L"\n"
                L"  EXISTING PATHS:\n"
                L"    " + logPaths.running.stdoutTxt + L"\n"
                L"    " + logPaths.success.stdoutTxt + L"\n"
                L"    " + logPaths.failure.stdoutTxt
            );
            result.earlyExitCode = 255;
            return;
        }
    }
    if (!config.stderrDirInclStdout.empty()) {
        logPaths.running.stderrSrAndChildInclStdoutTxt =
            FileHelpers::JoinPath(
                config.stderrDirInclStdout,
                config.executionId + L"_stderr_incl_stdout_running.log"
            );
        logPaths.success.stderrSrAndChildInclStdoutTxt =
            FileHelpers::JoinPath(
                config.stderrDirInclStdout,
                config.executionId + L"_stderr_incl_stdout_success.log"
            );
        logPaths.failure.stderrSrAndChildInclStdoutTxt =
            FileHelpers::JoinPath(
                config.stderrDirInclStdout,
                config.executionId + L"_stderr_incl_stdout_failure.log"
            );
        if (FileHelpers::FileExists(logPaths.running.stderrSrAndChildInclStdoutTxt) ||
            FileHelpers::FileExists(logPaths.success.stderrSrAndChildInclStdoutTxt) ||
            FileHelpers::FileExists(logPaths.failure.stderrSrAndChildInclStdoutTxt)) {
            lifecycleDiag.FatalErrorLine(
                L"Refusing to start: stderr-sr-and-child-incl-stdout log files already exist\n"
                L"  EXECUTION_ID=" + config.executionId + L"\n"
                L"  DIR=" + config.stderrDirInclStdout + L"\n"
                L"  EXISTING PATHS:\n"
                L"    " + logPaths.running.stderrSrAndChildInclStdoutTxt + L"\n"
                L"    " + logPaths.success.stderrSrAndChildInclStdoutTxt + L"\n"
                L"    " + logPaths.failure.stderrSrAndChildInclStdoutTxt
            );
            result.earlyExitCode = 255;
            return;
        }
    }

    if (!config.stderrDirJsonl.empty()) {
        logPaths.running.stderrSrAndChildJsonl =
            FileHelpers::JoinPath(
                config.stderrDirJsonl,
                config.executionId + L"_stderr_running.jsonl"
            );
        logPaths.success.stderrSrAndChildJsonl =
            FileHelpers::JoinPath(
                config.stderrDirJsonl,
                config.executionId + L"_stderr_success.jsonl"
            );
        logPaths.failure.stderrSrAndChildJsonl =
            FileHelpers::JoinPath(
                config.stderrDirJsonl,
                config.executionId + L"_stderr_failure.jsonl"
            );

        if (FileHelpers::FileExists(logPaths.running.stderrSrAndChildJsonl) ||
            FileHelpers::FileExists(logPaths.success.stderrSrAndChildJsonl) ||
            FileHelpers::FileExists(logPaths.failure.stderrSrAndChildJsonl)) {
            lifecycleDiag.FatalErrorLine(
                L"Refusing to start: stderr-sr-and-child JSONL log files already exist\n"
                L"  EXECUTION_ID=" + config.executionId + L"\n"
                L"  DIR=" + config.stderrDirJsonl + L"\n"
                L"  EXISTING PATHS:\n"
                L"    " + logPaths.running.stderrSrAndChildJsonl + L"\n"
                L"    " + logPaths.success.stderrSrAndChildJsonl + L"\n"
                L"    " + logPaths.failure.stderrSrAndChildJsonl
            );
            result.earlyExitCode = 255;
            return;
        }
    }

    if (!config.stderrDirSrJsonl.empty()) {
        logPaths.running.stderrSrJsonl =
            FileHelpers::JoinPath(
                config.stderrDirSrJsonl,
                config.executionId + L"_stderr_sr_running.jsonl"
            );
        logPaths.success.stderrSrJsonl =
            FileHelpers::JoinPath(
                config.stderrDirSrJsonl,
                config.executionId + L"_stderr_sr_success.jsonl"
            );
        logPaths.failure.stderrSrJsonl =
            FileHelpers::JoinPath(
                config.stderrDirSrJsonl,
                config.executionId + L"_stderr_sr_failure.jsonl"
            );

        if (FileHelpers::FileExists(logPaths.running.stderrSrJsonl) ||
            FileHelpers::FileExists(logPaths.success.stderrSrJsonl) ||
            FileHelpers::FileExists(logPaths.failure.stderrSrJsonl)) {
            lifecycleDiag.FatalErrorLine(
                L"Refusing to start: stderr-sr JSONL log files already exist\n"
                L"  EXECUTION_ID=" + config.executionId + L"\n"
                L"  DIR=" + config.stderrDirSrJsonl + L"\n"
                L"  EXISTING PATHS:\n"
                L"    " + logPaths.running.stderrSrJsonl + L"\n"
                L"    " + logPaths.success.stderrSrJsonl + L"\n"
                L"    " + logPaths.failure.stderrSrJsonl
            );
            result.earlyExitCode = 255;
            return;
        }
    }

    if (!config.stderrDirChildJsonl.empty()) {
        logPaths.running.stderrChildJsonl =
            FileHelpers::JoinPath(
                config.stderrDirChildJsonl,
                config.executionId + L"_stderr_child_running.jsonl"
            );
        logPaths.success.stderrChildJsonl =
            FileHelpers::JoinPath(
                config.stderrDirChildJsonl,
                config.executionId + L"_stderr_child_success.jsonl"
            );
        logPaths.failure.stderrChildJsonl =
            FileHelpers::JoinPath(
                config.stderrDirChildJsonl,
                config.executionId + L"_stderr_child_failure.jsonl"
            );

        if (FileHelpers::FileExists(logPaths.running.stderrChildJsonl) ||
            FileHelpers::FileExists(logPaths.success.stderrChildJsonl) ||
            FileHelpers::FileExists(logPaths.failure.stderrChildJsonl)) {
            lifecycleDiag.FatalErrorLine(
                L"Refusing to start: stderr-child JSONL log files already exist\n"
                L"  EXECUTION_ID=" + config.executionId + L"\n"
                L"  DIR=" + config.stderrDirChildJsonl + L"\n"
                L"  EXISTING PATHS:\n"
                L"    " + logPaths.running.stderrChildJsonl + L"\n"
                L"    " + logPaths.success.stderrChildJsonl + L"\n"
                L"    " + logPaths.failure.stderrChildJsonl
            );
            result.earlyExitCode = 255;
            return;
        }
    }

    if (!config.stdoutDirJsonl.empty()) {
        logPaths.running.stdoutJsonl =
            FileHelpers::JoinPath(
                config.stdoutDirJsonl,
                config.executionId + L"_stdout_running.jsonl"
            );
        logPaths.success.stdoutJsonl =
            FileHelpers::JoinPath(
                config.stdoutDirJsonl,
                config.executionId + L"_stdout_success.jsonl"
            );
        logPaths.failure.stdoutJsonl =
            FileHelpers::JoinPath(
                config.stdoutDirJsonl,
                config.executionId + L"_stdout_failure.jsonl"
            );

        if (FileHelpers::FileExists(logPaths.running.stdoutJsonl) ||
            FileHelpers::FileExists(logPaths.success.stdoutJsonl) ||
            FileHelpers::FileExists(logPaths.failure.stdoutJsonl)) {
            lifecycleDiag.FatalErrorLine(
                L"Refusing to start: stdout JSONL log files already exist\n"
                L"  EXECUTION_ID=" + config.executionId + L"\n"
                L"  DIR=" + config.stdoutDirJsonl + L"\n"
                L"  EXISTING PATHS:\n"
                L"    " + logPaths.running.stdoutJsonl + L"\n"
                L"    " + logPaths.success.stdoutJsonl + L"\n"
                L"    " + logPaths.failure.stdoutJsonl
            );
            result.earlyExitCode = 255;
            return;
        }
    }
    if (!config.stderrDirInclStdoutJsonl.empty()) {
        logPaths.running.stderrSrAndChildInclStdoutJsonl =
            FileHelpers::JoinPath(
                config.stderrDirInclStdoutJsonl,
                config.executionId + L"_stderr_incl_stdout_running.jsonl"
            );
        logPaths.success.stderrSrAndChildInclStdoutJsonl =
            FileHelpers::JoinPath(
                config.stderrDirInclStdoutJsonl,
                config.executionId + L"_stderr_incl_stdout_success.jsonl"
            );
        logPaths.failure.stderrSrAndChildInclStdoutJsonl =
            FileHelpers::JoinPath(
                config.stderrDirInclStdoutJsonl,
                config.executionId + L"_stderr_incl_stdout_failure.jsonl"
            );
        if (FileHelpers::FileExists(logPaths.running.stderrSrAndChildInclStdoutJsonl) ||
            FileHelpers::FileExists(logPaths.success.stderrSrAndChildInclStdoutJsonl) ||
            FileHelpers::FileExists(logPaths.failure.stderrSrAndChildInclStdoutJsonl)) {
            lifecycleDiag.FatalErrorLine(
                L"Refusing to start: stderr-sr-and-child-incl-stdout JSONL log files already exist\n"
                L"  EXECUTION_ID=" + config.executionId + L"\n"
                L"  DIR=" + config.stderrDirInclStdoutJsonl + L"\n"
                L"  EXISTING PATHS:\n"
                L"    " + logPaths.running.stderrSrAndChildInclStdoutJsonl + L"\n"
                L"    " + logPaths.success.stderrSrAndChildInclStdoutJsonl + L"\n"
                L"    " + logPaths.failure.stderrSrAndChildInclStdoutJsonl
            );
            result.earlyExitCode = 255;
            return;
        }
    }

    // Create/open log directories and running log files.
    //
    // Directory semantics:
    // - EnsureDirExists() has mkdir-p behavior and creates missing directories.
    // - Relative directories are still resolved against SilentRunner's inherited current
    //   working directory, not against --cwd.
    // - CreateNewFile() uses no-overwrite creation for the *_running.log file.
    if (!config.probeDir.empty()) {
        DWORD gle = 0;
        if (!FileHelpers::EnsureDirExists(config.probeDir, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create/open --probe-dir: " + config.probeDir +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }

        if (!lifecycleDiag.TrySetProbeLogPath(logPaths.probe)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create probe log file: " + logPaths.probe
            );
            result.earlyExitCode = 255;
            return;
        }
        creationResults.probe = true;

        lifecycleDiag.ProbeLine(
            L"Probe log initialized; path=" + logPaths.probe
        );
    }
    if (!config.stderrDir.empty()) {
        DWORD gle = 0;
        if (!FileHelpers::EnsureDirExists(config.stderrDir, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create/open --stderr-dir: " + config.stderrDir +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Prepared stderr-sr-and-child log directory OK; path=" + config.stderrDir
        );

        gle = 0;
        if (!writers.stderrLogWriter.CreateNewFile(logPaths.running.stderrSrAndChildTxt, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create stderr-sr-and-child log file: " + logPaths.running.stderrSrAndChildTxt +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        creationResults.stderrSrAndChildTxt = true;

        lifecycleDiag.DebugLine(
            L"Created stderr-sr-and-child running log OK; path=" + logPaths.running.stderrSrAndChildTxt
        );
    }

    if (!config.stderrDirSr.empty()) {
        DWORD gle = 0;
        if (!FileHelpers::EnsureDirExists(config.stderrDirSr, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create/open --stderr-dir-sr: " + config.stderrDirSr +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Prepared stderr-sr log directory OK; path=" + config.stderrDirSr
        );

        gle = 0;
        if (!writers.stderrSrLogWriter.CreateNewFile(logPaths.running.stderrSrTxt, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create stderr-sr log file: " + logPaths.running.stderrSrTxt +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        creationResults.stderrSrTxt = true;

        lifecycleDiag.DebugLine(
            L"Created stderr-sr running log OK; path=" + logPaths.running.stderrSrTxt
        );
    }

    if (!config.stderrDirChild.empty()) {
        DWORD gle = 0;
        if (!FileHelpers::EnsureDirExists(config.stderrDirChild, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create/open --stderr-dir-child: " + config.stderrDirChild +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Prepared stderr-child log directory OK; path=" + config.stderrDirChild
        );

        gle = 0;
        if (!writers.stderrChildLogWriter.CreateNewFile(logPaths.running.stderrChildTxt, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create stderr-child log file: " + logPaths.running.stderrChildTxt +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        creationResults.stderrChildTxt = true;

        lifecycleDiag.DebugLine(
            L"Created stderr-child running log OK; path=" + logPaths.running.stderrChildTxt
        );
    }
    if (!config.stderrDirInclStdout.empty()) {
        DWORD gle = 0;
        if (!FileHelpers::EnsureDirExists(config.stderrDirInclStdout, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create/open --stderr-dir-incl-stdout: " + config.stderrDirInclStdout +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Prepared stderr-sr-and-child-incl-stdout log directory OK; path=" + config.stderrDirInclStdout
        );
        gle = 0;
        if (!writers.stderrSrAndChildInclStdoutLogWriter.CreateNewFile(logPaths.running.stderrSrAndChildInclStdoutTxt, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create stderr-sr-and-child-incl-stdout log file: " + logPaths.running.stderrSrAndChildInclStdoutTxt +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        creationResults.stderrSrAndChildInclStdoutTxt = true;

        lifecycleDiag.DebugLine(
            L"Created stderr-sr-and-child-incl-stdout running log OK; path=" + logPaths.running.stderrSrAndChildInclStdoutTxt
        );
    }

    if (!config.stdoutDir.empty()) {
        DWORD gle = 0;
        if (!FileHelpers::EnsureDirExists(config.stdoutDir, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create/open --stdout-dir: " + config.stdoutDir +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Prepared stdout log directory OK; path=" + config.stdoutDir
        );


        gle = 0;
        if (!writers.stdoutLogWriter.CreateNewFile(logPaths.running.stdoutTxt, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create stdout log file: " + logPaths.running.stdoutTxt +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        creationResults.stdoutTxt = true;

        lifecycleDiag.DebugLine(
            L"Created stdout running log OK; path=" + logPaths.running.stdoutTxt
        );
    }

    if (!config.stderrDirJsonl.empty()) {
        DWORD gle = 0;
        if (!FileHelpers::EnsureDirExists(config.stderrDirJsonl, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create/open --stderr-dir-jsonl: " + config.stderrDirJsonl +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Prepared stderr-sr-and-child JSONL log directory OK; path=" + config.stderrDirJsonl
        );

        gle = 0;
        if (!writers.stderrJsonlWriter.CreateNewFile(logPaths.running.stderrSrAndChildJsonl, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create stderr-sr-and-child JSONL log file: " + logPaths.running.stderrSrAndChildJsonl +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        creationResults.stderrSrAndChildJsonl = true;

        lifecycleDiag.DebugLine(
            L"Created stderr-sr-and-child JSONL running log OK; path=" + logPaths.running.stderrSrAndChildJsonl
        );
    }

    if (!config.stderrDirSrJsonl.empty()) {
        DWORD gle = 0;
        if (!FileHelpers::EnsureDirExists(config.stderrDirSrJsonl, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create/open --stderr-dir-sr-jsonl: " + config.stderrDirSrJsonl +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Prepared stderr-sr JSONL log directory OK; path=" + config.stderrDirSrJsonl
        );

        gle = 0;
        if (!writers.stderrSrJsonlWriter.CreateNewFile(logPaths.running.stderrSrJsonl, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create stderr-sr JSONL log file: " + logPaths.running.stderrSrJsonl +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        creationResults.stderrSrJsonl = true;

        lifecycleDiag.DebugLine(
            L"Created stderr-sr JSONL running log OK; path=" + logPaths.running.stderrSrJsonl
        );
    }

    if (!config.stderrDirChildJsonl.empty()) {
        DWORD gle = 0;
        if (!FileHelpers::EnsureDirExists(config.stderrDirChildJsonl, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create/open --stderr-dir-child-jsonl: " + config.stderrDirChildJsonl +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Prepared stderr-child JSONL log directory OK; path=" + config.stderrDirChildJsonl
        );

        gle = 0;
        if (!writers.stderrChildJsonlWriter.CreateNewFile(logPaths.running.stderrChildJsonl, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create stderr-child JSONL log file: " + logPaths.running.stderrChildJsonl +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        creationResults.stderrChildJsonl = true;

        lifecycleDiag.DebugLine(
            L"Created stderr-child JSONL running log OK; path=" + logPaths.running.stderrChildJsonl
        );
    }
    if (!config.stderrDirInclStdoutJsonl.empty()) {
        DWORD gle = 0;
        if (!FileHelpers::EnsureDirExists(config.stderrDirInclStdoutJsonl, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create/open --stderr-dir-incl-stdout-jsonl: " + config.stderrDirInclStdoutJsonl +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Prepared stderr-sr-and-child-incl-stdout JSONL log directory OK; path=" + config.stderrDirInclStdoutJsonl
        );
        gle = 0;
        if (!writers.stderrSrAndChildInclStdoutJsonlWriter.CreateNewFile(logPaths.running.stderrSrAndChildInclStdoutJsonl, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create stderr-sr-and-child-incl-stdout JSONL log file: " + logPaths.running.stderrSrAndChildInclStdoutJsonl +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        creationResults.stderrSrAndChildInclStdoutJsonl = true;

        lifecycleDiag.DebugLine(
            L"Created stderr-sr-and-child-incl-stdout JSONL running log OK; path=" + logPaths.running.stderrSrAndChildInclStdoutJsonl
        );
    }

    if (!config.stdoutDirJsonl.empty()) {
        DWORD gle = 0;
        if (!FileHelpers::EnsureDirExists(config.stdoutDirJsonl, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create/open --stdout-dir-jsonl: " + config.stdoutDirJsonl +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Prepared stdout JSONL log directory OK; path=" + config.stdoutDirJsonl
        );

        gle = 0;
        if (!writers.stdoutJsonlWriter.CreateNewFile(logPaths.running.stdoutJsonl, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create stdout JSONL log file: " + logPaths.running.stdoutJsonl +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        creationResults.stdoutJsonl = true;
        lifecycleDiag.DebugLine(
            L"Created stdout JSONL running log OK; path=" + logPaths.running.stdoutJsonl
        );
    }

    SRChildCmdBuilder childCmdBuilder;

    if (!childCmdBuilder.Build(
            config.argVector,
            config.childArgsStartIndex,
            config.executionMode,
            config.utf8
        )) {
        lifecycleDiag.FatalErrorLine(
            childCmdBuilder.err
        );
        result.earlyExitCode = 2;
        return;
    }

    result.fullCmdLineForCreateProcess =
        childCmdBuilder.fullCmdLineForCreateProcess;

    result.specialCharactersDebugMessage =
        childCmdBuilder.specialCharactersDebugMessage;

    fileSinkWorker.AttachLogWriters(
        creationResults.stdoutTxt,
        &writers.stdoutLogWriter,
        logPaths.running.stdoutTxt,

        creationResults.stderrSrAndChildTxt,
        &writers.stderrLogWriter,
        logPaths.running.stderrSrAndChildTxt,

        creationResults.stderrChildTxt,
        &writers.stderrChildLogWriter,
        logPaths.running.stderrChildTxt,

        creationResults.stderrSrTxt,
        &writers.stderrSrLogWriter,
        logPaths.running.stderrSrTxt,

        creationResults.stderrSrAndChildInclStdoutTxt,
        &writers.stderrSrAndChildInclStdoutLogWriter,
        logPaths.running.stderrSrAndChildInclStdoutTxt
    );

    fileSinkWorker.AttachJsonlWriters(

        creationResults.stdoutJsonl,
        &writers.stdoutJsonlWriter,
        logPaths.running.stdoutJsonl,

        creationResults.stderrSrAndChildJsonl,
        &writers.stderrJsonlWriter,
        logPaths.running.stderrSrAndChildJsonl,

        creationResults.stderrChildJsonl,
        &writers.stderrChildJsonlWriter,
        logPaths.running.stderrChildJsonl,

        creationResults.stderrSrJsonl,
        &writers.stderrSrJsonlWriter,
        logPaths.running.stderrSrJsonl,

        creationResults.stderrSrAndChildInclStdoutJsonl,
        &writers.stderrSrAndChildInclStdoutJsonlWriter,
        logPaths.running.stderrSrAndChildInclStdoutJsonl
    );

    result.ok = true;
    result.earlyExitCode = 0;
    return;
}
