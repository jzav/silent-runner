#include "SRPrepareRuntime.h"
#include "SRWorkerCommonPolicy.h"
#include "SRTargetLogFiles.h"

#include "SRChildCmdBuilder.h"
#include "ErrorHelpers.h"
#include "FileHelpers.h"
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
        const SR::JobTarget stderrParentTarget =
            parentEmitPolicy.StderrParentTarget();
        const wchar_t* sourceName =
            SR::JobTargetNameToString(stderrParentTarget);
        const wchar_t* dirArg = L"<unknown stderr target>";

        switch (stderrParentTarget) {
            case SR::JobTarget::StderrSrAndChildParent:
                dirArg = L"--stderr-dir or --stderr-dir-jsonl";
                break;
            case SR::JobTarget::StderrChildParent:
                dirArg = L"--stderr-dir-child or --stderr-dir-child-jsonl";
                break;
            case SR::JobTarget::StderrChildParentRaw:
                dirArg = L"--stderr-dir-child-raw";
                break;
            case SR::JobTarget::StderrSrParent:
                dirArg = L"--stderr-dir-sr or --stderr-dir-sr-jsonl";
                break;
            case SR::JobTarget::StderrSrAndChildInclStdoutParent:
                dirArg = L"--stderr-dir-incl-stdout or --stderr-dir-incl-stdout-jsonl";
                break;
            default:
                break;
        }

        messages.push_back(
            std::wstring(L"Stderr buffering is enabled for ") + sourceName +
            L" without a matching stderr log file and without a buffer limit.\n"
            L"  EMIT_MODE=end/success/failure may buffer stderr in RAM until replay.\n"
            L"  Consider using " + dirArg +
            L", --stderr-max-buffer-bytes, or --std-total-max-buffer-bytes."
        );
    }
}

static bool TryExpandConfiguredPath(
    const std::wstring& rawPath,
    const wchar_t* argumentName,
    std::wstring& expandedPath,
    std::wstring& err
) {
    std::wstring missingVariable;
    DWORD gle = 0;
    if (FileHelpers::TryExpandEnvironmentVariables(
            rawPath,
            expandedPath,
            missingVariable,
            &gle
        )) {
        return true;
    }
    err = std::wstring(L"Invalid value for ") +
        argumentName + L": ";
    if (!missingVariable.empty()) {
        err += L"environment variable %" +
            missingVariable + L"% is not defined";
    } else {
        err += L"failed to expand environment variables " +
            ErrorHelpers::FormatGle(gle);
    }
    return false;
}

static bool ValidateConfiguredCwd(
    std::wstring& cwd,
    std::wstring& err
) {
    if (cwd.empty()) {
        return true;
    }
    std::wstring expandedCwd;
    if (!TryExpandConfiguredPath(
            cwd,
            L"--cwd",
            expandedCwd,
            err
        )) {
        return false;
    }
    if (expandedCwd.empty() ||
        !FileHelpers::DirectoryExists(expandedCwd)) {
        err =
            L"Invalid value for --cwd: "
            L"path must point to an existing directory";
        return false;
    }
    cwd = expandedCwd;
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

    std::wstring expandedPath;
    if (!TryExpandConfiguredPath(
            rawPath,
            argumentName,
            expandedPath,
            err
        )) {
        return false;
    }
    std::wstring resolvedPath;
    if (!FileHelpers::TryResolveFullPath(
            expandedPath,
            resolvedPath
        )) {
        err =
            std::wstring(L"Invalid value for ") +
            argumentName +
            L": failed to resolve path";
        return false;
    }

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
    SR::PrepareRuntimeConfig& config,
    SR::ExecuteChildProcessConfig& runtimeConfig,
    SR::FinalizeExecutionConfig& finalizeConfig,
    const SRWorkerCommonPolicy& workerCommonPolicy,
    SRFileSinkWorker& fileSinkWorker,
    SRTargetLogFiles& targetLogFiles,
    const SRParentEmitPolicy& parentEmitPolicy,
    SRLifecycleDiagnostics& lifecycleDiag,
    SRPrepareResult& result
) {
    SRTargetLogFiles& logFiles = targetLogFiles;
    std::wstring probePath;
    finalizeConfig.comspecPath.clear();
    finalizeConfig.runOnSuccessPath.clear();
    finalizeConfig.runOnFailurePath.clear();

    AppendUnboundedBufferedReplayDebugMessages(
        config,
        parentEmitPolicy,
        result.unboundedReplayBufferDebugMessages
    );

    result.stdoutStdHandleProbe =
        HandleHelpers::ProbeStdHandleForWrite(GetStdHandle(STD_OUTPUT_HANDLE));
    result.stderrStdHandleProbe =
        HandleHelpers::ProbeStdHandleForWrite(GetStdHandle(STD_ERROR_HANDLE));

    std::wstring preparePathError;
    if (!FileHelpers::TryResolveComSpecPath(
            result.comspecPath,
            preparePathError
        )) {
        lifecycleDiag.FatalErrorLine(preparePathError);
        result.earlyExitCode = 255;
        return;
    }
    finalizeConfig.comspecPath = result.comspecPath;

    if (!ValidateConfiguredCwd(
            config.cwd,
            preparePathError
        )) {
        lifecycleDiag.FatalErrorLine(preparePathError);
        result.earlyExitCode = 2;
        return;
    }
    runtimeConfig.cwd = config.cwd;
    finalizeConfig.cwd = config.cwd;

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

    finalizeConfig.runOnSuccessPath =
        resolvedRunOnSuccessPath;
    finalizeConfig.runOnFailurePath =
        resolvedRunOnFailurePath;

    // Resolve and validate persistent log paths before creating any log files.
    // Relative directories are resolved against SilentRunner's inherited
    // working directory, not the child working directory (--cwd).
    // The probe log is prepared separately.
    if (!config.probeDir.empty()) {
        std::wstring expandedProbeDir;
        if (!TryExpandConfiguredPath(
                config.probeDir,
                L"--probe-dir",
                expandedProbeDir,
                preparePathError
            )) {
            lifecycleDiag.FatalErrorLine(preparePathError);
            result.earlyExitCode = 2;
            return;
        }
        if (expandedProbeDir.empty()) {
            lifecycleDiag.FatalErrorLine(
                L"Invalid value for --probe-dir: expanded path is empty"
            );
            result.earlyExitCode = 2;
            return;
        }
        config.probeDir = expandedProbeDir;
        probePath =
            FileHelpers::JoinPath(
                config.probeDir,
                workerCommonPolicy.ExecutionId() + L"_probe.log"
            );

        if (FileHelpers::FileExists(probePath)) {
            lifecycleDiag.FatalErrorLine(
                L"Refusing to start: probe log file already exists\n"
                L"  EXECUTION_ID=" + workerCommonPolicy.ExecutionId() + L"\n"
                L"  DIR=" + config.probeDir + L"\n"
                L"  EXISTING PATH:\n"
                L"    " + probePath
            );
            result.earlyExitCode = 255;
            return;
        }
    }


    LogCreationFailure logFailure;

    if (!logFiles.ResolveDirectories(&logFailure)) {
        const auto& target = logFiles.Target(logFailure.target);
        const bool invalidConfiguration =
            logFailure.reason == LogCreationFailureReason::ExpandDirectoryFailed;

        std::wstring message =
            invalidConfiguration
                ? L"Invalid value for log directory; target="
                : L"Failed to resolve log directory; target=";

        message +=
            std::wstring(SR::JobTargetNameToString(logFailure.target)) +
            L"; path=" + target.config.directory;

        if (invalidConfiguration && !logFailure.missingVariable.empty()) {
            message +=
                L"; environment variable %" +
                logFailure.missingVariable + L"% is not defined";
        } else if (invalidConfiguration && logFailure.gle == 0) {
            message += L"; expanded directory path is empty";
        } else {
            message += L" " + ErrorHelpers::FormatGle(logFailure.gle);
        }

        lifecycleDiag.FatalErrorLine(message);
        result.earlyExitCode = invalidConfiguration ? 2 : 255;
        return;
    }

    logFiles.BuildLogPaths(workerCommonPolicy.ExecutionId());

    if (!logFiles.ValidateLogPaths(&logFailure)) {
        const auto& target = logFiles.Target(logFailure.target);

        const std::wstring& path =
            logFailure.slot == TargetLogFileSlot::Running
                ? target.running.path
                : logFailure.slot == TargetLogFileSlot::Success
                    ? target.success.path
                    : target.failure.path;

        std::wstring message =
            L"Refusing to start: log path validation failed; target=" +
            std::wstring(SR::JobTargetNameToString(logFailure.target)) +
            L"; path=" + path;

        if (logFailure.reason == LogCreationFailureReason::DuplicatePath) {
            const auto slotName = [](TargetLogFileSlot slot) {
                switch (slot) {
                    case TargetLogFileSlot::Running: return L"running";
                    case TargetLogFileSlot::Success: return L"success";
                    case TargetLogFileSlot::Failure: return L"failure";
                }
                return L"unknown";
            };

            message +=
                L"; slot=" + std::wstring(slotName(logFailure.slot)) +
                L"; duplicate of target=" +
                std::wstring(
                    SR::JobTargetNameToString(logFailure.conflictingTarget)
                ) +
                L"; slot=" + slotName(logFailure.conflictingSlot);
        } else if (logFailure.reason == LogCreationFailureReason::ExistingPath) {
            message += L"; path already exists or cannot be checked";
        }

        if (logFailure.gle != 0) {
            message += L" " + ErrorHelpers::FormatGle(logFailure.gle);
        }

        lifecycleDiag.FatalErrorLine(message);
        result.earlyExitCode = 255;
        return;
    }

    // Prepare the probe log separately from persistent running logs.
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

        if (!lifecycleDiag.TrySetProbeLogPath(probePath)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create probe log file: " + probePath
            );
            result.earlyExitCode = 255;
            return;
        }

        lifecycleDiag.ProbeLine(
            L"Probe log initialized; path=" + probePath
        );
    }
    if (!logFiles.PrepareRunningLogs(&logFailure)) {
        const auto& target = logFiles.Target(logFailure.target);

        const std::wstring messagePrefix =
            logFailure.reason == LogCreationFailureReason::EnsureDirectoryFailed
                ? L"Failed to create/open log directory; target="
                : L"Failed to create running log file; target=";

        const std::wstring& path =
            logFailure.reason == LogCreationFailureReason::EnsureDirectoryFailed
                ? target.config.directory
                : target.running.path;

        lifecycleDiag.FatalErrorLine(
            messagePrefix +
            std::wstring(SR::JobTargetNameToString(logFailure.target)) +
            L"; path=" + path +
            L" " + ErrorHelpers::FormatGle(logFailure.gle)
        );
        result.earlyExitCode = 255;
        return;
    }

    SRChildCmdBuilder childCmdBuilder;

    if (!childCmdBuilder.Build(
            result.comspecPath,
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

    SR::JobTargetFilter txtLogFilter;
    txtLogFilter.format = SR::JobTargetFormat::Txt;
    SR::JobTargetFilter jsonlLogFilter;
    jsonlLogFilter.format = SR::JobTargetFormat::Jsonl;
    fileSinkWorker.AttachTxtLogWriters(
        logFiles.BuildRunningBindings(txtLogFilter)
    );
    fileSinkWorker.AttachJsonlLogWriters(
        logFiles.BuildRunningBindings(jsonlLogFilter)
    );

    result.ok = true;
    result.earlyExitCode = 0;
    return;
}
