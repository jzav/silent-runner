#include "SRPrepareRuntime.h"
#include <memory>

#include "CmdBuilder.h"
#include "ErrorHelpers.h"
#include "FileHelpers.h"
#include "LogWriter.h"
#include "SRLifecycleDiagnostics.h"

void PrepareRuntime(
    const SR::Options& opt,
    SRLifecycleDiagnostics& lifecycleDiag,
    SR::LogPaths& logPaths,
    SRPrepareResult& result
) {
    SRPreparedRuntime& prepared = result.prepared;
    prepared.stdoutStdHandleProbe =
        HandleHelpers::ProbeStdHandleForWrite(GetStdHandle(STD_OUTPUT_HANDLE));
    prepared.stderrStdHandleProbe =
        HandleHelpers::ProbeStdHandleForWrite(GetStdHandle(STD_ERROR_HANDLE));

    const bool srDiagFileRequested =
        !opt.stderrDir.empty() ||
        !opt.stderrSrDir.empty() ||
        !opt.stderrSrAndChildInclStdoutDir.empty() ||
        !opt.stderrJsonlDir.empty() ||
        !opt.stderrSrJsonlDir.empty() ||
        !opt.stderrSrAndChildInclStdoutJsonlDir.empty();

    const bool srDiagParentRequested =
        opt.stderrEmit != SR::EmitMode::Never &&
        opt.stderrEmitSource != SR::StderrEmitSource::Child;

    const bool srDiagParentAvailable =
        srDiagParentRequested &&
        prepared.stderrStdHandleProbe.probablyWritable;

    if (!srDiagFileRequested && !srDiagParentAvailable) {
        result.earlyExitCode = 254;
        return;
    }

    const bool userEnteredAnyIdPart =
        !opt.idPrefix.empty() ||
        !opt.idBase.empty() ||
        (opt.idSuffix != SR::IdSuffixMode::None);

    prepared.useDefaultSuffixMode = !userEnteredAnyIdPart;

    prepared.effectiveIdSuffixMode =
        prepared.useDefaultSuffixMode ? SR::IdSuffixMode::TimestampPid : opt.idSuffix;

    if (prepared.effectiveIdSuffixMode != SR::IdSuffixMode::None) {
        prepared.generatedSuffix = FileHelpers::BuildIdSuffix(prepared.effectiveIdSuffixMode);
    }

    prepared.executionId = FileHelpers::BuildExecutionId(
        opt.idPrefix,
        opt.idBase,
        prepared.generatedSuffix
    );

    prepared.stdoutRunningName = prepared.executionId + L"_stdout_running.log";
    prepared.stdoutSuccessName = prepared.executionId + L"_stdout_success.log";
    prepared.stdoutFailureName = prepared.executionId + L"_stdout_failure.log";
    
    prepared.stderrRunningName = prepared.executionId + L"_stderr_running.log";
    prepared.stderrSuccessName = prepared.executionId + L"_stderr_success.log";
    prepared.stderrFailureName = prepared.executionId + L"_stderr_failure.log";

    prepared.stderrChildRunningName = prepared.executionId + L"_stderr_child_running.log";
    prepared.stderrChildSuccessName = prepared.executionId + L"_stderr_child_success.log";
    prepared.stderrChildFailureName = prepared.executionId + L"_stderr_child_failure.log";

    prepared.stderrSrRunningName = prepared.executionId + L"_stderr_sr_running.log";
    prepared.stderrSrSuccessName = prepared.executionId + L"_stderr_sr_success.log";
    prepared.stderrSrFailureName = prepared.executionId + L"_stderr_sr_failure.log";
    prepared.stderrSrAndChildInclStdoutRunningName = prepared.executionId + L"_stderr_incl_stdout_running.log";
    prepared.stderrSrAndChildInclStdoutSuccessName = prepared.executionId + L"_stderr_incl_stdout_success.log";
    prepared.stderrSrAndChildInclStdoutFailureName = prepared.executionId + L"_stderr_incl_stdout_failure.log";
    prepared.stdoutJsonlRunningName = prepared.executionId + L"_stdout_running.jsonl";
    prepared.stdoutJsonlSuccessName = prepared.executionId + L"_stdout_success.jsonl";
    prepared.stdoutJsonlFailureName = prepared.executionId + L"_stdout_failure.jsonl";

    prepared.stderrJsonlRunningName = prepared.executionId + L"_stderr_running.jsonl";
    prepared.stderrJsonlSuccessName = prepared.executionId + L"_stderr_success.jsonl";
    prepared.stderrJsonlFailureName = prepared.executionId + L"_stderr_failure.jsonl";

    prepared.stderrChildJsonlRunningName = prepared.executionId + L"_stderr_child_running.jsonl";
    prepared.stderrChildJsonlSuccessName = prepared.executionId + L"_stderr_child_success.jsonl";
    prepared.stderrChildJsonlFailureName = prepared.executionId + L"_stderr_child_failure.jsonl";

    prepared.stderrSrJsonlRunningName = prepared.executionId + L"_stderr_sr_running.jsonl";
    prepared.stderrSrJsonlSuccessName = prepared.executionId + L"_stderr_sr_success.jsonl";
    prepared.stderrSrJsonlFailureName = prepared.executionId + L"_stderr_sr_failure.jsonl";
    prepared.stderrSrAndChildInclStdoutJsonlRunningName = prepared.executionId + L"_stderr_incl_stdout_running.jsonl";
    prepared.stderrSrAndChildInclStdoutJsonlSuccessName = prepared.executionId + L"_stderr_incl_stdout_success.jsonl";
    prepared.stderrSrAndChildInclStdoutJsonlFailureName = prepared.executionId + L"_stderr_incl_stdout_failure.jsonl";
    prepared.probeLogName = prepared.executionId + L"_probe.log";



    // Build the candidate log paths before opening any log files.
    //
    // Important:
    // - opt.stdoutDir / opt.stderrDir may be relative paths.
    // - Relative log directories are resolved later by WinAPI calls against
    //   SilentRunner's inherited current working directory (from parent process), not against --cwd.
    // - --cwd affects the child process and run-on-* hook working directory only.
    // - Preflight checks include running/success/failure names so SilentRunner does
    //   not overwrite an existing log from a previous execution ID.
    if (!opt.probeDir.empty()) {
        prepared.probeLogPath = FileHelpers::JoinPath(opt.probeDir, prepared.probeLogName);

        if (FileHelpers::FileExists(prepared.probeLogPath)) {
            lifecycleDiag.FatalErrorLine(
                L"Refusing to start: probe log file already exists\n"
                L"  EXECUTION_ID=" + prepared.executionId + L"\n"
                L"  DIR=" + opt.probeDir + L"\n"
                L"  EXISTING PATH:\n"
                L"    " + prepared.probeLogPath
            );
            result.earlyExitCode = 255;
            return;
        }
    }


    if (!opt.stderrDir.empty()) {
        logPaths.running.stderrSrAndChildTxt = FileHelpers::JoinPath(opt.stderrDir, prepared.stderrRunningName);
        logPaths.success.stderrSrAndChildTxt = FileHelpers::JoinPath(opt.stderrDir, prepared.stderrSuccessName);
        logPaths.failure.stderrSrAndChildTxt = FileHelpers::JoinPath(opt.stderrDir, prepared.stderrFailureName);

        if (FileHelpers::FileExists(logPaths.running.stderrSrAndChildTxt) ||
            FileHelpers::FileExists(logPaths.success.stderrSrAndChildTxt) ||
            FileHelpers::FileExists(logPaths.failure.stderrSrAndChildTxt)) {
            lifecycleDiag.FatalErrorLine(
                L"Refusing to start: stderr-sr-and-child log files already exist\n"
                L"  EXECUTION_ID=" + prepared.executionId + L"\n"
                L"  DIR=" + opt.stderrDir + L"\n"
                L"  EXISTING PATHS:\n"
                L"    " + logPaths.running.stderrSrAndChildTxt + L"\n"
                L"    " + logPaths.success.stderrSrAndChildTxt + L"\n"
                L"    " + logPaths.failure.stderrSrAndChildTxt
            );
            result.earlyExitCode = 255;
            return;
        }
    }

    if (!opt.stderrSrDir.empty()) {
        logPaths.running.stderrSrTxt = FileHelpers::JoinPath(opt.stderrSrDir, prepared.stderrSrRunningName);
        logPaths.success.stderrSrTxt = FileHelpers::JoinPath(opt.stderrSrDir, prepared.stderrSrSuccessName);
        logPaths.failure.stderrSrTxt = FileHelpers::JoinPath(opt.stderrSrDir, prepared.stderrSrFailureName);

        if (FileHelpers::FileExists(logPaths.running.stderrSrTxt) ||
            FileHelpers::FileExists(logPaths.success.stderrSrTxt) ||
            FileHelpers::FileExists(logPaths.failure.stderrSrTxt)) {
            lifecycleDiag.FatalErrorLine(
                L"Refusing to start: stderr-sr log files already exist\n"
                L"  EXECUTION_ID=" + prepared.executionId + L"\n"
                L"  DIR=" + opt.stderrSrDir + L"\n"
                L"  EXISTING PATHS:\n"
                L"    " + logPaths.running.stderrSrTxt + L"\n"
                L"    " + logPaths.success.stderrSrTxt + L"\n"
                L"    " + logPaths.failure.stderrSrTxt
            );
            result.earlyExitCode = 255;
            return;
        }
    }

    if (!opt.stderrChildDir.empty()) {
        logPaths.running.stderrChildTxt = FileHelpers::JoinPath(opt.stderrChildDir, prepared.stderrChildRunningName);
        logPaths.success.stderrChildTxt = FileHelpers::JoinPath(opt.stderrChildDir, prepared.stderrChildSuccessName);
        logPaths.failure.stderrChildTxt = FileHelpers::JoinPath(opt.stderrChildDir, prepared.stderrChildFailureName);

        if (FileHelpers::FileExists(logPaths.running.stderrChildTxt) ||
            FileHelpers::FileExists(logPaths.success.stderrChildTxt) ||
            FileHelpers::FileExists(logPaths.failure.stderrChildTxt)) {
            lifecycleDiag.FatalErrorLine(
                L"Refusing to start: stderr-child log files already exist\n"
                L"  EXECUTION_ID=" + prepared.executionId + L"\n"
                L"  DIR=" + opt.stderrChildDir + L"\n"
                L"  EXISTING PATHS:\n"
                L"    " + logPaths.running.stderrChildTxt + L"\n"
                L"    " + logPaths.success.stderrChildTxt + L"\n"
                L"    " + logPaths.failure.stderrChildTxt
            );
            result.earlyExitCode = 255;
            return;
        }
    }

    if (!opt.stdoutDir.empty()) {
        logPaths.running.stdoutTxt = FileHelpers::JoinPath(opt.stdoutDir, prepared.stdoutRunningName);
        logPaths.success.stdoutTxt = FileHelpers::JoinPath(opt.stdoutDir, prepared.stdoutSuccessName);
        logPaths.failure.stdoutTxt = FileHelpers::JoinPath(opt.stdoutDir, prepared.stdoutFailureName);

        if (FileHelpers::FileExists(logPaths.running.stdoutTxt) ||
            FileHelpers::FileExists(logPaths.success.stdoutTxt) ||
            FileHelpers::FileExists(logPaths.failure.stdoutTxt)) {
            lifecycleDiag.FatalErrorLine(
                L"Refusing to start: stdout log files already exist\n"
                L"  EXECUTION_ID=" + prepared.executionId + L"\n"
                L"  DIR=" + opt.stdoutDir + L"\n"
                L"  EXISTING PATHS:\n"
                L"    " + logPaths.running.stdoutTxt + L"\n"
                L"    " + logPaths.success.stdoutTxt + L"\n"
                L"    " + logPaths.failure.stdoutTxt
            );
            result.earlyExitCode = 255;
            return;
        }
    }
    if (!opt.stderrSrAndChildInclStdoutDir.empty()) {
        logPaths.running.stderrSrAndChildInclStdoutTxt = FileHelpers::JoinPath(opt.stderrSrAndChildInclStdoutDir, prepared.stderrSrAndChildInclStdoutRunningName);
        logPaths.success.stderrSrAndChildInclStdoutTxt = FileHelpers::JoinPath(opt.stderrSrAndChildInclStdoutDir, prepared.stderrSrAndChildInclStdoutSuccessName);
        logPaths.failure.stderrSrAndChildInclStdoutTxt = FileHelpers::JoinPath(opt.stderrSrAndChildInclStdoutDir, prepared.stderrSrAndChildInclStdoutFailureName);
        if (FileHelpers::FileExists(logPaths.running.stderrSrAndChildInclStdoutTxt) ||
            FileHelpers::FileExists(logPaths.success.stderrSrAndChildInclStdoutTxt) ||
            FileHelpers::FileExists(logPaths.failure.stderrSrAndChildInclStdoutTxt)) {
            lifecycleDiag.FatalErrorLine(
                L"Refusing to start: stderr-sr-and-child-incl-stdout log files already exist\n"
                L"  EXECUTION_ID=" + prepared.executionId + L"\n"
                L"  DIR=" + opt.stderrSrAndChildInclStdoutDir + L"\n"
                L"  EXISTING PATHS:\n"
                L"    " + logPaths.running.stderrSrAndChildInclStdoutTxt + L"\n"
                L"    " + logPaths.success.stderrSrAndChildInclStdoutTxt + L"\n"
                L"    " + logPaths.failure.stderrSrAndChildInclStdoutTxt
            );
            result.earlyExitCode = 255;
            return;
        }
    }

    if (!opt.stderrJsonlDir.empty()) {
        logPaths.running.stderrSrAndChildJsonl = FileHelpers::JoinPath(opt.stderrJsonlDir, prepared.stderrJsonlRunningName);
        logPaths.success.stderrSrAndChildJsonl = FileHelpers::JoinPath(opt.stderrJsonlDir, prepared.stderrJsonlSuccessName);
        logPaths.failure.stderrSrAndChildJsonl = FileHelpers::JoinPath(opt.stderrJsonlDir, prepared.stderrJsonlFailureName);

        if (FileHelpers::FileExists(logPaths.running.stderrSrAndChildJsonl) ||
            FileHelpers::FileExists(logPaths.success.stderrSrAndChildJsonl) ||
            FileHelpers::FileExists(logPaths.failure.stderrSrAndChildJsonl)) {
            lifecycleDiag.FatalErrorLine(
                L"Refusing to start: stderr-sr-and-child JSONL log files already exist\n"
                L"  EXECUTION_ID=" + prepared.executionId + L"\n"
                L"  DIR=" + opt.stderrJsonlDir + L"\n"
                L"  EXISTING PATHS:\n"
                L"    " + logPaths.running.stderrSrAndChildJsonl + L"\n"
                L"    " + logPaths.success.stderrSrAndChildJsonl + L"\n"
                L"    " + logPaths.failure.stderrSrAndChildJsonl
            );
            result.earlyExitCode = 255;
            return;
        }
    }

    if (!opt.stderrSrJsonlDir.empty()) {
        logPaths.running.stderrSrJsonl = FileHelpers::JoinPath(opt.stderrSrJsonlDir, prepared.stderrSrJsonlRunningName);
        logPaths.success.stderrSrJsonl = FileHelpers::JoinPath(opt.stderrSrJsonlDir, prepared.stderrSrJsonlSuccessName);
        logPaths.failure.stderrSrJsonl = FileHelpers::JoinPath(opt.stderrSrJsonlDir, prepared.stderrSrJsonlFailureName);

        if (FileHelpers::FileExists(logPaths.running.stderrSrJsonl) ||
            FileHelpers::FileExists(logPaths.success.stderrSrJsonl) ||
            FileHelpers::FileExists(logPaths.failure.stderrSrJsonl)) {
            lifecycleDiag.FatalErrorLine(
                L"Refusing to start: stderr-sr JSONL log files already exist\n"
                L"  EXECUTION_ID=" + prepared.executionId + L"\n"
                L"  DIR=" + opt.stderrSrJsonlDir + L"\n"
                L"  EXISTING PATHS:\n"
                L"    " + logPaths.running.stderrSrJsonl + L"\n"
                L"    " + logPaths.success.stderrSrJsonl + L"\n"
                L"    " + logPaths.failure.stderrSrJsonl
            );
            result.earlyExitCode = 255;
            return;
        }
    }

    if (!opt.stderrChildJsonlDir.empty()) {
        logPaths.running.stderrChildJsonl = FileHelpers::JoinPath(opt.stderrChildJsonlDir, prepared.stderrChildJsonlRunningName);
        logPaths.success.stderrChildJsonl = FileHelpers::JoinPath(opt.stderrChildJsonlDir, prepared.stderrChildJsonlSuccessName);
        logPaths.failure.stderrChildJsonl = FileHelpers::JoinPath(opt.stderrChildJsonlDir, prepared.stderrChildJsonlFailureName);

        if (FileHelpers::FileExists(logPaths.running.stderrChildJsonl) ||
            FileHelpers::FileExists(logPaths.success.stderrChildJsonl) ||
            FileHelpers::FileExists(logPaths.failure.stderrChildJsonl)) {
            lifecycleDiag.FatalErrorLine(
                L"Refusing to start: stderr-child JSONL log files already exist\n"
                L"  EXECUTION_ID=" + prepared.executionId + L"\n"
                L"  DIR=" + opt.stderrChildJsonlDir + L"\n"
                L"  EXISTING PATHS:\n"
                L"    " + logPaths.running.stderrChildJsonl + L"\n"
                L"    " + logPaths.success.stderrChildJsonl + L"\n"
                L"    " + logPaths.failure.stderrChildJsonl
            );
            result.earlyExitCode = 255;
            return;
        }
    }

    if (!opt.stdoutJsonlDir.empty()) {
        logPaths.running.stdoutJsonl = FileHelpers::JoinPath(opt.stdoutJsonlDir, prepared.stdoutJsonlRunningName);
        logPaths.success.stdoutJsonl = FileHelpers::JoinPath(opt.stdoutJsonlDir, prepared.stdoutJsonlSuccessName);
        logPaths.failure.stdoutJsonl = FileHelpers::JoinPath(opt.stdoutJsonlDir, prepared.stdoutJsonlFailureName);

        if (FileHelpers::FileExists(logPaths.running.stdoutJsonl) ||
            FileHelpers::FileExists(logPaths.success.stdoutJsonl) ||
            FileHelpers::FileExists(logPaths.failure.stdoutJsonl)) {
            lifecycleDiag.FatalErrorLine(
                L"Refusing to start: stdout JSONL log files already exist\n"
                L"  EXECUTION_ID=" + prepared.executionId + L"\n"
                L"  DIR=" + opt.stdoutJsonlDir + L"\n"
                L"  EXISTING PATHS:\n"
                L"    " + logPaths.running.stdoutJsonl + L"\n"
                L"    " + logPaths.success.stdoutJsonl + L"\n"
                L"    " + logPaths.failure.stdoutJsonl
            );
            result.earlyExitCode = 255;
            return;
        }
    }
    if (!opt.stderrSrAndChildInclStdoutJsonlDir.empty()) {
        logPaths.running.stderrSrAndChildInclStdoutJsonl = FileHelpers::JoinPath(opt.stderrSrAndChildInclStdoutJsonlDir, prepared.stderrSrAndChildInclStdoutJsonlRunningName);
        logPaths.success.stderrSrAndChildInclStdoutJsonl = FileHelpers::JoinPath(opt.stderrSrAndChildInclStdoutJsonlDir, prepared.stderrSrAndChildInclStdoutJsonlSuccessName);
        logPaths.failure.stderrSrAndChildInclStdoutJsonl = FileHelpers::JoinPath(opt.stderrSrAndChildInclStdoutJsonlDir, prepared.stderrSrAndChildInclStdoutJsonlFailureName);
        if (FileHelpers::FileExists(logPaths.running.stderrSrAndChildInclStdoutJsonl) ||
            FileHelpers::FileExists(logPaths.success.stderrSrAndChildInclStdoutJsonl) ||
            FileHelpers::FileExists(logPaths.failure.stderrSrAndChildInclStdoutJsonl)) {
            lifecycleDiag.FatalErrorLine(
                L"Refusing to start: stderr-sr-and-child-incl-stdout JSONL log files already exist\n"
                L"  EXECUTION_ID=" + prepared.executionId + L"\n"
                L"  DIR=" + opt.stderrSrAndChildInclStdoutJsonlDir + L"\n"
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
    if (!opt.probeDir.empty()) {
        DWORD gle = 0;
        if (!FileHelpers::EnsureDirExists(opt.probeDir, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create/open --probe-dir: " + opt.probeDir +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }

        if (!lifecycleDiag.TrySetProbeLogPath(prepared.probeLogPath)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create probe log file: " + prepared.probeLogPath
            );
            result.earlyExitCode = 255;
            return;
        }

        lifecycleDiag.ProbeLine(
            L"Probe log initialized; path=" + prepared.probeLogPath
        );
    }
    if (!opt.stderrDir.empty()) {
        DWORD gle = 0;
        if (!FileHelpers::EnsureDirExists(opt.stderrDir, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create/open --stderr-dir: " + opt.stderrDir +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Prepared stderr-sr-and-child log directory OK; path=" + opt.stderrDir
        );

        gle = 0;
        if (!prepared.stderrLogWriter.CreateNewFile(logPaths.running.stderrSrAndChildTxt, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create stderr-sr-and-child log file: " + logPaths.running.stderrSrAndChildTxt +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Created stderr-sr-and-child running log OK; path=" + logPaths.running.stderrSrAndChildTxt
        );
    }

    if (!opt.stderrSrDir.empty()) {
        DWORD gle = 0;
        if (!FileHelpers::EnsureDirExists(opt.stderrSrDir, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create/open --stderr-dir-sr: " + opt.stderrSrDir +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Prepared stderr-sr log directory OK; path=" + opt.stderrSrDir
        );

        gle = 0;
        if (!prepared.stderrSrLogWriter.CreateNewFile(logPaths.running.stderrSrTxt, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create stderr-sr log file: " + logPaths.running.stderrSrTxt +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Created stderr-sr running log OK; path=" + logPaths.running.stderrSrTxt
        );
    }

    if (!opt.stderrChildDir.empty()) {
        DWORD gle = 0;
        if (!FileHelpers::EnsureDirExists(opt.stderrChildDir, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create/open --stderr-dir-child: " + opt.stderrChildDir +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Prepared stderr-child log directory OK; path=" + opt.stderrChildDir
        );

        gle = 0;
        if (!prepared.stderrChildLogWriter.CreateNewFile(logPaths.running.stderrChildTxt, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create stderr-child log file: " + logPaths.running.stderrChildTxt +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Created stderr-child running log OK; path=" + logPaths.running.stderrChildTxt
        );
    }
    if (!opt.stderrSrAndChildInclStdoutDir.empty()) {
        DWORD gle = 0;
        if (!FileHelpers::EnsureDirExists(opt.stderrSrAndChildInclStdoutDir, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create/open --stderr-dir-incl-stdout: " + opt.stderrSrAndChildInclStdoutDir +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Prepared stderr-sr-and-child-incl-stdout log directory OK; path=" + opt.stderrSrAndChildInclStdoutDir
        );
        gle = 0;
        if (!prepared.stderrSrAndChildInclStdoutLogWriter.CreateNewFile(logPaths.running.stderrSrAndChildInclStdoutTxt, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create stderr-sr-and-child-incl-stdout log file: " + logPaths.running.stderrSrAndChildInclStdoutTxt +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Created stderr-sr-and-child-incl-stdout running log OK; path=" + logPaths.running.stderrSrAndChildInclStdoutTxt
        );
    }

    if (!opt.stdoutDir.empty()) {
        DWORD gle = 0;
        if (!FileHelpers::EnsureDirExists(opt.stdoutDir, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create/open --stdout-dir: " + opt.stdoutDir +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Prepared stdout log directory OK; path=" + opt.stdoutDir
        );


        gle = 0;
        if (!prepared.stdoutLogWriter.CreateNewFile(logPaths.running.stdoutTxt, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create stdout log file: " + logPaths.running.stdoutTxt +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Created stdout running log OK; path=" + logPaths.running.stdoutTxt
        );
    }

    if (!opt.stderrJsonlDir.empty()) {
        DWORD gle = 0;
        if (!FileHelpers::EnsureDirExists(opt.stderrJsonlDir, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create/open --stderr-dir-jsonl: " + opt.stderrJsonlDir +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Prepared stderr-sr-and-child JSONL log directory OK; path=" + opt.stderrJsonlDir
        );

        gle = 0;
        if (!prepared.stderrJsonlWriter.CreateNewFile(logPaths.running.stderrSrAndChildJsonl, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create stderr-sr-and-child JSONL log file: " + logPaths.running.stderrSrAndChildJsonl +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Created stderr-sr-and-child JSONL running log OK; path=" + logPaths.running.stderrSrAndChildJsonl
        );
    }

    if (!opt.stderrSrJsonlDir.empty()) {
        DWORD gle = 0;
        if (!FileHelpers::EnsureDirExists(opt.stderrSrJsonlDir, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create/open --stderr-dir-sr-jsonl: " + opt.stderrSrJsonlDir +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Prepared stderr-sr JSONL log directory OK; path=" + opt.stderrSrJsonlDir
        );

        gle = 0;
        if (!prepared.stderrSrJsonlWriter.CreateNewFile(logPaths.running.stderrSrJsonl, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create stderr-sr JSONL log file: " + logPaths.running.stderrSrJsonl +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Created stderr-sr JSONL running log OK; path=" + logPaths.running.stderrSrJsonl
        );
    }

    if (!opt.stderrChildJsonlDir.empty()) {
        DWORD gle = 0;
        if (!FileHelpers::EnsureDirExists(opt.stderrChildJsonlDir, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create/open --stderr-dir-child-jsonl: " + opt.stderrChildJsonlDir +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Prepared stderr-child JSONL log directory OK; path=" + opt.stderrChildJsonlDir
        );

        gle = 0;
        if (!prepared.stderrChildJsonlWriter.CreateNewFile(logPaths.running.stderrChildJsonl, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create stderr-child JSONL log file: " + logPaths.running.stderrChildJsonl +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Created stderr-child JSONL running log OK; path=" + logPaths.running.stderrChildJsonl
        );
    }
    if (!opt.stderrSrAndChildInclStdoutJsonlDir.empty()) {
        DWORD gle = 0;
        if (!FileHelpers::EnsureDirExists(opt.stderrSrAndChildInclStdoutJsonlDir, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create/open --stderr-dir-incl-stdout-jsonl: " + opt.stderrSrAndChildInclStdoutJsonlDir +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Prepared stderr-sr-and-child-incl-stdout JSONL log directory OK; path=" + opt.stderrSrAndChildInclStdoutJsonlDir
        );
        gle = 0;
        if (!prepared.stderrSrAndChildInclStdoutJsonlWriter.CreateNewFile(logPaths.running.stderrSrAndChildInclStdoutJsonl, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create stderr-sr-and-child-incl-stdout JSONL log file: " + logPaths.running.stderrSrAndChildInclStdoutJsonl +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Created stderr-sr-and-child-incl-stdout JSONL running log OK; path=" + logPaths.running.stderrSrAndChildInclStdoutJsonl
        );
    }

    if (!opt.stdoutJsonlDir.empty()) {
        DWORD gle = 0;
        if (!FileHelpers::EnsureDirExists(opt.stdoutJsonlDir, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create/open --stdout-dir-jsonl: " + opt.stdoutJsonlDir +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Prepared stdout JSONL log directory OK; path=" + opt.stdoutJsonlDir
        );

        gle = 0;
        if (!prepared.stdoutJsonlWriter.CreateNewFile(logPaths.running.stdoutJsonl, &gle)) {
            lifecycleDiag.FatalErrorLine(
                L"Failed to create stdout JSONL log file: " + logPaths.running.stdoutJsonl +
                L" " + ErrorHelpers::FormatGle(gle)
            );
            result.earlyExitCode = 255;
            return;
        }
        lifecycleDiag.DebugLine(
            L"Created stdout JSONL running log OK; path=" + logPaths.running.stdoutJsonl
        );
    }

    prepared.fullCmdLineForCreateProcess = CmdBuilder::BuildCmdExeCommandLine(opt);

    result.ok = true;
    result.earlyExitCode = 0;
    return;
}
