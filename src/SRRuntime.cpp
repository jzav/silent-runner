// SRRuntime - runner core orchestration
// -------------------------------------

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include <string>
#include <vector>
#include <exception>
#include <new>
#include <memory>

#include "SRRuntime.h"
#include "SRExecutionTimeline.h"


#include "CoreHelpers.h"
#include "ErrorHelpers.h"
#include "FileHelpers.h"
#include "HandleHelpers.h"
#include "ProcessHelpers.h"

#include "SRLogGatewayStdout.h"
#include "SRLogGatewayStderr.h"
#include "SRBufferLimiter.h"
#include "SRRuntimeStopReason.h"
#include "SRThreading.h"

#include "SRLifecycleDiagnostics.h"
#include "SRParentEmitPolicy.h"
#include "SRWorkerCommonPolicy.h"
#include "SRTargetLogFiles.h"

#include "SRChildStdReader.h"
#include "SRChildProcessWatcher.h"
#include "SRRuntimeCoordinator.h"
#include "SRTimeLimiter.h"
#include "SRWindowsJobObjectController.h"

using CoreHelpers::UniqueHandle;

namespace {

void DebugProcessChain_(
    SRLifecycleDiagnostics& diag,
    const wchar_t* tag,
    DWORD pid
) {
    if (!diag.IsDebugEnabled()) return;

    std::wstring line;
    if (tag && *tag) {
        line += tag;
        line += L": ";
    }
    line += ProcessHelpers::GetProcessDebugInfo(pid);
    diag.DebugLine(line);
}

void DebugStdHandleProbe_(
    SRLifecycleDiagnostics& diag,
    const wchar_t* tag,
    const HandleHelpers::StdHandleWriteProbeResult& probe
) {
    if (!diag.IsDebugEnabled()) return;

    std::wstring line;
    if (tag && *tag) {
        line += tag;
        line += L" ";
    }
    line += L"HANDLE=";
    if (probe.isNull) {
        line += L"NULL";
    } else if (probe.isInvalid) {
        line += L"INVALID_HANDLE_VALUE";
    } else {
        line += L"OK";
    }
    line += L" FILETYPE=";
    line += std::to_wstring(probe.fileType);
    if (probe.fileTypeGle != 0) {
        line += L" FILETYPE_GLE=";
        line += std::to_wstring(probe.fileTypeGle);
    }
    line += L" PROBABLY_WRITABLE=";
    line += probe.probablyWritable ? L"yes" : L"no";
    diag.DebugLine(line);
}

} // namespace

// Inspired by .NET 11 SafeFileHandle.CreateAnonymousPipe (Windows):
// https://github.com/dotnet/runtime/blob/main/src/libraries/System.Private.CoreLib/src/Microsoft/Win32/SafeHandles/SafeFileHandle.Windows.cs
//
// Use a unique named pipe to provide overlapped reads to SilentRunner while
// keeping the child's write handle synchronous and inheritable.
// FIRST_PIPE_INSTANCE and a single server instance prevent name reuse.
// Both ends must be opened successfully before the handles are exposed.
static bool CreateOverlappedChildOutputPipe(
    UniqueHandle& readPipe,
    UniqueHandle& writePipe,
    DWORD& outGle
) {
    outGle = ERROR_SUCCESS;

    BYTE randomBytes[16]{};
    const NTSTATUS status = BCryptGenRandom(
        nullptr,
        randomBytes,
        static_cast<ULONG>(sizeof(randomBytes)),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    if (status < 0) {
        outGle = ERROR_GEN_FAILURE;
        return false;
    }

    static constexpr wchar_t hexDigits[] = L"0123456789abcdef";
    std::wstring pipeName = L"\\\\.\\pipe\\LOCAL\\SilentRunner_";
    pipeName.reserve(pipeName.size() + sizeof(randomBytes) * 2);

    for (BYTE value : randomBytes) {
        pipeName.push_back(hexDigits[value >> 4]);
        pipeName.push_back(hexDigits[value & 0x0f]);
    }

    UniqueHandle server(CreateNamedPipeW(
        pipeName.c_str(),
        PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1,
        0,
        16 * 1024,
        120000,
        nullptr
    ));
    if (!server.valid()) {
        outGle = GetLastError();
        return false;
    }

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    UniqueHandle client(CreateFileW(
        pipeName.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ,
        &sa,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS,
        nullptr
    ));
    if (!client.valid()) {
        outGle = GetLastError();
        return false;
    }

    readPipe = std::move(server);
    writePipe = std::move(client);
    return true;
}
void ExecuteChildProcess(
    const SR::ExecuteChildProcessConfig& config,
    const SR::FileSinkWorkerTargetLayout& fileSinkWorkerTargetLayout,
    const std::vector<TargetLogPathBinding>& runningLogPaths,
    const std::wstring& comspecPath,
    const std::wstring& fullCmdLineForCreateProcess,
    const HandleHelpers::StdHandleWriteProbeResult& stdoutStdHandleProbe,
    const HandleHelpers::StdHandleWriteProbeResult& stderrStdHandleProbe,
    const std::wstring& specialCharactersDebugMessage,
    const std::vector<std::wstring>& unboundedReplayBufferDebugMessages,
    SRLifecycleDiagnostics& lifecycleDiag,
    std::shared_ptr<ExecutionTimeline> executionTimeline,
    const SRParentEmitPolicy& parentEmitPolicy,
    const SRWorkerCommonPolicy& workerCommonPolicy,
    SRBufferLimiter* bufferLimitPtr,
    SRRuntimeCoordinator& coordinator,
    SRTimeLimiter& timeLimiter,
    SRRuntimeResult& result
) {

    // -------------------------------------------------------
    // Child output gateway setup (diagnostics already use lifecycleDiag)
    // -------------------------------------------------------


    // SRMain owns the Runtime result; SRRuntime updates it directly.



    SRLifecycleDiagnostics& diag = lifecycleDiag;
    SRLogGatewayStdout stdoutRouter;
    SRLogGatewayStderr stderrRouter;

    // SRTargetLogFiles owns log paths and file writers.
    // ExecutionTimeline -> JobsExchange -> SRFileSinkWorker delivers events to file targets.
    // Gateways are lightweight entry points into ExecutionTimeline.
    // ExecutionTimeline owns event ordering, replay metadata and job creation;
    // JobsExchange dispatches pending jobs to dedicated workers.


    stdoutRouter.Init(
        parentEmitPolicy,
        bufferLimitPtr,
        executionTimeline.get()
    );


    stderrRouter.Init(
        parentEmitPolicy,
        bufferLimitPtr,
        executionTimeline.get()
    );


    // SR diagnostics and child stderr are routed independently into
    // ExecutionTimeline, which owns their ordering and replay metadata.
    SRWindowsJobObjectController jobController(lifecycleDiag);
    SRChildProcessWatcher childWatcher;
    childWatcher.Init(coordinator, jobController, lifecycleDiag);
    UniqueHandle childProc;
    UniqueHandle childThread;
    std::unique_ptr<SRChildStreamReader> stdoutReader;
    std::unique_ptr<SRChildStreamReader> stderrReader;



    // Severity policy in SRRuntime:
    // - diag.ErrorLine(...) is for recoverable runtime errors or best-effort cleanup
    //   failures where SR can continue the current shutdown/finalization path.
    // - ReportRuntimeFatal(...) records a fatal Runtime outcome.
    //   Emitting FATAL diagnostics does not itself request termination.
    //   Termination follows coordinator policy or an explicit Runtime stop path.
    //
    // Runtime fatal handling has two distinct paths:
    //
    // 1) Before child start:
    //    No child streaming/replay exists yet, so emit the fatal immediately
    //    through lifecycleDiag. The fatal becomes the primary visible error.
    //
    // 2) After child start:
    //    Record the fatal through lifecycleDiag so ExecutionTimeline owns the
    //    canonical event. Delivery/replay is handled by ExecutionTimeline,
    //    JobsExchange and the active worker/policy configuration.


    auto ReportRuntimeFatal = [&](const std::wstring& msg) {
        result.fatal = true;
        lifecycleDiag.FatalErrorLine(msg);
    };




    auto FinalizeChildProcess = [&](int exitCode) -> void {
        // All started readers have finished: either the coordinator reported
        // Completed, or AbortProcessTreeAndReaders() completed their shutdown.
        if (stdoutReader) stdoutReader->Join();
        if (stderrReader) stderrReader->Join();

        bool readerFailed = false;
        auto ReaderFailed = [](const SRChildStreamReader& reader) noexcept {
            return reader.ReadError() != ERROR_SUCCESS ||
                   reader.CancelError() != ERROR_SUCCESS ||
                   reader.ExceptionCaught() || reader.RoutingFailed();
        };
        if (stdoutReader && ReaderFailed(*stdoutReader)) readerFailed = true;
        if (stderrReader && ReaderFailed(*stderrReader)) readerFailed = true;
        if (stdoutReader || stderrReader) diag.VerboseLine(L"Reader threads joined");

        // Explicit lifecycle; destructors are the exception fallbacks.
        timeLimiter.Stop();
        childWatcher.Stop();
        jobController.Shutdown();

        if (result.stopReason == SRRuntimeStopReason::StopReason::NormalExit) {
            if (!childWatcher.childExitCode.has_value()) {
                // A reported supervision failure is summarized below.
                if (childWatcher.childExitCodeError == ERROR_SUCCESS &&
                    !coordinator.RuntimeFailureDetected()) {
                    ReportRuntimeFatal(L"Main child exit code unavailable");
                }
                exitCode = 255;
            } else {
                exitCode = static_cast<int>(*childWatcher.childExitCode);
            }
        }
        if (childWatcher.childExitCode.has_value()) {
            if (!executionTimeline->SetRuntimeChildExitCode(*childWatcher.childExitCode)) {
                lifecycleDiag.FatalErrorLine(L"Failed to record child exit code");
                exitCode = 255;
                result.fatal = true;
            }
        } else if (childWatcher.childExitCodeError != ERROR_SUCCESS) {
            // The watcher has already logged the failure at its source.
            exitCode = 255;
            result.fatal = true;
        }
        if (coordinator.RuntimeFailureDetected()) {
            if (result.stopReason != SRRuntimeStopReason::StopReason::RuntimeFailure) {
                const std::wstring failureMessage =
                    L"Runtime supervision failure; cause=" +
                    std::wstring(SRRuntimeCoordinator::RuntimeFailureCauseToString(
                        coordinator.FirstRuntimeFailureCause()));
                if (result.stopReason == SRRuntimeStopReason::StopReason::NormalExit) {
                    ReportRuntimeFatal(
                        failureMessage + L"; action=completed_without_abort; exit_code=255"
                    );
                } else {
                    lifecycleDiag.ErrorLine(failureMessage + L"; exit_code=255");
                }
            }
            exitCode = 255;
        }
        if (readerFailed) exitCode = 255;
        result.exitCode = exitCode;
        return;
    };



    diag.DebugLine(L"ID_PREFIX=" + (workerCommonPolicy.IdPrefix().empty() ? std::wstring(L"none") : workerCommonPolicy.IdPrefix()));
    diag.DebugLine(L"ID_BASE=" + (workerCommonPolicy.IdBase().empty() ? std::wstring(L"none") : workerCommonPolicy.IdBase()));

    std::wstring suffixMode = SR::IdSuffixModeToString(workerCommonPolicy.EffectiveIdSuffixMode());

    if (workerCommonPolicy.UseDefaultSuffixMode()) {

        suffixMode += L" (default)";
    }
    diag.DebugLine(L"ID_SUFFIX_MODE=" + suffixMode);
    diag.DebugLine(L"ID_SUFFIX=" + (workerCommonPolicy.GeneratedSuffix().empty() ? std::wstring(L"none") : workerCommonPolicy.GeneratedSuffix()));

    diag.InfoLine(L"EXECUTION_ID=" + workerCommonPolicy.ExecutionId());

    if (!workerCommonPolicy.ParsingToken().empty()) {
        diag.DebugLine(
            L"PARSINGTOKEN=" +
            FileHelpers::Utf8ToWide(workerCommonPolicy.ParsingToken())
        );
    }
    diag.InfoLine(L"EXECUTION_MODE=" + std::wstring(SR::ExecutionModeToString(config.executionMode)));
    diag.InfoLine(
        L"CHILD_CWD=" +
        (config.cwd.empty() ? std::wstring(L"(inherited)") : config.cwd) +
        L" CHILD_UTF8=" + (config.utf8 ? L"TRUE" : L"FALSE") +
        L" CHILD_INHERIT_STDIN=" + (config.inheritStdin ? L"TRUE" : L"FALSE")
    );
    diag.DebugLine(
        L"JSONL_PAYLOAD_REPRESENTATION=" +
        FileHelpers::Utf8ToWide(
            SR::JsonlPayloadRepresentationToToken(config.jsonlPayloadRepresentation)
        )
    );
    diag.DebugLine(
        std::wstring(L"DEBUG=") + (config.debug ? L"TRUE" : L"FALSE") +
        L" VERBOSE=" + (config.verbose ? L"TRUE" : L"FALSE")
    );
    diag.InfoLine(
        L"RUN_ON_SUCCESS=" +
        (config.runOnSuccessPath.empty() ? std::wstring(L"none") : config.runOnSuccessPath)
    );
    diag.InfoLine(
        L"RUN_ON_FAILURE=" +
        (config.runOnFailurePath.empty() ? std::wstring(L"none") : config.runOnFailurePath)
    );

    if (!specialCharactersDebugMessage.empty()) {
        diag.DebugLine(specialCharactersDebugMessage);
    }

    for (const std::wstring& msg : unboundedReplayBufferDebugMessages) {
        diag.DebugLine(msg);
    }


    DebugStdHandleProbe_(diag, L"STDOUT", stdoutStdHandleProbe);

    diag.InfoLine(
        L"STDOUT_EMIT_TARGET=" +
        std::wstring(SR::JobTargetNameToString(parentEmitPolicy.StdoutParentTarget())) +
        L" EMIT_MODE=" +
        std::wstring(SR::EmitModeToString(parentEmitPolicy.StdoutEmitMode()))
    );
    
    DebugStdHandleProbe_(diag, L"STDERR", stderrStdHandleProbe);

    diag.InfoLine(
        L"STDERR_EMIT_TARGET=" +
        std::wstring(SR::JobTargetNameToString(parentEmitPolicy.StderrParentTarget())) +
        L" EMIT_MODE=" +
        std::wstring(SR::EmitModeToString(parentEmitPolicy.StderrEmitMode()))
    );
    diag.DebugLine(
        L"STDOUT_EVENT_FRAMING=" +
        std::wstring(SR::ChildEventFramingToString(config.stdoutEventFraming)) +
        L" NEWLINE_MAX_BYTES=" +
        std::to_wstring(config.stdoutEventNewlineMaxBytes)
    );
    diag.DebugLine(
        L"STDERR_CHILD_EVENT_FRAMING=" +
        std::wstring(SR::ChildEventFramingToString(config.stderrChildEventFraming)) +
        L" NEWLINE_MAX_BYTES=" +
        std::to_wstring(config.stderrChildEventNewlineMaxBytes)
    );

    for (const auto& binding : runningLogPaths) {
        if (!binding.created) {
            continue;
        }
        const std::size_t configIndex =
            fileSinkWorkerTargetLayout.ConfigIndexOf(binding.target);
        if (configIndex == SR::kInvalidJobTargetWorkerConfigIndex) {
            continue;
        }
        const auto& targetEntry =
            fileSinkWorkerTargetLayout.targets[configIndex];
        if (!targetEntry.logFileKey) {
            continue;
        }
        diag.InfoLine(
            std::wstring(targetEntry.logFileKey) +
            L"=" +
            *binding.path +
            L" KEEP_LOG_MODE=" +
            std::wstring(
                SR::KeepLogModeToView(
                    binding.keepLogMode
                )
            )
        );
    }


    diag.DebugLine(L"fullCmdLine=" + fullCmdLineForCreateProcess);

    diag.InfoLine(L"timeoutMs=" + std::to_wstring(timeLimiter.TimeoutMs()));
    diag.InfoLine(
        L"STDOUT_MAX_BUFFER_BYTES=" + std::to_wstring(config.stdoutMaxBufferBytes) +
        L" STDERR_MAX_BUFFER_BYTES=" + std::to_wstring(config.stderrMaxBufferBytes) +
        L" STD_TOTAL_MAX_BUFFER_BYTES=" + std::to_wstring(config.stdTotalMaxBufferBytes)
    );
    DebugProcessChain_(diag, L"Self", GetCurrentProcessId());

    // Child output pipes use overlapped reads and synchronous child writes.
    UniqueHandle stdoutReadPipe, stdoutWritePipe;
    UniqueHandle stderrReadPipe, stderrWritePipe;

    // The Job Object monitor is required; IOCP is required for DEBUG diagnostics, optional otherwise.
    SRWindowsJobObjectController::InitFailure jobInitFailure;
    if (!jobController.Init(coordinator, jobInitFailure)) {
        if (jobInitFailure.reason == SRWindowsJobObjectController::InitFailureReason::CreateJobObject) {
            ReportRuntimeFatal(L"CreateJobObjectW failed; " + ErrorHelpers::FormatGle(jobInitFailure.gle));
        } else if (jobInitFailure.reason == SRWindowsJobObjectController::InitFailureReason::SetKillOnJobClose) {
            ReportRuntimeFatal(L"[JOB] SetInformationJobObject(KILL_ON_JOB_CLOSE) failed; " + ErrorHelpers::FormatGle(jobInitFailure.gle));
        } else if (jobInitFailure.reason == SRWindowsJobObjectController::InitFailureReason::CreateIocp) {
            ReportRuntimeFatal(L"[JOB] CreateIoCompletionPort failed; " + ErrorHelpers::FormatGle(jobInitFailure.gle));
        } else if (jobInitFailure.reason == SRWindowsJobObjectController::InitFailureReason::AssociateIocp) {
            ReportRuntimeFatal(L"[JOB] Job Object IOCP association failed; " + ErrorHelpers::FormatGle(jobInitFailure.gle));
        } else if (jobInitFailure.reason == SRWindowsJobObjectController::InitFailureReason::StartMonitorThread) {
            ReportRuntimeFatal(L"[JOB] Process-tree monitoring thread failed to start");

        } else {
            ReportRuntimeFatal(L"[JOB] Job Object controller already initialized");
        }
        return FinalizeChildProcess(255);
    }

    DWORD pipeGle = ERROR_SUCCESS;
    if (!CreateOverlappedChildOutputPipe(
            stdoutReadPipe, stdoutWritePipe, pipeGle)) {
        ReportRuntimeFatal(
            L"CreateOverlappedChildOutputPipe(stdout) failed; " +
            ErrorHelpers::FormatGle(pipeGle)
        );
        return FinalizeChildProcess(255);
    }
    diag.VerboseLine(L"Overlapped stdout read pipe created");

    if (!CreateOverlappedChildOutputPipe(
            stderrReadPipe, stderrWritePipe, pipeGle)) {
        ReportRuntimeFatal(
            L"CreateOverlappedChildOutputPipe(stderr) failed; " +
            ErrorHelpers::FormatGle(pipeGle)
        );
        return FinalizeChildProcess(255);
    }
    diag.VerboseLine(L"Overlapped stderr read pipe created");

    // stdin handling:
    // - default: bind child stdin to NUL (EOF) -- but MUST be inheritable
    // - --inherit-stdin: pass parent stdin if it exists, otherwise fallback to NUL
    UniqueHandle nulNonInherit;
    UniqueHandle childIn; // inheritable handle we pass to the child (best effort)
    HANDLE sourceStdin = nullptr;

    if (config.inheritStdin) {
        sourceStdin = GetStdHandle(STD_INPUT_HANDLE);
        if (!sourceStdin || sourceStdin == INVALID_HANDLE_VALUE) sourceStdin = nullptr;
    }

    if (!sourceStdin) {
        nulNonInherit.reset(CreateFileW(
            L"NUL",
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        ));
        sourceStdin = nulNonInherit.valid() ? nulNonInherit.get() : nullptr;
    }

    DWORD stdinDupGle = 0;

    if (sourceStdin) {
        HANDLE dupIn = nullptr;
        const BOOL okDup = DuplicateHandle(
            GetCurrentProcess(),
            sourceStdin,
            GetCurrentProcess(),
            &dupIn,
            0,
            TRUE,
            DUPLICATE_SAME_ACCESS
        );
        if (okDup && dupIn) {
            childIn.reset(dupIn);
        } else {
            stdinDupGle = GetLastError();
        }
    }

    if (!childIn.valid()) {
        if (config.inheritStdin) {
            std::wstring msg = L"--inherit-stdin requested but an inheritable stdin handle could not be created";
            if (stdinDupGle != 0) {
                msg += L"; ";
                msg += ErrorHelpers::FormatGle(stdinDupGle);
            }
            ReportRuntimeFatal(msg);
            return FinalizeChildProcess(255);
        } else {
            diag.DebugLine(L"WARNING: could not create inheritable stdin handle (falling back to no stdin)");
        }
    } else {
        diag.VerboseLine(L"stdin handle prepared (inheritable dup)");
    }

    PROCESS_INFORMATION pi{};
    {
        struct ProcThreadAttrListGuard {
            LPPROC_THREAD_ATTRIBUTE_LIST list = nullptr;
            ~ProcThreadAttrListGuard() {
                if (list) DeleteProcThreadAttributeList(list);
            }
        };

        STARTUPINFOEXW siex{};
        siex.StartupInfo.cb = sizeof(siex);
        siex.StartupInfo.dwFlags = STARTF_USESTDHANDLES;

        siex.StartupInfo.hStdOutput = stdoutWritePipe.get();
        siex.StartupInfo.hStdError  = stderrWritePipe.get();
        siex.StartupInfo.hStdInput  = childIn.valid() ? childIn.get() : nullptr;

        std::vector<HANDLE> inheritList;
        inheritList.reserve(3);
        if (siex.StartupInfo.hStdInput)  inheritList.push_back(siex.StartupInfo.hStdInput);
        if (siex.StartupInfo.hStdOutput) inheritList.push_back(siex.StartupInfo.hStdOutput);
        if (siex.StartupInfo.hStdError)  inheritList.push_back(siex.StartupInfo.hStdError);

        SIZE_T attrSize = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &attrSize);
        if (attrSize == 0) {
            DWORD gle = GetLastError();
            ReportRuntimeFatal(L"InitializeProcThreadAttributeList(size query) failed; " + ErrorHelpers::FormatGle(gle));
            return FinalizeChildProcess(255);
        }

        std::vector<unsigned char> attrBuf(attrSize);
        siex.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attrBuf.data());

        if (!InitializeProcThreadAttributeList(siex.lpAttributeList, 1, 0, &attrSize)) {
            DWORD gle = GetLastError();
            ReportRuntimeFatal(L"InitializeProcThreadAttributeList(init) failed; " + ErrorHelpers::FormatGle(gle));
            return FinalizeChildProcess(255);
        }
        diag.VerboseLine(L"InitializeProcThreadAttributeList(init) OK");

        ProcThreadAttrListGuard attrGuard;
        attrGuard.list = siex.lpAttributeList;

        if (!UpdateProcThreadAttribute(
                siex.lpAttributeList,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                inheritList.data(),
                inheritList.size() * sizeof(HANDLE),
                nullptr,
                nullptr)) {
            DWORD gle = GetLastError();
            ReportRuntimeFatal(L"UpdateProcThreadAttribute(HANDLE_LIST) failed; " + ErrorHelpers::FormatGle(gle));
            return FinalizeChildProcess(255);
        }
        diag.VerboseLine(L"UpdateProcThreadAttribute(HANDLE_LIST) OK");

        // CreateProcessW mutates the command-line buffer and receives --cwd only as
        // lpCurrentDirectory.
        //
        // Important:
        // - --cwd changes only the child current directory through lpCurrentDirectory.
        // - SilentRunner itself does not call SetCurrentDirectoryW here.
        // - Therefore, SR option paths such as --stdout-dir/--stderr-dir are not
        //   resolved against --cwd.
        std::wstring cmd = fullCmdLineForCreateProcess; // CreateProcessW requires mutable buffer

        BOOL ok = CreateProcessW(
            comspecPath.c_str(), // Explicit executable path
            cmd.data(),
            nullptr,
            nullptr,
            TRUE,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_SUSPENDED,
            nullptr,
            config.cwd.empty() ? nullptr : config.cwd.c_str(),
            &siex.StartupInfo,
            &pi
        );
        if (!ok) {
            DWORD gle = GetLastError();
            ReportRuntimeFatal(L"CreateProcessW failed; " + ErrorHelpers::FormatGle(gle));
            return FinalizeChildProcess(255);
        }

        diag.DebugLine(L"CreateProcessW OK; CHILD_PID=" + std::to_wstring(pi.dwProcessId));
        DebugProcessChain_(diag, L"Child", pi.dwProcessId);
    }

    childProc.reset(pi.hProcess);
    childThread.reset(pi.hThread);

    DWORD assignGle = 0;
    if (!jobController.AssignProcess(childProc.get(), assignGle)) {
        DWORD gle = assignGle;
        diag.ErrorLine(L"[JOB] AssignProcessToJobObject failed; " + ErrorHelpers::FormatGle(gle));
        if (childProc.valid() && !TerminateProcess(childProc.get(), 1)) {
            const DWORD terminateGle = GetLastError();
            diag.ErrorLine(L"TerminateUnassignedProcess: TerminateProcess failed; " + ErrorHelpers::FormatGle(terminateGle));
        }
        return FinalizeChildProcess(255);
    }

    diag.VerboseLine(L"[JOB] AssignProcessToJobObject OK");

    // Parent no longer needs these.
    stdoutWritePipe.reset();
    stderrWritePipe.reset();
    childIn.reset();

    // Stop the process tree. On timeout or requested runtime failure, allow
    // a shared grace period for reader completion before cancelling reads.
    // Joining and evaluating reader errors belong to FinalizeChildProcess().
    auto AbortProcessTreeAndReaders = [&](SRRuntimeStopReason::StopReason reason) -> bool {
        DWORD gle = 0;
        bool stopFailed = false;
        if (!jobController.Abort(
                SRRuntimeStopReason::ToChildAbortExitCode(reason), gle)) {
            diag.ErrorLine(L"TerminateJobObject failed; " + ErrorHelpers::FormatGle(gle));
            stopFailed = true;
            if (childProc.valid()) {
                TerminateProcess(childProc.get(),
                    SRRuntimeStopReason::ToChildAbortExitCode(reason));
            }
        }
        const bool allowReaderDrainGrace =
            (reason == SRRuntimeStopReason::StopReason::Timeout ||
             reason == SRRuntimeStopReason::StopReason::RuntimeFailure) &&
            !stopFailed && stdoutReader && stderrReader;
        if (allowReaderDrainGrace) {
            coordinator.WaitForReadersAfterAbort();
        }
        if (stdoutReader && (!allowReaderDrainGrace || !stdoutReader->Finished())) {
            stdoutReader->Abort();
        }
        if (stderrReader && (!allowReaderDrainGrace || !stderrReader->Finished())) {
            stderrReader->Abort();
        }
        return !stopFailed;
    };

    try {
        stdoutReader = std::make_unique<SRChildStreamReader>(
            std::move(stdoutReadPipe), stdoutRouter, coordinator, lifecycleDiag,
            config.stdoutEventFraming, config.stdoutEventNewlineMaxBytes
        );
        stderrReader = std::make_unique<SRChildStreamReader>(
            std::move(stderrReadPipe), stderrRouter, coordinator, lifecycleDiag,
            config.stderrChildEventFraming, config.stderrChildEventNewlineMaxBytes
        );
        stdoutReader->Start();
        stderrReader->Start();

        DWORD watcherGle = 0;
        if (!childWatcher.WaitForExitAsync(childProc.get(), watcherGle)) {
            ReportRuntimeFatal(L"SRChildProcessWatcher::WaitForExitAsync failed; " +
                ErrorHelpers::FormatGle(watcherGle));
            result.stopReason = SRRuntimeStopReason::StopReason::RuntimeSetupFailed;
            AbortProcessTreeAndReaders(result.stopReason);
            return FinalizeChildProcess(255);
        }

        DWORD timerGle = ERROR_SUCCESS;
        if (!timeLimiter.Start(timerGle)) {
            ReportRuntimeFatal(L"SRTimeLimiter::Start failed; " + ErrorHelpers::FormatGle(timerGle));
            result.stopReason = SRRuntimeStopReason::StopReason::RuntimeSetupFailed;
            AbortProcessTreeAndReaders(result.stopReason);
            return FinalizeChildProcess(255);
        }

        {
            DWORD rr = ResumeThread(childThread.get());
            if (rr == (DWORD)-1) {
                DWORD gle = GetLastError();
                ReportRuntimeFatal(L"[JOB] ResumeThread failed; " + ErrorHelpers::FormatGle(gle));
                result.stopReason = SRRuntimeStopReason::StopReason::ResumeThreadFailed;
                AbortProcessTreeAndReaders(result.stopReason);
                return FinalizeChildProcess(255);
            }
            diag.DebugLine(
                L"[TIMELINE] Event numbers shown in an output may not form a continuous sequence; "
                L"this does not necessarily indicate lost events. "
                L"See https://github.com/jzav/silent-runner/blob/main/docs/architecture.md#timeline-and-event-filtering"
            );
            diag.DebugLine(L"[JOB] ResumeThread OK; Child process started.");
            result.childStarted = true;
        }

        // Job zero does not guarantee stdout/stderr EOF. A process outside our
        // Job Object may still hold a duplicated pipe write handle, preventing
        // EOF even after all managed processes have exited. Windows cannot
        // determine whether that process will produce more output.
        //
        // Normal completion waits for both readers to reach EOF rather than
        // cancelling pending reads. --timeout-ms also covers this wait:
        // if Runtime is not complete when the timer fires, it returns 124
        // and terminates the process tree. Readers receive a short grace
        // period to finish naturally before pending reads are cancelled.
        // The existing reader Abort()/CancelIoEx() path still waits for
        // pending I/O completion before releasing its resources.
        for (;;) {
            DWORD timeoutJobQueryGle = ERROR_SUCCESS;
            const SRRuntimeCoordinator::Action action =
                coordinator.WaitForActionSync(jobController, timeoutJobQueryGle);
            const SRRuntimeStopReason::StopReason stopReason = coordinator.StopReason();
            result.stopReason = stopReason;

            executionTimeline->ProbeLine(
                L"[RUNTIME][WAIT] action=" +
                std::wstring(action == SRRuntimeCoordinator::Action::Completed
                    ? L"COMPLETED" : L"ABORT") +
                L" stopReason=" +
                std::wstring(SRRuntimeStopReason::ToDiagnosticLabel(stopReason))
            );

            if (action == SRRuntimeCoordinator::Action::Completed) break;

            if (stopReason == SRRuntimeStopReason::StopReason::Timeout) {
                if (timeoutJobQueryGle != ERROR_SUCCESS) {
                    try {
                        diag.ErrorLine(
                            L"[JOB] Timeout Job zero verification failed; " +
                            ErrorHelpers::FormatGle(timeoutJobQueryGle)
                        );
                    } catch (...) {
                        // Diagnostic failure must not change the timeout decision.
                    }
                }
                ReportRuntimeFatal(
                    L"Runtime stop: Timeout exceeded; timeout_ms=" +
                    std::to_wstring(timeLimiter.TimeoutMs()) +
                    L" exit_code=124"
                );
            } else if (stopReason == SRRuntimeStopReason::StopReason::BufferLimit) {
                std::wstring which = L"?";
                SRBufferLimiter::StreamType first =
                    bufferLimitPtr ? bufferLimitPtr->FirstHitStream()
                                   : SRBufferLimiter::StreamType::None;
                if (first == SRBufferLimiter::StreamType::Stdout) which = L"stdout";
                else if (first == SRBufferLimiter::StreamType::Stderr) which = L"stderr";

                std::wstring bufferLimitFatalMessage =
                    L"Runtime stop: Buffer limit exceeded; first_hit=" + which +
                    L" stdout_max=" + std::to_wstring(bufferLimitPtr ? bufferLimitPtr->StdoutMaxBytes() : 0) +
                    L" stderr_max=" + std::to_wstring(bufferLimitPtr ? bufferLimitPtr->StderrMaxBytes() : 0) +
                    L" total_max=" + std::to_wstring(bufferLimitPtr ? bufferLimitPtr->TotalMaxBytes() : 0) +
                    L" action=abort";
                ReportRuntimeFatal(bufferLimitFatalMessage);
            }

            if (stopReason == SRRuntimeStopReason::StopReason::RuntimeFailure) {
                // This flag records the policy action, not the result of TerminateJobObject.
                result.abortedOnRuntimeFailure = true;
                ReportRuntimeFatal(
                    L"Runtime abort requested: --abort-on-runtime-failure triggered; cause=" +
                    std::wstring(SRRuntimeCoordinator::RuntimeFailureCauseToString(
                        coordinator.FirstRuntimeFailureCause())) +
                    L"; exit_code=255"
                );
            }

            // Abort() confirms reader completion. Other abort reasons still wait
            // for coordinator confirmation before finalization.
            if (!AbortProcessTreeAndReaders(stopReason)) {
                return FinalizeChildProcess(255);
            }
            if (stopReason == SRRuntimeStopReason::StopReason::RuntimeFailure) {
                // Monitoring may be unavailable; do not wait for Job zero.
                return FinalizeChildProcess(255);
            }
        }

        return FinalizeChildProcess(SRRuntimeStopReason::ToSRExitCode(result.stopReason));
    // Unhandled exceptions indicate a potentially catastrophic or inconsistent
    // Runtime state. Unlike reported supervision failures, they intentionally
    // trigger best-effort process-tree termination regardless of
    // --abort-on-runtime-failure. Continuing execution is not considered safe.
    } catch (const std::bad_alloc&) {
        result.stopReason = SRRuntimeStopReason::StopReason::UnhandledException;
        AbortProcessTreeAndReaders(result.stopReason);
        ReportRuntimeFatal(L"Unhandled std::bad_alloc in ExecuteChildProcess");
        return FinalizeChildProcess(255);
    } catch (const std::exception& ex) {
        result.stopReason = SRRuntimeStopReason::StopReason::UnhandledException;
        AbortProcessTreeAndReaders(result.stopReason);
        const std::wstring detail = FileHelpers::Utf8ToWide(ex.what());
        if (!detail.empty()) {
            ReportRuntimeFatal(
                L"Unhandled std::exception in ExecuteChildProcess; " + detail
            );
        } else {
            ReportRuntimeFatal(L"Unhandled std::exception in ExecuteChildProcess");
        }
        return FinalizeChildProcess(255);
    } catch (...) {
        result.stopReason = SRRuntimeStopReason::StopReason::UnhandledException;
        AbortProcessTreeAndReaders(result.stopReason);
        ReportRuntimeFatal(L"Unhandled unknown exception in ExecuteChildProcess");
        return FinalizeChildProcess(255);
    }

}
