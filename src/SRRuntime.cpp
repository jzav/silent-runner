// SRRuntime - runner core orchestration
// -------------------------------------

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string>
#include <thread>
#include <vector>
#include <exception>
#include <new>
#include <memory>

#include "SRRuntime.h"

#include "CoreHelpers.h"
#include "ErrorHelpers.h"
#include "FileHelpers.h"
#include "HandleHelpers.h"

#include "SRLogGatewayDiagnostics.h"
#include "SRLogGatewayStdout.h"
#include "SRLogGatewayStderr.h"
#include "SRBufferLimiter.h"
#include "SRRuntimeStopReason.h"
#include "SRThreading.h"

#include "SRLifecycleDiagnostics.h"
#include "SRParentEmitPolicy.h"
#include "SRWorkerCommonPolicy.h"

#include "ChildStdReader.h"
#include "JobController.h"

using CoreHelpers::UniqueHandle;

static void StopAndUnblockReaders(
    SRLogGatewayDiagnostics& diag,
    UniqueHandle& job,
    UniqueHandle& childProc,
    UniqueHandle& stdoutReadPipe,
    UniqueHandle& stderrReadPipe,
    DWORD graceMs,
    DWORD terminateCode
) {
    if (!childProc.valid()) {
        diag.DebugLine(L"StopAndUnblock: child process handle missing");
        stdoutReadPipe.reset();
        stderrReadPipe.reset();
        return;
    }

    if (job.valid()) {
        if (!TerminateJobObject(job.get(), terminateCode)) {
            DWORD gle = GetLastError();
            diag.ErrorLine(L"StopAndUnblock: TerminateJobObject failed; " + ErrorHelpers::FormatGle(gle));
        }
    } else {
        if (!TerminateProcess(childProc.get(), terminateCode)) {
            DWORD gle = GetLastError();
            diag.ErrorLine(L"StopAndUnblock: TerminateProcess failed; " + ErrorHelpers::FormatGle(gle));
        } else if (terminateCode == 124) {
            diag.DebugLine(L"StopAndUnblock: TerminateProcess(child, 124) fallback from missing job handle");
        }
    }

    DWORD w = WaitForSingleObject(childProc.get(), graceMs);
    if (w == WAIT_OBJECT_0) {
        diag.DebugLine(L"StopAndUnblock: process exited during grace");
        return;
    }
    if (w == WAIT_FAILED) {
        DWORD gle = GetLastError();
        diag.ErrorLine(L"StopAndUnblock: WaitForSingleObject(grace) failed; " + ErrorHelpers::FormatGle(gle));
        stdoutReadPipe.reset();
        stderrReadPipe.reset();
        return;
    }

    diag.DebugLine(L"StopAndUnblock: grace expired -> force-unblock readers");
    stdoutReadPipe.reset();
    stderrReadPipe.reset();
}

SRRuntimeResult RunHiddenWithRouting(
    const std::wstring& fullCmdLineForCreateProcess,
    const std::wstring& executionId,
    const std::wstring& generatedSuffix,
    SR::IdSuffixMode effectiveIdSuffixMode,
    bool useDefaultSuffixMode,
    SRLifecycleDiagnostics& lifecycleDiag,
    std::shared_ptr<ExecutionTimeline> executionTimeline,
    const SRParentEmitPolicy& parentEmitPolicy,
    const SRWorkerCommonPolicy& workerCommonPolicy,
    SRBufferLimiter* bufferLimitPtr,
    const SR::Options& opt,
    const SR::LogPaths& logPaths,
    const HandleHelpers::StdHandleWriteProbeResult& stdoutStdHandleProbe,
    const HandleHelpers::StdHandleWriteProbeResult& stderrStdHandleProbe


) {
    // -------------------------------------------------------
    // Gateway setup (must happen before any INFO/DEBUG is logged)
    // -------------------------------------------------------


    SRRuntimeResult result;



    SRLogGatewayDiagnostics diag;
    SRLogGatewayStdout stdoutRouter;
    SRLogGatewayStderr stderrRouter;

    // File output is owned by ExecutionTimeline -> JobsExchange -> SRFileSinkWorker.
    // Gateways are lightweight entry points into ExecutionTimeline.
    // ExecutionTimeline owns event ordering, replay metadata and job creation;
    // JobsExchange dispatches pending jobs to dedicated workers.


    stdoutRouter.Init(
        opt.stdoutEmit,
        &parentEmitPolicy,
        bufferLimitPtr,
        executionTimeline.get()
    );


    stderrRouter.Init(
        opt.stderrEmit,
        opt.stderrEmitSource,
        &parentEmitPolicy,
        bufferLimitPtr,
        executionTimeline.get()
    );


    // Runtime diagnostics enter the same stderr gateway as child stderr.
    //
    // Important:
    // - Runtime diagnostics are formatted as stderr-view text events.
    // - ExecutionTimeline owns their canonical ordering and replay metadata.
    // - File and parent delivery are performed later through JobsExchange
    //   and dedicated workers, not directly from SRRuntime.

    diag.Init(
        opt.debug,
        &stderrRouter
    );


    // Severity policy in SRRuntime:
    // - diag.ErrorLine(...) is for recoverable runtime errors or best-effort cleanup
    //   failures where SR can continue the current shutdown/finalization path.
    // - ReportRuntimeFatal(...) is for errors that prevent runtime from fulfilling
    //   its purpose, or for forced runtime stops where the child must be aborted.
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




    auto BuildRuntimeResult = [&](int exitCode) -> SRRuntimeResult {
        result.exitCode = exitCode;
        return result;
    };


    if (bufferLimitPtr && bufferLimitPtr->EventFailureDetected()) {
        result.stopReason = SRRuntimeStopReason::StopReason::WaitFailed;
        ReportRuntimeFatal(
            L"Fatal runtime setup: buffer-limit event operation failed; operation=" +
            std::wstring(bufferLimitPtr->FirstEventFailureOperationName()) +
            L" " +
            ErrorHelpers::FormatGle(bufferLimitPtr->FirstEventFailureGle())
        );
        return BuildRuntimeResult(255);
    }

    diag.InfoLine(L"ID_PREFIX=" + (opt.idPrefix.empty() ? std::wstring(L"none") : opt.idPrefix));
    diag.InfoLine(L"ID_BASE=" + (opt.idBase.empty() ? std::wstring(L"none") : opt.idBase));

    std::wstring suffixMode = SR::IdSuffixModeToString(effectiveIdSuffixMode);
    if (useDefaultSuffixMode) {
        suffixMode += L" (default)";
    }
    diag.InfoLine(L"ID_SUFFIX_MODE=" + suffixMode);
    diag.InfoLine(L"ID_SUFFIX=" + (generatedSuffix.empty() ? std::wstring(L"none") : generatedSuffix));
    diag.InfoLine(L"EXECUTION_ID=" + executionId);
    if (!workerCommonPolicy.ParsingToken().empty()) {
        diag.InfoLine(
            L"PARSINGTOKEN=" +
            FileHelpers::Utf8ToWide(workerCommonPolicy.ParsingToken())
        );
    }
    diag.InfoLine(L"EXECUTION_MODE=" + std::wstring(SR::ExecutionModeToString(opt.executionMode)));

    for (const std::wstring& msg : opt.parserDebugMessages) {
        diag.DebugLine(msg);
    }

    diag.DebugStdHandleProbe(L"STDOUT", stdoutStdHandleProbe);
    diag.InfoLine(L"STDOUT_EMIT=" + std::wstring(SR::EmitModeToString(opt.stdoutEmit)));
    
    diag.DebugStdHandleProbe(L"STDERR", stderrStdHandleProbe);
    diag.InfoLine(L"STDERR_EMIT=" + std::wstring(SR::EmitModeToString(opt.stderrEmit)));
    diag.InfoLine(L"STDERR_EMIT_SOURCE=" + std::wstring(SR::StderrEmitSourceToString(opt.stderrEmitSource)));

    if (!logPaths.running.stdoutTxt.empty()) {
        diag.InfoLine(L"STDOUT_LOG_FILE=" + logPaths.running.stdoutTxt);
    }
    if (!logPaths.running.stderrSrAndChildTxt.empty()) {
        diag.InfoLine(L"STDERR_LOG_FILE=" + logPaths.running.stderrSrAndChildTxt);
    }
    if (!logPaths.running.stderrChildTxt.empty()) {
        diag.InfoLine(L"STDERR_CHILD_LOG_FILE=" + logPaths.running.stderrChildTxt);
    }
    if (!logPaths.running.stderrSrTxt.empty()) {
        diag.InfoLine(L"STDERR_SR_LOG_FILE=" + logPaths.running.stderrSrTxt);
    }


    diag.DebugLine(L"fullCmdLine=" + fullCmdLineForCreateProcess);
    diag.InfoLine(L"timeoutMs=" + std::to_wstring(opt.timeoutMs));
    diag.DebugProcessChain(L"Self", GetCurrentProcessId());

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    UniqueHandle stdoutReadPipe, stdoutWritePipe;
    UniqueHandle stderrReadPipe, stderrWritePipe;

    // Job object: kill-tree on close.
    UniqueHandle job(CreateJobObjectW(nullptr, nullptr));
    if (!job.valid()) {
        DWORD gle = GetLastError();
        ReportRuntimeFatal(L"CreateJobObjectW failed; " + ErrorHelpers::FormatGle(gle));
        return BuildRuntimeResult(255);
    }
    diag.DebugLine(L"[JOB] job object created OK");

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli{};
    jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation, &jeli, sizeof(jeli))) {
        DWORD gle = GetLastError();
        ReportRuntimeFatal(L"[JOB] SetInformationJobObject(KILL_ON_JOB_CLOSE) failed; " + ErrorHelpers::FormatGle(gle));
        return BuildRuntimeResult(255);
    }
    diag.DebugLine(L"[JOB] job limit KILL_ON_JOB_CLOSE set OK");

    // Job notification monitor (debug only).
    JobController::JobIocpMonitor jobMon;
    JobController::JobMonGuard jobMonGuard(&jobMon);
    jobMon.start(diag, job.get());

    if (!CreatePipe(stdoutReadPipe.put(), stdoutWritePipe.put(), &sa, 0)) {
        DWORD gle = GetLastError();
        ReportRuntimeFatal(L"CreatePipe(stdoutReadPipe + stdoutWritePipe) failed; " + ErrorHelpers::FormatGle(gle));
        return BuildRuntimeResult(255);
    }
    diag.DebugLine(L"CreatePipe(stdoutReadPipe + stdoutWritePipe) OK");

    if (!CreatePipe(stderrReadPipe.put(), stderrWritePipe.put(), &sa, 0)) {
        DWORD gle = GetLastError();
        ReportRuntimeFatal(L"CreatePipe(stderrReadPipe + stderrWritePipe) failed; " + ErrorHelpers::FormatGle(gle));
        return BuildRuntimeResult(255);
    }
    diag.DebugLine(L"CreatePipe(stderrReadPipe + stderrWritePipe) OK");

    // stdin handling:
    // - default: bind child stdin to NUL (EOF) -- but MUST be inheritable
    // - --inherit-stdin: pass parent stdin if it exists, otherwise fallback to NUL
    UniqueHandle nulNonInherit;
    UniqueHandle childIn; // inheritable handle we pass to the child (best effort)
    HANDLE sourceStdin = nullptr;

    if (opt.inheritStdin) {
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
        if (opt.inheritStdin) {
            std::wstring msg = L"--inherit-stdin requested but an inheritable stdin handle could not be created";
            if (stdinDupGle != 0) {
                msg += L"; ";
                msg += ErrorHelpers::FormatGle(stdinDupGle);
            }
            ReportRuntimeFatal(msg);
            return BuildRuntimeResult(255);
        } else {
            diag.DebugLine(L"WARNING: could not create inheritable stdin handle (falling back to no stdin)");
        }
    } else {
        diag.DebugLine(L"stdin handle prepared (inheritable dup)");
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
            return BuildRuntimeResult(255);
        }

        std::vector<unsigned char> attrBuf(attrSize);
        siex.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attrBuf.data());

        if (!InitializeProcThreadAttributeList(siex.lpAttributeList, 1, 0, &attrSize)) {
            DWORD gle = GetLastError();
            ReportRuntimeFatal(L"InitializeProcThreadAttributeList(init) failed; " + ErrorHelpers::FormatGle(gle));
            return BuildRuntimeResult(255);
        }
        diag.DebugLine(L"InitializeProcThreadAttributeList(init) OK");

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
            return BuildRuntimeResult(255);
        }
        diag.DebugLine(L"UpdateProcThreadAttribute(HANDLE_LIST) OK");

        // CreateProcessW mutates the command-line buffer and receives --cwd only as
        // lpCurrentDirectory.
        //
        // Important:
        // - opt.cwd changes the working directory of the child process.
        // - SilentRunner itself does not call SetCurrentDirectoryW here.
        // - Therefore, SR option paths such as --stdout-dir/--stderr-dir are not
        //   resolved against opt.cwd.
        std::wstring cmd = fullCmdLineForCreateProcess; // CreateProcessW requires mutable buffer
        BOOL ok = CreateProcessW(
            nullptr,
            cmd.data(),
            nullptr,
            nullptr,
            TRUE,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_SUSPENDED,
            nullptr,
            opt.cwd.empty() ? nullptr : opt.cwd.c_str(),
            &siex.StartupInfo,
            &pi
        );
        if (!ok) {
            DWORD gle = GetLastError();
            ReportRuntimeFatal(L"CreateProcessW failed; " + ErrorHelpers::FormatGle(gle));
            return BuildRuntimeResult(255);
        }

        diag.DebugLine(L"CreateProcessW OK; CHILD_PID=" + std::to_wstring(pi.dwProcessId));
        diag.DebugProcessChain(L"Child", pi.dwProcessId);
    }

    UniqueHandle childProc(pi.hProcess);
    UniqueHandle childThread(pi.hThread);

    if (!AssignProcessToJobObject(job.get(), childProc.get())) {
        DWORD gle = GetLastError();
        diag.ErrorLine(L"[JOB] AssignProcessToJobObject failed; " + ErrorHelpers::FormatGle(gle));
        JobController::KillJobBestEffort(job, childProc, diag);
        return BuildRuntimeResult(255);
    }

    diag.DebugLine(L"[JOB] AssignProcessToJobObject OK");

    // Parent no longer needs these.
    stdoutWritePipe.reset();
    stderrWritePipe.reset();
    childIn.reset();

    DWORD stdoutReadGle = 0;
    bool stdoutReaderExceptionCaught = false;
    std::wstring stdoutReaderExceptionText;

    DWORD stderrReadGle = 0;
    bool stderrReaderExceptionCaught = false;
    std::wstring stderrReaderExceptionText;

    std::thread stdoutReaderThread;
    std::thread stderrReaderThread;

    // Join reader threads and convert reader failures into runtime diagnostics.
    //
    // Important:
    // - Reader thread exceptions are caught inside the reader lambdas so unwinding
    //   cannot destroy a still-joinable std::thread and trigger std::terminate.
    // - This helper must be called on every path that starts reader threads before
    //   returning from RunHiddenWithRouting.
    // - Reader failures are reported through runtime diagnostics, which means they
    //   may appear in the stderr-sr-and-child timeline.
    auto JoinReadersAndFailIfNeeded = [&](const wchar_t* context) -> bool {
        if (stdoutReaderThread.joinable()) stdoutReaderThread.join();
        if (stderrReaderThread.joinable()) stderrReaderThread.join();

        if (stdoutReadGle != 0) {
            std::wstring msg;
            if (context && *context) {
                msg += L"[";
                msg += context;
                msg += L"] ";
            }
            msg += L"stdout reader failed; ";
            msg += ErrorHelpers::FormatGle(stdoutReadGle);
            diag.ErrorLine(msg);
        }

        if (stderrReadGle != 0) {
            std::wstring msg;
            if (context && *context) {
                msg += L"[";
                msg += context;
                msg += L"] ";
            }
            msg += L"stderr reader failed; ";
            msg += ErrorHelpers::FormatGle(stderrReadGle);
            diag.ErrorLine(msg);
        }

        if (stdoutReaderExceptionCaught) {
            std::wstring msg;
            if (context && *context) {
                msg += L"[";
                msg += context;
                msg += L"] ";
            }
            msg += L"stdout reader failed; exception=" + stdoutReaderExceptionText;
            diag.ErrorLine(msg);
        }

        if (stderrReaderExceptionCaught) {
            std::wstring msg;
            if (context && *context) {
                msg += L"[";
                msg += context;
                msg += L"] ";
            }
            msg += L"stderr reader failed; exception=" + stderrReaderExceptionText;
            diag.ErrorLine(msg);
        }

        return
            (stdoutReadGle != 0) ||
            (stderrReadGle != 0) ||
            stdoutReaderExceptionCaught ||
            stderrReaderExceptionCaught;
    };

    auto ExecuteForcedStopAndJoin = [&](SRRuntimeStopReason::StopReason reason) -> bool {
        StopAndUnblockReaders(
            diag,
            job,
            childProc,
            stdoutReadPipe,
            stderrReadPipe,
            2000,
            SRRuntimeStopReason::ToChildTerminateExitCode(reason)
        );

        return JoinReadersAndFailIfNeeded(
            SRRuntimeStopReason::ToReaderJoinDiagnosticLabel(reason)
        );
    };

    try {
        stdoutReaderThread = std::thread([&] {
            SRThreading::RunGuardedThreadEntry(
                [&] {
                    if (stdoutReadPipe.valid()) {
                        stdoutReadGle = ChildStdReader::ReadAndRouteStdoutPipe(
                            stdoutReadPipe.get(),
                            stdoutRouter
                        );
                    }
                },
                [&](const SRThreading::ThreadExceptionInfo& ex) {
                    stdoutReaderExceptionText = ex.text;
                    stdoutReaderExceptionCaught = true;
                }
            );
        });

        stderrReaderThread = std::thread([&] {
            SRThreading::RunGuardedThreadEntry(
                [&] {
                    if (stderrReadPipe.valid()) {
                        stderrReadGle = ChildStdReader::ReadAndRouteStderrPipe(
                            stderrReadPipe.get(),
                            stderrRouter
                        );
                    }
                },
                [&](const SRThreading::ThreadExceptionInfo& ex) {
                    stderrReaderExceptionCaught = true;
                    stderrReaderExceptionText = ex.text;
                }
            );
        });

        {
            DWORD rr = ResumeThread(childThread.get());
            if (rr == (DWORD)-1) {
                DWORD gle = GetLastError();
                ReportRuntimeFatal(L"[JOB] ResumeThread failed; " + ErrorHelpers::FormatGle(gle));
                ExecuteForcedStopAndJoin(SRRuntimeStopReason::StopReason::ResumeThreadFailed);
                result.stopReason = SRRuntimeStopReason::StopReason::ResumeThreadFailed;
                return BuildRuntimeResult(255);
            }
            diag.DebugLine(
                L"[TIMELINE] Timeline entries are shared by SR diagnostics, child stdout and child stderr. "
                L"Individual outputs may contain only a subset of timeline entries due to stream filtering "
                L"(stderr-sr-and-child/stderr-sr/stderr-child/stderr-sr-and-child-incl-stdout) or diagnostic-level "
                L"filtering (debug/verbose). TXT output groups consecutive child stdout or child stderr events into "
                L"a single segment because child stream events are not line-aware and per-event headers could split "
                L"raw output within a line. The segment header identifies the first event in that segment; therefore, "
                L"gaps in eventOrderNo values visible in TXT headers do not necessarily indicate missing timeline events. "
                L"JSONL output preserves each timeline event as a separate record and provides the complete "
                L"event-level representation."
            );
            diag.DebugLine(L"[JOB] ResumeThread OK; Child process started.");
            result.childStarted = true;
        }

        DWORD wait = WAIT_FAILED;
        HANDLE limitEvent = bufferLimitPtr ? bufferLimitPtr->LimitEventHandle() : nullptr;

        if (limitEvent) {
            HANDLE waitHandles[2] = { childProc.get(), limitEvent };
            wait = (opt.timeoutMs == 0)
                ? WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE)
                : WaitForMultipleObjects(2, waitHandles, FALSE, opt.timeoutMs);
        } else {
            wait = (opt.timeoutMs == 0)
                ? WaitForSingleObject(childProc.get(), INFINITE)
                : WaitForSingleObject(childProc.get(), opt.timeoutMs);
        }

        if (bufferLimitPtr && bufferLimitPtr->EventFailureDetected()) {
            diag.ErrorLine(
                L"Buffer-limit event failure detected; operation=" +
                std::wstring(bufferLimitPtr->FirstEventFailureOperationName()) +
                L" " +
                ErrorHelpers::FormatGle(bufferLimitPtr->FirstEventFailureGle())
            );
        }

        const SRRuntimeStopReason::StopReason stopReason =
            SRRuntimeStopReason::FromWaitResult(wait);

        executionTimeline->ProbeLine(
            L"[RUNTIME][WAIT] wait=" + std::to_wstring(wait) +
            L" stopReason=" +
            std::wstring(SRRuntimeStopReason::ToReaderJoinDiagnosticLabel(stopReason)) +
            L" limitHit=" +
            std::wstring(
                bufferLimitPtr && bufferLimitPtr->LimitHit()
                    ? L"TRUE"
                    : L"FALSE"
            )
        );

        result.stopReason = stopReason;

        if (stopReason == SRRuntimeStopReason::StopReason::WaitFailed) {
            DWORD gle = GetLastError();

            const bool joinFailed = ExecuteForcedStopAndJoin(stopReason);


            ReportRuntimeFatal(
                L"Fatal runtime stop reason: WaitForSingleObject/WaitForMultipleObjects failed; " +
                ErrorHelpers::FormatGle(gle)
            );

            return BuildRuntimeResult(joinFailed ? 255 : SRRuntimeStopReason::ToSRExitCode(stopReason));
        }

        if (stopReason == SRRuntimeStopReason::StopReason::Timeout) {
            const bool joinFailed = ExecuteForcedStopAndJoin(stopReason);


            ReportRuntimeFatal(
                L"Fatal runtime stop: Timeout exceeded; timeout_ms=" +
                std::to_wstring(opt.timeoutMs) +
                L" exit_code=124"
            );

            return BuildRuntimeResult(joinFailed ? 255 : SRRuntimeStopReason::ToSRExitCode(stopReason));
        }

        if (stopReason == SRRuntimeStopReason::StopReason::BufferLimit) {
            std::wstring which = L"?";
            SRBufferLimiter::StreamType first =
                bufferLimitPtr ? bufferLimitPtr->FirstHitStream()
                            : SRBufferLimiter::StreamType::None;

            if (first == SRBufferLimiter::StreamType::Stdout) which = L"stdout";
            else if (first == SRBufferLimiter::StreamType::Stderr) which = L"stderr";

            const bool joinFailed = ExecuteForcedStopAndJoin(stopReason);


            std::wstring bufferLimitFatalMessage =
                L"Fatal runtime stop: Buffer limit exceeded; first_hit=" + which +
                L" stdout_max=" + std::to_wstring(opt.stdoutMaxBufferBytes) +
                L" stderr_max=" + std::to_wstring(opt.stderrMaxBufferBytes) +
                L" total_max=" + std::to_wstring(opt.maxTotalBufferBytes) +
                L" action=abort";

            ReportRuntimeFatal(bufferLimitFatalMessage);
            
            return BuildRuntimeResult(joinFailed ? 255 : SRRuntimeStopReason::ToSRExitCode(stopReason));
        }

        int exitCode = 0;
        diag.DebugLine(L"Child exited");
        if (JoinReadersAndFailIfNeeded(SRRuntimeStopReason::ToReaderJoinDiagnosticLabel(stopReason))) return BuildRuntimeResult(255);
        diag.DebugLine(L"Reader threads joined");



        DWORD childExitCode = 0;
        if (!GetExitCodeProcess(childProc.get(), &childExitCode)) {
            DWORD gle = GetLastError();
            diag.ErrorLine(L"GetExitCodeProcess failed; " + ErrorHelpers::FormatGle(gle));
            exitCode = 255;
        } else {
            exitCode = static_cast<int>(childExitCode);
            diag.DebugLine(L"GetExitCodeProcess OK; exitCode=" + std::to_wstring(exitCode));
        }

        return BuildRuntimeResult(exitCode);
    } catch (const std::bad_alloc&) {
        ExecuteForcedStopAndJoin(SRRuntimeStopReason::StopReason::UnhandledException);

        ReportRuntimeFatal(L"Unhandled std::bad_alloc in RunHiddenWithRouting");

        result.stopReason = SRRuntimeStopReason::StopReason::UnhandledException;
        return BuildRuntimeResult(255);

    } catch (const std::exception& ex) {
        ExecuteForcedStopAndJoin(SRRuntimeStopReason::StopReason::UnhandledException);

        const std::wstring detail = FileHelpers::Utf8ToWide(ex.what());
        if (!detail.empty()) {
            ReportRuntimeFatal(
                L"Unhandled std::exception in RunHiddenWithRouting; " + detail
            );
        } else {
            ReportRuntimeFatal(L"Unhandled std::exception in RunHiddenWithRouting");
        }

        result.stopReason = SRRuntimeStopReason::StopReason::UnhandledException;
        return BuildRuntimeResult(255);

    } catch (...) {
        ExecuteForcedStopAndJoin(SRRuntimeStopReason::StopReason::UnhandledException);

        ReportRuntimeFatal(L"Unhandled unknown exception in RunHiddenWithRouting");

        result.stopReason = SRRuntimeStopReason::StopReason::UnhandledException;
        return BuildRuntimeResult(255);
    }
}
