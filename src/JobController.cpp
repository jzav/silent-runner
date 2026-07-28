#include <unordered_map>
#include <utility>

#include "JobController.h"

#include "SRLogGatewayDiagnostics.h"
#include "ErrorHelpers.h"
#include "ProcessHelpers.h"
#include "SRThreading.h"

namespace JobController {

static constexpr const wchar_t* kJobTagPrefix = L"[JOB]";

void KillJobBestEffort(CoreHelpers::UniqueHandle& job, CoreHelpers::UniqueHandle& proc, SRLogGatewayDiagnostics& diag) {
    if (job.valid()) {
        if (!TerminateJobObject(job.get(), 1)) {
            DWORD gle = GetLastError();
            diag.ErrorLine(L"KillJobBestEffort: TerminateJobObject failed; " + ErrorHelpers::FormatGle(gle));
        }
        return;
    }

    if (proc.valid()) {
        if (!TerminateProcess(proc.get(), 1)) {
            DWORD gle = GetLastError();
            diag.ErrorLine(L"KillJobBestEffort: TerminateProcess fallback failed; " + ErrorHelpers::FormatGle(gle));
        }
    }
}

void JobIocpMonitor::start(SRLogGatewayDiagnostics& diag, HANDLE jobHandle) {
    if (!diag.IsDebugEnabled()) return;
    
    const std::wstring jobTag = kJobTagPrefix;

    // IOCP = I/O Completion Port
    diag.DebugLine(jobTag + L" IOCP MONITOR_START");

    if (!jobHandle) {
        diag.DebugLine(jobTag + L" MONITOR_START skipped: null_job_handle");
        return;
    }

    iocp.reset(CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1));
    if (!iocp.valid()) {
        DWORD gle = GetLastError();
        diag.DebugLine(jobTag + L" IOCP_CREATE_FAILED; job monitoring disabled; " + ErrorHelpers::FormatGle(gle));
        return;
    }

    JOBOBJECT_ASSOCIATE_COMPLETION_PORT port{};
    port.CompletionKey = (PVOID)jobHandle; // returned as CompletionKey in GQCS
    port.CompletionPort = iocp.get();

    if (!SetInformationJobObject(
            jobHandle,
            JobObjectAssociateCompletionPortInformation,
            &port,
            sizeof(port))) {
        DWORD gle = GetLastError();
        diag.DebugLine(jobTag + L" IOCP_ASSOCIATE_FAILED; job monitoring disabled; " + ErrorHelpers::FormatGle(gle));
        // disable monitoring (don't break runner)
        iocp.reset();
        return;
    }

    diag.DebugLine(jobTag + L" IOCP_ASSOCIATED OK");

    try {
        th = std::thread([this, &diag, jobTag]() {
            SRThreading::RunGuardedThreadEntry(
                [this, &diag, jobTag]() {
                    std::unordered_map<DWORD, std::wstring> processCache;
                    for (;;) {
                        DWORD msg = 0;
                        ULONG_PTR key = 0;
                        LPOVERLAPPED ov = nullptr;

                        BOOL ok = GetQueuedCompletionStatus(
                            iocp.get(),
                            &msg,
                            &key,
                            &ov,
                            INFINITE
                        );

                        if (!ok) {
                            DWORD gle = GetLastError();

                            if (gle == ERROR_ABANDONED_WAIT_0 || gle == ERROR_INVALID_HANDLE) {
                                diag.DebugLine(jobTag + L" IOCP_WAIT_ABORTED; " + ErrorHelpers::FormatGle(gle));
                            } else {
                                diag.DebugLine(jobTag + L" IOCP_WAIT_FAILED; " + ErrorHelpers::FormatGle(gle));
                            }

                            break;
                        }

                        // Our quit packet: key == 0 and ov == (LPOVERLAPPED)1
                        if (key == 0 && ov == (LPOVERLAPPED)1) {
                            diag.DebugLine(jobTag + L" IOCP MONITOR_STOP_SIGNAL_RECEIVED");
                            break;
                        }

                        DWORD pid = (DWORD)(ULONG_PTR)ov;

                        if (msg == JOB_OBJECT_MSG_NEW_PROCESS) {
                            const std::wstring info = ProcessHelpers::GetProcessDebugInfo(pid);
                            processCache[pid] = info;
                            diag.DebugLine(jobTag + L" NEW_PROCESS " + info);
                        } else if (msg == JOB_OBJECT_MSG_EXIT_PROCESS) {
                            auto it = processCache.find(pid);
                            if (it != processCache.end()) {
                                diag.DebugLine(jobTag + L" EXIT_PROCESS " + it->second);
                                processCache.erase(it);
                            } else {
                                diag.DebugLine(jobTag + L" EXIT_PROCESS PID=" + std::to_wstring(pid));
                            }
                        } else if (msg == JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS) {
                            auto it = processCache.find(pid);
                            if (it != processCache.end()) {
                                diag.DebugLine(jobTag + L" ABNORMAL_EXIT " + it->second);
                                processCache.erase(it);
                            } else {
                                diag.DebugLine(jobTag + L" ABNORMAL_EXIT PID=" + std::to_wstring(pid));
                            }
                        } else if (msg == JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO) {
                            diag.DebugLine(jobTag + L" ACTIVE_PROCESS_ZERO");
                            processCache.clear();
                        } else {
                            // optional
                        }
                    }
                },
                [&diag, jobTag](const SRThreading::ThreadExceptionInfo& ex) {
                    diag.DebugLine(
                        jobTag +
                        L" IOCP_MONITOR_EXCEPTION; monitoring disabled; " +
                        ex.text
                    );
                }
            );
        });
    } catch (...) {
        diag.DebugLine(
            jobTag +
            L" IOCP_THREAD_START_FAILED; monitoring disabled"
        );
        iocp.reset();
        return;
    }
}

void JobIocpMonitor::stop_and_join() {
    if (iocp.valid()) {
        if (!PostQueuedCompletionStatus(iocp.get(), 0, 0, (LPOVERLAPPED)1)) {
            iocp.reset();
        }
    }

    if (th.joinable()) th.join();
    iocp.reset();
}

JobMonGuard::~JobMonGuard() {
    if (mon) mon->stop_and_join();
}

} // namespace JobController
