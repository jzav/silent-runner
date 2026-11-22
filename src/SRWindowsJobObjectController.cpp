#include "SRWindowsJobObjectController.h"

#include <unordered_map>

#include "SRLifecycleDiagnostics.h"
#include "ErrorHelpers.h"
#include "ProcessHelpers.h"
#include "SRThreading.h"
#include "SRRuntimeCoordinator.h"

namespace {
constexpr const wchar_t* kJobTagPrefix = L"[JOB]";
constexpr DWORD kCompletionCheckIntervalMs = 300;
constexpr unsigned kJobZeroQueryFailureThreshold = 3;
}

SRWindowsJobObjectController::~SRWindowsJobObjectController() noexcept {
    Shutdown();
}

bool SRWindowsJobObjectController::Init(
    SRRuntimeCoordinator& coordinator,
    InitFailure& failure
) {
    failure = {};


    if (initAttempted_) {
        failure.reason = InitFailureReason::AlreadyInitialized;

        return false;
    }
    initAttempted_ = true;

    job_.reset(CreateJobObjectW(nullptr, nullptr));
    if (!job_.valid()) {
        failure.gle = GetLastError();
        failure.reason = InitFailureReason::CreateJobObject;

        return false;
    }
    diag_.VerboseLine(L"[JOB] job object created OK");

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli{};
    jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(
            job_.get(), JobObjectExtendedLimitInformation, &jeli, sizeof(jeli))) {
        failure.gle = GetLastError();
        failure.reason = InitFailureReason::SetKillOnJobClose;

        return false;
    }
    diag_.VerboseLine(L"[JOB] job limit KILL_ON_JOB_CLOSE set OK");

    // Bind the coordinator before starting the Job Object monitoring thread.
    coordinator_ = &coordinator;

    if (!StartMonitor_(failure)) {
        return false;
    }
    return true;
}

bool SRWindowsJobObjectController::AssignProcess(HANDLE process, DWORD& outGle) const noexcept {
    outGle = 0;
    if (!job_.valid() || !process || process == INVALID_HANDLE_VALUE) {
        outGle = ERROR_INVALID_HANDLE;
        return false;
    }
    if (!AssignProcessToJobObject(job_.get(), process)) {
        outGle = GetLastError();
        return false;
    }
    return true;
}

bool SRWindowsJobObjectController::Abort(DWORD exitCode, DWORD& outGle) noexcept {
    outGle = 0;
    if (!job_.valid()) {
        outGle = ERROR_INVALID_HANDLE;
        return false;
    }
    if (!TerminateJobObject(job_.get(), exitCode)) {
        outGle = GetLastError();
        return false;
    }

    // Termination succeeded even if completion monitoring cannot be enabled.
    // Monitoring failures are tracked separately.
    RequestProcessTreeCompletionCheck();
    return true;
}

bool SRWindowsJobObjectController::RequestProcessTreeCompletionCheck() noexcept {
    if (stopping_.load(std::memory_order_acquire) ||
        !monitorThread_.joinable()) {
        return false;
    }

    // Completion checks are independent of IOCP availability.
    // The monitor wakes at least once per interval without an activation packet.
    CompletionCheckState expected = CompletionCheckState::NotRequested;
    completionCheckState_.compare_exchange_strong(
        expected,
        CompletionCheckState::Requested,
        std::memory_order_acq_rel
    );
    return true;
}

bool SRWindowsJobObjectController::TryGetActiveProcessCount(DWORD& count, DWORD& outGle) const noexcept {
    count = 0;
    outGle = 0;
    if (!job_.valid()) {
        outGle = ERROR_INVALID_HANDLE;
        return false;
    }

    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting{};
    if (!QueryInformationJobObject(
            job_.get(),
            JobObjectBasicAccountingInformation,
            &accounting,
            sizeof(accounting),
            nullptr)) {
        outGle = GetLastError();
        return false;
    }
    count = accounting.ActiveProcesses;
    return true;
}

bool SRWindowsJobObjectController::StartMonitor_(InitFailure& failure) {
    const std::wstring jobTag = kJobTagPrefix;
    diag_.DebugLine(jobTag + L" JOB_MONITOR_START");

    // IOCP is required for DEBUG process diagnostics. Job accounting remains authoritative.
    const auto reportIocpFailure = [&](const wchar_t* operation, DWORD gle) noexcept {
        notificationFailed_.store(true, std::memory_order_release);
        try {
            diag_.ErrorLine(
                jobTag + L" " + operation + L"; polling-only mode; " +
                ErrorHelpers::FormatGle(gle)
            );
        } catch (...) {
            // Optional diagnostics must not prevent monitoring startup.
        }
    };

    iocp_.reset(CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1));
    if (!iocp_.valid()) {
        const DWORD gle = GetLastError();
        if (diag_.IsDebugEnabled()) {
            failure.reason = InitFailureReason::CreateIocp;
            failure.gle = gle;
            return false;
        }
        reportIocpFailure(L"IOCP_CREATE_FAILED", gle);
    } else {
        JOBOBJECT_ASSOCIATE_COMPLETION_PORT port{};
        port.CompletionKey = job_.get();
        port.CompletionPort = iocp_.get();

        if (!SetInformationJobObject(
                job_.get(),
                JobObjectAssociateCompletionPortInformation,
                &port,
                sizeof(port))) {
            const DWORD gle = GetLastError();
            iocp_.reset();
            if (diag_.IsDebugEnabled()) {
                failure.reason = InitFailureReason::AssociateIocp;
                failure.gle = gle;
                return false;
            }
            reportIocpFailure(L"IOCP_ASSOCIATE_FAILED", gle);
        } else {
            iocpAssociated_ = true;
            diag_.VerboseLine(jobTag + L" IOCP_ASSOCIATED OK");
        }
    }

    // The worker only uses captured native handles; Shutdown() joins it
    // before releasing the Job Object and IOCP.
    const HANDLE portHandle = iocp_.get();
    const HANDLE jobHandle = job_.get();
    try {
        monitorThread_ = std::thread([this, jobTag, jobHandle, portHandle]() {
            const auto notifyFailure = [this](SRRuntimeCoordinator::RuntimeFailureCause cause) noexcept {
                notificationFailed_.store(true, std::memory_order_release);
                try {
                    coordinator_->ReportRuntimeFailure(cause);
                } catch (...) {
                    // Failure reporting must not escape the monitoring thread.
                }
            };

            SRThreading::RunGuardedThreadEntry(
                [this, jobTag, jobHandle, portHandle, &notifyFailure]() {
                    struct ProcessInfo {
                        std::wstring debugInfo;
                        CoreHelpers::UniqueHandle handle;
                    };
                    std::unordered_map<DWORD, ProcessInfo> processCache;
                    bool isAvailable = (portHandle != nullptr && portHandle != INVALID_HANDLE_VALUE);
                    bool queryFailureReported = false;
                    unsigned consecutiveQueryFailures = 0;
                    for (;;) {
                        if (stopping_.load(std::memory_order_acquire)) break;

                        DWORD msg = 0;
                        ULONG_PTR key = 0;
                        LPOVERLAPPED ov = nullptr;
                        BOOL ok = FALSE;

                        if (isAvailable) {
                            ok = GetQueuedCompletionStatus(
                                portHandle,
                                &msg,
                                &key,
                                &ov,
                                kCompletionCheckIntervalMs
                            );

                            if (!ok) {
                                const DWORD gle = GetLastError();
                                // A failed completion packet is not a failed port.
                                if (ov == nullptr && gle != WAIT_TIMEOUT) {
                                    if (stopping_.load(std::memory_order_acquire)) break;

                                    isAvailable = false;
                                    processCache.clear();
                                    notificationFailed_.store(true, std::memory_order_release);
                                    try {
                                        diag_.ErrorLine(
                                            jobTag + L" IOCP_WAIT_FAILED; notifications disabled; " +
                                            ErrorHelpers::FormatGle(gle)
                                        );
                                    } catch (...) {
                                        // Diagnostics must not stop process-tree monitoring.
                                    }
                                }
                            } else if (
                                key == 0 &&
                                ov == reinterpret_cast<LPOVERLAPPED>(1)
                            ) {
                                diag_.VerboseLine(
                                    jobTag + L" IOCP MONITOR_STOP_SIGNAL_RECEIVED"
                                );
                                break;
                            }
                        } else {
                            // Keep the same thread alive for completion checks.
                            Sleep(kCompletionCheckIntervalMs);
                        }
                        // IOCP process notifications are only used for DEBUG diagnostics.
                        // Completion checks below continue even when IOCP is unavailable.
                        if (isAvailable && ok && diag_.IsDebugEnabled() &&
                            key == reinterpret_cast<ULONG_PTR>(jobHandle)) {
                            const DWORD pid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(ov));
                            if (msg == JOB_OBJECT_MSG_NEW_PROCESS) {
                                CoreHelpers::UniqueHandle processHandle(
                                    OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)
                                );
                                const DWORD openGle = processHandle.valid() ? 0 : GetLastError();
                                const std::wstring info = ProcessHelpers::GetProcessDebugInfo(pid, processHandle.get());
                                processCache[pid] = {info, std::move(processHandle)};
                                diag_.DebugLine(jobTag + L" NEW_PROCESS " + info);
                                if (openGle != 0) {
                                    diag_.DebugLine(
                                        jobTag + L" OPEN_PROCESS_FAILED PID=" + std::to_wstring(pid) +
                                        L"; " + ErrorHelpers::FormatGle(openGle)
                                    );
                                }
                            } else if (msg == JOB_OBJECT_MSG_EXIT_PROCESS ||
                                           msg == JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS) {
                                const wchar_t* eventName =
                                    msg == JOB_OBJECT_MSG_EXIT_PROCESS
                                        ? L" EXIT_PROCESS " : L" ABNORMAL_EXIT ";
                                auto it = processCache.find(pid);
                                if (it != processCache.end()) {
                                    std::wstring line = jobTag + eventName + it->second.debugInfo;
                                    if (it->second.handle.valid()) {
                                        DWORD exitCode = 0;
                                        if (GetExitCodeProcess(it->second.handle.get(), &exitCode)) {
                                            line += L" EXIT_CODE=" + std::to_wstring(exitCode);
                                        } else {
                                            const DWORD gle = GetLastError();
                                            diag_.DebugLine(
                                                jobTag + L" GET_EXIT_CODE_FAILED PID=" +
                                                std::to_wstring(pid) + L"; " +
                                                ErrorHelpers::FormatGle(gle)
                                            );
                                        }
                                    }
                                    diag_.DebugLine(line);
                                    processCache.erase(it);
                                } else {
                                    diag_.DebugLine(
                                        jobTag + eventName + L"PID=" + std::to_wstring(pid)
                                );
                                }
                            }
                        }

                        if (completionCheckState_.load(std::memory_order_acquire) ==
                            CompletionCheckState::Requested) {
                            DWORD activeProcesses = 0;
                            DWORD queryGle = 0;

                            if (!TryGetActiveProcessCount(
                                    activeProcesses,
                                    queryGle)) {
                                // Report after three consecutive failures; keep polling until Job zero.
                                if (consecutiveQueryFailures < kJobZeroQueryFailureThreshold) {
                                    ++consecutiveQueryFailures;
                                }
                                if (!queryFailureReported &&
                                    consecutiveQueryFailures == kJobZeroQueryFailureThreshold) {
                                    queryFailureReported = true;
                                    try {
                                        // Lifecycle diagnostics records the event through ExecutionTimeline.
                                        diag_.ErrorLine(
                                            jobTag + L" QUERY_ACTIVE_PROCESSES_FAILED; " +
                                            ErrorHelpers::FormatGle(queryGle)
                                        );
                                    } catch (...) {
                                        // Failure reporting must not stop Job accounting retries.
                                    }
                                    notifyFailure(
                                        SRRuntimeCoordinator::RuntimeFailureCause::JobAccountingQueryFailed);
                                }
                                continue;
                            }
                            consecutiveQueryFailures = 0;
                            if (activeProcesses == 0) {
                                CompletionCheckState expected =
                                    CompletionCheckState::Requested;

                                if (completionCheckState_.compare_exchange_strong(
                                        expected,
                                        CompletionCheckState::Finished,
                                        std::memory_order_acq_rel)) {
                                    processCache.clear();
                                    coordinator_->ReportProcessTreeFinished();
                                    try {
                                        diag_.DebugLine(jobTag + L" ACTIVE_PROCESSES_ZERO_CONFIRMED");
                                    } catch (...) {
                                        // Optional diagnostics must not disrupt completion monitoring.
                                    }

                                }
                            }
                        }
                    }
                },
                [this, jobTag, &notifyFailure](const SRThreading::ThreadExceptionInfo& ex) {
                    notifyFailure(SRRuntimeCoordinator::RuntimeFailureCause::JobMonitorThreadException);
                    try {
                        diag_.ErrorLine(jobTag + L" JOB_MONITOR_EXCEPTION; monitoring unavailable; " + ex.text);
                    } catch (...) {
                        // Exception callbacks must not throw from the guarded thread entry.
                    }
                }
            );
        });
    } catch (...) {
        notificationFailed_.store(true, std::memory_order_release);
        StopMonitor_();
        failure.reason = InitFailureReason::StartMonitorThread;
        // std::thread failures do not provide a Win32 GetLastError value.
        return false;
    }
    return true;
}

void SRWindowsJobObjectController::StopMonitor_() noexcept {
    stopping_.store(true, std::memory_order_release);
    if (iocp_.valid() && monitorThread_.joinable()) {
        if (!PostQueuedCompletionStatus(iocp_.get(), 0, 0, reinterpret_cast<LPOVERLAPPED>(1))) {
            // Closing the port releases a pending GetQueuedCompletionStatus call.
            iocp_.reset();
        }
    }
    if (monitorThread_.joinable()) monitorThread_.join();

    // Windows 8+ supports disassociating the completion port from a live job.
    if (iocpAssociated_ && job_.valid()) {
        JOBOBJECT_ASSOCIATE_COMPLETION_PORT detached{};
        if (!SetInformationJobObject(
                job_.get(),
                JobObjectAssociateCompletionPortInformation,
                &detached,
                sizeof(detached))) {
            const DWORD gle = GetLastError();
            if (diag_.IsDebugEnabled()) {
                try {
                    diag_.DebugLine(
                        std::wstring(kJobTagPrefix) +
                        L" IOCP_DISASSOCIATE_FAILED; " +
                        ErrorHelpers::FormatGle(gle)
                    );
                } catch (...) {
                    // Teardown diagnostics must not throw.
                }
            }
        }
        iocpAssociated_ = false;
    }
    iocp_.reset();
}

void SRWindowsJobObjectController::Shutdown() noexcept {
    StopMonitor_();

    // Closing the last Job Object handle terminates any remaining job processes.
    job_.reset();
}
