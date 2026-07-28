#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string>
#include <thread>

#include "CoreHelpers.h"

class SRLogGatewayDiagnostics;

namespace JobController {

// Best-effort process tree kill.
void KillJobBestEffort(CoreHelpers::UniqueHandle& job, CoreHelpers::UniqueHandle& proc, SRLogGatewayDiagnostics& diag);

// Debug-only IOCP-based monitor for job object events.
struct JobIocpMonitor {
    CoreHelpers::UniqueHandle iocp;
    std::thread th;

    void start(SRLogGatewayDiagnostics& diag, HANDLE jobHandle);
    void stop_and_join();
};

// RAII guard for JobIocpMonitor.
struct JobMonGuard {
    JobIocpMonitor* mon = nullptr;

    JobMonGuard() = default;
    explicit JobMonGuard(JobIocpMonitor* m) : mon(m) {}

    JobMonGuard(const JobMonGuard&) = delete;
    JobMonGuard& operator=(const JobMonGuard&) = delete;
    JobMonGuard(JobMonGuard&&) = delete;
    JobMonGuard& operator=(JobMonGuard&&) = delete;

    ~JobMonGuard();
};

} // namespace JobController
