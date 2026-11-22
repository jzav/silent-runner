#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mutex>
#include <string>
#include <thread>

#include "CoreHelpers.h"

#include "SRTypes.h"

class SRLogGatewayStdout;
class SRLogGatewayStderr;
class SRRuntimeCoordinator;
class SRLifecycleDiagnostics;

namespace SRChildStdReader {

DWORD ReadAndRouteStdoutPipe(
    HANDLE hRead,
    HANDLE stopEvent,
    SRLogGatewayStdout& stdoutRouter,
    SR::ChildEventFraming eventFraming,
    uint64_t eventNewlineMaxBytes,
    DWORD* cancelError = nullptr,
    bool* routingFailed = nullptr
);

DWORD ReadAndRouteStderrPipe(
    HANDLE hRead,
    HANDLE stopEvent,
    SRLogGatewayStderr& stderrRouter,
    SR::ChildEventFraming eventFraming,
    uint64_t eventNewlineMaxBytes,
    DWORD* cancelError = nullptr,
    bool* routingFailed = nullptr
);

} // namespace SRChildStdReader

// Owns one overlapped child pipe, its reader thread, and cancellation event.
// The caller owns the runtime shutdown sequence; this class only stops reading.
class SRChildStreamReader {
public:
    SRChildStreamReader(
        CoreHelpers::UniqueHandle&& readPipe,
        SRLogGatewayStdout& router,
        SRRuntimeCoordinator& coordinator,
        SRLifecycleDiagnostics& diag,
        SR::ChildEventFraming framing,
        uint64_t newlineMaxBytes
    );

    SRChildStreamReader(
        CoreHelpers::UniqueHandle&& readPipe,
        SRLogGatewayStderr& router,
        SRRuntimeCoordinator& coordinator,
        SRLifecycleDiagnostics& diag,
        SR::ChildEventFraming framing,
        uint64_t newlineMaxBytes
    );

    ~SRChildStreamReader();

    SRChildStreamReader(const SRChildStreamReader&) = delete;
    SRChildStreamReader& operator=(const SRChildStreamReader&) = delete;

    void Start();

    // Signals the stop event and waits for the reader thread to finish.
    // The reader cancels and completes any pending overlapped I/O itself.
    void Abort();

    // Joins the reader thread. Call only after completion or Abort().
    void Join();

    bool Finished() const;

    // Results become final after Join().
    DWORD ReadError() const noexcept { return readError_; }
    DWORD CancelError() const noexcept { return cancelError_; }
    bool ExceptionCaught() const noexcept { return exceptionCaught_; }
    bool RoutingFailed() const noexcept { return routingFailed_; }
    const std::wstring& ExceptionText() const noexcept { return exceptionText_; }

private:
    void Run_() noexcept;
    void LogResult_() noexcept;

    CoreHelpers::UniqueHandle readPipe_;
    CoreHelpers::UniqueHandle stopEvent_;
    SRRuntimeCoordinator& coordinator_;
    SRLifecycleDiagnostics& diag_;

    SRLogGatewayStdout* stdoutRouter_ = nullptr;
    SRLogGatewayStderr* stderrRouter_ = nullptr;

    SR::ChildEventFraming framing_;
    uint64_t newlineMaxBytes_;

    std::thread workerThread_;
    mutable std::mutex stateMutex_;
    bool finished_ = false;
    DWORD readError_ = 0;
    DWORD cancelError_ = 0;
    bool exceptionCaught_ = false;
    bool routingFailed_ = false;

    std::wstring exceptionText_;
};
