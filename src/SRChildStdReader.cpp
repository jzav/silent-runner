// SRChildStdReader.cpp
// ------------------
// Read child stdout/stderr pipes and forward raw bytes to the provided gateway.


#include "SRChildStdReader.h"
#include <vector>
#include <optional>
#include <system_error>
#include <utility>

#include "ErrorHelpers.h"
#include "SRLifecycleDiagnostics.h"
#include "SRRuntimeCoordinator.h"
#include "SRThreading.h"

#include "SRLogGatewayStdout.h"
#include "SRLogGatewayStderr.h"

namespace SRChildStdReader {

namespace {

using RouteBytesFn = void (*)(void* ctx, const char* data, size_t size);

class ChildEventFramer {
public:
    ChildEventFramer(
        SR::ChildEventFraming framing,
        uint64_t newlineMaxBytes,
        RouteBytesFn routeBytes,
        void* routeContext
    )
        : framing_(framing),
          newlineMaxBytes_(newlineMaxBytes),
          routeBytes_(routeBytes),
          routeContext_(routeContext) {
    }

    void Consume(const char* data, size_t size) {
        for (size_t i = 0; i < size; ++i) {
            const char ch = data[i];

            if (framing_ == SR::ChildEventFraming::Lf) {
                pending_.push_back(ch);

                if (ch == '\n' || ReachedNewlineMaxBytes_()) {
                    Emit_();
                }

                continue;
            }

            if (awaitingCrlfThresholdResolution_) {
                if (ch == '\n') {
                    pending_.push_back(ch);
                    Emit_();
                    continue;
                }

                Emit_();
            }

            pending_.push_back(ch);

            const size_t pendingSize = pending_.size();
            if (pendingSize >= 2 &&
                pending_[pendingSize - 2] == '\r' &&
                pending_[pendingSize - 1] == '\n') {
                Emit_();
                continue;
            }

            if (ReachedNewlineMaxBytes_()) {
                if (ch == '\r') {
                    awaitingCrlfThresholdResolution_ = true;
                } else {
                    Emit_();
                }
            }
        }
    }

    void Flush() {
        awaitingCrlfThresholdResolution_ = false;
        Emit_();
    }

private:
    bool ReachedNewlineMaxBytes_() const noexcept {
        return
            static_cast<uint64_t>(pending_.size()) >= newlineMaxBytes_;
    }

    void Emit_() {
        if (pending_.empty()) {
            awaitingCrlfThresholdResolution_ = false;
            return;
        }

        routeBytes_(
            routeContext_,
            pending_.data(),
            pending_.size()
        );

        pending_.clear();
        awaitingCrlfThresholdResolution_ = false;
    }

    SR::ChildEventFraming framing_;
    uint64_t newlineMaxBytes_;
    RouteBytesFn routeBytes_;
    void* routeContext_;
    std::vector<char> pending_;
    bool awaitingCrlfThresholdResolution_ = false;
};

static DWORD ReadPipeCore_(
    HANDLE hRead,
    HANDLE stopEvent,
    SR::ChildEventFraming eventFraming,
    uint64_t eventNewlineMaxBytes,
    RouteBytesFn routeBytes,
    void* routeContext,
    DWORD* cancelError,
    bool* routingFailed
) {
    if (!hRead || hRead == INVALID_HANDLE_VALUE ||
        !stopEvent || stopEvent == INVALID_HANDLE_VALUE ||
        !routeBytes) {
        return ERROR_INVALID_PARAMETER;
    }
    if (routingFailed) *routingFailed = false;
    if (cancelError) *cancelError = ERROR_SUCCESS;

    CoreHelpers::UniqueHandle completionEvent(
        CreateEventW(nullptr, TRUE, FALSE, nullptr)
    );
    if (!completionEvent.valid()) {
        return GetLastError();
    }
    if (eventFraming == SR::ChildEventFraming::Chunk) {
        if (eventNewlineMaxBytes != 0) return ERROR_INVALID_PARAMETER;
    } else if ((eventFraming != SR::ChildEventFraming::Lf &&
                eventFraming != SR::ChildEventFraming::Crlf) ||
               eventNewlineMaxBytes == 0) {
        return ERROR_INVALID_PARAMETER;
    }

    std::optional<ChildEventFramer> framer;
    if (eventFraming != SR::ChildEventFraming::Chunk) {
        framer.emplace(eventFraming, eventNewlineMaxBytes, routeBytes, routeContext);
    }

    bool drainOnly = false;
    auto disableRouting = [&]() noexcept {
        drainOnly = true;
        if (routingFailed) *routingFailed = true;
        // Release any partially framed data, including potentially large buffers.
        framer.reset();
    };

    auto safelyRoute = [&](const char* data, size_t size) noexcept {
        if (drainOnly) return;
        try {
            if (framer) {
                framer->Consume(data, size);
            } else {
                routeBytes(routeContext, data, size);
            }
        } catch (...) {
            // A failure in framing or downstream routing must not stop draining
            // the pipe: the child might otherwise block on its next write.
            disableRouting();
        }
    };

    auto safelyFlush = [&]() noexcept {
        if (!framer) return;
        try {
            framer->Flush();
        } catch (...) {
            disableRouting();
        }
    };

    constexpr DWORD kBufferSize = 1u << 15;
    char buffer[kBufferSize];

    for (;;) {
        const DWORD stopState = WaitForSingleObject(stopEvent, 0);
        if (stopState == WAIT_OBJECT_0) {
            safelyFlush();
            return ERROR_SUCCESS;
        }
        if (stopState != WAIT_TIMEOUT) {
            const DWORD gle = (stopState == WAIT_FAILED)
                ? GetLastError() : ERROR_GEN_FAILURE;
            safelyFlush();
            return gle;
        }

        if (!ResetEvent(completionEvent.get())) {
            const DWORD gle = GetLastError();
            safelyFlush();
            return gle;
        }

        // Exactly one outstanding read per reader. The OVERLAPPED structure
        // and buffer remain alive until GetOverlappedResult confirms completion.
        OVERLAPPED overlapped{};
        overlapped.hEvent = completionEvent.get();

        DWORD bytesRead = 0;
        BOOL ok = ReadFile(
            hRead,
            buffer,
            kBufferSize,
            &bytesRead,
            &overlapped
        );
        DWORD gle = ok ? ERROR_SUCCESS : GetLastError();

        if (!ok && gle == ERROR_IO_PENDING) {
            const HANDLE waitHandles[] = {
                completionEvent.get(),
                stopEvent
            };
            const DWORD waitResult = WaitForMultipleObjects(
                2, waitHandles, FALSE, INFINITE
            );

            DWORD waitError = ERROR_SUCCESS;
            if (waitResult != WAIT_OBJECT_0) {
                if (waitResult != WAIT_OBJECT_0 + 1) {
                    waitError = (waitResult == WAIT_FAILED)
                        ? GetLastError() : ERROR_GEN_FAILURE;
                }

                // The reader owns the request and cancels it from its own
                // thread. ERROR_NOT_FOUND can mean it already completed.
                if (!CancelIoEx(hRead, &overlapped)) {
                    const DWORD cancelGle = GetLastError();
                    if (cancelGle != ERROR_NOT_FOUND &&
                        cancelError &&
                        *cancelError == ERROR_SUCCESS) {
                        *cancelError = cancelGle;
                    }
                }
            }

            // CancelIoEx only requests cancellation; I/O completion must still be
            // confirmed before releasing the OVERLAPPED structure or its buffer.
            // In the pathological case where Windows never completes the request,
            // GetOverlappedResult(TRUE) can wait indefinitely, even with
            // --abort-on-runtime-failure enabled.
            // This is considered extremely unlikely for local named pipes.
            // Like .NET and libuv, we rely on I/O completion rather than introducing
            // a watchdog or risking use-after-free by abandoning pending I/O.
            ok = GetOverlappedResult(
                hRead,
                &overlapped,
                &bytesRead,
                TRUE
            );
            gle = ok ? ERROR_SUCCESS : GetLastError();

            if (waitError != ERROR_SUCCESS) {
                safelyFlush();
                return waitError;
            }
        }

        if (!ok) {
            safelyFlush();
            if (gle == ERROR_BROKEN_PIPE ||
                gle == ERROR_HANDLE_EOF) {
                return ERROR_SUCCESS;
            }
            if (gle == ERROR_OPERATION_ABORTED &&
                WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0) {
                return ERROR_SUCCESS;
            }
            return gle;
        }

        if (bytesRead == 0) {
            safelyFlush();
            return ERROR_SUCCESS;
        }

        safelyRoute(buffer, static_cast<size_t>(bytesRead));
    }
}

static void RouteStdoutBytes_(void* ctx, const char* data, size_t size) {
    auto* router = static_cast<SRLogGatewayStdout*>(ctx);
    if (!router || !data || size == 0) return;
    router->RouteChildBytes(data, size);
}

static void RouteStderrBytes_(void* ctx, const char* data, size_t size) {
    auto* router = static_cast<SRLogGatewayStderr*>(ctx);
    if (!router || !data || size == 0) return;
    router->RouteChildBytes(data, size);
}

} // namespace

DWORD ReadAndRouteStdoutPipe(
    HANDLE hRead,
    HANDLE stopEvent,
    SRLogGatewayStdout& stdoutRouter,
    SR::ChildEventFraming eventFraming,
    uint64_t eventNewlineMaxBytes,
    DWORD* cancelError,
    bool* routingFailed
) {
    return ReadPipeCore_(
        hRead,
        stopEvent,
        eventFraming,
        eventNewlineMaxBytes,
        &RouteStdoutBytes_,
        &stdoutRouter,
        cancelError,
        routingFailed
    );
}

DWORD ReadAndRouteStderrPipe(
    HANDLE hRead,
    HANDLE stopEvent,
    SRLogGatewayStderr& stderrRouter,
    SR::ChildEventFraming eventFraming,
    uint64_t eventNewlineMaxBytes,
    DWORD* cancelError,
    bool* routingFailed
) {
    return ReadPipeCore_(
        hRead,
        stopEvent,
        eventFraming,
        eventNewlineMaxBytes,
        &RouteStderrBytes_,
        &stderrRouter,
        cancelError,
        routingFailed
    );
}
} // namespace SRChildStdReader

SRChildStreamReader::SRChildStreamReader(
    CoreHelpers::UniqueHandle&& readPipe,
    SRLogGatewayStdout& router,
    SRRuntimeCoordinator& coordinator,
    SRLifecycleDiagnostics& diag,
    SR::ChildEventFraming framing,
    uint64_t newlineMaxBytes
)
    : readPipe_(std::move(readPipe)),
      coordinator_(coordinator),
      diag_(diag),
      stdoutRouter_(&router),
      framing_(framing),
      newlineMaxBytes_(newlineMaxBytes) {
}

SRChildStreamReader::SRChildStreamReader(
    CoreHelpers::UniqueHandle&& readPipe,
    SRLogGatewayStderr& router,
    SRRuntimeCoordinator& coordinator,
    SRLifecycleDiagnostics& diag,
    SR::ChildEventFraming framing,
    uint64_t newlineMaxBytes
)
    : readPipe_(std::move(readPipe)),
      coordinator_(coordinator),
      diag_(diag),
      stderrRouter_(&router),
      framing_(framing),
      newlineMaxBytes_(newlineMaxBytes) {
}

SRChildStreamReader::~SRChildStreamReader() {
    if (workerThread_.joinable()) {
        Abort();
    }
}

void SRChildStreamReader::Start() {
    stopEvent_.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!stopEvent_.valid()) {
        throw std::system_error(
            static_cast<int>(GetLastError()),
            std::system_category(),
            "CreateEventW(stopEvent) failed"
        );
    }

    workerThread_ = std::thread([this] {
        Run_();
    });
}

void SRChildStreamReader::Run_() noexcept {
    if (diag_.IsDebugEnabled()) {
        try {
            diag_.DebugLine(
                stdoutRouter_ ? L"stdout reader started" : L"stderr reader started"
            );
        } catch (...) {
            // Optional diagnostics must not interrupt the reader.
        }
    }

    SRThreading::RunGuardedThreadEntry(
        [&] {
            if (stdoutRouter_) {
                readError_ = SRChildStdReader::ReadAndRouteStdoutPipe(
                    readPipe_.get(),
                    stopEvent_.get(),
                    *stdoutRouter_,
                    framing_,
                    newlineMaxBytes_,
                    &cancelError_,
                    &routingFailed_
                );
            } else {
                readError_ = SRChildStdReader::ReadAndRouteStderrPipe(
                    readPipe_.get(),
                    stopEvent_.get(),
                    *stderrRouter_,
                    framing_,
                    newlineMaxBytes_,
                    &cancelError_,
                    &routingFailed_
                );
            }
        },
        [&](const SRThreading::ThreadExceptionInfo& ex) {
            exceptionCaught_ = true;
            exceptionText_ = ex.text;
        }
    );

    // Close the read end before reporting completion. An unexpectedly failed
    // reader must not leave an open but undrained pipe while Runtime waits
    // for the child process tree to finish.
    readPipe_.reset();


    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        finished_ = true;
    }
    // Log before reporting completion so diagnostic replay-buffer accounting
    // is included in the coordinator's final decision. Logging is best-effort.
    LogResult_();
    if (stdoutRouter_) {
        coordinator_.ReportStdoutReaderFinished();
    } else {
        coordinator_.ReportStderrReaderFinished();
    }
}

void SRChildStreamReader::LogResult_() noexcept {
    const wchar_t* stream = stdoutRouter_ ? L"stdout" : L"stderr";
    if (readError_ != ERROR_SUCCESS ||
        cancelError_ != ERROR_SUCCESS ||
        exceptionCaught_ || routingFailed_) {
        try {
            std::wstring message = std::wstring(stream) + L" reader failed";
            if (readError_ != ERROR_SUCCESS) {
                message += L"; " + ErrorHelpers::FormatGle(readError_);
            }
            if (cancelError_ != ERROR_SUCCESS) {
                message += L"; CancelIoEx: " + ErrorHelpers::FormatGle(cancelError_);
            }
            if (exceptionCaught_) {
                message += L"; exception=" + exceptionText_;
            }
            if (routingFailed_) {
                message += L"; routing failed, remaining output drained without processing";
            }
            diag_.ErrorLine(message);
        } catch (...) {
            // A failed diagnostic event must not prevent reader completion.
        }
    }
    if (diag_.IsDebugEnabled()) {
        try {
            diag_.DebugLine(std::wstring(stream) + L" reader finished");
        } catch (...) {
        }
    }
}

void SRChildStreamReader::Abort() {
    if (stopEvent_.valid()) {
        // The reader observes this event and cancels its own pending I/O.
        SetEvent(stopEvent_.get());
    }
    Join();
}

void SRChildStreamReader::Join() {
    if (workerThread_.joinable()) {
        workerThread_.join();
    }

    // The thread has completed all I/O before these handles are released.
    readPipe_.reset();
    stopEvent_.reset();
}

bool SRChildStreamReader::Finished() const {
    std::lock_guard<std::mutex> lock(stateMutex_);
    return finished_;
}
