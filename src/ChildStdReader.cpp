// ChildStdReader.cpp
// ------------------
 // Read child stdout/stderr pipes and forward raw bytes to the provided gateway.


#include "ChildStdReader.h"
#include <vector>

#include "SRLogGatewayStdout.h"
#include "SRLogGatewayStderr.h"

namespace ChildStdReader {

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
    SR::ChildEventFraming eventFraming,
    uint64_t eventNewlineMaxBytes,
    RouteBytesFn routeBytes,
    void* routeContext
) {
    if (!hRead || !routeBytes) return ERROR_INVALID_PARAMETER;

    if (eventFraming == SR::ChildEventFraming::Chunk) {
        if (eventNewlineMaxBytes != 0) return ERROR_INVALID_PARAMETER;

        constexpr DWORD kBufferSize = 1u << 15;
        char buffer[kBufferSize];
        DWORD bytesRead = 0;

        for (;;) {
            const BOOL ok = ReadFile(
                hRead,
                buffer,
                kBufferSize,
                &bytesRead,
                nullptr
            );
            if (!ok) {
                const DWORD gle = GetLastError();
                if (gle == ERROR_BROKEN_PIPE) return 0;
                return gle;
            }

            if (bytesRead == 0) return 0;

            routeBytes(
                routeContext,
                buffer,
                static_cast<size_t>(bytesRead)
            );
        }
    }

    if ((eventFraming != SR::ChildEventFraming::Lf &&
         eventFraming != SR::ChildEventFraming::Crlf) ||
        eventNewlineMaxBytes == 0) {
        return ERROR_INVALID_PARAMETER;
    }

    ChildEventFramer framer(
        eventFraming,
        eventNewlineMaxBytes,
        routeBytes,
        routeContext
    );

    constexpr DWORD kBufferSize = 1u << 15;
    char buffer[kBufferSize];
    DWORD bytesRead = 0;

    for (;;) {
        const BOOL ok = ReadFile(
            hRead,
            buffer,
            kBufferSize,
            &bytesRead,
            nullptr
        );
        if (!ok) {
            const DWORD gle = GetLastError();
            framer.Flush();
            if (gle == ERROR_BROKEN_PIPE) return 0;
            return gle;
        }

        if (bytesRead == 0) {
            framer.Flush();
            return 0;
        }

        framer.Consume(
            buffer,
            static_cast<size_t>(bytesRead)
        );
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
    SRLogGatewayStdout& stdoutRouter,
    SR::ChildEventFraming eventFraming,
    uint64_t eventNewlineMaxBytes
) {
    return ReadPipeCore_(
        hRead,
        eventFraming,
        eventNewlineMaxBytes,
        &RouteStdoutBytes_,
        &stdoutRouter
    );
}

DWORD ReadAndRouteStderrPipe(
    HANDLE hRead,
    SRLogGatewayStderr& stderrRouter,
    SR::ChildEventFraming eventFraming,
    uint64_t eventNewlineMaxBytes
) {
    return ReadPipeCore_(
        hRead,
        eventFraming,
        eventNewlineMaxBytes,
        &RouteStderrBytes_,
        &stderrRouter
    );
}

} // namespace ChildStdReader
