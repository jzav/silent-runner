// ChildStdReader.cpp
// ------------------
 // Read child stdout/stderr pipes and forward raw bytes to the provided gateway.


#include "ChildStdReader.h"

#include "SRLogGatewayStdout.h"
#include "SRLogGatewayStderr.h"

namespace ChildStdReader {

namespace {

static DWORD ReadPipeCore_(
    HANDLE hRead,
    void (*routeBytes)(void* ctx, const char* data, size_t size),
    void* routeContext
) {
    if (!hRead || !routeBytes) return ERROR_INVALID_PARAMETER;

    constexpr DWORD kBufferSize = 1u << 15;
    char buffer[kBufferSize];
    DWORD bytesRead = 0;

    for (;;) {
        const BOOL ok = ReadFile(hRead, buffer, kBufferSize, &bytesRead, nullptr);
        if (!ok) {
            const DWORD gle = GetLastError();
            if (gle == ERROR_BROKEN_PIPE) return 0;
            return gle;
        }

        if (bytesRead == 0) return 0;

        routeBytes(routeContext, buffer, static_cast<size_t>(bytesRead));
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
    SRLogGatewayStdout& stdoutRouter
) {
    return ReadPipeCore_(hRead, &RouteStdoutBytes_, &stdoutRouter);
}

DWORD ReadAndRouteStderrPipe(
    HANDLE hRead,
    SRLogGatewayStderr& stderrRouter
) {
    return ReadPipeCore_(hRead, &RouteStderrBytes_, &stderrRouter);
}

} // namespace ChildStdReader
