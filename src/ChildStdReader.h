#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

class SRLogGatewayStdout;
class SRLogGatewayStderr;

namespace ChildStdReader {

DWORD ReadAndRouteStdoutPipe(
    HANDLE hRead,
    SRLogGatewayStdout& stdoutRouter
);

DWORD ReadAndRouteStderrPipe(
    HANDLE hRead,
    SRLogGatewayStderr& stderrRouter
);

} // namespace ChildStdReader
