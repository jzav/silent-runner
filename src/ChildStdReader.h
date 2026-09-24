#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "SRTypes.h"

class SRLogGatewayStdout;
class SRLogGatewayStderr;

namespace ChildStdReader {

DWORD ReadAndRouteStdoutPipe(
    HANDLE hRead,
    SRLogGatewayStdout& stdoutRouter,
    SR::ChildEventFraming eventFraming,
    uint64_t eventNewlineMaxBytes
);

DWORD ReadAndRouteStderrPipe(
    HANDLE hRead,
    SRLogGatewayStderr& stderrRouter,
    SR::ChildEventFraming eventFraming,
    uint64_t eventNewlineMaxBytes
);

} // namespace ChildStdReader
