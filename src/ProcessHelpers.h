#pragma once

#include <windows.h>
#include <string>

namespace ProcessHelpers {

    // Returns parent PID of given process.
    // Returns 0 if not available (error or system process).
    DWORD GetParentPid(DWORD pid);

    // Returns full image path of given process.
    // Returns empty string on failure.
    std::wstring GetProcessImagePath(DWORD pid);

    // Returns best-effort debug info about process and its parent.
    // Never throws. Missing pieces are replaced with "?".
    std::wstring GetProcessDebugInfo(DWORD pid);

} // namespace ProcessHelpers
