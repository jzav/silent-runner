#pragma once

#include <windows.h>
#include <string>

namespace ProcessHelpers {

    // Returns parent PID of given process.
    // Returns 0 if not available (error or system process).
    DWORD GetParentPid(DWORD pid);

    // Returns full image path of given process.
    // Returns empty string on failure.
    // An existing process handle can be reused to avoid opening the process again.
    std::wstring GetProcessImagePath(DWORD pid, HANDLE processHandle = nullptr);

    // Returns best-effort debug info about process and its parent.
    // Never throws. Missing pieces are replaced with "?".
    // Optionally reuses an existing process handle for image lookup.
    std::wstring GetProcessDebugInfo(DWORD pid, HANDLE processHandle = nullptr);

} // namespace ProcessHelpers
