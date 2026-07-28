#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string>
#include <vector>

namespace SRRunHook {

struct EnvironmentVariable {
    std::wstring name;
    std::wstring value;
};

// Starts a post-runtime hook through cmd.exe and returns immediately.
// The hook path is a validated existing file path; no hook arguments are added.
// Run context is provided by environment variables prepared by the caller.
bool RunHookDetached(
    const std::wstring& hookPath,
    const std::wstring& cwd,
    const std::vector<EnvironmentVariable>& environmentVariables,
    DWORD& gle,
    DWORD& pid
);

} // namespace SRRunHook
