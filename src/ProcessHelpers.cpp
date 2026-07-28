#include "CoreHelpers.h"
#include "ProcessHelpers.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

namespace ProcessHelpers {

DWORD GetParentPid(DWORD pid) {
    CoreHelpers::UniqueHandle snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snap.valid()) return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snap.get(), &pe)) return 0;

    do {
        if (pe.th32ProcessID == pid) return pe.th32ParentProcessID;
    } while (Process32NextW(snap.get(), &pe));

    return 0;
}

std::wstring GetProcessImagePath(DWORD pid) {
    CoreHelpers::UniqueHandle h(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!h.valid()) return L"";

    wchar_t buf[32768];
    DWORD sz = (DWORD)(sizeof(buf) / sizeof(buf[0]));
    if (!QueryFullProcessImageNameW(h.get(), 0, buf, &sz)) return L"";
    return std::wstring(buf, sz);
}

// Returns best-effort debug info about process and its parent.
// Never throws. Missing pieces are replaced with "?".
std::wstring GetProcessDebugInfo(DWORD pid) {
    std::wstring result;

    // --- PID ---
    result += L"PID=" + std::to_wstring(pid);

    // --- PID image ---
    std::wstring image = GetProcessImagePath(pid);
    result += L" PIDIMAGE=";
    result += (!image.empty() ? image : L"?");

    // --- Parent PID ---
    DWORD parentPid = GetParentPid(pid);
    const bool isSelfParent = (parentPid == pid && parentPid != 0);

    result += L" PARENTPID=";
    if (parentPid != 0) {
        result += std::to_wstring(parentPid);
    } else {
        result += L"?";
    }

    // --- Parent image ---
    result += L" PARENTPIDIMAGE=";

    if (isSelfParent) {
        result += L"(self)";
    } else if (parentPid != 0) {
        std::wstring parentImage = GetProcessImagePath(parentPid);
        result += (!parentImage.empty() ? parentImage : L"?");
    } else {
        result += L"?";
    }

    // --- Self-parent marker (diagnostic only) ---
    if (isSelfParent) {
        result += L" (self-parent)";
    }

    return result;
}

} // namespace ProcessHelpers
