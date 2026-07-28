#include "ErrorHelpers.h"

namespace ErrorHelpers {

std::wstring Win32ErrorToString(DWORD gle) {
    if (gle == 0) return L"(no error)";
    wchar_t* msg = nullptr;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD lang = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);

    DWORD n = FormatMessageW(flags, nullptr, gle, lang, (LPWSTR)&msg, 0, nullptr);
    std::wstring out;
    if (n && msg) {
        out.assign(msg, msg + n);
        LocalFree(msg);
        // Trim trailing newlines/spaces
        while (!out.empty() && (out.back() == L'\r' || out.back() == L'\n' || out.back() == L' ' || out.back() == L'\t')) {
            out.pop_back();
        }
    } else {
        out = L"(FormatMessageW failed; GLE=" + std::to_wstring(gle) + L")";
    }
    return out;
}

std::wstring FormatGle(DWORD gle) {
    return L"GLE=" + std::to_wstring(gle) + L" MSG=" + Win32ErrorToString(gle);
}

} // namespace ErrorHelpers
