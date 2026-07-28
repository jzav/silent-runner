#include "CmdBuilder.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace CmdBuilder {

std::wstring GetComSpec() {
    wchar_t buf[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"ComSpec", buf, MAX_PATH);
    if (n > 0 && n < MAX_PATH) return std::wstring(buf, n);
    return L"C:\\Windows\\System32\\cmd.exe";
}

// Quotes only when required by whitespace.
//
// Important:
// - This is intentionally not a full cmd.exe escaping layer.
// - Shell metacharacters such as &, |, >, <, ^, %, ! keep their cmd.exe meaning.
// - Script-or-exe mode records suspicious metacharacters as diagnostics, but
//   does not reject them.
// - Complex command logic should be placed in a .cmd/script file or passed via
//   raw command mode (-c).
std::wstring QuoteIfNeeded(const std::wstring& s) {
    if (s.empty()) return L"\"\"";
    bool need = false;
    for (wchar_t c : s) {
        if (c == L' ' || c == L'\t') { need = true; break; }
    }
    if (!need) return s;

    std::wstring out;
    out.push_back(L'"');
    for (wchar_t c : s) {
        if (c == L'"') out.append(L"\\\"");
        else out.push_back(c);
    }
    out.push_back(L'"');
    return out;
}

// Builds the command line passed to CreateProcessW.
//
// Important:
// - SilentRunner always executes through cmd.exe /d /s /c.
// - opt.inner is already either the raw -c command string or the script-or-exe
//   token sequence assembled by the argument parser.
// - The returned string must be mutable before passing it to CreateProcessW.
std::wstring BuildCmdExeCommandLine(const SR::Options& opt) {
    // Build:
    //   cmd.exe /d /s /c "<inner>"
    // Optionally:
    //   cmd.exe /d /s /c "chcp 65001>nul & <inner>"
    std::wstring comspec = GetComSpec();
    std::wstring inner = opt.inner;

    if (opt.utf8) {
        inner = L"chcp 65001>nul & " + inner;
    }

    return comspec + L" /d /s /c \"" + inner + L"\"";
}

} // namespace CmdBuilder
