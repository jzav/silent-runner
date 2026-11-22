#include "SRRunHook.h"

#include <algorithm>
#include <cwchar>

#include "CoreHelpers.h"
#include "TextHelpers.h"

namespace SRRunHook {

namespace {

static std::wstring BuildHookCommandLine_(const std::wstring& comspec, const std::wstring& hookPath) {
    // Build:
    //   "cmd.exe" /d /s /c ""<hookPath>""
    //
    // The hook path is path-only and validated before runtime:
    // - no double quotes
    // - no arguments
    // - existing regular file
    //
    // Hook path is pre-resolved to an absolute path; cmd.exe only executes it.
    return L"\"" + comspec + L"\" /d /s /c \"\"" + hookPath + L"\"\"";
}


static bool EnvironmentNameEquals_(const wchar_t* entry, const std::wstring& name) noexcept {
    if (!entry || name.empty()) return false;

    size_t index = 0;
    while (entry[index] != L'\0' && entry[index] != L'=') {
        if (index >= name.size()) return false;
        if (TextHelpers::ToUpperAscii(entry[index]) != TextHelpers::ToUpperAscii(name[index])) return false;
        ++index;
    }

    return entry[index] == L'=' && index == name.size();
}

static bool IsOverriddenEnvironmentName_(
    const wchar_t* entry,
    const std::vector<EnvironmentVariable>& environmentVariables
) noexcept {
    for (const EnvironmentVariable& variable : environmentVariables) {
        if (EnvironmentNameEquals_(entry, variable.name)) {
            return true;
        }
    }

    return false;
}

static bool EnvironmentEntryLess_(
    const std::wstring& left,
    const std::wstring& right
) noexcept {
    const auto nameLength = [](const std::wstring& entry) noexcept {
        // Preserve special drive-current-directory names such as "=C:".
        const size_t separator = entry.find(
            L'=', (!entry.empty() && entry.front() == L'=') ? 1 : 0
        );
        return static_cast<int>(
            separator == std::wstring::npos ? entry.size() : separator
        );
    };
    return CompareStringOrdinal(
        left.c_str(), nameLength(left),
        right.c_str(), nameLength(right),
        TRUE
    ) == CSTR_LESS_THAN;
}

static bool BuildEnvironmentBlock_(
    const std::vector<EnvironmentVariable>& environmentVariables,
    std::wstring& environmentBlock,
    DWORD& gle
) {
    gle = 0;
    environmentBlock.clear();
    std::vector<std::wstring> entries;

    LPWCH rawEnvironment = GetEnvironmentStringsW();
    if (!rawEnvironment) {
        gle = GetLastError();
        if (gle == 0) gle = ERROR_ENVVAR_NOT_FOUND;
        return false;
    }

    for (const wchar_t* entry = rawEnvironment; *entry; entry += std::wcslen(entry) + 1) {
        if (!IsOverriddenEnvironmentName_(entry, environmentVariables)) {
            entries.emplace_back(entry);
        }
    }

    FreeEnvironmentStringsW(rawEnvironment);

    for (const EnvironmentVariable& variable : environmentVariables) {
        if (!variable.name.empty()) {
            entries.emplace_back(variable.name + L"=" + variable.value);
        }
    }
    std::sort(entries.begin(), entries.end(), EnvironmentEntryLess_);
    for (const std::wstring& entry : entries) {
        environmentBlock.append(entry);
        environmentBlock.push_back(L'\0');
    }
    environmentBlock.push_back(L'\0');
    if (entries.empty()) {
        environmentBlock.push_back(L'\0');
    }
    return true;
}

} // namespace

bool RunHookDetached(
    const std::wstring& comspecPath,
    const std::wstring& hookPath,
    const std::wstring& cwd,
    const std::vector<EnvironmentVariable>& environmentVariables,
    DWORD& gle,
    DWORD& pid
) {
    gle = 0;
    pid = 0;

    if (comspecPath.empty() || hookPath.empty()) {
        gle = ERROR_INVALID_PARAMETER;
        return false;
    }

    std::wstring environmentBlock;
    if (!BuildEnvironmentBlock_(environmentVariables, environmentBlock, gle)) {
        return false;
    }

    std::wstring commandLine =
        BuildHookCommandLine_(comspecPath, hookPath);

    STARTUPINFOW si{};
    si.cb = sizeof(si);

    PROCESS_INFORMATION pi{};

    const DWORD creationFlags =
        DETACHED_PROCESS |
        CREATE_NEW_PROCESS_GROUP |
        CREATE_UNICODE_ENVIRONMENT;

    const BOOL ok = CreateProcessW(
        comspecPath.c_str(),
        commandLine.data(),
        nullptr,
        nullptr,
        FALSE,
        creationFlags,
        environmentBlock.data(),
        cwd.empty() ? nullptr : cwd.c_str(),
        &si,
        &pi
    );

    if (!ok) {
        gle = GetLastError();
        return false;
    }

    pid = pi.dwProcessId;

    CoreHelpers::UniqueHandle processHandle(pi.hProcess);
    CoreHelpers::UniqueHandle threadHandle(pi.hThread);

    return true;
}

} // namespace SRRunHook
