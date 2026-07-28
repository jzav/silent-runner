#include "FileHelpers.h"

#include <cwchar>

#include "HandleHelpers.h"

#include "CoreHelpers.h"

using CoreHelpers::UniqueHandle;

namespace FileHelpers {

bool FileExists(const std::wstring& path) noexcept {
    const DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return false;
    }
    return (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

static std::wstring NormalizeDirPath(std::wstring dir) {
    if (dir.empty()) return dir;

    for (auto& ch : dir) {
        if (ch == L'/') ch = L'\\';
    }

    while (dir.size() > 1 && dir.back() == L'\\') {
        // Keep drive root intact: "C:\"
        if (dir.size() == 3 && dir[1] == L':' && dir[2] == L'\\') {
            break;
        }

        // Keep UNC share root intact: "\\server\share"
        if (dir.size() >= 2 && dir[0] == L'\\' && dir[1] == L'\\') {
            const size_t serverSep = dir.find(L'\\', 2);
            if (serverSep != std::wstring::npos) {
                const size_t shareSep = dir.find(L'\\', serverSep + 1);
                if (shareSep == std::wstring::npos) {
                    break;
                }
            }
        }

        dir.pop_back();
    }

    return dir;
}


// Ensures that a directory path exists (mkdir -p semantics).
//
// Behavior:
// - Creates all missing intermediate directories in the specified path.
// - Accepts both absolute and relative paths.
// - Treats an existing directory as success (including ERROR_ALREADY_EXISTS
//   if the path is verified to be a directory).
// - Returns false on the first failure and, if outGle is non-null,
//   stores the corresponding WinAPI error code (GetLastError()).
//
// Path handling:
// - Forward slashes ('/') are normalized to backslashes ('\').
// - Empty or invalid paths result in failure (ERROR_PATH_NOT_FOUND).
// - UNC paths (\\server\share\...) are handled specially:
//   * The \\server\share root is treated as existing.
//   * Creation begins only after the share component.
//   * Invalid UNC roots result in ERROR_BAD_NETPATH.
//
// Relative paths:
// - Relative paths are resolved by WinAPI against the current working
//   directory of the SilentRunner process.
// - This function does NOT use or consider --cwd (child working directory).
// - Path resolution is delegated to CreateDirectoryW / GetFileAttributesW.
//
// Error handling:
// - On failure, returns false and sets *outGle to the first failing
//   GetLastError() value (if outGle is non-null).
// - On success, *outGle is set to 0 (if provided).
//
// Notes:
// - If a path component exists but is not a directory, the function fails.
// - The operation is not atomic; partial directory creation may occur
//   before a failure is reported.
bool EnsureDirExists(std::wstring dir, DWORD* outGle) {
    if (outGle) *outGle = 0;

    dir = NormalizeDirPath(std::move(dir));
    if (dir.empty()) {
        if (outGle) *outGle = ERROR_PATH_NOT_FOUND;
        return false;
    }

    auto is_dir = [](const std::wstring& path) -> bool {
        DWORD attr = GetFileAttributesW(path.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES) return false;
        return (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
    };

    auto try_create_one = [&](const std::wstring& path) -> bool {
        if (CreateDirectoryW(path.c_str(), nullptr)) return true;

        DWORD gle = GetLastError();
        if (gle == ERROR_ALREADY_EXISTS && is_dir(path)) return true;

        if (outGle) *outGle = gle;
        return false;
    };

    size_t start = 0;

    if (dir.size() >= 3 && dir[1] == L':' && dir[2] == L'\\') {
        start = 3;
    } else if (dir.size() >= 2 && dir[0] == L'\\' && dir[1] == L'\\') {
        size_t p = dir.find(L'\\', 2);
        if (p == std::wstring::npos) {
            if (outGle) *outGle = ERROR_BAD_NETPATH;
            return false;
        }

        p = dir.find(L'\\', p + 1);
        if (p == std::wstring::npos) {
            if (is_dir(dir)) return true;
            if (outGle) *outGle = GetLastError();
            return false;
        }

        start = p + 1;
    } else {
        start = 0;
    }

    for (size_t i = start; i <= dir.size();) {
        size_t next = dir.find(L'\\', i);
        std::wstring sub = (next == std::wstring::npos) ? dir : dir.substr(0, next);

        if (!sub.empty()) {
            if (!try_create_one(sub)) return false;
        }

        if (next == std::wstring::npos) break;
        i = next + 1;
        while (i < dir.size() && dir[i] == L'\\') i++;
    }

    return true;
}


std::wstring JoinPath(std::wstring dir, const std::wstring& name) {
    dir = NormalizeDirPath(std::move(dir));

    if (dir.empty()) return name;
    return dir + L"\\" + name;
}

std::wstring MakeRunUtcTimestamp() {
    SYSTEMTIME st;
    GetSystemTime(&st);

    wchar_t buf[128];
    swprintf_s(
        buf,
        L"%04u-%02u-%02u_%02u-%02u-%02uZ",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond
    );
    return std::wstring(buf);
}

std::wstring MakeRunPidToken() {
    wchar_t buf[64];
    swprintf_s(buf, L"pid%u", GetCurrentProcessId());
    return std::wstring(buf);
}

std::wstring BuildIdSuffix(SR::IdSuffixMode mode) {
    switch (mode) {
        case SR::IdSuffixMode::Timestamp:
            return MakeRunUtcTimestamp();
        case SR::IdSuffixMode::Pid:
            return MakeRunPidToken();
        case SR::IdSuffixMode::TimestampPid:
            return MakeRunUtcTimestamp() + L"_" + MakeRunPidToken();
        case SR::IdSuffixMode::PidTimestamp:
            return MakeRunPidToken() + L"_" + MakeRunUtcTimestamp();
        case SR::IdSuffixMode::None:
        default:
            return L"";
    }
}

std::wstring BuildDefaultExecutionIdUtcPid() {
    return BuildIdSuffix(SR::IdSuffixMode::TimestampPid);
}

std::wstring BuildExecutionId(
    const std::wstring& idPrefix,
    const std::wstring& idBase,
    const std::wstring& generatedSuffix
) {
    std::wstring executionId;

    auto append_part = [&](const std::wstring& part) {
        if (part.empty()) return;
        if (!executionId.empty()) executionId += L"_";
        executionId += part;
    };

    append_part(idPrefix);
    append_part(idBase);
    append_part(generatedSuffix);

    if (executionId.empty()) {
        return BuildDefaultExecutionIdUtcPid();
    }

    return executionId;
}

std::vector<char> WideToUtf8(const std::wstring& s) {
    if (s.empty()) return {};
    int need = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    if (need <= 0) return {};
    std::vector<char> buf((size_t)need);
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), buf.data(), need, nullptr, nullptr);
    return buf;
}

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";

    // 1) try strict UTF-8
    int requiredWideCharCount = MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        s.data(),
        static_cast<int>(s.size()),
        nullptr,
        0
    );

    if (requiredWideCharCount > 0) {
        std::wstring out(requiredWideCharCount, L'\0');

        if (MultiByteToWideChar(
                CP_UTF8,
                MB_ERR_INVALID_CHARS,
                s.data(),
                static_cast<int>(s.size()),
                out.data(),
                requiredWideCharCount
            ) > 0) {
            return out;
        }
    }

    // 2) fallback: ANSI (ACP)
    requiredWideCharCount = MultiByteToWideChar(
        CP_ACP,
        0,
        s.data(),
        static_cast<int>(s.size()),
        nullptr,
        0
    );

    if (requiredWideCharCount > 0) {
        std::wstring out(requiredWideCharCount, L'\0');

        if (MultiByteToWideChar(
                CP_ACP,
                0,
                s.data(),
                static_cast<int>(s.size()),
                out.data(),
                requiredWideCharCount
            ) > 0) {
            return out;
        }
    }

    return L""; // úplný fail
}

bool StreamFileToHandle(const std::wstring& path, HANDLE dst, DWORD* outGle) {
    if (outGle) *outGle = 0;

    UniqueHandle h(CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    ));
    if (!h.valid()) {
        if (outGle) *outGle = GetLastError();
        return false;
    }

    const DWORD BUFSZ = 64u * 1024u;
    std::vector<char> buf(BUFSZ);

    for (;;) {
        DWORD got = 0;
        if (!ReadFile(h.get(), buf.data(), BUFSZ, &got, nullptr)) {
            if (outGle) *outGle = GetLastError();
            return false;
        }
        if (got == 0) break;

        DWORD writeGle = 0;
        if (!HandleHelpers::WriteAllToHandleOrGetGle(dst, buf.data(), got, &writeGle)) {
            if (outGle) *outGle = (writeGle != 0) ? writeGle : ERROR_WRITE_FAULT;
            return false;
        }
    }

    return true;
}

} // namespace FileHelpers
