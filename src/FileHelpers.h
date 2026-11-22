#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string>
#include <vector>

#include "SRTypes.h"

namespace FileHelpers {

bool TryResolveComSpecPath(
    std::wstring& resolvedPath,
    std::wstring& err
);
// Expand environment variables once, independently for each path component.
// Components are separated by '\' or '/', so percent signs cannot pair
// across path separators. Undefined references are rejected.
// References introduced by expansion are not processed again.
bool TryExpandEnvironmentVariables(
    const std::wstring& input,
    std::wstring& expanded,
    std::wstring& missingVariable,
    DWORD* outGle = nullptr
);

// Resolve a path against the current directory of the SilentRunner process.
// Does not require the path or its parent directories to exist.
bool TryResolveFullPath(
    const std::wstring& path,
    std::wstring& resolvedPath,
    DWORD* outGle = nullptr
);

// Returns true if a regular file exists at the given path.
// Returns false if the file does not exist or the path points to a directory.
bool FileExists(const std::wstring& path) noexcept;

// Returns true if the path points to an existing directory.
bool DirectoryExists(const std::wstring& path) noexcept;

// Ensure directory path recursively (mkdir -p style).
bool EnsureDirExists(std::wstring dir, DWORD* outGle);


// JoinPath(dir, name)
std::wstring JoinPath(std::wstring dir, const std::wstring& name);

// "2026-02-21_11-34-07Z_pid1234" (UTC)
std::wstring BuildDefaultExecutionIdUtcPid();

// For Execution IDs and log filenames: "2026-02-21_11-34-07Z" (UTC).
std::wstring MakeRunUtcTimestamp();

// For event, phase, and diagnostic timestamps: "2026-02-21T11:34:07.123Z" (UTC).
std::wstring MakeEventUtcTimestamp();

// "pid1234"
std::wstring MakeRunPidToken();

// Build suffix according to requested mode.
std::wstring BuildIdSuffix(SR::IdSuffixMode mode);

// Build execution ID from non-empty parts in this order:
//   idPrefix + idBase + generatedSuffix
// using '_' as separator. If all parts are empty, returns
// BuildDefaultExecutionIdUtcPid().
std::wstring BuildExecutionId(
    const std::wstring& idPrefix,
    const std::wstring& idBase,
    const std::wstring& generatedSuffix
);

// UTF-16 wide string -> UTF-8 bytes
std::vector<char> WideToUtf8(const std::wstring& s);

// UTF-8 bytes / narrow string -> UTF-16 wide string
std::wstring Utf8ToWide(const std::string& s);

// Stream a file to a destination handle in chunks (no large allocations).
// Returns true on success; on failure sets *outGle and returns false.
bool StreamFileToHandle(const std::wstring& path, HANDLE dst, DWORD* outGle);

} // namespace FileHelpers
