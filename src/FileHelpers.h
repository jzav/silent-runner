#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string>
#include <vector>

#include "SRTypes.h"

namespace FileHelpers {

// Returns true if a regular file exists at the given path.
// Returns false if the file does not exist or the path points to a directory.
bool FileExists(const std::wstring& path) noexcept;

// Ensure directory path recursively (mkdir -p style).
bool EnsureDirExists(std::wstring dir, DWORD* outGle);


// JoinPath(dir, name)
std::wstring JoinPath(std::wstring dir, const std::wstring& name);

// "2026-02-21_11-34-07Z_pid1234" (UTC)
std::wstring BuildDefaultExecutionIdUtcPid();

// "2026-02-21_11-34-07Z" (UTC)
std::wstring MakeRunUtcTimestamp();

// "pid1234"
std::wstring MakeRunPidToken();

// Build suffix according to requested mode.
std::wstring BuildIdSuffix(SR::IdSuffixMode mode);

// Build execution ID from non-empty parts in this order:
//   idPrefix + idBase + generatedSuffix
// using '_' as separator. If all parts are empty, returns
// MakeDefaultExecutionIdUtcPid().
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
