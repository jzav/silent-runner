#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstddef>

namespace HandleHelpers {

struct StdHandleWriteProbeResult {
    bool isNull = false;
    bool isInvalid = false;
    DWORD fileType = FILE_TYPE_UNKNOWN;
    DWORD fileTypeGle = 0;
    bool probablyWritable = false;
    };

// Conservative write-probe for a standard handle.
// FILE_TYPE_UNKNOWN is treated as "probably writable" and the caller
// may inspect fileTypeGle for additional debug context.
StdHandleWriteProbeResult ProbeStdHandleForWrite(HANDLE h);

// Convenience wrapper for legacy bool-style checks.
bool IsStdHandleProbablyWritable(HANDLE h);

// Writes the whole buffer. Returns true on success.
// On failure returns false and (if outGle != nullptr) sets *outGle = GetLastError().
bool WriteAllToHandleOrGetGle(HANDLE h, const char* p, size_t n, DWORD* outGle);

// Best-effort: attempts to write all bytes, stops on first failure, ignores GLE.
void WriteAllToHandleIgnoreGle(HANDLE h, const char* p, size_t n);

} // namespace HandleHelpers
