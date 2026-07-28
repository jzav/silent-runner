#include "HandleHelpers.h"

namespace HandleHelpers {

StdHandleWriteProbeResult ProbeStdHandleForWrite(HANDLE h) {
    StdHandleWriteProbeResult result;
    result.isNull = (h == nullptr);
    result.isInvalid = (h == INVALID_HANDLE_VALUE);

    if (result.isNull || result.isInvalid) {
        return result;
    }

    SetLastError(0);
    result.fileType = GetFileType(h);

    if (result.fileType == FILE_TYPE_UNKNOWN) {
        result.fileTypeGle = GetLastError();
    }

    result.probablyWritable =
        (result.fileType == FILE_TYPE_CHAR) ||
        (result.fileType == FILE_TYPE_PIPE) ||
        (result.fileType == FILE_TYPE_DISK) ||
        (result.fileType == FILE_TYPE_UNKNOWN);

    return result;
}

bool IsStdHandleProbablyWritable(HANDLE h) {
    return ProbeStdHandleForWrite(h).probablyWritable;
}

bool WriteAllToHandleOrGetGle(HANDLE h, const char* p, size_t n, DWORD* outGle) {
    if (outGle) *outGle = 0;
    if (!h || h == INVALID_HANDLE_VALUE || !p || n == 0) return true;

    size_t left = n;
    while (left > 0) {
        DWORD chunk = (left > 0x7fffffffULL) ? 0x7fffffffUL : (DWORD)left;
        DWORD written = 0;
        if (!WriteFile(h, p, chunk, &written, nullptr)) {
            if (outGle) *outGle = GetLastError();
            return false;
        }
        if (written == 0) {
            if (outGle) *outGle = ERROR_WRITE_FAULT;
            return false;
        }
        p += written;
        left -= written;
    }
    return true;
}

void WriteAllToHandleIgnoreGle(HANDLE h, const char* p, size_t n) {
    if (!h || h == INVALID_HANDLE_VALUE || !p || n == 0) return;

    size_t left = n;
    while (left > 0) {
        DWORD chunk = (left > 0x7fffffffULL) ? 0x7fffffffUL : (DWORD)left;
        DWORD written = 0;
        if (!WriteFile(h, p, chunk, &written, nullptr)) break;
        if (written == 0) break;
        p += written;
        left -= written;
    }
}

} // namespace HandleHelpers
