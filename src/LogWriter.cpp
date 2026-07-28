#include "LogWriter.h"

#include <cstddef>  // size_t
#include <vector>
#include <utility>

#include "FileHelpers.h"
#include "HandleHelpers.h"

using CoreHelpers::UniqueHandle;

namespace LogWriter {

// Creates a new log file for a running stream.
//
// Important:
// - Uses CREATE_NEW, so an existing file is treated as failure.
// - The file is opened for append-only writes and shared for reading so tools
//   can inspect the running log while SilentRunner is still writing it.
// - The caller is responsible for creating the directory before this call.
bool FileWriter::CreateNewFile(const std::wstring& path, DWORD* outGle) {
    if (outGle) *outGle = 0;

    CoreHelpers::UniqueHandle newHandle(CreateFileW(
        path.c_str(),
        FILE_APPEND_DATA,
        FILE_SHARE_READ,
        nullptr,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    ));
    if (!newHandle.valid()) {
        if (outGle) *outGle = GetLastError();
        return false;
    }

    h_ = std::move(newHandle);
    path_ = path;
    return true;
}
// Reopens an existing log file for append.
//
// Used after *_running.log has been renamed to its final success/failure name
// so final diagnostics can continue writing to the kept stderr log.

bool FileWriter::OpenAppendFile(const std::wstring& path, DWORD* outGle) {
    if (outGle) *outGle = 0;

    CoreHelpers::UniqueHandle newHandle(CreateFileW(
        path.c_str(),
        FILE_APPEND_DATA,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    ));
    if (!newHandle.valid()) {
        if (outGle) *outGle = GetLastError();
        return false;
    }

    h_ = std::move(newHandle);
    path_ = path;
    return true;
}


bool FileWriter::IsOpen() const noexcept { return h_.valid(); }
HANDLE FileWriter::Handle() const noexcept { return h_.get(); }
const std::wstring& FileWriter::Path() const noexcept { return path_; }

bool FileWriter::WriteRaw(const char* p, size_t n, DWORD* outGle) {
    return HandleHelpers::WriteAllToHandleOrGetGle(h_.get(), p, n, outGle);
}
bool FileWriter::WriteLine(const char* p, size_t n, DWORD* outGle) {
    if (!WriteRaw(p, n, outGle)) return false;

    static constexpr char kLf = '\n';
    return WriteRaw(&kLf, 1, outGle);
}

bool FileWriter::Flush(DWORD* outGle) {
    if (outGle) *outGle = 0;
    if (!h_.valid()) return true;
    if (!FlushFileBuffers(h_.get())) {
        if (outGle) *outGle = GetLastError();
        return false;
    }
    return true;
}

void FileWriter::Close() { h_.reset(); }

bool ShouldKeepLogFile(SR::KeepLogMode mode, bool isSuccess) {
    switch (mode) {
        case SR::KeepLogMode::Always:  return true;
        case SR::KeepLogMode::Success: return isSuccess;
        case SR::KeepLogMode::Failure: return !isSuccess;
    }
    return true;
}

bool TryDeleteLogFile(
    const std::wstring& path,
    DWORD* outGle
) {
    if (outGle) *outGle = 0;
    if (DeleteFileW(path.c_str())) {
        return true;
    }
    if (outGle) *outGle = GetLastError();
    return false;
}

// Renames a log file without overwrite.
//
// MoveFileExW is called with flags=0, so an existing destination path causes
// failure. This protects previous success/failure logs from being overwritten.
bool TryRenameLogFile(
    const std::wstring& from,
    const std::wstring& to,
    DWORD* outGle
) {
    if (outGle) *outGle = 0;
    if (MoveFileExW(from.c_str(), to.c_str(), 0)) {
        return true;
    }
    if (outGle) *outGle = GetLastError();
    return false;
}

} // namespace LogWriter
