#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstddef>  // size_t
#include <string>

#include "CoreHelpers.h"

namespace LogWriter {

 // Byte-oriented writer for per-execution persistent log files.
 // Presentation (Raw, Headered, or JSON record) is handled by the file sink worker.
class FileWriter {
public:
    FileWriter() = default;

    bool CreateNewFile(const std::wstring& path, DWORD* outGle);
    bool OpenAppendFile(const std::wstring& path, DWORD* outGle);
    bool IsOpen() const noexcept;
    HANDLE Handle() const noexcept;
    const std::wstring& Path() const noexcept;

    bool WriteRaw(const char* p, size_t n, DWORD* outGle);
    bool WriteLine(const char* p, size_t n, DWORD* outGle);
    bool Flush(DWORD* outGle);
    bool Close(DWORD* outGle);

private:
    CoreHelpers::UniqueHandle h_;
    std::wstring path_;
};


bool TryDeleteLogFile(
    const std::wstring& path,
    DWORD* outGle
);

bool TryRenameLogFile(
    const std::wstring& from,
    const std::wstring& to,
    DWORD* outGle
);

} // namespace LogWriter
