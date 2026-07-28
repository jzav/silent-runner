#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstddef>  // size_t
#include <string>

#include "CoreHelpers.h"
#include "SRTypes.h"

namespace LogWriter {

// A thin wrapper around file output used for writing logs and routed streams.
// We keep it in FileHelpers earlier only if we truly need it elsewhere;
// here it's explicitly "log file" for std-dir.
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
    void Close();

private:
    CoreHelpers::UniqueHandle h_;
    std::wstring path_;
};

bool ShouldKeepLogFile(SR::KeepLogMode mode, bool isSuccess);

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
