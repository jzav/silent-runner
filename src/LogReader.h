#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstddef>
#include <string>

#include "CoreHelpers.h"

namespace LogReader {

enum class ReadResult {
    Completed,
    CallbackStopped,
    IoFailed
};

using ChunkCallback = bool (*)(
    void* context,
    const char* data,
    std::size_t size
);

using LineCallback = bool (*)(
    void* context,
    const std::string& line
);

class FileReader {
public:
    FileReader() = default;

    FileReader(const FileReader&) = delete;
    FileReader& operator=(const FileReader&) = delete;

    FileReader(FileReader&&) = delete;
    FileReader& operator=(FileReader&&) = delete;

    bool OpenExistingFile(
        const std::wstring& path,
        DWORD* outGle
    );

    bool Read(
        void* buffer,
        DWORD bufferSize,
        DWORD& bytesRead,
        DWORD* outGle
    );

    ReadResult ReadChunks(
        DWORD chunkSize,
        ChunkCallback callback,
        void* context,
        DWORD* outGle
    );

    ReadResult ReadLines(
        DWORD chunkSize,
        LineCallback callback,
        void* context,
        DWORD* outGle
    );

    bool IsOpen() const noexcept;
    HANDLE Handle() const noexcept;
    const std::wstring& Path() const noexcept;
    void Close();

private:
    CoreHelpers::UniqueHandle handle_;
    std::wstring path_;
};

} // namespace LogReader
