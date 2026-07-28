#include "LogReader.h"

#include <string>
#include <vector>
#include <utility>

namespace LogReader {

bool FileReader::OpenExistingFile(
    const std::wstring& path,
    DWORD* outGle
) {
    if (outGle) *outGle = 0;

    CoreHelpers::UniqueHandle newHandle(CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    ));
    if (!newHandle.valid()) {
        if (outGle) *outGle = GetLastError();
        return false;
    }

    handle_ = std::move(newHandle);
    path_ = path;
    return true;
}

bool FileReader::Read(
    void* buffer,
    DWORD bufferSize,
    DWORD& bytesRead,
    DWORD* outGle
) {
    if (outGle) *outGle = 0;
    bytesRead = 0;

    if (!handle_.valid() || !buffer || bufferSize == 0) {
        if (outGle) *outGle = ERROR_INVALID_PARAMETER;
        return false;
    }

    if (!ReadFile(
            handle_.get(),
            buffer,
            bufferSize,
            &bytesRead,
            nullptr)) {
        if (outGle) *outGle = GetLastError();
        return false;
    }

    return true;
}

ReadResult FileReader::ReadChunks(
    DWORD chunkSize,
    ChunkCallback callback,
    void* context,
    DWORD* outGle
) {
    if (outGle) *outGle = 0;

    if (!handle_.valid() || chunkSize == 0 || !callback) {
        if (outGle) *outGle = ERROR_INVALID_PARAMETER;
        return ReadResult::IoFailed;
    }

    std::vector<char> buffer(chunkSize);

    for (;;) {
        DWORD bytesRead = 0;
        if (!Read(
                buffer.data(),
                chunkSize,
                bytesRead,
                outGle)) {
            return ReadResult::IoFailed;
        }

        if (bytesRead == 0) {
            return ReadResult::Completed;
        }

        if (!callback(
                context,
                buffer.data(),
                static_cast<std::size_t>(bytesRead))) {
            return ReadResult::CallbackStopped;
        }
    }
}

ReadResult FileReader::ReadLines(
    DWORD chunkSize,
    LineCallback callback,
    void* context,
    DWORD* outGle
) {
    if (outGle) *outGle = 0;

    if (!handle_.valid() || chunkSize == 0 || !callback) {
        if (outGle) *outGle = ERROR_INVALID_PARAMETER;
        return ReadResult::IoFailed;
    }

    std::vector<char> buffer(chunkSize);
    std::string pending;

    for (;;) {
        DWORD bytesRead = 0;
        if (!Read(
                buffer.data(),
                chunkSize,
                bytesRead,
                outGle)) {
            return ReadResult::IoFailed;
        }

        if (bytesRead == 0) {
            break;
        }

        pending.append(
            buffer.data(),
            static_cast<std::size_t>(bytesRead)
        );

        std::size_t lineStart = 0;

        for (;;) {
            const std::size_t lfPos = pending.find('\n', lineStart);
            if (lfPos == std::string::npos) {
                if (lineStart != 0) {
                    pending.erase(0, lineStart);
                }
                break;
            }

            std::size_t lineEnd = lfPos;
            if (lineEnd > lineStart &&
                pending[lineEnd - 1] == '\r') {
                --lineEnd;
            }

            const std::string line =
                pending.substr(lineStart, lineEnd - lineStart);

            if (!callback(context, line)) {
                return ReadResult::CallbackStopped;
            }

            lineStart = lfPos + 1;
        }
    }

    if (!pending.empty()) {
        if (!pending.empty() && pending.back() == '\r') {
            pending.pop_back();
        }

        if (!callback(context, pending)) {
            return ReadResult::CallbackStopped;
        }
    }

    return ReadResult::Completed;
}

bool FileReader::IsOpen() const noexcept {
    return handle_.valid();
}

HANDLE FileReader::Handle() const noexcept {
    return handle_.get();
}

const std::wstring& FileReader::Path() const noexcept {
    return path_;
}

void FileReader::Close() {
    handle_.reset();
}

} // namespace LogReader
