// ParentStdEmitter.cpp
// --------------------
// Responsibility:
// - Emit raw bytes or text to the *parent* STDOUT / STDERR handles.
// - Maintain "once" flags for unwritable parent STDOUT / STDERR
//   (used by diagnostics to avoid repeating the same warning).
//
// Non-responsibility:
// - Reading child pipes.
// - Buffering, truncation limits, or stream policies.
// - Log writing of output.
// - Replay of end/success/failure buffers.
// - Any diagnostics policy or logging logic.
//
// Design note:
// - This module intentionally contains only low-level emit primitives.
// - Higher-level diagnostics (e.g., detecting unwritable handles and
//   producing debug messages) live in SRDiagnostics.

#include "ParentStdEmitter.h"

#include <atomic>
#include <string>
#include <vector>

#include "FileHelpers.h"
#include "HandleHelpers.h"

namespace ParentStdEmitter {

// Best-effort emit to parent STDOUT (ignore GLE)
void EmitStdoutBytesIgnoreGle(const char* p, size_t n) {
    if (!p || n == 0) return;
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    HandleHelpers::WriteAllToHandleIgnoreGle(hOut, p, n);
}

// Best-effort emit to parent STDERR (ignore GLE)
void EmitStderrBytesIgnoreGle(const char* p, size_t n) {
    if (!p || n == 0) return;
    HANDLE hErr = GetStdHandle(STD_ERROR_HANDLE);
    HandleHelpers::WriteAllToHandleIgnoreGle(hErr, p, n);
}

// Emit to parent STDOUT (report GLE)
bool TryEmitStdoutBytes(const char* p, size_t n, DWORD* outGle) {
    if (outGle) *outGle = 0;
    if (!p || n == 0) return true;

    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD gle = 0;
    const bool ok = HandleHelpers::WriteAllToHandleOrGetGle(hOut, p, n, &gle);
    if (!ok && outGle) *outGle = gle;
    return ok;
}

// Emit to parent STDERR (report GLE)
bool TryEmitStderrBytes(const char* p, size_t n, DWORD* outGle) {
    if (outGle) *outGle = 0;
    if (!p || n == 0) return true;

    HANDLE hErr = GetStdHandle(STD_ERROR_HANDLE);
    DWORD gle = 0;
    const bool ok = HandleHelpers::WriteAllToHandleOrGetGle(hErr, p, n, &gle);
    if (!ok && outGle) *outGle = gle;
    return ok;
}

// Convenience: wide text -> UTF-8 -> parent STD (best-effort)
void EmitStdoutUtf16(const std::wstring& s) {
    if (s.empty()) return;
    std::vector<char> u = FileHelpers::WideToUtf8(s);
    if (u.empty()) return;
    EmitStdoutBytesIgnoreGle(u.data(), u.size());
}

void EmitStderrUtf16(const std::wstring& s) {
    if (s.empty()) return;
    std::vector<char> u = FileHelpers::WideToUtf8(s);
    if (u.empty()) return;
    EmitStderrBytesIgnoreGle(u.data(), u.size());
}

// Absolute last-resort stderr write.
// Intended for emergency fallback paths only (e.g. terminate handler fallback).
// Best effort only: no allocation, no UTF conversion, no diagnostics.
void EmitStderrLastResort(const char* p, size_t n) noexcept {
    if (!p || n == 0) return;

    HANDLE hErr = GetStdHandle(STD_ERROR_HANDLE);
    if (!hErr || hErr == INVALID_HANDLE_VALUE) return;

    while (n > 0) {
        const DWORD chunk =
            (n > static_cast<size_t>(0x7fffffffUL))
                ? 0x7fffffffUL
                : static_cast<DWORD>(n);

        DWORD written = 0;
        if (!WriteFile(hErr, p, chunk, &written, nullptr)) {
            return;
        }

        if (written == 0) {
            return;
        }

        p += written;
        n -= static_cast<size_t>(written);
    }
}

} // namespace ParentStdEmitter
