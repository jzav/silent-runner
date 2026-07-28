#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <atomic>
#include <cstddef>  // size_t
#include <string>   // std::wstring

namespace ParentStdEmitter {

// Best-effort emit to parent STDOUT/STDERR (ignore GLE).
void EmitStdoutBytesIgnoreGle(const char* p, size_t n);
void EmitStderrBytesIgnoreGle(const char* p, size_t n);

// Emit to parent STDOUT/STDERR (report GLE).
bool TryEmitStdoutBytes(const char* p, size_t n, DWORD* outGle);
bool TryEmitStderrBytes(const char* p, size_t n, DWORD* outGle);

// Convenience: wide text -> UTF-8 -> parent STD (best-effort).
void EmitStdoutUtf16(const std::wstring& s);
void EmitStderrUtf16(const std::wstring& s);

// Absolute last-resort stderr write.
// Best effort only. No allocation, no UTF conversion, no exceptions.
void EmitStderrLastResort(const char* p, size_t n) noexcept;

} // namespace ParentStdEmitter
