#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// CoreHelpers - low-level core primitives
// --------------------------------------
// Contains minimal, dependency-free utilities and RAII types shared across the codebase.
// Currently provides UniqueHandle, a fundamental RAII wrapper for HANDLE.
//
// This module is intended for small, general-purpose building blocks that:
// - have no dependency on higher-level components (runtime, logging, routing, CLI),
// - can be reused across the entire project,
// - could exist as standalone utilities.
//
// Add new items here only if they fit this "core primitive" role.

namespace CoreHelpers {

class UniqueHandle {
public:
    UniqueHandle() noexcept : h_(nullptr) {}
    explicit UniqueHandle(HANDLE h) noexcept : h_(h) {}

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& other) noexcept : h_(other.h_) { other.h_ = nullptr; }
    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) {
            reset();
            h_ = other.h_;
            other.h_ = nullptr;
        }
        return *this;
    }

    ~UniqueHandle() { reset(); }

    HANDLE get() const noexcept { return h_; }
    bool valid() const noexcept { return h_ && h_ != INVALID_HANDLE_VALUE; }

    // For WinAPI out-params: CreatePipe(&r, &w, ...) etc.
    // Use with care: this resets the current handle first.
    HANDLE* put() noexcept {
        reset();
        return &h_;
    }

    HANDLE release() noexcept {
        HANDLE tmp = h_;
        h_ = nullptr;
        return tmp;
    }

    void reset(HANDLE h = nullptr) noexcept {
        if (h_ && h_ != INVALID_HANDLE_VALUE) {
            CloseHandle(h_);
        }
        h_ = h;
    }

private:
    HANDLE h_;
};

} // namespace CoreHelpers
