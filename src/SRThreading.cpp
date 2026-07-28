// SRThreading.cpp
#include "SRThreading.h"

#include <exception>
#include <new>

#include "FileHelpers.h"

namespace SRThreading {

ThreadExceptionInfo MakeBadAllocThreadExceptionInfo() noexcept {
    ThreadExceptionInfo info;
    info.text = L"std::bad_alloc";
    return info;
}

ThreadExceptionInfo MakeStdExceptionThreadExceptionInfo(
    const std::exception& ex
) noexcept {
    ThreadExceptionInfo info;

    try {
        const std::wstring detail = FileHelpers::Utf8ToWide(ex.what());
        if (!detail.empty()) {
            info.text = L"std::exception: " + detail;
        } else {
            info.text = L"std::exception";
        }
    } catch (...) {
        info.text = L"std::exception";
    }

    return info;
}

ThreadExceptionInfo MakeUnknownThreadExceptionInfo() noexcept {
    ThreadExceptionInfo info;
    info.text = L"unknown exception";
    return info;
}

} // namespace SRThreading
