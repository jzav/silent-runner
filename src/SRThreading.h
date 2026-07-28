// SRThreading.h
#pragma once

#include <exception>
#include <new>
#include <string>
#include <utility>

namespace SRThreading {

struct ThreadExceptionInfo {
    std::wstring text;
};

ThreadExceptionInfo MakeBadAllocThreadExceptionInfo() noexcept;
ThreadExceptionInfo MakeStdExceptionThreadExceptionInfo(const std::exception& ex) noexcept;
ThreadExceptionInfo MakeUnknownThreadExceptionInfo() noexcept;

template <typename Fn, typename OnException>
void RunGuardedThreadEntry(
    Fn&& fn,
    OnException&& onException
) noexcept {
    try {
        std::forward<Fn>(fn)();
    } catch (const std::bad_alloc&) {
        std::forward<OnException>(onException)(
            MakeBadAllocThreadExceptionInfo()
        );
    } catch (const std::exception& ex) {
        std::forward<OnException>(onException)(
            MakeStdExceptionThreadExceptionInfo(ex)
        );
    } catch (...) {
        std::forward<OnException>(onException)(
            MakeUnknownThreadExceptionInfo()
        );
    }
}

} // namespace SRThreading
