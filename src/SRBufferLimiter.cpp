#include "SRBufferLimiter.h"
#include "SRLifecycleDiagnostics.h"


#define WIN32_LEAN_AND_MEAN
#include <windows.h>

void SRBufferLimiter::Init(
    const SR::Options& opt,
    SRLifecycleDiagnostics* diagnosticsOrNull
) noexcept {
    diagnostics_ = diagnosticsOrNull;

    eventFailureDetected_.store(false, std::memory_order_relaxed);
    firstEventFailureOperation_.store(
        static_cast<int>(EventOperation::None),
        std::memory_order_relaxed
    );
    firstEventFailureGle_.store(0, std::memory_order_relaxed);

    stdoutMax_ = opt.stdoutMaxBufferBytes;
    stderrMax_ = opt.stderrMaxBufferBytes;
    totalMax_  = opt.maxTotalBufferBytes;

    ResetRuntimeState();

    const bool anyLimitEnabled =
        (stdoutMax_ != 0) ||
        (stderrMax_ != 0) ||
        (totalMax_  != 0);

    if (anyLimitEnabled) {
        HANDLE eventHandle = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!eventHandle) {
            RecordEventFailure_(EventOperation::Create, GetLastError());
        }
        limitEvent_.reset(eventHandle);
    } else {
        limitEvent_.reset();
    }
}


void SRBufferLimiter::ResetRuntimeState() noexcept {

    limitSignaled_.store(false, std::memory_order_relaxed);
    firstHitStream_.store(static_cast<int>(StreamType::None), std::memory_order_relaxed);

    stdoutLimitReached_.store(false, std::memory_order_relaxed);
    stderrLimitReached_.store(false, std::memory_order_relaxed);
    totalLimitReached_.store(false, std::memory_order_relaxed);


    if (limitEvent_.valid()) {
        if (!ResetEvent(limitEvent_.get())) {
            RecordEventFailure_(EventOperation::Reset, GetLastError());
        }
    }
}


bool SRBufferLimiter::TryReserveStdout(
    size_t bytes,
    const SR::BufferUsage& usage
) noexcept {
    return TryReserve_(
        StreamType::Stdout,
        bytes,
        usage.stdoutBufferedBytes,
        usage.totalBufferedBytes
    );
}

bool SRBufferLimiter::TryReserveStderr(
    size_t bytes,
    const SR::BufferUsage& usage
) noexcept {
    return TryReserve_(
        StreamType::Stderr,
        bytes,
        usage.stderrBufferedBytes,
        usage.totalBufferedBytes
    );
}

bool SRBufferLimiter::LimitHit() const noexcept {
    return limitSignaled_.load(std::memory_order_relaxed);
}

SRBufferLimiter::StreamType SRBufferLimiter::FirstHitStream() const noexcept {
    return static_cast<StreamType>(firstHitStream_.load(std::memory_order_relaxed));
}

bool SRBufferLimiter::StdoutLimitReached() const noexcept {
    return stdoutLimitReached_.load(std::memory_order_relaxed);
}

bool SRBufferLimiter::StderrLimitReached() const noexcept {
    return stderrLimitReached_.load(std::memory_order_relaxed);
}

bool SRBufferLimiter::TotalLimitReached() const noexcept {
    return totalLimitReached_.load(std::memory_order_relaxed);
}


HANDLE SRBufferLimiter::LimitEventHandle() const noexcept {
    return limitEvent_.valid() ? limitEvent_.get() : nullptr;
}
bool SRBufferLimiter::EventFailureDetected() const noexcept {
    return eventFailureDetected_.load(std::memory_order_relaxed);
}

SRBufferLimiter::EventOperation
SRBufferLimiter::FirstEventFailureOperation() const noexcept {
    return static_cast<EventOperation>(
        firstEventFailureOperation_.load(std::memory_order_relaxed)
    );
}

const wchar_t* SRBufferLimiter::FirstEventFailureOperationName() const noexcept {
    switch (FirstEventFailureOperation()) {
        case EventOperation::Create: return L"CreateEventW";
        case EventOperation::Reset:  return L"ResetEvent";
        case EventOperation::Set:    return L"SetEvent";
        case EventOperation::None:
        default:
            return L"none";
    }
}

DWORD SRBufferLimiter::FirstEventFailureGle() const noexcept {
    return firstEventFailureGle_.load(std::memory_order_relaxed);
}

void SRBufferLimiter::RecordEventFailure_(
    EventOperation operation,
    DWORD gle
) noexcept {
    bool expected = false;
    if (eventFailureDetected_.compare_exchange_strong(
            expected,
            true,
            std::memory_order_relaxed)) {
        firstEventFailureOperation_.store(
            static_cast<int>(operation),
            std::memory_order_relaxed
        );
        firstEventFailureGle_.store(
            (gle != 0) ? gle : ERROR_INVALID_FUNCTION,
            std::memory_order_relaxed
        );
    }
}


bool SRBufferLimiter::TryReserve_(
    StreamType stream,
    size_t bytes,
    uint64_t streamBufferedBytes,
    uint64_t totalBufferedBytes
) noexcept {
    auto probeReserve = [&](bool allowed, const wchar_t* reason) noexcept {
        if (!diagnostics_) return;

        try {
            const wchar_t* streamName =
                stream == StreamType::Stdout
                    ? L"STDOUT"
                    : stream == StreamType::Stderr
                        ? L"STDERR"
                        : L"INVALID";

            const uint64_t streamMax =
                stream == StreamType::Stdout
                    ? stdoutMax_
                    : stream == StreamType::Stderr
                        ? stderrMax_
                        : 0;

            diagnostics_->ProbeLine(
                std::wstring(L"[BUFFER][RESERVE] stream=") +
                streamName +
                L" bytes=" +
                std::to_wstring(static_cast<uint64_t>(bytes)) +
                L" streamBufferedBytes=" +
                std::to_wstring(streamBufferedBytes) +
                L" streamMax=" +
                std::to_wstring(streamMax) +
                L" totalBufferedBytes=" +
                std::to_wstring(totalBufferedBytes) +
                L" totalMax=" +
                std::to_wstring(totalMax_) +
                L" result=" +
                (allowed ? L"ALLOWED" : L"DENIED") +
                L" reason=" +
                reason
            );
        } catch (...) {
        }
    };

    if (bytes == 0) {
        probeReserve(true, L"ZERO_BYTES");
    }

    if (bytes == 0) return true;

    const uint64_t n = static_cast<uint64_t>(bytes);

    uint64_t streamMax = 0;
    if (stream == StreamType::Stdout) {
        streamMax = stdoutMax_;
    } else if (stream == StreamType::Stderr) {
        streamMax = stderrMax_;
    } else {
        SignalLimitHit_(stream);
        probeReserve(false, L"INVALID_STREAM");

        return false;
    }

    if (streamMax != 0 &&
        (streamBufferedBytes > streamMax ||
         n > streamMax - streamBufferedBytes)) {
        if (stream == StreamType::Stdout) {
            stdoutLimitReached_.store(true, std::memory_order_relaxed);
        } else {
            stderrLimitReached_.store(true, std::memory_order_relaxed);
        }

        SignalLimitHit_(stream);
        probeReserve(false, L"STREAM_LIMIT");

        return false;

    }

    if (totalMax_ != 0 &&
        (totalBufferedBytes > totalMax_ ||
         n > totalMax_ - totalBufferedBytes)) {
        totalLimitReached_.store(true, std::memory_order_relaxed);

        SignalLimitHit_(stream);
        probeReserve(false, L"TOTAL_LIMIT");

        return false;

    }

    probeReserve(true, L"WITHIN_LIMITS");


    return true;
}

void SRBufferLimiter::SignalLimitHit_(StreamType stream) noexcept {
    bool expected = false;
    if (limitSignaled_.compare_exchange_strong(expected, true, std::memory_order_relaxed)) {
        firstHitStream_.store(static_cast<int>(stream), std::memory_order_relaxed);

        if (limitEvent_.valid()) {
            if (!SetEvent(limitEvent_.get())) {
                RecordEventFailure_(EventOperation::Set, GetLastError());
            }
        }
    }
}
