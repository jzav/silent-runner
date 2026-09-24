#include "SRWorkerCommonPolicy.h"
#include "SRConfigsBuilderTypes.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

namespace {

constexpr std::size_t kParsingTokenByteCount = 16;

bool TryGenerateParsingToken_(
    std::string& tokenOut
) noexcept {
    tokenOut.clear();

    unsigned char randomBytes[kParsingTokenByteCount]{};

    const NTSTATUS status = BCryptGenRandom(
        nullptr,
        randomBytes,
        static_cast<ULONG>(sizeof(randomBytes)),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    if (status < 0) {
        return false;
    }

    static constexpr char kHexDigits[] =
        "0123456789abcdef";

    try {
        tokenOut.resize(kParsingTokenByteCount * 2);
    } catch (...) {
        tokenOut.clear();
        return false;
    }

    for (std::size_t i = 0; i < kParsingTokenByteCount; ++i) {
        const unsigned char value = randomBytes[i];

        tokenOut[i * 2]     = kHexDigits[(value >> 4) & 0x0f];
        tokenOut[i * 2 + 1] = kHexDigits[value & 0x0f];
    }

    return true;
}

} // namespace

bool SRWorkerCommonPolicy::Init(
    const SR::SRWorkerCommonPolicyConfig& config
) noexcept {
    needsParsingToken_ = false;
    parsingToken_.clear();

    stdoutPresentation_ =
        config.stdoutPresentation;
    stderrChildPresentation_ =
        config.stderrChildPresentation;

    if (!config.needsParsingToken) {
        return true;
    }

    if (!TryGenerateParsingToken_(parsingToken_)) {
        return false;
    }

    needsParsingToken_ = true;
    return true;
}

bool SRWorkerCommonPolicy::NeedsParsingToken() const noexcept {
    return needsParsingToken_;
}

const std::string&
SRWorkerCommonPolicy::ParsingToken() const noexcept {
    return parsingToken_;
}
SR::ChildOutputPresentation
SRWorkerCommonPolicy::StdoutPresentation() const noexcept {
    return stdoutPresentation_;
}

SR::ChildOutputPresentation
SRWorkerCommonPolicy::StderrChildPresentation() const noexcept {
    return stderrChildPresentation_;
}
