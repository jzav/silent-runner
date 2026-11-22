#include "SRWorkerCommonPolicy.h"
#include "FileHelpers.h"

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
    executionId_.clear();
    generatedSuffix_.clear();

    try {
        idPrefix_ = config.idPrefix;
        idBase_ = config.idBase;
        const bool anyIdPart =
            !idPrefix_.empty() || !idBase_.empty() ||
            config.idSuffix != SR::IdSuffixMode::None;
        useDefaultSuffixMode_ = !anyIdPart;
        effectiveIdSuffixMode_ = useDefaultSuffixMode_
            ? SR::IdSuffixMode::TimestampPid : config.idSuffix;
        generatedSuffix_ = FileHelpers::BuildIdSuffix(effectiveIdSuffixMode_);
        executionId_ = FileHelpers::BuildExecutionId(
            idPrefix_, idBase_, generatedSuffix_
        );
    } catch (...) {
        return false;
    }

    stdoutTxtHeaderGranularity_ =
        config.stdoutTxtHeaderGranularity;
    stderrChildTxtHeaderGranularity_ =
        config.stderrChildTxtHeaderGranularity;

    if (!config.needsParsingToken) {
        return true;
    }

    if (!TryGenerateParsingToken_(parsingToken_)) {
        return false;
    }

    needsParsingToken_ = true;
    return true;
}



const std::wstring& SRWorkerCommonPolicy::ExecutionId() const noexcept { return executionId_; }
const std::wstring& SRWorkerCommonPolicy::IdPrefix() const noexcept { return idPrefix_; }
const std::wstring& SRWorkerCommonPolicy::IdBase() const noexcept { return idBase_; }
const std::wstring& SRWorkerCommonPolicy::GeneratedSuffix() const noexcept { return generatedSuffix_; }
SR::IdSuffixMode SRWorkerCommonPolicy::EffectiveIdSuffixMode() const noexcept { return effectiveIdSuffixMode_; }
bool SRWorkerCommonPolicy::UseDefaultSuffixMode() const noexcept { return useDefaultSuffixMode_; }

bool SRWorkerCommonPolicy::NeedsParsingToken() const noexcept {
    return needsParsingToken_;
}

const std::string&
SRWorkerCommonPolicy::ParsingToken() const noexcept {
    return parsingToken_;
}
SR::ChildTxtHeaderGranularity
SRWorkerCommonPolicy::StdoutTxtHeaderGranularity() const noexcept {
    return stdoutTxtHeaderGranularity_;
}

SR::ChildTxtHeaderGranularity
SRWorkerCommonPolicy::StderrChildTxtHeaderGranularity() const noexcept {
    return stderrChildTxtHeaderGranularity_;

}
