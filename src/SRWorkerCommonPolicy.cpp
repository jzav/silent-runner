#include "SRWorkerCommonPolicy.h"

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
    const SR::Options& opt
) noexcept {
    needsParsingToken_ = false;
    parsingToken_.clear();
    fileSinkParsingTokenTargets_.clear();
    parentParsingTokenTargets_.clear();

    try {
        SR::JobTargetFilter fileSinkParsingTokenFilter;
        fileSinkParsingTokenFilter.worker =
            SR::JobTargetWorker::SRFileSinkWorker;
        fileSinkParsingTokenFilter.headerParsingTokenEnabled = true;

        fileSinkParsingTokenTargets_ =
            SR::RetrieveJobTargets(fileSinkParsingTokenFilter);

        SR::JobTargetFilter parentParsingTokenFilter;
        parentParsingTokenFilter.worker =
            SR::JobTargetWorker::SRParentEmitWorker;
        parentParsingTokenFilter.headerParsingTokenEnabled = true;

        parentParsingTokenTargets_ =
            SR::RetrieveJobTargets(parentParsingTokenFilter);
    } catch (...) {
        fileSinkParsingTokenTargets_.clear();
        parentParsingTokenTargets_.clear();
        return false;
    }


    const bool fileSinkNeedsParsingToken =
        !opt.stderrDir.empty() ||
        !opt.stderrSrDir.empty();

    const bool parentEmitNeedsParsingToken =
        opt.stderrEmit != SR::EmitMode::Never &&
        (
            opt.stderrEmitSource ==
                SR::StderrEmitSource::Mixed ||
            opt.stderrEmitSource ==
                SR::StderrEmitSource::SilentRunner
        );

    const bool needsParsingToken =
        fileSinkNeedsParsingToken ||
        parentEmitNeedsParsingToken;

    if (!needsParsingToken) {
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

const std::vector<SR::JobTarget>&
SRWorkerCommonPolicy::FileSinkParsingTokenTargets() const noexcept {
    return fileSinkParsingTokenTargets_;
}

const std::vector<SR::JobTarget>&
SRWorkerCommonPolicy::ParentParsingTokenTargets() const noexcept {
    return parentParsingTokenTargets_;
}
