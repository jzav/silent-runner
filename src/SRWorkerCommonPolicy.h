#pragma once

#include <string>
#include <vector>


#include "SRJobTypes.h"

namespace SR {
struct SRWorkerCommonPolicyConfig;
}

// Common configuration shared by multiple workers.
//
// The parsing token is generated during initialization when required by
// the finalized configuration. The token remains immutable for
// the lifetime of the process.
class SRWorkerCommonPolicy {
public:
    SRWorkerCommonPolicy() = default;

    SRWorkerCommonPolicy(const SRWorkerCommonPolicy&) = delete;
    SRWorkerCommonPolicy& operator=(const SRWorkerCommonPolicy&) = delete;
    SRWorkerCommonPolicy(SRWorkerCommonPolicy&&) = delete;
    SRWorkerCommonPolicy& operator=(SRWorkerCommonPolicy&&) = delete;

    bool Init(
        const SR::SRWorkerCommonPolicyConfig& config
    ) noexcept;

    bool NeedsParsingToken() const noexcept;

    const std::string& ParsingToken() const noexcept;
    SR::ChildOutputPresentation StdoutPresentation() const noexcept;
    SR::ChildOutputPresentation StderrChildPresentation() const noexcept;



private:
    bool needsParsingToken_ = false;
    std::string parsingToken_;
    SR::ChildOutputPresentation stdoutPresentation_ =
        SR::ChildOutputPresentation::Block;
    SR::ChildOutputPresentation stderrChildPresentation_ =
        SR::ChildOutputPresentation::Block;


};
