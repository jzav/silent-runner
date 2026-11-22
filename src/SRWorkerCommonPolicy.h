#pragma once

#include <string>
#include <vector>


#include "SRTypes.h"




// Common configuration shared by multiple workers.
//
// The execution ID and optional parsing token are generated once during
// initialization and remain immutable throughout the execution.
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


    const std::wstring& ExecutionId() const noexcept;
    const std::wstring& IdPrefix() const noexcept;
    const std::wstring& IdBase() const noexcept;
    const std::wstring& GeneratedSuffix() const noexcept;
    SR::IdSuffixMode EffectiveIdSuffixMode() const noexcept;
    bool UseDefaultSuffixMode() const noexcept;

    bool NeedsParsingToken() const noexcept;

    const std::string& ParsingToken() const noexcept;
    SR::ChildTxtHeaderGranularity StdoutTxtHeaderGranularity() const noexcept;
    SR::ChildTxtHeaderGranularity StderrChildTxtHeaderGranularity() const noexcept;



private:
    std::wstring executionId_;
    std::wstring idPrefix_;
    std::wstring idBase_;
    std::wstring generatedSuffix_;
    SR::IdSuffixMode effectiveIdSuffixMode_ = SR::IdSuffixMode::None;
    bool useDefaultSuffixMode_ = false;
    bool needsParsingToken_ = false;
    std::string parsingToken_;
    SR::ChildTxtHeaderGranularity stdoutTxtHeaderGranularity_ =
        SR::ChildTxtHeaderGranularity::Block;
    SR::ChildTxtHeaderGranularity stderrChildTxtHeaderGranularity_ =

        SR::ChildTxtHeaderGranularity::Block;


};
