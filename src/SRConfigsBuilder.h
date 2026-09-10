#pragma once

#include <array>
#include <string>

#include "SRConfigsBuilderTypes.h"


namespace SR {

class SRConfigsBuilder {
public:
    SRConfigs configs{};
    bool helpRequested = false;
    std::wstring err{};

    bool Build(
        int argc,
        wchar_t** argv
    );

private:
    void ParseArguments(
        int argc,
        wchar_t** argv
    );

    bool ValidateParsedArguments();
    bool ResolveArguments();
    bool ValidateResolvedArguments();
    void SetErrorIfNone(
        const std::wstring& fallbackError
    );


    void BuildConsumerConfigs();
    void AppendDerivedValues();

    std::array<ConfigArgumentData, kConfigArgumentCount> configArguments_ =
        MakeConfigArgumentData();
    ConfigDerivedValues derivedValues_{};

    std::wstring unknownArgumentParsingError_;
};


} // namespace SR
