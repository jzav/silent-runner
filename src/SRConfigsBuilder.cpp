#include "SRConfigsBuilder.h"
#include <cwctype>


#include "TextHelpers.h"

namespace SR {
namespace {

namespace ParsingHelpers {

bool IsTokenArgumentKey(
    const std::wstring& token,
    const std::array<ConfigArgumentData, kConfigArgumentCount>& configArguments
) {
    std::wstring key = token;

    if (TextHelpers::StartsWith(token, L"--")) {
        const std::size_t equalsPosition = token.find(L'=');
        if (equalsPosition != std::wstring::npos) {
            key = token.substr(0, equalsPosition);
        }
    }

    for (const auto& configArgument : configArguments) {
        if (TextHelpers::EqualsOrdinalIgnoreCase(
                key,
                configArgument.spelling
            ) ||
            (configArgument.alias != nullptr &&
             TextHelpers::EqualsOrdinalIgnoreCase(
                 key,
                 configArgument.alias
             ))) {
            return true;
        }
    }

    return TextHelpers::StartsWith(key, L"--");
}

void AppendParsingError(
    std::wstring& parsingError,
    const std::wstring& error
) {
    if (!parsingError.empty()) {
        parsingError += L" | ";
    }

    parsingError += error;
}

} // namespace ParsingHelpers
} // namespace



namespace Resolution {

bool ResolveBool(
    const ConfigArgumentData& configArgument,
    bool& value,
    std::wstring& err
) {


    value = configArgument.optionValueSpecified;
    return true;
}

bool ResolveWString(
    const ConfigArgumentData& configArgument,
    std::wstring& value,
    std::wstring& err
) {

    value = configArgument.optionValue;
    return true;
}

bool ResolveUInt32(
    const ConfigArgumentData& configArgument,
    uint32_t& value,
    std::wstring& err
) {


    if (!configArgument.optionValueSpecified) {
        value = 0;
        return true;
    }

    return TextHelpers::TryParseUInt32(
        configArgument.optionValue,
        value
    );
}

bool ResolveUInt64(
    const ConfigArgumentData& configArgument,
    uint64_t& value,
    std::wstring& err
) {


    if (!configArgument.optionValueSpecified) {
        value = 0;
        return true;
    }

    return TextHelpers::TryParseUInt64(
        configArgument.optionValue,
        value
    );
}

bool ResolveIdSuffixMode(
    const ConfigArgumentData& configArgument,
    SR::IdSuffixMode& value,
    std::wstring& err
) {
    if (!configArgument.optionValueSpecified) {
        value = SR::IdSuffixMode::None;
        return true;
    }

    if (!SR::TryParseIdSuffixModeIgnoreCase(
            configArgument.optionValue,
            value
        )) {
        err =
            std::wstring(L"Invalid value for ") +
            configArgument.spelling +
            L". Allowed values:\n"
            L"  timestamp\n"
            L"  pid\n"
            L"  timestamp+pid\n"
            L"  pid+timestamp";
        return false;
    }

    return true;
}


bool ResolveEmitMode(
    const ConfigArgumentData& configArgument,
    SR::EmitMode& value,
    std::wstring& err
) {
    if (!configArgument.optionValueSpecified) {
        value = SR::EmitMode::Never;
        return true;
    }

    if (!SR::TryParseEmitModeIgnoreCase(
            configArgument.optionValue,
            value
        )) {
        err =
            std::wstring(L"Invalid value for ") +
            configArgument.spelling +
            L". Allowed values:\n";
        SR::AppendEmitModeHelp(err);
        TextHelpers::TrimTrailingNewlines(err);
        return false;
    }

    return true;
}


bool ResolveKeepLogMode(
    const ConfigArgumentData& configArgument,
    SR::KeepLogMode& value,
    std::wstring& err
) {
    if (!configArgument.optionValueSpecified) {
        value = SR::KeepLogMode::Always;
        return true;
    }

    if (!SR::TryParseKeepLogModeIgnoreCase(
            configArgument.optionValue,
            value
        )) {
        err =
            std::wstring(L"Invalid value for ") +
            configArgument.spelling +
            L". Allowed values:\n";
        SR::AppendKeepLogModeHelp(err);
        TextHelpers::TrimTrailingNewlines(err);
        return false;
    }

    return true;
}


bool ResolveExecutionMode(
    const ConfigArgumentData& rawCommandArgument,
    SR::ExecutionMode& value,
    std::wstring& err
) {


    value = rawCommandArgument.optionValueSpecified
        ? SR::ExecutionMode::RawCommand
        : SR::ExecutionMode::ScriptOrExe;
    return true;
}

} // namespace Resolution


namespace {

namespace ValidationHelpers {


bool ValidateId(const std::wstring& value) {
    if (value.empty()) {
        return false;
    }

    for (wchar_t ch : value) {
        if ((ch >= L'a' && ch <= L'z') ||
            (ch >= L'A' && ch <= L'Z') ||
            (ch >= L'0' && ch <= L'9') ||
            ch == L'.' ||
            ch == L'_' ||
            ch == L'-') {
            continue;
        }

        return false;
    }

    return true;
}


bool ValidatePathArgument(
    const ConfigArgumentData& configArgument,
    std::wstring& err
) {
    const std::wstring& rawPath =
        configArgument.optionValue;
    const wchar_t* argumentName =
        configArgument.spelling;

    if (rawPath.empty()) {
        err =
            std::wstring(L"Invalid value for ") +
            argumentName +
            L": path must not be empty";
        return false;
    }

    if (iswspace(rawPath.front()) ||
        iswspace(rawPath.back())) {
        err =
            std::wstring(L"Invalid value for ") +
            argumentName +
            L": paths containing leading or trailing whitespace are not supported";
        return false;
    }

    if (rawPath.find(L'"') != std::wstring::npos) {
        err =
            std::wstring(L"Invalid value for ") +
            argumentName +
            L": paths containing double quotes are not supported";
        return false;
    }

    if (rawPath.find_first_of(L"<>|?*") != std::wstring::npos) {
        err =
            std::wstring(L"Invalid value for ") +
            argumentName +
            L": paths containing invalid characters (< > | ? *) are not supported";
        return false;
    }

    return true;
}


bool ValidateStdoutEmitArgument(
    const std::array<ConfigArgumentData, kConfigArgumentCount>& configArguments,
    ConfigArgument argument,
    std::wstring& err
) {
    const ConfigArgumentData& configArgument =
        configArguments[static_cast<std::size_t>(argument)];

    const SR::EmitMode mode =
        std::get<SR::EmitMode>(configArgument.typedValue);

    if (!(SR::EmitModeStreamMask(mode) & SR::STDOUT)) {
        err =
            std::wstring(L"Invalid value for ") +
            configArgument.spelling +
            L". Allowed values:\n";
        SR::AppendEmitModeHelpForStdout(err);
        TextHelpers::TrimTrailingNewlines(err);
        return false;
    }

    return true;
}

bool ValidateStderrEmitArgument(
    const std::array<ConfigArgumentData, kConfigArgumentCount>& configArguments,
    ConfigArgument argument,
    std::wstring& err
) {
    const ConfigArgumentData& configArgument =
        configArguments[static_cast<std::size_t>(argument)];

    const SR::EmitMode mode =
        std::get<SR::EmitMode>(configArgument.typedValue);

    if (!(SR::EmitModeStreamMask(mode) & SR::STDERR)) {
        err =
            std::wstring(L"Invalid value for ") +
            configArgument.spelling +
            L". Allowed values:\n";
        SR::AppendEmitModeHelpForStderr(err);
        TextHelpers::TrimTrailingNewlines(err);
        return false;
    }

    return true;
}

} // namespace ValidationHelpers


namespace Validation {

bool StderrEmitMutualExclusivity(
    const std::array<ConfigArgumentData, kConfigArgumentCount>& configArguments,
    std::wstring& err
) {
    const bool stderrEmitSpecified =
        configArguments[
            static_cast<std::size_t>(ConfigArgument::StderrEmit)
        ].optionValueSpecified;
    const bool stderrEmitChildSpecified =
        configArguments[
            static_cast<std::size_t>(ConfigArgument::StderrEmitChild)
        ].optionValueSpecified;
    const bool stderrEmitSrSpecified =
        configArguments[
            static_cast<std::size_t>(ConfigArgument::StderrEmitSr)
        ].optionValueSpecified;
    const bool stderrEmitInclStdoutSpecified =
        configArguments[
            static_cast<std::size_t>(ConfigArgument::StderrEmitInclStdout)
        ].optionValueSpecified;

    if (stderrEmitSpecified &&
        (stderrEmitChildSpecified ||
         stderrEmitSrSpecified ||
         stderrEmitInclStdoutSpecified)) {
        err =
            L"--stderr-emit must not be combined with --stderr-emit-child, --stderr-emit-sr, or --stderr-emit-incl-stdout";
        return false;
    }

    if (stderrEmitChildSpecified &&
        (stderrEmitSrSpecified ||
         stderrEmitInclStdoutSpecified)) {
        err =
            L"--stderr-emit-child must not be combined with --stderr-emit, --stderr-emit-sr, or --stderr-emit-incl-stdout";
        return false;
    }

    if (stderrEmitSrSpecified &&
        stderrEmitInclStdoutSpecified) {
        err =
            L"--stderr-emit-sr must not be combined with --stderr-emit, --stderr-emit-child, or --stderr-emit-incl-stdout";
        return false;
    }

    return true;
}

bool PathArgument(
    const std::array<ConfigArgumentData, kConfigArgumentCount>& configArguments,
    ConfigArgument argument,
    std::wstring& err
) {
    const ConfigArgumentData& configArgument =
        configArguments[static_cast<std::size_t>(argument)];

    if (!configArgument.optionValueSpecified) {
        return true;
    }

    return ValidationHelpers::ValidatePathArgument(
        configArgument,
        err
    );
}

bool IdPrefix(
    const std::array<ConfigArgumentData, kConfigArgumentCount>& configArguments,
    std::wstring& err
) {
    const ConfigArgumentData& configArgument =
        configArguments[
            static_cast<std::size_t>(ConfigArgument::IdPrefix)
        ];

    if (!configArgument.optionValueSpecified) {
        return true;
    }

    if (!ValidationHelpers::ValidateId(configArgument.optionValue)) {
        err = L"Invalid --id-prefix (allowed: A-Za-z0-9._-)";
        return false;
    }

    return true;
}

bool IdBase(
    const std::array<ConfigArgumentData, kConfigArgumentCount>& configArguments,
    std::wstring& err
) {
    const ConfigArgumentData& configArgument =
        configArguments[
            static_cast<std::size_t>(ConfigArgument::IdBase)
        ];

    if (!configArgument.optionValueSpecified) {
        return true;
    }

    if (!ValidationHelpers::ValidateId(configArgument.optionValue)) {
        err = L"Invalid --id-base (allowed: A-Za-z0-9._-)";
        return false;
    }

    return true;
}


bool StdoutEmit(
    const std::array<ConfigArgumentData, kConfigArgumentCount>& configArguments,
    std::wstring& err
) {
    return ValidationHelpers::ValidateStdoutEmitArgument(
        configArguments,
        ConfigArgument::StdoutEmit,
        err
    );
}


bool StderrEmit(
    const std::array<ConfigArgumentData, kConfigArgumentCount>& configArguments,
    std::wstring& err
) {
    return ValidationHelpers::ValidateStderrEmitArgument(
        configArguments,
        ConfigArgument::StderrEmit,
        err
    );
}

bool StderrEmitChild(
    const std::array<ConfigArgumentData, kConfigArgumentCount>& configArguments,
    std::wstring& err
) {
    return ValidationHelpers::ValidateStderrEmitArgument(
        configArguments,
        ConfigArgument::StderrEmitChild,
        err
    );
}

bool StderrEmitSr(
    const std::array<ConfigArgumentData, kConfigArgumentCount>& configArguments,
    std::wstring& err
) {
    return ValidationHelpers::ValidateStderrEmitArgument(
        configArguments,
        ConfigArgument::StderrEmitSr,
        err
    );
}

bool StderrEmitInclStdout(
    const std::array<ConfigArgumentData, kConfigArgumentCount>& configArguments,
    std::wstring& err
) {
    return ValidationHelpers::ValidateStderrEmitArgument(
        configArguments,
        ConfigArgument::StderrEmitInclStdout,
        err
    );
}


} // namespace Validation

} // namespace

void SRConfigsBuilder::SetErrorIfNone(
    const std::wstring& fallbackError
) {
    if (this->err.empty()) {
        this->err = fallbackError;
    }
}

bool SRConfigsBuilder::Build(
    int argc,
    wchar_t** argv
) {
    this->helpRequested = false;
    this->err.clear();

    ParseArguments(
        argc,
        argv
    );

    if (!ValidateParsedArguments()) {
        SetErrorIfNone(
            L"Parsed argument validation failed"
        );
        return false;
    }

    if (this->helpRequested) {
        return true;
    }

    if (!ResolveArguments()) {
        SetErrorIfNone(
            L"Argument resolution failed"
        );
        return false;
    }

    if (!ValidateResolvedArguments()) {
        SetErrorIfNone(
            L"Resolved argument validation failed"
        );
        return false;
    }

    BuildConsumerConfigs();
    AppendDerivedValues();

    return true;
}
void SRConfigsBuilder::ParseArguments(
    int argc,
    wchar_t** argv
) {
    derivedValues_.argVector = std::vector<std::wstring>(argv, argv + argc);
    derivedValues_.childArgsStartIndex = argc;

    for (int i = 1; i < argc; ++i) {
        std::wstring token = argv[i];
        std::wstring key = token;
        std::wstring inlineValue;

        if (TextHelpers::StartsWith(token, L"--")) {
            const std::size_t equalsPosition = token.find(L'=');
            if (equalsPosition != std::wstring::npos) {
                key = token.substr(0, equalsPosition);
                inlineValue = token.substr(equalsPosition + 1);
            }
        }

        bool matched = false;

        for (auto& configArgument : configArguments_) {
            const bool spellingMatches =
                TextHelpers::EqualsOrdinalIgnoreCase(
                    key,
                    configArgument.spelling
                );

            const bool aliasMatches =
                configArgument.alias != nullptr &&
                TextHelpers::EqualsOrdinalIgnoreCase(
                    key,
                    configArgument.alias
                );

            if (!spellingMatches && !aliasMatches) {
                continue;
            }

            matched = true;

            if (configArgument.optionValueSpecified) {
            ParsingHelpers::AppendParsingError(
                    configArgument.parsingError,
                    L"Duplicate " +
                    std::wstring(configArgument.spelling)
                );
            }

            if (configArgument.parsingMode ==
                ConfigArgumentParsingMode::Value) {
                if (!inlineValue.empty()) {
                    configArgument.optionValue = inlineValue;
                } else if (i + 1 >= argc) {
                    ParsingHelpers::AppendParsingError(
                        configArgument.parsingError,
                        L"Missing value for " +
                        std::wstring(configArgument.spelling)
                    );
                } else if (ParsingHelpers::IsTokenArgumentKey(
                        argv[i + 1],
                        configArguments_
                    )) {
                    ParsingHelpers::AppendParsingError(
                        configArgument.parsingError,
                        L"Missing value for " +
                        std::wstring(configArgument.spelling)
                    );
                } else {
                    configArgument.optionValue = argv[++i];

                    if (configArgument.optionValue.empty()) {
                        ParsingHelpers::AppendParsingError(
                            configArgument.parsingError,
                            L"Missing value for " +
                            std::wstring(configArgument.spelling)
                        );
                    }
                }
            }

            configArgument.optionValueSpecified = true;

            if (configArgument.parsingMode ==
                ConfigArgumentParsingMode::ChildCommand) {
                if (i + 1 >= argc) {
                    ParsingHelpers::AppendParsingError(
                        configArgument.parsingError,
                        L"Missing value for " +
                        std::wstring(configArgument.spelling)
                    );
                }

                derivedValues_.childArgsStartIndex = i + 1;
                return;
            }

            break;
        }

        if (matched) {
            continue;
        }

        if (TextHelpers::StartsWith(key, L"--")) {
            ParsingHelpers::AppendParsingError(
                unknownArgumentParsingError_,
                L"Unknown argument: " + key
            );
            continue;
        }

        derivedValues_.childArgsStartIndex = i;
        return;
    }
}

bool SRConfigsBuilder::ValidateParsedArguments() {
    if (configArguments_[
            static_cast<std::size_t>(ConfigArgument::Help)
        ].optionValueSpecified) {
        this->helpRequested = true;
        return true;
    }

    if (!unknownArgumentParsingError_.empty()) {
        this->err = unknownArgumentParsingError_;
        return false;
    }

    for (const auto& configArgument : configArguments_) {
        if (!configArgument.parsingError.empty()) {
            this->err = configArgument.parsingError;
            return false;
        }
    }

    if (!Validation::StderrEmitMutualExclusivity(
            configArguments_,
            this->err
        )) {
        return false;
    }

    if (!Validation::PathArgument(configArguments_, ConfigArgument::ProbeDir, this->err)) {
        return false;
    }

    if (!Validation::PathArgument(configArguments_, ConfigArgument::Cwd, this->err)) {
        return false;
    }

    if (!Validation::PathArgument(configArguments_, ConfigArgument::StdoutDir, this->err)) {
        return false;
    }

    if (!Validation::PathArgument(configArguments_, ConfigArgument::StdoutDirJsonl, this->err)) {
        return false;
    }

    if (!Validation::PathArgument(configArguments_, ConfigArgument::StderrDir, this->err)) {
        return false;
    }

    if (!Validation::PathArgument(configArguments_, ConfigArgument::StderrDirJsonl, this->err)) {
        return false;
    }

    if (!Validation::PathArgument(configArguments_, ConfigArgument::StderrDirChild, this->err)) {
        return false;
    }

    if (!Validation::PathArgument(configArguments_, ConfigArgument::StderrDirChildJsonl, this->err)) {
        return false;
    }

    if (!Validation::PathArgument(configArguments_, ConfigArgument::StderrDirSr, this->err)) {
        return false;
    }

    if (!Validation::PathArgument(configArguments_, ConfigArgument::StderrDirSrJsonl, this->err)) {
        return false;
    }

    if (!Validation::PathArgument(configArguments_, ConfigArgument::StderrDirInclStdout, this->err)) {
        return false;
    }

    if (!Validation::PathArgument(configArguments_, ConfigArgument::StderrDirInclStdoutJsonl, this->err)) {
        return false;
    }

    if (!Validation::PathArgument(configArguments_, ConfigArgument::RunOnSuccess, this->err)) {
        return false;
    }

    if (!Validation::PathArgument(configArguments_, ConfigArgument::RunOnFailure, this->err)) {
        return false;
    }

    if (!Validation::IdPrefix(configArguments_, this->err)) {
        return false;
    }

    if (!Validation::IdBase(configArguments_, this->err)) {
        return false;
    }

    return true;
}


bool SRConfigsBuilder::ResolveArguments() {
    for (auto& configArgument : configArguments_) {
        if (!ResolveConfigValue(configArgument, this->err)) {
            SetErrorIfNone(
                std::wstring(L"Invalid value for ") +
                configArgument.spelling
            );
            return false;
        }
    }

    auto& stdoutEmitArgument =
        configArguments_[
            static_cast<std::size_t>(ConfigArgument::StdoutEmit)
        ];

    if (!stdoutEmitArgument.optionValueSpecified) {
        stdoutEmitArgument.typedValue = SR::EmitMode::Stream;
    }

    auto& stderrEmitArgument =
        configArguments_[
            static_cast<std::size_t>(ConfigArgument::StderrEmit)
        ];

    const auto& stderrEmitChildArgument =
        configArguments_[
            static_cast<std::size_t>(ConfigArgument::StderrEmitChild)
        ];

    const auto& stderrEmitSrArgument =
        configArguments_[
            static_cast<std::size_t>(ConfigArgument::StderrEmitSr)
        ];

    const auto& stderrEmitInclStdoutArgument =
        configArguments_[
            static_cast<std::size_t>(ConfigArgument::StderrEmitInclStdout)
        ];

    if (!stderrEmitArgument.optionValueSpecified &&
        !stderrEmitChildArgument.optionValueSpecified &&
        !stderrEmitSrArgument.optionValueSpecified &&
        !stderrEmitInclStdoutArgument.optionValueSpecified) {
        stderrEmitArgument.typedValue = SR::EmitMode::Stream;
        derivedValues_.stderrEmit =
            SR::EmitMode::Stream;
        derivedValues_.stderrEmitSource =
            SR::StderrEmitSource::SrAndChild;
    } else if (stderrEmitArgument.optionValueSpecified) {
        derivedValues_.stderrEmit =
            std::get<SR::EmitMode>(stderrEmitArgument.typedValue);
        derivedValues_.stderrEmitSource =
            SR::StderrEmitSource::SrAndChild;
    } else if (stderrEmitChildArgument.optionValueSpecified) {
        derivedValues_.stderrEmit =
            std::get<SR::EmitMode>(stderrEmitChildArgument.typedValue);
        derivedValues_.stderrEmitSource =
            SR::StderrEmitSource::Child;
    } else if (stderrEmitSrArgument.optionValueSpecified) {
        derivedValues_.stderrEmit =
            std::get<SR::EmitMode>(stderrEmitSrArgument.typedValue);
        derivedValues_.stderrEmitSource =
            SR::StderrEmitSource::Sr;
    } else if (stderrEmitInclStdoutArgument.optionValueSpecified) {
        derivedValues_.stderrEmit =
            std::get<SR::EmitMode>(stderrEmitInclStdoutArgument.typedValue);
        derivedValues_.stderrEmitSource =
            SR::StderrEmitSource::SrAndChildInclStdout;
    }

    auto& debugArgument =
        configArguments_[
            static_cast<std::size_t>(ConfigArgument::Debug)
        ];

    const auto& verboseArgument =
        configArguments_[
            static_cast<std::size_t>(ConfigArgument::Verbose)
        ];

    if (std::get<bool>(verboseArgument.typedValue)) {
        debugArgument.typedValue = true;
    }
    return true;
}


bool SRConfigsBuilder::ValidateResolvedArguments() {
    if (!Validation::StdoutEmit(configArguments_, this->err)) {
        return false;
    }

    if (!Validation::StderrEmit(configArguments_, this->err)) {
        return false;
    }

    if (!Validation::StderrEmitChild(configArguments_, this->err)) {
        return false;
    }

    if (!Validation::StderrEmitSr(configArguments_, this->err)) {
        return false;
    }

    if (!Validation::StderrEmitInclStdout(configArguments_, this->err)) {
        return false;
    }

    return true;
}

void SRConfigsBuilder::BuildConsumerConfigs() {
    BuildConsumerConfigsHelper(
        configArguments_,
        configs
    );
}

void SRConfigsBuilder::AppendDerivedValues() {
    AppendDerivedValuesHelper(
        derivedValues_,
        configs
    );
}
} // namespace SR
