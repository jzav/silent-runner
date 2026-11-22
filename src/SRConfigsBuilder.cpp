#include "SRConfigsBuilder.h"
#include <cwctype>
#include <vector>



#include "TextHelpers.h"
#include "SRJobTypes.h"

namespace SR {
namespace {

namespace ParsingHelpers {

bool IsTokenArgumentKey(
    const std::wstring& token,
    const ConfigArguments& configArguments
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

bool ResolveChildEventFraming(
    const ConfigArgumentData& configArgument,
    SR::ChildEventFraming& value,
    std::wstring& err
) {
    if (!configArgument.optionValueSpecified) {
        value = SR::ChildEventFraming::Chunk;
        return true;
    }

    if (!SR::TryParseChildEventFramingIgnoreCase(
            configArgument.optionValue,
            value
        )) {
        err =
            std::wstring(L"Invalid value for ") +
            configArgument.spelling +
            L". Allowed values:\n"
            L"  chunk\n"
            L"  lf\n"
            L"  newline\n"
            L"  crlf";
        return false;
    }

    return true;
}

bool ResolveJsonlPayloadRepresentation(
    const ConfigArgumentData& configArgument,
    SR::JsonlPayloadRepresentation& value,
    std::wstring& err
) {
    if (!configArgument.optionValueSpecified) {
        value = SR::JsonlPayloadRepresentation::Text;
        return true;
    }

    if (!SR::TryParseJsonlPayloadRepresentationIgnoreCase(
            configArgument.optionValue,
            value
        )) {
        err =
            std::wstring(L"Invalid value for ") +
            configArgument.spelling +
            L". Allowed values:\n"
            L"  text\n"
            L"  base64\n"
            L"  text+base64\n"
            L"  base64+text";
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
    const ConfigArgumentData& commandStringArgument,
    SR::ExecutionMode& value,
    std::wstring& err
) {


    value = commandStringArgument.optionValueSpecified
        ? SR::ExecutionMode::CommandString
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
    const ConfigArguments& configArguments,
    ConfigArgument argument,
    std::wstring& err
) {
    const ConfigArgumentData& configArgument =
        configArguments.GetData(argument);

    SR::EmitMode mode{};
    configArguments.CopyValue(argument, mode);

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
    const ConfigArguments& configArguments,
    ConfigArgument argument,
    std::wstring& err
) {
    const ConfigArgumentData& configArgument =
        configArguments.GetData(argument);

    SR::EmitMode mode{};
    configArguments.CopyValue(argument, mode);

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

bool ValidateChildEventNewlineMaxBytes(
    const ConfigArguments& configArguments,
    ConfigArgument framingArgumentId,
    ConfigArgument newlineMaxBytesArgumentId,
    std::wstring& err
) {
    const ConfigArgumentData& framingArgument =
        configArguments.GetData(framingArgumentId);

    const ConfigArgumentData& newlineMaxBytesArgument =
        configArguments.GetData(newlineMaxBytesArgumentId);

    SR::ChildEventFraming framing{};
    configArguments.CopyValue(framingArgumentId, framing);

    if (configArguments.IsSpecified(newlineMaxBytesArgumentId) &&
        framing == SR::ChildEventFraming::Chunk) {
        err =
            std::wstring(newlineMaxBytesArgument.spelling) +
            L" requires " +
            framingArgument.spelling +
            L" to be lf, newline, or crlf";
        return false;
    }

    uint64_t newlineMaxBytes{};
    configArguments.CopyValue(newlineMaxBytesArgumentId, newlineMaxBytes);

    if (configArguments.IsSpecified(newlineMaxBytesArgumentId) &&
        newlineMaxBytes == 0) {
        err =
            std::wstring(L"Invalid value for ") +
            newlineMaxBytesArgument.spelling +
            L": must be greater than 0";
        return false;
    }

    return true;
}


} // namespace ValidationHelpers


namespace Validation {

bool StderrEmitMutualExclusivity(
    const ConfigArguments& configArguments,
    std::wstring& err
) {
    const ConfigArgument stdoutArguments[] = {
        ConfigArgument::StdoutEmit,
        ConfigArgument::StdoutEmitRaw
    };

    const ConfigArgument stderrArguments[] = {
        ConfigArgument::StderrEmit,
        ConfigArgument::StderrEmitChild,
        ConfigArgument::StderrEmitChildRaw,
        ConfigArgument::StderrEmitSr,
        ConfigArgument::StderrEmitInclStdout
    };

    auto validateExclusive = [&](
        const auto& arguments
    ) -> bool {
        ConfigArgument firstSpecified = ConfigArgument::Count;

        for (const ConfigArgument argument : arguments) {
            if (!configArguments.IsSpecified(argument)) {
                continue;
            }

            if (firstSpecified != ConfigArgument::Count) {
                err =
                    std::wstring(L"Mutually exclusive options: ") +
                    configArguments.GetData(firstSpecified).spelling +
                    L" and " +
                    configArguments.GetData(argument).spelling;
                return false;
            }

            firstSpecified = argument;
        }

        return true;
    };

    return validateExclusive(stdoutArguments) &&
           validateExclusive(stderrArguments);
}

bool PathArgument(
    const ConfigArguments& configArguments,
    ConfigArgument argument,
    std::wstring& err
) {
    const ConfigArgumentData& configArgument =
        configArguments.GetData(argument);

    if (!configArguments.IsSpecified(argument)) {
        return true;
    }

    return ValidationHelpers::ValidatePathArgument(
        configArgument,
        err
    );
}

bool IdPrefix(
    const ConfigArguments& configArguments,
    std::wstring& err
) {
    const ConfigArgumentData& configArgument =
        configArguments.GetData(ConfigArgument::IdPrefix);

    if (!configArguments.IsSpecified(ConfigArgument::IdPrefix)) {
        return true;
    }

    if (!ValidationHelpers::ValidateId(configArgument.optionValue)) {
        err = L"Invalid --id-prefix (allowed: A-Za-z0-9._-)";
        return false;
    }

    return true;
}

bool IdBase(
    const ConfigArguments& configArguments,
    std::wstring& err
) {
    const ConfigArgumentData& configArgument =
        configArguments.GetData(ConfigArgument::IdBase);

    if (!configArguments.IsSpecified(ConfigArgument::IdBase)) {
        return true;
    }

    if (!ValidationHelpers::ValidateId(configArgument.optionValue)) {
        err = L"Invalid --id-base (allowed: A-Za-z0-9._-)";
        return false;
    }

    return true;
}


bool StdoutEmit(
    const ConfigArguments& configArguments,
    std::wstring& err
) {
    return ValidationHelpers::ValidateStdoutEmitArgument(
        configArguments,
        ConfigArgument::StdoutEmit,
        err
    );
}


bool StdoutEmitRaw(
    const ConfigArguments& configArguments,
    std::wstring& err
) {
    return ValidationHelpers::ValidateStdoutEmitArgument(
        configArguments,
        ConfigArgument::StdoutEmitRaw,
        err
    );
}

bool StderrEmit(
    const ConfigArguments& configArguments,
    std::wstring& err
) {
    return ValidationHelpers::ValidateStderrEmitArgument(
        configArguments,
        ConfigArgument::StderrEmit,
        err
    );
}

bool StderrEmitChild(
    const ConfigArguments& configArguments,
    std::wstring& err
) {
    return ValidationHelpers::ValidateStderrEmitArgument(
        configArguments,
        ConfigArgument::StderrEmitChild,
        err
    );
}

bool StderrEmitChildRaw(
    const ConfigArguments& configArguments,
    std::wstring& err
) {
    return ValidationHelpers::ValidateStderrEmitArgument(
        configArguments,
        ConfigArgument::StderrEmitChildRaw,
        err
    );
}

bool StderrEmitSr(
    const ConfigArguments& configArguments,
    std::wstring& err
) {
    return ValidationHelpers::ValidateStderrEmitArgument(
        configArguments,
        ConfigArgument::StderrEmitSr,
        err
    );
}

bool StderrEmitInclStdout(
    const ConfigArguments& configArguments,
    std::wstring& err
) {
    return ValidationHelpers::ValidateStderrEmitArgument(
        configArguments,
        ConfigArgument::StderrEmitInclStdout,
        err
    );
}

bool StdoutEventNewlineMaxBytes(
    const ConfigArguments& configArguments,
    std::wstring& err
) {
    return ValidationHelpers::ValidateChildEventNewlineMaxBytes(
        configArguments,
        ConfigArgument::StdoutEventFraming,
        ConfigArgument::StdoutEventNewlineMaxBytes,
        err
    );
}

bool StderrChildEventNewlineMaxBytes(
    const ConfigArguments& configArguments,
    std::wstring& err
) {
    return ValidationHelpers::ValidateChildEventNewlineMaxBytes(
        configArguments,
        ConfigArgument::StderrChildEventFraming,
        ConfigArgument::StderrChildEventNewlineMaxBytes,
        err
    );
}



} // namespace Validation

} // namespace

SRConfigsBuilder::WorkerTargetConfigEntry::WorkerTargetConfigEntry(
    const WorkerTargetLayoutEntry& entry
) : source(&entry) {
    configArgument = ResolveConfigArgument(entry.configArgument);
    keepLogConfigArgument =
        ResolveConfigArgument(entry.keepLogConfigArgument);
}

void SRConfigsBuilder::Init(
    const FileSinkWorkerTargetLayout& fileSinkTargetLayout,
    const ParentEmitWorkerTargetLayout& parentEmitTargetLayout
) {
    configArguments_.Init();

    fileSinkWorkerTargetConfigs_ =
        WorkerTargetConfigs<FileSinkWorkerTargetLayout>(
            fileSinkTargetLayout
        );

    parentEmitWorkerTargetConfigs_ =
        WorkerTargetConfigs<ParentEmitWorkerTargetLayout>(
            parentEmitTargetLayout
        );
}

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

    DeriveValues();
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
    if (configArguments_.IsSpecified(ConfigArgument::Help)) {
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

    if (!Validation::PathArgument(configArguments_, ConfigArgument::StdoutDirRaw, this->err)) {
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

    if (!Validation::PathArgument(configArguments_, ConfigArgument::StderrDirChildRaw, this->err)) {
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


    if (!configArguments_.IsSpecified(ConfigArgument::StdoutEmit) &&
        !configArguments_.IsSpecified(ConfigArgument::StdoutEmitRaw)) {

        configArguments_.SetValue(
            ConfigArgument::StdoutEmit,
            SR::EmitMode::Stream
        );
    }

    if (configArguments_.GetValue<ConfigArgument::StdoutEventFraming>() !=
            SR::ChildEventFraming::Chunk &&
        !configArguments_.IsSpecified(ConfigArgument::StdoutEventNewlineMaxBytes)) {
        configArguments_.SetValue(
            ConfigArgument::StdoutEventNewlineMaxBytes,
            SR::kDefaultChildEventNewlineMaxBytes
        );
    }

    if (configArguments_.GetValue<ConfigArgument::StderrChildEventFraming>() !=
            SR::ChildEventFraming::Chunk &&
        !configArguments_.IsSpecified(ConfigArgument::StderrChildEventNewlineMaxBytes)) {
        configArguments_.SetValue(
            ConfigArgument::StderrChildEventNewlineMaxBytes,
            SR::kDefaultChildEventNewlineMaxBytes
        );
    }

    if (!configArguments_.IsSpecified(ConfigArgument::StderrEmit) &&
        !configArguments_.IsSpecified(ConfigArgument::StderrEmitChild) &&
        !configArguments_.IsSpecified(ConfigArgument::StderrEmitChildRaw) &&
        !configArguments_.IsSpecified(ConfigArgument::StderrEmitSr) &&
        !configArguments_.IsSpecified(ConfigArgument::StderrEmitInclStdout)) {
        configArguments_.SetValue(
            ConfigArgument::StderrEmit,
            SR::EmitMode::Stream
        );
    }

    if (configArguments_.GetValue<ConfigArgument::Verbose>()) {
        configArguments_.SetValue(ConfigArgument::Debug, true);
    }
    return true;
}


void SRConfigsBuilder::DeriveValues() {
    SR::TargetLogConfigs targetLogConfigs;
    bool fileSinkNeedsParsingToken = false;

    for (const auto& targetConfigEntry : fileSinkWorkerTargetConfigs_.targets) {

        const ConfigArgument configArgument =
            targetConfigEntry.configArgument;

        const ConfigArgument keepLogConfigArgument =
            targetConfigEntry.keepLogConfigArgument;
        auto& targetLogConfig =
            targetLogConfigs.For(targetConfigEntry.source->target);

        targetLogConfig.directoryRequested =
            configArguments_.IsSpecified(configArgument);
        configArguments_.CopyValue(
            configArgument,
            targetLogConfig.directory
        );
        configArguments_.CopyValue(
            keepLogConfigArgument,
            targetLogConfig.keepLogMode
        );

        if (targetConfigEntry.source->headerEnabled &&
            targetLogConfig.directoryRequested) {
            fileSinkNeedsParsingToken = true;
        }
    }
    derivedValues_.targetLogConfigs =
        targetLogConfigs;
    derivedValues_.stdoutTxtHeaderGranularity =
        SR::ChildTxtHeaderGranularityOf(
            configArguments_.GetValue<ConfigArgument::StdoutEventFraming>()
        );

    derivedValues_.stderrChildTxtHeaderGranularity =
        SR::ChildTxtHeaderGranularityOf(

            configArguments_.GetValue<ConfigArgument::StderrChildEventFraming>()
        );


    derivedValues_.stdoutParentTarget =
        SR::JobTarget::StdoutParent;
    derivedValues_.stderrParentTarget =
        SR::JobTarget::StderrSrAndChildParent;

    derivedValues_.stdoutEmitMode =
        configArguments_.GetValue<ConfigArgument::StdoutEmit>();
    derivedValues_.stderrEmitMode =
        configArguments_.GetValue<ConfigArgument::StderrEmit>();

    bool stdoutHeaderEnabled = true;
    bool stderrHeaderEnabled = true;

    for (const auto& targetConfigEntry : parentEmitWorkerTargetConfigs_.targets) {
        const ConfigArgument configArgument =
            targetConfigEntry.configArgument;

        if (!configArguments_.IsSpecified(configArgument)) {
            continue;
        }

        SR::EmitMode emitMode{};
        configArguments_.CopyValue(configArgument, emitMode);

        if (targetConfigEntry.source->stream == SR::JobTargetStream::Stdout) {
            derivedValues_.stdoutParentTarget =
                targetConfigEntry.source->target;
            derivedValues_.stdoutEmitMode = emitMode;
            stdoutHeaderEnabled =
                targetConfigEntry.source->headerEnabled;
        } else {
            derivedValues_.stderrParentTarget =
                targetConfigEntry.source->target;
            derivedValues_.stderrEmitMode = emitMode;
            stderrHeaderEnabled =
                targetConfigEntry.source->headerEnabled;
        }
    }

    const bool parentEmitNeedsParsingToken =
        (stdoutHeaderEnabled &&
         derivedValues_.stdoutEmitMode != SR::EmitMode::Never) ||
        (stderrHeaderEnabled &&
         derivedValues_.stderrEmitMode != SR::EmitMode::Never);

    derivedValues_.needsParsingToken =
        fileSinkNeedsParsingToken ||
        parentEmitNeedsParsingToken;

}

bool SRConfigsBuilder::ValidateResolvedArguments() {
    if (!Validation::StdoutEmit(configArguments_, this->err)) {
        return false;
    }

    if (!Validation::StdoutEmitRaw(configArguments_, this->err)) {
        return false;
    }


    if (!Validation::StderrEmit(configArguments_, this->err)) {
        return false;
    }

    if (!Validation::StderrEmitChild(configArguments_, this->err)) {
        return false;
    }

    if (!Validation::StderrEmitChildRaw(configArguments_, this->err)) {
        return false;
    }
    if (!Validation::StderrEmitSr(configArguments_, this->err)) {
        return false;
    }

    if (!Validation::StderrEmitInclStdout(configArguments_, this->err)) {
        return false;
    }

    if (!Validation::StdoutEventNewlineMaxBytes(
            configArguments_,
            this->err
        )) {
        return false;
    }

    if (!Validation::StderrChildEventNewlineMaxBytes(
            configArguments_,
            this->err
        )) {
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
