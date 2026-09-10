#include "SRChildCmdBuilder.h"
#include "HelpGenerator.h"
#include "FileHelpers.h"

constexpr const wchar_t* kUnsupportedScriptOrExeMetacharacters =
    L"&|><()^%!";

bool SRChildCmdBuilder::Build(
    const std::vector<std::wstring>& argVector,
    int childArgsStartIndex,
    SR::ExecutionMode executionMode,
    bool utf8
) {
    fullCmdLineForCreateProcess.clear();
    specialCharactersDebugMessage.clear();
    err.clear();

    executionMode_ = executionMode;

    ParseChildCommand(
        argVector,
        childArgsStartIndex
    );

    if (!ValidateParsedChildCommand()) {
        return false;
    }

    SpecialCharsDebugItems specialCharsDebugItems;

    std::wstring commandForCmdExe =
        BuildCommandForCmdExe(
            specialCharsDebugItems
        );

    if (executionMode_ == SR::ExecutionMode::ScriptOrExe) {
        specialCharactersDebugMessage =
            BuildSpecialCharactersDebugMessage(
                specialCharsDebugItems
            );
    }

    if (utf8) {
        commandForCmdExe =
            L"chcp 65001>nul & " + commandForCmdExe;
    }

    fullCmdLineForCreateProcess =
        FileHelpers::GetComSpec() +

        L" /d /s /c \"" +
        commandForCmdExe +
        L"\"";

    return true;
}

void SRChildCmdBuilder::ParseChildCommand(
    const std::vector<std::wstring>& argVector,
    int childArgsStartIndex
) {
    childArgsStartIndexValid_ = false;
    parsedRawCommand_ = ParsedRawCommand{};
    parsedScriptOrExeCommand_ = ParsedScriptOrExeCommand{};

    if (executionMode_ == SR::ExecutionMode::RawCommand) {
        ParseRawCommand(
            argVector,
            childArgsStartIndex
        );
    } else {
        ParseScriptOrExeCommand(
            argVector,
            childArgsStartIndex
        );
    }
}

void SRChildCmdBuilder::ParseRawCommand(
    const std::vector<std::wstring>& argVector,
    int childArgsStartIndex
) {
    if (childArgsStartIndex < 0 ||
        static_cast<std::size_t>(childArgsStartIndex) >= argVector.size()) {
        return;
    }

    const std::size_t startIndex =
        static_cast<std::size_t>(childArgsStartIndex);

    childArgsStartIndexValid_ = true;
    parsedRawCommand_.command =
        argVector[startIndex];
    parsedRawCommand_.childArgCount =
        argVector.size() - startIndex;
}

void SRChildCmdBuilder::ParseScriptOrExeCommand(
    const std::vector<std::wstring>& argVector,
    int childArgsStartIndex
) {
    if (childArgsStartIndex < 0 ||
        static_cast<std::size_t>(childArgsStartIndex) >= argVector.size()) {
        return;
    }

    const std::size_t startIndex =
        static_cast<std::size_t>(childArgsStartIndex);

    childArgsStartIndexValid_ = true;

    parsedScriptOrExeCommand_.command =
        argVector[startIndex];

    parsedScriptOrExeCommand_.commandArguments.assign(
        argVector.begin() + startIndex + 1,
        argVector.end()
    );

}

bool SRChildCmdBuilder::ValidateParsedChildCommand() {
    if (executionMode_ == SR::ExecutionMode::RawCommand) {
        return ValidateParsedRawCommand();
    }

    return ValidateParsedScriptOrExeCommand();
}

bool SRChildCmdBuilder::ValidateParsedRawCommand() {
    if (!childArgsStartIndexValid_) {
        err = L"Missing value for -c";
        return false;
    }

    if (parsedRawCommand_.childArgCount != 1) {
        err =
            L"-c expects a single command string argument (use quotes if needed)";
        return false;
    }

    if (parsedRawCommand_.command.empty()) {
        err = L"-c command string must not be empty";
        return false;
    }

    return true;
}

bool SRChildCmdBuilder::ValidateParsedScriptOrExeCommand() {
    if (!childArgsStartIndexValid_ ||
        parsedScriptOrExeCommand_.command.empty()) {
        err =
            L"Missing command or executable target.\n\n" +
            HelpGenerator::Generate();
        return false;
    }

    return true;
}


std::wstring SRChildCmdBuilder::BuildCommandForCmdExe(
    SpecialCharsDebugItems& specialCharsDebugItems
) const {
    if (executionMode_ == SR::ExecutionMode::RawCommand) {
        return BuildRawCommand();
    }

    return BuildScriptOrExeCommand(
        specialCharsDebugItems
    );
}

std::wstring SRChildCmdBuilder::BuildRawCommand() const {
    return parsedRawCommand_.command;
}

std::wstring SRChildCmdBuilder::BuildScriptOrExeCommand(
    SpecialCharsDebugItems& specialCharsDebugItems
) const {
    std::wstring commandForCmdExe;

    auto appendToken =
        [&](
            const std::wstring& token,
            bool prependSpace
        ) {
            SpecialCharsDebugItem item;
            item.detected =
                DetectSpecialScriptOrExeCmdChars(token);

            if (!item.detected.empty()) {
                item.rawArg = token;
                specialCharsDebugItems.items.push_back(item);
            }

            if (prependSpace) {
                commandForCmdExe.push_back(L' ');
            }

            commandForCmdExe.append(
                QuoteIfNeeded(token)
            );
        };

    appendToken(
        parsedScriptOrExeCommand_.command,
        false
    );

    for (const auto& argument :
        parsedScriptOrExeCommand_.commandArguments) {
        appendToken(
            argument,
            true
        );
    }

    return commandForCmdExe;
}

std::wstring SRChildCmdBuilder::BuildSpecialCharactersDebugMessage(
    const SpecialCharsDebugItems& specialCharsDebugItems
) {
    if (specialCharsDebugItems.items.empty()) {
        return L"";
    }

    std::wstring message =
        L"Script-or-exe argument contains characters that may trigger cmd.exe shell operations or affect interpretation:\n\n";

    for (const auto& item : specialCharsDebugItems.items) {
        message +=
            L"  ARGUMENT=\"" + item.rawArg + L"\"\n"
            L"  CHARS=" + item.detected + L"\n\n";
    }

    message +=
        L"  EFFECTS=chaining (&, &&, ||), output piping (|), redirection (>, <), grouping ( ), escaping (^), variable expansion (%...%, !...!)\n\n"
        L"For complex command logic, use a .cmd or other script file (multi-line supported).\n"
        L"For raw command strings, use -c \"<command>\".\n"
        L"For examples and detailed usage, see documentation.";

    return message;
}

std::wstring SRChildCmdBuilder::DetectSpecialScriptOrExeCmdChars(
    const std::wstring& rawArg
) {
    std::wstring detected;

    for (const wchar_t* p = kUnsupportedScriptOrExeMetacharacters; *p; ++p) {
        if (rawArg.find(*p) != std::wstring::npos) {
            if (!detected.empty()) {
                detected += L" ";
            }

            detected.push_back(*p);
        }
    }

    return detected;
}


// Quotes only when required by whitespace.
//
// Important:
// - This is intentionally not a full cmd.exe escaping layer.
// - Shell metacharacters such as &, |, >, <, ^, %, ! keep their cmd.exe meaning.
// - Script-or-exe mode records suspicious metacharacters as diagnostics, but
//   does not reject them.
// - Complex command logic should be placed in a .cmd/script file or passed via
//   raw command mode (-c).
std::wstring SRChildCmdBuilder::QuoteIfNeeded(const std::wstring& s) {
    if (s.empty()) {
        return L"\"\"";
    }

    bool need = false;

    for (wchar_t c : s) {
        if (c == L' ' || c == L'\t') {
            need = true;
            break;
        }
    }

    if (!need) {
        return s;
    }

    std::wstring out;
    out.push_back(L'"');

    for (wchar_t c : s) {
        if (c == L'"') {
            out.append(L"\\\"");
        } else {
            out.push_back(c);
        }
    }

    out.push_back(L'"');
    return out;
}
