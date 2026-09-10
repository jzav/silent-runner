#pragma once
#include <cstddef>
#include <string>
#include <vector>
#include "SRTypes.h"

class SRChildCmdBuilder {
public:
    std::wstring fullCmdLineForCreateProcess;
    std::wstring specialCharactersDebugMessage;
    std::wstring err;

    bool Build(
        const std::vector<std::wstring>& argVector,
        int childArgsStartIndex,
        SR::ExecutionMode executionMode,
        bool utf8
    );

private:
    struct ParsedRawCommand {
        std::wstring command;
        std::size_t childArgCount = 0;
    };

    struct ParsedScriptOrExeCommand {
        std::wstring command;
        std::vector<std::wstring> commandArguments;
    };


    struct SpecialCharsDebugItem {
        std::wstring rawArg;
        std::wstring detected;
    };

    struct SpecialCharsDebugItems {
        std::vector<SpecialCharsDebugItem> items;
    };

    void ParseChildCommand(
        const std::vector<std::wstring>& argVector,
        int childArgsStartIndex
    );

    void ParseRawCommand(
        const std::vector<std::wstring>& argVector,
        int childArgsStartIndex
    );

    void ParseScriptOrExeCommand(
        const std::vector<std::wstring>& argVector,
        int childArgsStartIndex
    );

    bool ValidateParsedChildCommand();
    bool ValidateParsedRawCommand();
    bool ValidateParsedScriptOrExeCommand();

    std::wstring BuildCommandForCmdExe(
        SpecialCharsDebugItems& specialCharsDebugItems
    ) const;

    std::wstring BuildRawCommand() const;

    std::wstring BuildScriptOrExeCommand(
        SpecialCharsDebugItems& specialCharsDebugItems
    ) const;

    static std::wstring BuildSpecialCharactersDebugMessage(
        const SpecialCharsDebugItems& specialCharsDebugItems
    );

    static std::wstring DetectSpecialScriptOrExeCmdChars(
        const std::wstring& rawArg
    );

    static std::wstring QuoteIfNeeded(const std::wstring& value);

    SR::ExecutionMode executionMode_ =
        SR::ExecutionMode::ScriptOrExe;

    bool childArgsStartIndexValid_ = false;

    ParsedRawCommand parsedRawCommand_{};
    ParsedScriptOrExeCommand parsedScriptOrExeCommand_{};
};
