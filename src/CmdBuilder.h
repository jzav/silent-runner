#pragma once

#include <string>

#include "SRTypes.h"

namespace CmdBuilder {

std::wstring GetComSpec();
std::wstring QuoteIfNeeded(const std::wstring& s);
std::wstring BuildCmdExeCommandLine(const SR::Options& opt);

} // namespace CmdBuilder
