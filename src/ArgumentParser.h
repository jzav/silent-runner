#pragma once

#include <string>

#include "SRTypes.h"

namespace ArgumentParser {

// Build usage/help text.
std::wstring BuildUsageText();

// Returns true on success; on failure returns false and sets err.
bool ParseArgs(int argc, wchar_t** argv, SR::Options& opt, std::wstring& err);

} // namespace ArgumentParser
