#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string>

namespace ErrorHelpers {

// Convert Win32 error code to a readable message (best effort).
std::wstring Win32ErrorToString(DWORD gle);

// "GLE=... MSG=..."
std::wstring FormatGle(DWORD gle);

} // namespace ErrorHelpers
