// ============================================================================
// SRRuntimeStopReason.h
// ----------------------------------------------------------------------------
// Internal completion and abort reason model for SRRuntime.
//
// Scope:
//   - INTERNAL USE ONLY (SRRuntime layer)
//   - Not part of public SR API
//
// Target: C++17
// ============================================================================

#pragma once

#include <windows.h>

namespace SRRuntimeStopReason {

// ----------------------------------------------------------------------------
// StopReason
// ----------------------------------------------------------------------------

enum class StopReason {
    None = 0,
    NormalExit,
    RuntimeSetupFailed,
    ResumeThreadFailed,
    Timeout,
    BufferLimit,
    RuntimeFailure,
    UnhandledException
};

// ----------------------------------------------------------------------------
// Mapping helpers
// ----------------------------------------------------------------------------

const wchar_t* ToDiagnosticLabel(StopReason reason) noexcept;
DWORD ToChildAbortExitCode(StopReason reason) noexcept;
int ToSRExitCode(StopReason reason) noexcept;

} // namespace SRRuntimeStopReason
