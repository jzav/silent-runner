// ============================================================================
// SRRuntimeStopReason.h
// ----------------------------------------------------------------------------
// Internal termination reason model for SRRuntime.
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
    WaitFailed,
    ResumeThreadFailed,
    Timeout,
    BufferLimit,
    UnhandledException
};

// ----------------------------------------------------------------------------
// Mapping helpers
// ----------------------------------------------------------------------------

const wchar_t* ToReaderJoinDiagnosticLabel(StopReason reason) noexcept;
DWORD ToChildTerminateExitCode(StopReason reason) noexcept;
int ToSRExitCode(StopReason reason) noexcept;
bool ShouldTreatAsSRFailure(StopReason reason, int exitCode) noexcept;
StopReason FromWaitResult(DWORD waitResult) noexcept;

} // namespace SRRuntimeStopReason
