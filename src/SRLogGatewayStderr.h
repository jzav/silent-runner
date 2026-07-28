// SRLogGatewayStderr.h
// -------------------
 // Responsibility:
 // - Serialize and route logical STDERR views:
 //   - mixed stderr: child stderr bytes plus SilentRunner diagnostics
 //   - child stderr: only child stderr bytes
 //   - SilentRunner stderr: only SilentRunner diagnostic lines
 // - Use one active parent/replay view selected by StderrEmitSource.

//
// Non-responsibility:
// - Formatting [SILENTRUNNER-.] (belongs to SRDiagnostics)
// - "ERRORS" immediate path (belongs to SRDiagnostics::FatalErrorLine)
// - Reading child pipes (belongs to ChildStdReader)

#pragma once

#include <cstddef>   // size_t
#include <memory>    // std::unique_ptr
#include <mutex>     // std::mutex
#include <string>    // std::wstring
#include <vector>    // std::vector

#include "SRTypes.h"
#include "SRExecutionTimeline.h"

class SRBufferLimiter;
class SRParentEmitPolicy;

class SRLogGatewayStderr {
public:
    SRLogGatewayStderr() = default;
    SRLogGatewayStderr(const SRLogGatewayStderr&) = delete;
    SRLogGatewayStderr& operator=(const SRLogGatewayStderr&) = delete;

    // Init routing targets.
    // NOTE: Pointers are borrowed (owned by SRRuntime stack / orchestration).
    void Init(
        SR::EmitMode emitMode,
        SR::StderrEmitSource emitSource,
        const SRParentEmitPolicy* parentEmitPolicyOrNull,
        SRBufferLimiter* bufferLimitOrNull,
        ExecutionTimeline* executionTimelineOrNull
    ) noexcept;





    // Main API for child STDERR chunks (bytes).
    // This is the one ChildStdReader should call for stderr routing.
    void RouteChildBytes(
        const char* p,
        size_t n
    );

    void RouteDiagnosticLineUtf16(
        SR::DiagnosticSeverity severity,
        const std::wstring& msg
    );



private:
    void EnsureMutex_();

    bool ShouldRouteToActiveStderrView_(SR::StderrEmitSource source) const noexcept;

    void RouteBytesLocked_(
        SR::StderrEmitSource source,
        const char* p,
        size_t n,
        const SR::DiagnosticSeverity* runtimeDiagSeverityOrNull = nullptr,
        const std::wstring* runtimeDiagMessageOrNull = nullptr
    );


private:
    // keep mutex out-of-line (8 bytes pointer instead of full mutex object).
    std::unique_ptr<std::mutex> mutex_;

    SR::EmitMode emitMode_ = SR::EmitMode::Stream;
    SR::StderrEmitSource emitSource_ = SR::StderrEmitSource::Mixed;
    const SRParentEmitPolicy* parentEmitPolicy_ = nullptr;

    SRBufferLimiter* bufferLimit_ = nullptr;
    ExecutionTimeline* executionTimeline_ = nullptr;


};
