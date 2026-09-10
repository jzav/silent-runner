#pragma once

#include <string>

#include "SRTypes.h"
#include "SRExecutionTimeline.h"

namespace SR {
struct SRLifecycleDiagnosticsConfig;
}

class SRBufferLimiter;
class SRParentEmitPolicy;




class SRLifecycleDiagnostics {
public:
    SRLifecycleDiagnostics() = default;
    SRLifecycleDiagnostics(const SRLifecycleDiagnostics&) = delete;
    SRLifecycleDiagnostics& operator=(const SRLifecycleDiagnostics&) = delete;

    bool Init(
        const SR::SRLifecycleDiagnosticsConfig& config,
        const SRParentEmitPolicy& parentEmitPolicy,
        ExecutionTimeline* executionTimelineOrNull
    ) noexcept;




    void SetBufferLimiter(SRBufferLimiter* bufferLimitOrNull) noexcept;


    bool TrySetProbeLogPath(const std::wstring& value) noexcept;
    const std::wstring& ProbeLogPath() const noexcept { return probeLogPath_; }




    void InfoLine(const std::wstring& msg);
    void DebugLine(const std::wstring& msg);
    void VerboseLine(const std::wstring& msg);
    void ErrorLine(const std::wstring& msg);
    void FatalErrorLine(const std::wstring& msg);
    void ProbeLine(const std::wstring& msg);

    static void BestEffortEmitFormattedToParentStderr(
        const std::wstring& timestampUtc,
        SR::DiagnosticSeverity severity,
        SR::LifecyclePhase phase,
        const std::wstring& msg
    ) noexcept;

    static void LastResortEmitFormattedToParentStderr(
        const std::wstring& timestampUtc,
        SR::DiagnosticSeverity severity,
        SR::LifecyclePhase phase,
        const std::wstring& msg
    ) noexcept;

    bool IsDebugEnabled() const noexcept { return debugEnabled_; }







private:
    void EmitLineWithSeverity_(
        SR::DiagnosticSeverity severity,
        const std::wstring& msg
    );

private:
    bool debugEnabled_ = false;
    bool verboseEnabled_ = false;
    SRBufferLimiter* bufferLimit_ = nullptr;
    const SRParentEmitPolicy* parentEmitPolicy_ = nullptr;


    ExecutionTimeline* executionTimeline_ = nullptr;
    std::wstring probeLogPath_;






};
