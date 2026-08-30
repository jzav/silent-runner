#pragma once

#include <string>

#include "SRTypes.h"
#include "SRExecutionTimeline.h"



class SRLifecycleDiagnostics {
public:
    SRLifecycleDiagnostics() = default;
    SRLifecycleDiagnostics(const SRLifecycleDiagnostics&) = delete;
    SRLifecycleDiagnostics& operator=(const SRLifecycleDiagnostics&) = delete;

    bool Init(
        SR::EmitMode emitMode,
        ExecutionTimeline* executionTimelineOrNull
    ) noexcept;




    void SetDebugEnabled(bool value) noexcept;
    void SetVerboseEnabled(bool value) noexcept;
    void SetEmitMode(SR::EmitMode value) noexcept;
    void SetStderrEmitSource(SR::StderrEmitSource value) noexcept;
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
    SR::EmitMode EmitMode() const noexcept { return emitMode_; }







private:


    void EmitLineWithSeverity_(
        SR::DiagnosticSeverity severity,
        const std::wstring& msg
    );

private:
    bool debugEnabled_ = false;
    bool verboseEnabled_ = false;
    SR::EmitMode emitMode_ = SR::EmitMode::Stream;
    SR::StderrEmitSource stderrEmitSource_ = SR::StderrEmitSource::SrAndChild;
    ExecutionTimeline* executionTimeline_ = nullptr;
    std::wstring probeLogPath_;






};
