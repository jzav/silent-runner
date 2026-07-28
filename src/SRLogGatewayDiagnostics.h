#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <atomic>
#include <string>
#include "HandleHelpers.h"

class SRLogGatewayStderr;

class SRLogGatewayDiagnostics {
public:
    SRLogGatewayDiagnostics() = default;
    SRLogGatewayDiagnostics(const SRLogGatewayDiagnostics&) = delete;
    SRLogGatewayDiagnostics& operator=(const SRLogGatewayDiagnostics&) = delete;

    void Init(
        bool debugEnabled,
        SRLogGatewayStderr* stderrRouterOrNull
    ) noexcept;

    void InfoLine(const std::wstring& msg);
    void DebugLine(const std::wstring& msg);
    void ErrorLine(const std::wstring& msg);
    void DebugProcessChain(const wchar_t* tag, DWORD pid);
    void DebugStdHandleProbe(
        const wchar_t* tag,
        const HandleHelpers::StdHandleWriteProbeResult& probe
    );
    bool IsDebugEnabled() const noexcept { return debugEnabled_; }

private:
    bool debugEnabled_ = false;
    SRLogGatewayStderr* stderrRouter_ = nullptr;
};
