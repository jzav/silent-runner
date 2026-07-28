#include "SRLogGatewayDiagnostics.h"

#include "SRLogGatewayStderr.h"
#include "ProcessHelpers.h"
#include "SRTypes.h"

 // Runtime diagnostic gateway adapter.
 //
 // Runtime diagnostics delegate visible-line formatting to SRLogGatewayStderr.
 // SRLogGatewayStderr forwards events into ExecutionTimeline.



void SRLogGatewayDiagnostics::Init(
    bool debugEnabled,
    SRLogGatewayStderr* stderrRouterOrNull
) noexcept {
    debugEnabled_ = debugEnabled;
    stderrRouter_ = stderrRouterOrNull;
}

void SRLogGatewayDiagnostics::InfoLine(const std::wstring& msg) {
    if (msg.empty() || !stderrRouter_) return;
    stderrRouter_->RouteDiagnosticLineUtf16(SR::DiagnosticSeverity::Info, msg);
}

void SRLogGatewayDiagnostics::DebugLine(const std::wstring& msg) {
    if (!debugEnabled_ || msg.empty() || !stderrRouter_) return;
    stderrRouter_->RouteDiagnosticLineUtf16(SR::DiagnosticSeverity::Debug, msg);
}

void SRLogGatewayDiagnostics::ErrorLine(const std::wstring& msg) {
    if (msg.empty() || !stderrRouter_) return;
    stderrRouter_->RouteDiagnosticLineUtf16(SR::DiagnosticSeverity::Error, msg);
}

void SRLogGatewayDiagnostics::DebugProcessChain(const wchar_t* tag, DWORD pid) {
    std::wstring line;

    if (tag && *tag) {
        line += tag;
        line += L": ";
    }

    line += ProcessHelpers::GetProcessDebugInfo(pid);

    DebugLine(line);
}

void SRLogGatewayDiagnostics::DebugStdHandleProbe(
    const wchar_t* tag,
    const HandleHelpers::StdHandleWriteProbeResult& probe
) {
    std::wstring line;

    if (tag && *tag) {
        line += tag;
        line += L" ";
    }

    line += L"HANDLE=";
    if (probe.isNull) {
        line += L"NULL";
    } else if (probe.isInvalid) {
        line += L"INVALID_HANDLE_VALUE";
    } else {
        line += L"OK";
    }

    line += L" FILETYPE=";
    line += std::to_wstring(probe.fileType);

    if (probe.fileTypeGle != 0) {
        line += L" FILETYPE_GLE=";
        line += std::to_wstring(probe.fileTypeGle);
    }

    line += L" PROBABLY_WRITABLE=";
    line += probe.probablyWritable ? L"yes" : L"no";

    DebugLine(line);
}
