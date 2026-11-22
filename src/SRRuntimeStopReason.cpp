#include "SRRuntimeStopReason.h"

namespace SRRuntimeStopReason {

const wchar_t* ToDiagnosticLabel(StopReason reason) noexcept {
    switch (reason) {
        case StopReason::NormalExit:            return L"NORMAL_EXIT";
        case StopReason::RuntimeSetupFailed:    return L"RUNTIME_SETUP_FAILED";
        case StopReason::ResumeThreadFailed:    return L"RESUME_THREAD_FAILED";
        case StopReason::Timeout:               return L"TIMEOUT";
        case StopReason::BufferLimit:           return L"BUFFER_LIMIT";
        case StopReason::RuntimeFailure:        return L"RUNTIME_FAILURE";
        case StopReason::UnhandledException:    return L"UNHANDLED_EXCEPTION";
        case StopReason::None:
        default:                                return L"UNKNOWN";
    }
}

DWORD ToChildAbortExitCode(StopReason reason) noexcept {
    switch (reason) {
        case StopReason::Timeout:
            return 124;

        case StopReason::BufferLimit:
        case StopReason::RuntimeSetupFailed:
        case StopReason::ResumeThreadFailed:
        case StopReason::RuntimeFailure:
        case StopReason::UnhandledException:
            return 1;

        case StopReason::NormalExit:
        case StopReason::None:
        default:
            return 0;
    }
}

int ToSRExitCode(StopReason reason) noexcept {
    switch (reason) {
        case StopReason::Timeout:
            return 124;

        case StopReason::BufferLimit:
            return 125;

        case StopReason::RuntimeSetupFailed:
        case StopReason::ResumeThreadFailed:
        case StopReason::RuntimeFailure:
        case StopReason::UnhandledException:
            return 255;

        case StopReason::NormalExit:
        case StopReason::None:
        default:
            return 0;
    }
}

} // namespace SRRuntimeStopReason
