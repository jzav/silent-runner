#include "SRRuntimeStopReason.h"

namespace SRRuntimeStopReason {

const wchar_t* ToReaderJoinDiagnosticLabel(StopReason reason) noexcept {
    switch (reason) {
        case StopReason::NormalExit:            return L"NORMAL_EXIT";
        case StopReason::WaitFailed:            return L"WAIT_FAILED";
        case StopReason::ResumeThreadFailed:    return L"RESUME_THREAD_FAILED";
        case StopReason::Timeout:               return L"TIMEOUT";
        case StopReason::BufferLimit:           return L"BUFFER_LIMIT";
        case StopReason::UnhandledException:    return L"UNHANDLED_EXCEPTION";
        case StopReason::None:
        default:                                return L"UNKNOWN";
    }
}

DWORD ToChildTerminateExitCode(StopReason reason) noexcept {
    switch (reason) {
        case StopReason::Timeout:
            return 124;

        case StopReason::BufferLimit:
        case StopReason::WaitFailed:
        case StopReason::ResumeThreadFailed:
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

        case StopReason::WaitFailed:
        case StopReason::ResumeThreadFailed:
        case StopReason::UnhandledException:
            return 255;

        case StopReason::NormalExit:
        case StopReason::None:
        default:
            return 0;
    }
}

bool ShouldTreatAsSRFailure(StopReason reason, int exitCode) noexcept {
    switch (reason) {
        case StopReason::NormalExit:
            return exitCode != 0;

        case StopReason::Timeout:
        case StopReason::BufferLimit:
        case StopReason::WaitFailed:
        case StopReason::ResumeThreadFailed:
        case StopReason::UnhandledException:
            return true;

        case StopReason::None:
        default:
            return false;
    }
}

StopReason FromWaitResult(DWORD waitResult) noexcept {
    if (waitResult == WAIT_FAILED) {
        return StopReason::WaitFailed;
    }

    if (waitResult == WAIT_TIMEOUT) {
        return StopReason::Timeout;
    }

    if (waitResult == WAIT_OBJECT_0) {
        return StopReason::NormalExit;
    }

    if (waitResult == WAIT_OBJECT_0 + 1) {
        return StopReason::BufferLimit;
    }

    return StopReason::WaitFailed;
}

} // namespace SRRuntimeStopReason
