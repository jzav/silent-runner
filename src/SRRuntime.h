#pragma once

#include <string>
#include <memory>
#include <vector>


#include "SRTypes.h"
#include "HandleHelpers.h"
#include "SRExecutionTimeline.h"
#include "SRLifecycleDiagnostics.h"
namespace SR {
struct RunHiddenWithRoutingConfig;
}

class SRBufferLimiter;

class SRParentEmitPolicy;
class SRWorkerCommonPolicy;

struct SRRuntimeResult {
    int exitCode = 255;
    SRRuntimeStopReason::StopReason stopReason = SRRuntimeStopReason::StopReason::None;
    bool childStarted = false;
    bool fatal = false;
};

SRRuntimeResult RunHiddenWithRouting(
    const SR::RunHiddenWithRoutingConfig& config,
    const SR::LogPaths& logPaths,
    const std::wstring& fullCmdLineForCreateProcess,
    const HandleHelpers::StdHandleWriteProbeResult& stdoutStdHandleProbe,
    const HandleHelpers::StdHandleWriteProbeResult& stderrStdHandleProbe,
    const std::wstring& specialCharactersDebugMessage,
    const std::vector<std::wstring>& unboundedReplayBufferDebugMessages,
    SRLifecycleDiagnostics& lifecycleDiag,
    std::shared_ptr<ExecutionTimeline> executionTimeline,
    const SRParentEmitPolicy& parentEmitPolicy,
    const SRWorkerCommonPolicy& workerCommonPolicy,
    SRBufferLimiter* bufferLimitPtr
);
