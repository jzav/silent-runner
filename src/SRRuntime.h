#pragma once

#include <string>
#include <memory>
#include <vector>


#include "SRTypes.h"
#include "SRJobTypes.h"
#include "SRRuntimeStopReason.h"

class SRTimeLimiter;
class SRBufferLimiter;
class SRRuntimeCoordinator;
class ExecutionTimeline;
class SRLifecycleDiagnostics;
struct TargetLogPathBinding;
namespace HandleHelpers { struct StdHandleWriteProbeResult; }

class SRParentEmitPolicy;
class SRWorkerCommonPolicy;

// Stores the Runtime outcome. SRMain owns the instance and passes it by reference.
struct SRRuntimeResult {
    int exitCode = 255;
    SRRuntimeStopReason::StopReason stopReason = SRRuntimeStopReason::StopReason::None;
    // True when RuntimeFailure triggered an abort action (not a termination guarantee).
    bool abortedOnRuntimeFailure = false;
    bool childStarted = false;
    bool fatal = false;
};

// SRRuntime executes child creation, process-tree termination, and reader/watcher
// cleanup. SRRuntimeCoordinator decides policy-driven completion/abort actions.
// Final replay, log retention, and hook launch belong to the finalization stage.
void ExecuteChildProcess(

    const SR::ExecuteChildProcessConfig& config,
    const SR::FileSinkWorkerTargetLayout& fileSinkWorkerTargetLayout,
    const std::vector<TargetLogPathBinding>& runningLogPaths,
    const std::wstring& comspecPath,
    const std::wstring& fullCmdLineForCreateProcess,
    const HandleHelpers::StdHandleWriteProbeResult& stdoutStdHandleProbe,
    const HandleHelpers::StdHandleWriteProbeResult& stderrStdHandleProbe,
    const std::wstring& specialCharactersDebugMessage,
    const std::vector<std::wstring>& unboundedReplayBufferDebugMessages,
    SRLifecycleDiagnostics& lifecycleDiag,
    std::shared_ptr<ExecutionTimeline> executionTimeline,
    const SRParentEmitPolicy& parentEmitPolicy,
    const SRWorkerCommonPolicy& workerCommonPolicy,
    SRBufferLimiter* bufferLimitPtr,
    SRRuntimeCoordinator& coordinator,
    SRTimeLimiter& timeLimiter,
    SRRuntimeResult& result
);
