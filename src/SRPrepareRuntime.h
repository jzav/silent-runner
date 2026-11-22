#pragma once

#include <array>
#include <string>
#include <vector>

#include "HandleHelpers.h"
#include "SRTypes.h"
#include "SRJobTypes.h"

class SRLifecycleDiagnostics;
class SRParentEmitPolicy;
class SRFileSinkWorker;
class SRTargetLogFiles;
class SRWorkerCommonPolicy;


struct SRPrepareResult {
    bool ok = false;
    int earlyExitCode = 255;

    std::wstring comspecPath;
    std::wstring fullCmdLineForCreateProcess;
    HandleHelpers::StdHandleWriteProbeResult stdoutStdHandleProbe;
    HandleHelpers::StdHandleWriteProbeResult stderrStdHandleProbe;

    std::wstring specialCharactersDebugMessage;
    std::vector<std::wstring> unboundedReplayBufferDebugMessages;
};

void PrepareRuntime(
    SR::PrepareRuntimeConfig& config,
    SR::ExecuteChildProcessConfig& runtimeConfig,
    SR::FinalizeExecutionConfig& finalizeConfig,
    const SRWorkerCommonPolicy& workerCommonPolicy,
    SRFileSinkWorker& fileSinkWorker,
    SRTargetLogFiles& targetLogFiles,
    const SRParentEmitPolicy& parentEmitPolicy,
    SRLifecycleDiagnostics& lifecycleDiag,
    SRPrepareResult& result
);
