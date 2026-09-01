#pragma once

#include <string>
#include <memory>


#include "SRTypes.h"
#include "HandleHelpers.h"
#include "SRExecutionTimeline.h"
#include "SRLifecycleDiagnostics.h"

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
    const std::wstring& fullCmdLineForCreateProcess,
    const std::wstring& executionId,
    const std::wstring& generatedSuffix,
    SR::IdSuffixMode effectiveIdSuffixMode,
    bool useDefaultSuffixMode,
    SRLifecycleDiagnostics& lifecycleDiag,
    std::shared_ptr<ExecutionTimeline> executionTimeline,
    const SRParentEmitPolicy& parentEmitPolicy,
    const SRWorkerCommonPolicy& workerCommonPolicy,
    SRBufferLimiter* bufferLimitPtr,
    const SR::Options& opt,
    const SR::LogPaths& logPaths,
    const HandleHelpers::StdHandleWriteProbeResult& stdoutStdHandleProbe,
    const HandleHelpers::StdHandleWriteProbeResult& stderrStdHandleProbe


);
