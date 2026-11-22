#pragma once

#include <optional>
#include <string>
#include "SRTypes.h"
#include "SRJobTypes.h"
namespace SR {
struct FinalizeExecutionConfig;
}


struct SRWorkers;
class SRTargetLogFiles;
struct SRRuntimeResult;
class SRLifecycleDiagnostics;
class ExecutionTimeline;
class SRParentEmitPolicy;


// Applies the selected phase result to delayed replay, log finalization,
// worker shutdown, and detached hook launch. It may change the final exit
// code but does not supervise or terminate the child process tree.
int FinalizeExecution(
    const SR::FinalizeExecutionConfig& config,

    SRWorkers& workers,

    SRTargetLogFiles& logFiles,
    const SR::WorkerTargetLayout<SR::JobTargetWorker::SRFileSinkWorker>& fileSinkTargetLayout,
    SRParentEmitPolicy& parentEmitPolicy,
    const std::string& parsingToken,

    int exitCode,
    SRLifecycleDiagnostics& lifecycleDiag,
    const SRRuntimeResult* runtimeResultOrNull,
    ExecutionTimeline* executionTimelineOrNull,
    std::optional<int> prepareExitCode,
    std::optional<int> runtimeExitCode
);
