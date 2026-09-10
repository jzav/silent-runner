#pragma once

#include <string>
#include "SRTypes.h"
namespace SR {
struct FinalizeExecutionConfig;
}


struct SRWorkers;
struct SRLogFiles;
struct SRRuntimeResult;
class SRLifecycleDiagnostics;
class ExecutionTimeline;
class SRParentEmitPolicy;


int FinalizeExecution(
    const SR::FinalizeExecutionConfig& config,

    SRWorkers& workers,

    SRLogFiles& logFiles,
    SRParentEmitPolicy& parentEmitPolicy,
    const std::string& parsingToken,

    int exitCode,
    SRLifecycleDiagnostics& lifecycleDiag,
    const SRRuntimeResult* runtimeResultOrNull,
    ExecutionTimeline* executionTimelineOrNull
);
