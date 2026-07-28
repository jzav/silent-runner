#pragma once

#include <string>
#include "SRTypes.h"



struct SRPreparedRuntime;
struct SRRuntimeResult;
class SRLifecycleDiagnostics;
class ExecutionTimeline;
class SRParentEmitPolicy;


int FinalizeExecution(
    const SR::Options& opt,
    SRPreparedRuntime& prepared,
    const SR::LogPaths& logPaths,
    SRParentEmitPolicy& parentEmitPolicy,
    const std::string& parsingToken,

    int exitCode,
    SRLifecycleDiagnostics& lifecycleDiag,
    const SRRuntimeResult* runtimeResultOrNull,
    ExecutionTimeline* executionTimelineOrNull
);
