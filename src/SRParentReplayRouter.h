#pragma once

#include "SRParentReplayTypes.h"
#include "SRTypes.h"

class ExecutionTimeline;
class SRLifecycleDiagnostics;
class SRReplayJsonlToParent;
class SRReplayTxtToParent;

class SRParentReplayRouter {
public:
    SRParentReplayRouter() = default;

    SRParentReplayRouter(const SRParentReplayRouter&) = delete;
    SRParentReplayRouter& operator=(const SRParentReplayRouter&) = delete;

    bool Init(SRLifecycleDiagnostics& lifecycleDiag) noexcept;


    void SetExecutionTimeline(
        ExecutionTimeline& executionTimeline
    ) noexcept;

    void SetReplayTxtToParent(
        SRReplayTxtToParent& replayTxtToParent
    ) noexcept;

    void SetReplayJsonlToParent(
        SRReplayJsonlToParent& replayJsonlToParent
    ) noexcept;

    bool ReplayToParent(
        const SR::ParentReplayPolicySnapshot& policySnapshot,
        bool executionSucceeded,
        const SR::LogPaths& logPaths
    );

private:
    bool BuildReplayParameters_(
        const SR::ParentReplayPolicySnapshot& policySnapshot,
        bool executionSucceeded,
        const SR::LogPaths& logPaths,
        SR::ParentReplayParameters& parameters
    ) const noexcept;

    bool BuildStdoutReplayParameters_(
        const SR::ParentReplayPolicySnapshot& policySnapshot,
        bool executionSucceeded,
        const SR::LogPathSet& logPaths,
        SR::ParentReplayParameterSet& parameters
    ) const noexcept;

    bool BuildStderrReplayParameters_(
        const SR::ParentReplayPolicySnapshot& policySnapshot,
        bool executionSucceeded,
        const SR::LogPathSet& logPaths,
        SR::ParentReplayParameterSet& parameters
    ) const noexcept;

    bool ReplayTimeline_(
        const SR::ParentReplayParameters& parameters
    );

    SRLifecycleDiagnostics* lifecycleDiag_ = nullptr; // non-owning
    ExecutionTimeline* executionTimeline_ = nullptr; // non-owning
    SRReplayTxtToParent* replayTxtToParent_ = nullptr; // non-owning
    SRReplayJsonlToParent* replayJsonlToParent_ = nullptr; // non-owning
};
