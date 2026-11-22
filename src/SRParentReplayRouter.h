#pragma once

#include <vector>
#include "SRParentEmitPolicyTypes.h"
#include "SRTypes.h"

class ExecutionTimeline;
class SRLifecycleDiagnostics;
class SRReplayJsonlToParent;
class SRReplayTxtToParent;
struct TargetLogPathBinding;
namespace SR {
struct ParentReplayParameters;
struct ParentReplayParameterSet;
}

class SRParentReplayRouter {
public:
    SRParentReplayRouter() = default;

    SRParentReplayRouter(const SRParentReplayRouter&) = delete;
    SRParentReplayRouter& operator=(const SRParentReplayRouter&) = delete;

    bool Init(
        SRLifecycleDiagnostics& lifecycleDiag,
        const SR::ParentReplaySourceLayout& replaySourceLayout
    ) noexcept;


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
        const std::vector<TargetLogPathBinding>& replayLogPaths
    );

private:
    bool BuildReplayParameters_(
        const SR::ParentReplayPolicySnapshot& policySnapshot,
        bool executionSucceeded,
        const std::vector<TargetLogPathBinding>& replayLogPaths,
        SR::ParentReplayParameters& parameters
    ) const noexcept;
    bool BuildStdoutReplayParameters_(
        const SR::ParentReplayPolicySnapshot& policySnapshot,
        bool executionSucceeded,
        const std::vector<TargetLogPathBinding>& replayLogPaths,
        SR::ParentReplayParameterSet& parameters
    ) const noexcept;
    bool BuildStderrReplayParameters_(
        const SR::ParentReplayPolicySnapshot& policySnapshot,
        bool executionSucceeded,
        const std::vector<TargetLogPathBinding>& replayLogPaths,
        SR::ParentReplayParameterSet& parameters
    ) const noexcept;

    void SelectPersistentReplaySource_(
        SR::JobTarget parentTarget,
        const std::vector<TargetLogPathBinding>& replayLogPaths,

        SR::ParentReplayParameterSet& parameters
    ) const noexcept;
    bool ReplayTimeline_(
        const SR::ParentReplayParameters& parameters
    );

    SR::ParentReplaySourceLayout replaySourceLayout_{};
    SRLifecycleDiagnostics* lifecycleDiag_ = nullptr; // non-owning
    ExecutionTimeline* executionTimeline_ = nullptr; // non-owning
    SRReplayTxtToParent* replayTxtToParent_ = nullptr; // non-owning
    SRReplayJsonlToParent* replayJsonlToParent_ = nullptr; // non-owning
};
