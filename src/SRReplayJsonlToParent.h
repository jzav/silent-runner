#pragma once

#include "SRParentReplayTypes.h"

class SRJobsExchange;
class SRLifecycleDiagnostics;

class SRReplayJsonlToParent {
public:
    SRReplayJsonlToParent() = default;

    SRReplayJsonlToParent(const SRReplayJsonlToParent&) = delete;
    SRReplayJsonlToParent& operator=(const SRReplayJsonlToParent&) = delete;

    bool Init(SRLifecycleDiagnostics* diagnostics) noexcept;
    void SetJobsExchange(SRJobsExchange& jobsExchange) noexcept;

    bool ReplayToParent(
        const SR::ParentReplayParameters& parameters
    );

private:
    bool ReplayByParameterSet_(
        const SR::ParentReplayParameterSet& parameters
    );

    SRJobsExchange* jobsExchange_ = nullptr; // non-owning
    SRLifecycleDiagnostics* diagnostics_ = nullptr; // non-owning
};
