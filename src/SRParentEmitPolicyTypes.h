#pragma once

#include <array>
#include <cstddef>
#include "SRJobTypes.h"
#include "SRTypes.h"

namespace SR {

#define SR_PARENT_REPLAY_SOURCE_TABLE(X) \
    /* Columns: parentTarget, sourceTarget, priority (lower value wins) */ \
    X(StdoutParent, StdoutJsonl, 1u) \
    X(StdoutParent, StdoutTxt, 2u) \
    X(StderrSrAndChildParent, StderrSrAndChildJsonl, 1u) \
    X(StderrSrAndChildParent, StderrSrAndChildTxt, 2u) \
    X(StderrChildParent, StderrChildJsonl, 1u) \
    X(StderrChildParent, StderrChildTxt, 2u) \
    X(StderrSrParent, StderrSrJsonl, 1u) \
    X(StderrSrParent, StderrSrTxt, 2u) \
    X(StderrSrAndChildInclStdoutParent, StderrSrAndChildInclStdoutJsonl, 1u) \
    X(StderrSrAndChildInclStdoutParent, StderrSrAndChildInclStdoutTxt, 2u) \
    X(StdoutParentRaw, StdoutTxtRaw, 1u) \
    X(StderrChildParentRaw, StderrChildTxtRaw, 1u)
struct ParentReplaySourceLayoutEntry {
    JobTarget parentTarget{};
    JobTarget sourceTarget{};
    unsigned priority = 0;
};
#define SR_X_COUNT_PARENT_REPLAY_SOURCE(parentTarget, sourceTarget, priority) + 1
static constexpr std::size_t kParentReplaySourceCount =
    0 SR_PARENT_REPLAY_SOURCE_TABLE(SR_X_COUNT_PARENT_REPLAY_SOURCE);
#undef SR_X_COUNT_PARENT_REPLAY_SOURCE
struct ParentReplaySourceLayout {
    std::array<
        ParentReplaySourceLayoutEntry,
        kParentReplaySourceCount
    > entries{};
};
static constexpr ParentReplaySourceLayout kParentReplaySourceLayout ={{
#define SR_X_PARENT_REPLAY_SOURCE_ENTRY(parentTarget, sourceTarget, priority) \
    ParentReplaySourceLayoutEntry{ \
        JobTarget::parentTarget, \
        JobTarget::sourceTarget, \
        priority \
    },
    SR_PARENT_REPLAY_SOURCE_TABLE(SR_X_PARENT_REPLAY_SOURCE_ENTRY)
#undef SR_X_PARENT_REPLAY_SOURCE_ENTRY
}};

struct SRParentEmitPolicyConfig {
    JobTarget stdoutParentTarget = JobTarget::StdoutParent;
    JobTarget stderrParentTarget = JobTarget::StderrSrAndChildParent;
    EmitMode stdoutEmitMode = EmitMode::Stream;
    EmitMode stderrEmitMode = EmitMode::Stream;
};
struct ParentReplayPolicySnapshot {
    JobTarget stdoutParentTarget = JobTarget::StdoutParent;
    JobTarget stderrParentTarget = JobTarget::StderrSrAndChildParent;
    EmitMode stdoutEmitMode = EmitMode::Never;
    EmitMode stderrEmitMode = EmitMode::Never;
    bool needsStdoutReplayBuffer = false;
    bool needsStderrReplayBuffer = false;
};

} // namespace SR
