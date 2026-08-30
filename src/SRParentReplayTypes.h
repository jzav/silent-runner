#pragma once

#include <string>

#include "SRJobTypes.h"

namespace SR {

enum class ParentReplaySource {
    None,
    Timeline,
    Txt,
    Jsonl
};


struct ParentReplayParameterSet {
    ParentReplaySource source = ParentReplaySource::None;
    JobTarget target = JobTarget::StdoutParent;
    std::wstring path;
};

struct ParentReplayPolicySnapshot {
    EmitMode stdoutEmitMode = EmitMode::Never;
    EmitMode stderrEmitMode = EmitMode::Never;
    StderrEmitSource stderrEmitSource = StderrEmitSource::SrAndChild;
    bool needsStdoutReplayBuffer = false;
    bool needsStderrReplayBuffer = false;
};

struct ParentReplayParameters {
    ParentReplayParameterSet stdoutParentReplayParameters;
    ParentReplayParameterSet stderrParentReplayParameters;
};

} // namespace SR
