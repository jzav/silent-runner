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

struct ParentReplayParameters {
    ParentReplayParameterSet stdoutParentReplayParameters;
    ParentReplayParameterSet stderrParentReplayParameters;
};

} // namespace SR
