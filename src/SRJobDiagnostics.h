#pragma once

#include <string>

#include "SRJobTypes.h"

namespace SR {

inline std::wstring FormatJobTargetState(
    const wchar_t* label,
    JobTarget target,
    JobState state
) {
    std::wstring line;

    if (label) {
        line += label;
    }

    line += L" target=";
    line += JobTargetNameToString(target);

    line += L" state=";
    line += JobStateNameToString(state);

    return line;
}

} // namespace SR
