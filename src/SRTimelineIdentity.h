// SRTimelineIdentity.h
#pragma once

#include <cstddef>
#include <vector>

#include "SRTypes.h"

class PhaseTimeline;

namespace SR {

struct TimelineEntryKey {
    LifecyclePhase phase = LifecyclePhase::Prepare;
    uint32_t phaseOrderNo = 0;
    uint64_t eventOrderNo = 0;
};

struct TimelineEntryLocation {
    ::PhaseTimeline* phaseTimeline = nullptr;
    std::size_t index = 0;
};

enum class TimelineEntryKeyLocationPairResolveStatus {
    Resolved,
    NotFound
};

struct TimelineEntryKeyLocationPair {
    TimelineEntryKey key;
    TimelineEntryLocation location;
    TimelineEntryKeyLocationPairResolveStatus resolveStatus =
        TimelineEntryKeyLocationPairResolveStatus::NotFound;
};

using TimelineEntryKeyLocationPairs =
    std::vector<TimelineEntryKeyLocationPair>;

struct GetAllDelayedFilter {
    bool stdoutParent = false;
    bool stderrSrAndChildParent = false;
    bool stderrChildParent = false;
    bool stderrSrParent = false;
    bool stderrSrAndChildInclStdoutParent = false;

};


using JobQueueItem = TimelineEntryKeyLocationPair;
using JobQueueItems = std::vector<JobQueueItem>;

} // namespace SR
