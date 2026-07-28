// SRUnobtainableResults.h
#pragma once

#include <mutex>
#include <vector>

#include "SRPendingJobTypes.h"
#include "SRTimelineIdentity.h"

namespace SR {


//
// Tracks job targets whose worker became permanently unavailable
// before producing a final JobResult.
//
// The goal is not to recover lost worker results.
// The goal is to prevent permanent TimelineEntry retention caused by
// workers that can no longer produce them.
//
// Primary purpose:
//  - prevent unbounded Timeline buffer growth,
//  - allow fallback pruning of TimelineEntries blocked only by
//    unavailable workers.
//
// UnobtainableResults are auxiliary metadata consumed only by
// ExecutionTimeline::PruneUnobtainableLocked().
//
struct UnobtainableResult {
    TimelineEntryKey key{};
    JobTarget target = JobTarget::StdoutParent;
};

struct ResolvedUnobtainableResult {
    UnobtainableResult result;
    TimelineEntryLocation location;
    TimelineEntryKeyLocationPairResolveStatus resolveStatus =
        TimelineEntryKeyLocationPairResolveStatus::NotFound;
};

using UnobtainableResultItems = std::vector<UnobtainableResult>;
using ResolvedUnobtainableResultItems =
    std::vector<ResolvedUnobtainableResult>;

class UnobtainableResults {
public:
    UnobtainableResults() = default;

    UnobtainableResults(const UnobtainableResults&) = delete;
    UnobtainableResults& operator=(const UnobtainableResults&) = delete;

    void Add(const UnobtainableResult& result);
    UnobtainableResultItems Retrieve() const;
    void RemoveNotFound(
        const ResolvedUnobtainableResultItems& resolvedResults
    );

private:
    mutable std::mutex mutex_;
    UnobtainableResultItems results_;
};

} // namespace SR
