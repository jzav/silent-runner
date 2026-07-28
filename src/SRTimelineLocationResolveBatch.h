#pragma once

#include <cstddef>
#include <variant>
#include <vector>

#include "SRJobTypes.h"
#include "SRUnobtainableResults.h"
#include "SRTimelineIdentity.h"

namespace SR {

struct CompletedResultsGroup {
    TimelineEntryKey key;
    TimelineEntryLocation location;
    TimelineEntryKeyLocationPairResolveStatus resolveStatus =
        TimelineEntryKeyLocationPairResolveStatus::NotFound;
    JobResults results;
};
using CompletedResultsGroups = std::vector<CompletedResultsGroup>;

class TimelineEntryLocationResolveBatch {
public:
    using ResolveItem =
        std::variant<
            CompletedResultsGroup,
            JobQueueItem,
            ResolvedUnobtainableResult
        >;

    struct SplitResult {
        CompletedResultsGroups completedResultsGroups;
        JobQueueItems jobQueueItems;
        ResolvedUnobtainableResultItems unobtainableResults;
    };

    void AppendCompletedResultsGroup(
        const CompletedResultsGroup& group
    );

    void AppendJobQueueItem(
        const JobQueueItem& item
    );

    void AppendUnobtainableResult(
        const UnobtainableResult& result
    );

    bool HasPrepare() const noexcept;
    bool HasRuntime() const noexcept;
    bool HasPendingPrepareKeys() const noexcept;
    bool HasPendingRuntimeKeys() const noexcept;

    std::vector<std::size_t> TakeFromPrepareIndex(
        const TimelineEntryKey& key
    );

    std::vector<std::size_t> TakeFromRuntimeIndex(
        const TimelineEntryKey& key
    );

    bool UpdateTimelineEntryLocation(
        std::size_t itemIndex,
        const TimelineEntryLocation& location
    );

    SplitResult Split() const;

private:
    struct ResolveIndexEntry {
        TimelineEntryKey key;
        std::vector<std::size_t> itemIndexes;
    };

    using ResolveIndex = std::vector<ResolveIndexEntry>;

    static bool KeysEqual_(
        const TimelineEntryKey& a,
        const TimelineEntryKey& b
    ) noexcept;

    void AppendItem_(
        ResolveItem item,
        const TimelineEntryKey& key
    );

    static void AppendToIndex_(
        ResolveIndex& index,
        const TimelineEntryKey& key,
        std::size_t itemIndex
    );

    static std::vector<std::size_t> TakeFromIndex_(
        ResolveIndex& index,
        const TimelineEntryKey& key
    );

    bool hasPrepare_ = false;
    bool hasRuntime_ = false;

    std::vector<ResolveItem> items_;
    ResolveIndex prepareIndex_;
    ResolveIndex runtimeIndex_;
};

} // namespace SR
