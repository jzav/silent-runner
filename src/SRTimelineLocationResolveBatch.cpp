#include "SRTimelineLocationResolveBatch.h"

#include <utility>
#include <type_traits>

namespace SR {

void TimelineEntryLocationResolveBatch::AppendCompletedResultsGroup(
    const CompletedResultsGroup& group
) {
    AppendItem_(ResolveItem{ group }, group.key);
}

void TimelineEntryLocationResolveBatch::AppendJobQueueItem(
    const JobQueueItem& item
) {
    AppendItem_(ResolveItem{ item }, item.key);
}

void TimelineEntryLocationResolveBatch::AppendUnobtainableResult(
    const UnobtainableResult& result
) {
    ResolvedUnobtainableResult resolved;
    resolved.result = result;

    AppendItem_(ResolveItem{ resolved }, result.key);
}

bool TimelineEntryLocationResolveBatch::HasPrepare() const noexcept {
    return hasPrepare_;
}

bool TimelineEntryLocationResolveBatch::HasRuntime() const noexcept {
    return hasRuntime_;
}

bool TimelineEntryLocationResolveBatch::HasPendingPrepareKeys() const noexcept {
    return !prepareIndex_.empty();
}

bool TimelineEntryLocationResolveBatch::HasPendingRuntimeKeys() const noexcept {
    return !runtimeIndex_.empty();
}

std::vector<std::size_t> TimelineEntryLocationResolveBatch::TakeFromPrepareIndex(
    const TimelineEntryKey& key
) {
    return TakeFromIndex_(prepareIndex_, key);
}

std::vector<std::size_t> TimelineEntryLocationResolveBatch::TakeFromRuntimeIndex(
    const TimelineEntryKey& key
) {
    return TakeFromIndex_(runtimeIndex_, key);
}

bool TimelineEntryLocationResolveBatch::UpdateTimelineEntryLocation(
    std::size_t itemIndex,
    const TimelineEntryLocation& location
) {
    if (itemIndex >= items_.size()) {
        return false;
    }

    std::visit(
        [&](auto& item) {
            item.location = location;
            item.resolveStatus =
                TimelineEntryKeyLocationPairResolveStatus::Resolved;
        },
        items_[itemIndex]
    );

    return true;
}

TimelineEntryLocationResolveBatch::SplitResult
TimelineEntryLocationResolveBatch::Split() const {
    SplitResult result;

    for (const ResolveItem& item : items_) {
        if (const auto* group = std::get_if<CompletedResultsGroup>(&item)) {
            result.completedResultsGroups.push_back(*group);
        } else if (const auto* jobQueueItem = std::get_if<JobQueueItem>(&item)) {
            result.jobQueueItems.push_back(*jobQueueItem);
        } else if (const auto* unobtainableResult =
            std::get_if<ResolvedUnobtainableResult>(&item)) {
            result.unobtainableResults.push_back(*unobtainableResult);
        }
    }

    return result;
}

bool TimelineEntryLocationResolveBatch::KeysEqual_(
    const TimelineEntryKey& a,
    const TimelineEntryKey& b
) noexcept {
    return
        a.phase == b.phase &&
        a.phaseOrderNo == b.phaseOrderNo &&
        a.eventOrderNo == b.eventOrderNo;
}

void TimelineEntryLocationResolveBatch::AppendItem_(
    ResolveItem item,
    const TimelineEntryKey& key
) {
    items_.push_back(std::move(item));

    const std::size_t itemIndex = items_.size() - 1;

    if (key.phase == SR::LifecyclePhase::Prepare) {
        hasPrepare_ = true;
        AppendToIndex_(prepareIndex_, key, itemIndex);
    } else if (key.phase == SR::LifecyclePhase::Runtime) {
        hasRuntime_ = true;
        AppendToIndex_(runtimeIndex_, key, itemIndex);
    }
}

void TimelineEntryLocationResolveBatch::AppendToIndex_(
    ResolveIndex& index,
    const TimelineEntryKey& key,
    std::size_t itemIndex
) {
    for (ResolveIndexEntry& entry : index) {
        if (KeysEqual_(entry.key, key)) {
            entry.itemIndexes.push_back(itemIndex);
            return;
        }
    }

    ResolveIndexEntry entry;
    entry.key = key;
    entry.itemIndexes.push_back(itemIndex);
    index.push_back(std::move(entry));
}

std::vector<std::size_t> TimelineEntryLocationResolveBatch::TakeFromIndex_(
    ResolveIndex& index,
    const TimelineEntryKey& key
) {
    for (auto it = index.begin(); it != index.end(); ++it) {
        if (!KeysEqual_(it->key, key)) {
            continue;
        }

        std::vector<std::size_t> itemIndexes =
            std::move(it->itemIndexes);
        index.erase(it);
        return itemIndexes;
    }

    return {};
}

} // namespace SR
