// SRUnobtainableResults.cpp
#include "SRUnobtainableResults.h"

#include <algorithm>

namespace SR {

void UnobtainableResults::Add(const UnobtainableResult& result) {
    std::lock_guard<std::mutex> lock(mutex_);

    const auto it = std::find_if(
        results_.begin(),
        results_.end(),
        [&](const UnobtainableResult& existing) {
            return
                existing.key.phase == result.key.phase &&
                existing.key.phaseOrderNo == result.key.phaseOrderNo &&
                existing.key.eventOrderNo == result.key.eventOrderNo &&
                existing.target == result.target;
        }
    );

    if (it == results_.end()) {
        results_.push_back(result);
    }
}

UnobtainableResultItems UnobtainableResults::Retrieve() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return results_;
}

void UnobtainableResults::RemoveNotFound(
    const ResolvedUnobtainableResultItems& resolvedResults
) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const ResolvedUnobtainableResult& resolved : resolvedResults) {
        if (resolved.resolveStatus !=
            TimelineEntryKeyLocationPairResolveStatus::NotFound) {
            continue;
        }

        results_.erase(
            std::remove_if(
                results_.begin(),
                results_.end(),
                [&](const UnobtainableResult& existing) {
                    return
                        existing.key.phase == resolved.result.key.phase &&
                        existing.key.phaseOrderNo ==
                            resolved.result.key.phaseOrderNo &&
                        existing.key.eventOrderNo ==
                            resolved.result.key.eventOrderNo &&
                        existing.target == resolved.result.target;
                }
            ),
            results_.end()
        );
    }
}

} // namespace SR
