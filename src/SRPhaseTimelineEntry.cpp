#include "SRPhaseTimelineEntry.h"

namespace SR {

bool IsJobResultPruneable(const EventJobResult& result) noexcept {
    return SR::IsPruneableJobState(result.state);
}

bool AreAllJobResultsPruneable(
    JobPayloadType payloadType,
    const EventJobResults& results
) noexcept {
    for (const EventJobResult& result : results.items) {
        if (!CanRouteJobPayloadTypeToTarget(payloadType, result.target)) {
            continue;
        }

        if (!IsJobResultPruneable(result)) {
            return false;
        }
    }

    return true;
}

} // namespace SR
