#include "SRPhaseTimeline.h"
#include "FileHelpers.h"


PhaseEventStamp PhaseTimeline::Stamp() {
    PhaseEventStamp stamp;
    stamp.phase = phase;
    stamp.phaseOrderNo = phaseOrderNo;
    stamp.eventOrderNo = nextEventOrderNo++;
    stamp.timestampUtc = FileHelpers::MakeRunUtcTimestamp();
    return stamp;
}

void PhaseTimeline::Reset(
    SR::LifecyclePhase phaseValue,
    uint32_t phaseOrderNoValue,
    const std::wstring& nameValue
) {
    phase = phaseValue;
    phaseOrderNo = phaseOrderNoValue;
    name = nameValue;
    phaseStartUtc.clear();
    phaseEndUtc.clear();
    nextEventOrderNo = 0;

    bufferUsage = SR::BufferUsage{};

    entries.clear();

}

void PhaseTimeline::Start() {
    if (phaseStartUtc.empty()) {
        phaseStartUtc = FileHelpers::MakeRunUtcTimestamp();
    }
}

void PhaseTimeline::End() {
    if (phaseEndUtc.empty()) {
        phaseEndUtc = FileHelpers::MakeRunUtcTimestamp();
    }
}

void PhaseTimeline::AppendSrDiag(
    SR::DiagnosticSeverity severity,
    const std::wstring& message
) {
    PhaseEventStamp stamp = Stamp();

    SR::SrDiagEntry entry;
    entry.key.phase = stamp.phase;
    entry.key.phaseOrderNo = stamp.phaseOrderNo;
    entry.key.eventOrderNo = stamp.eventOrderNo;
    entry.timestampUtc = stamp.timestampUtc;
    entry.severity = severity;
    entry.message = message;
    entry.payloadByteCount =
        static_cast<uint64_t>(FileHelpers::WideToUtf8(message).size());

    entries.push_back(entry);

}

void PhaseTimeline::AppendChildStdout(
    const char* bytes,
    size_t byteCount,
    SR::ReplayPayloadStorage replayPayloadStorage
) {
    PhaseEventStamp stamp = Stamp();

    const uint64_t byteCount64 = static_cast<uint64_t>(byteCount);

    SR::ChildStdoutEntry entry;
    entry.key.phase = stamp.phase;
    entry.key.phaseOrderNo = stamp.phaseOrderNo;
    entry.key.eventOrderNo = stamp.eventOrderNo;
    entry.timestampUtc = stamp.timestampUtc;
    entry.payloadByteCount = byteCount64;
    entry.replayPayloadStorage = replayPayloadStorage;

    if (replayPayloadStorage == SR::ReplayPayloadStorage::Store) {
        entry.bytes.assign(bytes, bytes + byteCount);
        bufferUsage.stdoutBufferedBytes += byteCount64;
        bufferUsage.totalBufferedBytes += byteCount64;
    } else if (replayPayloadStorage == SR::ReplayPayloadStorage::NotNeeded) {
        entry.bytes.assign(bytes, bytes + byteCount);
    } else {
        bufferUsage.stdoutDroppedBytes += byteCount64;
        bufferUsage.totalDroppedBytes += byteCount64;
        ++bufferUsage.stdoutDroppedEvents;
        ++bufferUsage.totalDroppedEvents;
    }

    entries.push_back(entry);
}

void PhaseTimeline::AppendChildStderr(
    const char* bytes,
    size_t byteCount,
    SR::ReplayPayloadStorage replayPayloadStorage
) {
    PhaseEventStamp stamp = Stamp();

    const uint64_t byteCount64 = static_cast<uint64_t>(byteCount);

    SR::ChildStderrEntry entry;
    entry.key.phase = stamp.phase;
    entry.key.phaseOrderNo = stamp.phaseOrderNo;
    entry.key.eventOrderNo = stamp.eventOrderNo;
    entry.timestampUtc = stamp.timestampUtc;
    entry.payloadByteCount = byteCount64;
    entry.replayPayloadStorage = replayPayloadStorage;

    if (replayPayloadStorage == SR::ReplayPayloadStorage::Store) {
        entry.bytes.assign(bytes, bytes + byteCount);
        bufferUsage.stderrBufferedBytes += byteCount64;
        bufferUsage.totalBufferedBytes += byteCount64;
    } else if (replayPayloadStorage == SR::ReplayPayloadStorage::NotNeeded) {
        entry.bytes.assign(bytes, bytes + byteCount);
    } else {
        bufferUsage.stderrDroppedBytes += byteCount64;
        bufferUsage.totalDroppedBytes += byteCount64;
        ++bufferUsage.stderrDroppedEvents;
        ++bufferUsage.totalDroppedEvents;
    }

    entries.push_back(entry);
}

void PhaseTimeline::GetAllDelayed(
    const SR::GetAllDelayedFilter& filter,
    SR::JobQueueItems& delayedItems
) {
    for (std::size_t index = 0; index < entries.size(); ++index) {
        std::visit(
            [&](const auto& entry) {
                const SR::EventJobResults& jobResults = entry.jobResults;

                const bool matchesFilter =
                    (filter.stdoutParent &&
                     jobResults.At(SR::JobTarget::StdoutParent).state ==
                         SR::JobState::Delayed) ||
                    (filter.stderrMixedParent &&
                     jobResults.At(SR::JobTarget::StderrMixedParent).state ==
                         SR::JobState::Delayed) ||
                    (filter.stderrChildParent &&
                     jobResults.At(SR::JobTarget::StderrChildParent).state ==
                         SR::JobState::Delayed) ||
                    (filter.stderrSrParent &&
                     jobResults.At(SR::JobTarget::StderrSrParent).state ==
                         SR::JobState::Delayed);

                if (!matchesFilter) {
                    return;
                }

                SR::JobQueueItem item;
                item.key = entry.key;
                item.location.phaseTimeline = this;
                item.location.index = index;
                item.resolveStatus =
                    SR::TimelineEntryKeyLocationPairResolveStatus::Resolved;

                delayedItems.push_back(std::move(item));
            },
            entries[index]
        );
    }
}
