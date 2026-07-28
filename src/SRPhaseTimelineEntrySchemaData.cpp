#include "SRPhaseTimelineEntrySchemaData.h"

#include "SRPhaseTimelineEntry.h"
#include "TextHelpers.h"

namespace SR {
namespace {

bool PayloadDroppedFromReplayStorage_(
    ReplayPayloadStorage replayPayloadStorage
) noexcept {
    return replayPayloadStorage == ReplayPayloadStorage::DroppedByBufferLimit;
}

} // namespace

SRPhaseTimelineEntrySchemaData::SrDiagData::SrDiagData(
    const SrDiagEntry& entry
)
    : source(&entry),
      payloadType(SR::JobPayloadTypeName(entry.payloadType)),
      phase(SR::LifecyclePhaseToString(entry.key.phase)),
      phaseOrderNo(entry.key.phaseOrderNo),
      eventOrderNo(entry.key.eventOrderNo),
      timestampUtc(entry.timestampUtc),
      payloadDropped(
          PayloadDroppedFromReplayStorage_(entry.replayPayloadStorage)
      ),
      payloadByteCount(entry.payloadByteCount),
      severity(SR::DiagnosticSeverityToToken(entry.severity)),
      message(entry.message) {}


SRPhaseTimelineEntrySchemaData::ChildStdoutData::ChildStdoutData(
    const ChildStdoutEntry& entry
)
    : source(&entry),
      payloadType(SR::JobPayloadTypeName(entry.payloadType)),
      phase(SR::LifecyclePhaseToString(entry.key.phase)),
      phaseOrderNo(entry.key.phaseOrderNo),
      eventOrderNo(entry.key.eventOrderNo),
      timestampUtc(entry.timestampUtc),
      payloadDropped(
          PayloadDroppedFromReplayStorage_(entry.replayPayloadStorage)
      ),
      payloadByteCount(entry.payloadByteCount),
      payloadBase64(TextHelpers::PayloadBase64FromBytes(entry.bytes)) {}

SRPhaseTimelineEntrySchemaData::ChildStderrData::ChildStderrData(
    const ChildStderrEntry& entry
)
    : source(&entry),
      payloadType(SR::JobPayloadTypeName(entry.payloadType)),
      phase(SR::LifecyclePhaseToString(entry.key.phase)),
      phaseOrderNo(entry.key.phaseOrderNo),
      eventOrderNo(entry.key.eventOrderNo),
      timestampUtc(entry.timestampUtc),
      payloadDropped(
          PayloadDroppedFromReplayStorage_(entry.replayPayloadStorage)
      ),
      payloadByteCount(entry.payloadByteCount),
      payloadBase64(TextHelpers::PayloadBase64FromBytes(entry.bytes)) {}

} // namespace SR
