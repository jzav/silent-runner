#include "SRPhaseTimelineEntrySchemaData.h"
#include <vector>

#include "SRPhaseTimelineEntry.h"
#include "TextHelpers.h"

namespace SR {
namespace {

bool PayloadDroppedFromReplayStorage_(
    ReplayPayloadStorage replayPayloadStorage
) noexcept {
    return replayPayloadStorage == ReplayPayloadStorage::DroppedByBufferLimit;
}

std::string PayloadBase64FromUtf8Text_(
    const std::wstring& text
) {
    const std::string utf8 =
        TextHelpers::Utf16ToUtf8(text);

    const std::vector<char> bytes(
        utf8.begin(),
        utf8.end()
    );

    return TextHelpers::PayloadBase64FromBytes(bytes);
}

void PopulateSrDiagPayloadFields_(
    const std::wstring& message,
    bool payloadDropped,
    JsonlPayloadRepresentation payloadRepresentationMode,
    std::string& payloadRepresentation,
    std::wstring& payloadText,
    std::string& payloadBase64
) {
    if (payloadDropped) {
        return;
    }

    switch (payloadRepresentationMode) {
        case JsonlPayloadRepresentation::Text:
            payloadRepresentation =
                JsonlPayloadRepresentationToToken(
                    JsonlPayloadRepresentation::Text
                );
            payloadText = message;
            return;

        case JsonlPayloadRepresentation::Base64:
            payloadRepresentation =
                JsonlPayloadRepresentationToToken(
                    JsonlPayloadRepresentation::Base64
                );
            payloadBase64 =
                PayloadBase64FromUtf8Text_(message);
            return;

        case JsonlPayloadRepresentation::TextAndBase64:
            payloadRepresentation =
                JsonlPayloadRepresentationToToken(
                    JsonlPayloadRepresentation::TextAndBase64
                );
            payloadText = message;
            payloadBase64 =
                PayloadBase64FromUtf8Text_(message);
            return;
    }

    payloadRepresentation = "text";
    payloadText = message;
}

void PopulateChildPayloadFields_(
    const std::vector<char>& bytes,
    bool payloadDropped,
    JsonlPayloadRepresentation payloadRepresentationMode,
    std::string& payloadRepresentation,
    std::string& payloadText,
    std::string& payloadBase64
) {
    if (payloadDropped) {
        return;
    }

    if (payloadRepresentationMode == JsonlPayloadRepresentation::Base64) {
        payloadRepresentation =
            JsonlPayloadRepresentationToToken(
                JsonlPayloadRepresentation::Base64
            );
        payloadBase64 =
            TextHelpers::PayloadBase64FromBytes(bytes);
        return;
    }

    if (!TextHelpers::IsValidUtf8(bytes)) {
        payloadRepresentation =
            JsonlPayloadRepresentationToToken(
                JsonlPayloadRepresentation::Base64
            );
        payloadBase64 =
            TextHelpers::PayloadBase64FromBytes(bytes);
        return;
    }

    payloadText.assign(bytes.begin(), bytes.end());

    if (payloadRepresentationMode ==
        JsonlPayloadRepresentation::TextAndBase64) {
        payloadRepresentation =
            JsonlPayloadRepresentationToToken(
                JsonlPayloadRepresentation::TextAndBase64
            );
        payloadBase64 =
            TextHelpers::PayloadBase64FromBytes(bytes);
        return;
    }

    payloadRepresentation =
        JsonlPayloadRepresentationToToken(
            JsonlPayloadRepresentation::Text
        );
}


} // namespace

SRPhaseTimelineEntrySchemaData::SrDiagData::SrDiagData(
    const SrDiagEntry& entry,
    JsonlPayloadRepresentation payloadRepresentationMode
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
      severity(SR::DiagnosticSeverityToToken(entry.severity)) {
    PopulateSrDiagPayloadFields_(
        entry.message,
        payloadDropped,
        payloadRepresentationMode,
        payloadRepresentation,
        payloadText,
        payloadBase64
    );
}



SRPhaseTimelineEntrySchemaData::ChildStdoutData::ChildStdoutData(
    const ChildStdoutEntry& entry,
    JsonlPayloadRepresentation payloadRepresentationMode
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
      payloadByteCount(entry.payloadByteCount) {
    PopulateChildPayloadFields_(
        entry.bytes,
        payloadDropped,
        payloadRepresentationMode,
        payloadRepresentation,
        payloadText,
        payloadBase64
    );
}


SRPhaseTimelineEntrySchemaData::ChildStderrData::ChildStderrData(
    const ChildStderrEntry& entry,
    JsonlPayloadRepresentation payloadRepresentationMode
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
      payloadByteCount(entry.payloadByteCount) {
    PopulateChildPayloadFields_(
        entry.bytes,
        payloadDropped,
        payloadRepresentationMode,
        payloadRepresentation,
        payloadText,
        payloadBase64
    );
}



} // namespace SR
