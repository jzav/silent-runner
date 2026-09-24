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
    JsonlPayloadPresentation payloadPresentation,
    std::string& payloadRepresentation,
    std::wstring& payloadText,
    std::string& payloadBase64
) {
    if (payloadDropped) {
        return;
    }

    switch (payloadPresentation) {
        case JsonlPayloadPresentation::Text:
            payloadRepresentation =
                JsonlPayloadPresentationToToken(
                    JsonlPayloadPresentation::Text
                );
            payloadText = message;
            return;

        case JsonlPayloadPresentation::Base64:
            payloadRepresentation =
                JsonlPayloadPresentationToToken(
                    JsonlPayloadPresentation::Base64
                );
            payloadBase64 =
                PayloadBase64FromUtf8Text_(message);
            return;

        case JsonlPayloadPresentation::TextAndBase64:
            payloadRepresentation =
                JsonlPayloadPresentationToToken(
                    JsonlPayloadPresentation::TextAndBase64
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
    JsonlPayloadPresentation payloadPresentation,
    std::string& payloadRepresentation,
    std::string& payloadText,
    std::string& payloadBase64
) {
    if (payloadDropped) {
        return;
    }

    if (payloadPresentation == JsonlPayloadPresentation::Base64) {
        payloadRepresentation =
            JsonlPayloadPresentationToToken(
                JsonlPayloadPresentation::Base64
            );
        payloadBase64 =
            TextHelpers::PayloadBase64FromBytes(bytes);
        return;
    }

    if (!TextHelpers::IsValidUtf8(bytes)) {
        payloadRepresentation =
            JsonlPayloadPresentationToToken(
                JsonlPayloadPresentation::Base64
            );
        payloadBase64 =
            TextHelpers::PayloadBase64FromBytes(bytes);
        return;
    }

    payloadText.assign(bytes.begin(), bytes.end());

    if (payloadPresentation ==
        JsonlPayloadPresentation::TextAndBase64) {
        payloadRepresentation =
            JsonlPayloadPresentationToToken(
                JsonlPayloadPresentation::TextAndBase64
            );
        payloadBase64 =
            TextHelpers::PayloadBase64FromBytes(bytes);
        return;
    }

    payloadRepresentation =
        JsonlPayloadPresentationToToken(
            JsonlPayloadPresentation::Text
        );
}


} // namespace

SRPhaseTimelineEntrySchemaData::SrDiagData::SrDiagData(
    const SrDiagEntry& entry,
    JsonlPayloadPresentation payloadPresentation
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
        payloadPresentation,
        payloadRepresentation,
        payloadText,
        payloadBase64
    );
}



SRPhaseTimelineEntrySchemaData::ChildStdoutData::ChildStdoutData(
    const ChildStdoutEntry& entry,
    JsonlPayloadPresentation payloadPresentation
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
        payloadPresentation,
        payloadRepresentation,
        payloadText,
        payloadBase64
    );
}


SRPhaseTimelineEntrySchemaData::ChildStderrData::ChildStderrData(
    const ChildStderrEntry& entry,
    JsonlPayloadPresentation payloadPresentation
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
        payloadPresentation,
        payloadRepresentation,
        payloadText,
        payloadBase64
    );
}



} // namespace SR
