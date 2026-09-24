#pragma once
#include "SRPhaseTimelineEntrySchemaData.h"

// =====================================================================================
// SRPhaseTimelineEntry formatter/parser field tables
// =====================================================================================
//
// Row order is significant and preserves the current JSONL field order.
//
// The parsing token is TXT-header framing metadata. It is intentionally the final
// TXT-only field in header-capable tables.
//
// Formatter/parser expansion is responsible for:
// - skipping rows disabled for the selected format,
// - inserting/consuming JSON separators around schema fields,
// - supplying the schema data object and format-specific state.
//
//
// Table columns:
//   (member,
//    fieldName,
//
//    jsonEnabled,
//    jsonFormatter,
//    jsonParser,
//
//    txtEnabled,
//    txtFormatter,
//    txtParser,
//    txtSpacesAfter)
//
// txtSpacesAfter is the exact number of ASCII spaces emitted/consumed
// after an enabled TXT field. Use 0 for no inter-field spacing.

#define SR_PHASE_TIMELINE_SR_DIAG_SCHEMA_FIELD_TABLE(X) \
    X( \
        &SRPhaseTimelineEntrySchemaData::SrDiagData::payloadType, \
        "payloadType", \
        \
        true, \
        TextHelpers::AppendJsonStringField, \
        TextHelpers::TryParseJsonStringField, \
        \
        true, \
        TextHelpers::AppendTxtUpperStringField, \
        TextHelpers::TryParseTxtStringField, \
        1 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::SrDiagData::timestampUtc, \
        "tsUtc", \
        \
        true, \
        TextHelpers::AppendJsonWideStringField, \
        TextHelpers::TryParseJsonWideStringField, \
        \
        true, \
        TextHelpers::AppendTxtWideStringField, \
        TextHelpers::TryParseTxtWideStringField, \
        1 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::SrDiagData::phase, \
        "phase", \
        \
        true, \
        TextHelpers::AppendJsonWideStringField, \
        TextHelpers::TryParseJsonWideStringField, \
        \
        true, \
        TextHelpers::AppendTxtUpperWideStringField, \
        TextHelpers::TryParseTxtWideStringField, \
        0 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::SrDiagData::phaseOrderNo, \
        "phaseOrderNo", \
        \
        true, \
        TextHelpers::AppendJsonUInt64Field, \
        TextHelpers::TryParseJsonUInt64Field, \
        \
        true, \
        TextHelpers::AppendTxtUInt64Field, \
        TextHelpers::TryParseTxtUInt64Field, \
        0 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::SrDiagData::eventOrderNo, \
        "eventOrderNo", \
        \
        true, \
        TextHelpers::AppendJsonUInt64Field, \
        TextHelpers::TryParseJsonUInt64Field, \
        \
        true, \
        TextHelpers::AppendTxtUInt64Field, \
        TextHelpers::TryParseTxtUInt64Field, \
        1 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::SrDiagData::payloadDropped, \
        "payloadDropped", \
        \
        true, \
        TextHelpers::AppendJsonBoolField, \
        TextHelpers::TryParseJsonBoolField, \
        \
        true, \
        TextHelpers::AppendTxtUpperBoolField, \
        TextHelpers::TryParseTxtBoolField, \
        0 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::SrDiagData::payloadByteCount, \
        "payloadByteCount", \
        \
        true, \
        TextHelpers::AppendJsonUInt64Field, \
        TextHelpers::TryParseJsonUInt64Field, \
        \
        true, \
        TextHelpers::AppendTxtUInt64Field, \
        TextHelpers::TryParseTxtUInt64Field, \
        1 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::SrDiagData::payloadRepresentation, \
        "payloadRepresentation", \
        \
        true, \
        TextHelpers::AppendJsonStringField, \
        TextHelpers::TryParseJsonStringField, \
        \
        false, \
        nullptr, \
        nullptr, \
        0 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::SrDiagData::payloadText, \
        "payloadText", \
        \
        true, \
        TextHelpers::AppendJsonWideStringField, \
        TextHelpers::TryParseJsonWideStringField, \
        \
        false, \
        nullptr, \
        nullptr, \
        0 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::SrDiagData::payloadBase64, \
        "payloadBase64", \
        \
        true, \
        TextHelpers::AppendJsonStringField, \
        TextHelpers::TryParseJsonStringField, \
        \
        false, \
        nullptr, \
        nullptr, \
        0 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::SrDiagData::severity, \
        "severity", \
        \
        true, \
        TextHelpers::AppendJsonWideStringField, \
        TextHelpers::TryParseJsonWideStringField, \
        \
        true, \
        TextHelpers::AppendTxtUpperWideStringField, \
        TextHelpers::TryParseTxtWideStringField, \
        1 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::SrDiagData::parsingToken, \
        "parsingToken", \
        \
        false, \
        nullptr, \
        nullptr, \
        \
        true, \
        TextHelpers::AppendTxtStringField, \
        TextHelpers::TryParseTxtStringField, \
        0 \
    )

#define SR_PHASE_TIMELINE_CHILD_STDOUT_SCHEMA_FIELD_TABLE(X) \
    X( \
        &SRPhaseTimelineEntrySchemaData::ChildStdoutData::payloadType, \
        "payloadType", \
        \
        true, \
        TextHelpers::AppendJsonStringField, \
        TextHelpers::TryParseJsonStringField, \
        \
        true, \
        TextHelpers::AppendTxtUpperStringField, \
        TextHelpers::TryParseTxtStringField, \
        1 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::ChildStdoutData::timestampUtc, \
        "tsUtc", \
        \
        true, \
        TextHelpers::AppendJsonWideStringField, \
        TextHelpers::TryParseJsonWideStringField, \
        \
        true, \
        TextHelpers::AppendTxtWideStringField, \
        TextHelpers::TryParseTxtWideStringField, \
        1 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::ChildStdoutData::phase, \
        "phase", \
        \
        true, \
        TextHelpers::AppendJsonWideStringField, \
        TextHelpers::TryParseJsonWideStringField, \
        \
        true, \
        TextHelpers::AppendTxtUpperWideStringField, \
        TextHelpers::TryParseTxtWideStringField, \
        0 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::ChildStdoutData::phaseOrderNo, \
        "phaseOrderNo", \
        \
        true, \
        TextHelpers::AppendJsonUInt64Field, \
        TextHelpers::TryParseJsonUInt64Field, \
        \
        true, \
        TextHelpers::AppendTxtUInt64Field, \
        TextHelpers::TryParseTxtUInt64Field, \
        0 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::ChildStdoutData::eventOrderNo, \
        "eventOrderNo", \
        \
        true, \
        TextHelpers::AppendJsonUInt64Field, \
        TextHelpers::TryParseJsonUInt64Field, \
        \
        true, \
        TextHelpers::AppendTxtUInt64Field, \
        TextHelpers::TryParseTxtUInt64Field, \
        1 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::ChildStdoutData::payloadDropped, \
        "payloadDropped", \
        \
        true, \
        TextHelpers::AppendJsonBoolField, \
        TextHelpers::TryParseJsonBoolField, \
        \
        true, \
        TextHelpers::AppendTxtUpperBoolField, \
        TextHelpers::TryParseTxtBoolField, \
        0 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::ChildStdoutData::payloadByteCount, \
        "payloadByteCount", \
        \
        true, \
        TextHelpers::AppendJsonUInt64Field, \
        TextHelpers::TryParseJsonUInt64Field, \
        \
        true, \
        TextHelpers::AppendTxtUInt64Field, \
        TextHelpers::TryParseTxtUInt64Field, \
        1 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::ChildStdoutData::payloadRepresentation, \
        "payloadRepresentation", \
        \
        true, \
        TextHelpers::AppendJsonStringField, \
        TextHelpers::TryParseJsonStringField, \
        \
        false, \
        nullptr, \
        nullptr, \
        0 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::ChildStdoutData::payloadText, \
        "payloadText", \
        \
        true, \
        TextHelpers::AppendJsonStringField, \
        TextHelpers::TryParseJsonStringField, \
        \
        false, \
        nullptr, \
        nullptr, \
        0 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::ChildStdoutData::payloadBase64, \
        "payloadBase64", \
        \
        true, \
        TextHelpers::AppendJsonStringField, \
        TextHelpers::TryParseJsonStringField, \
        \
        false, \
        nullptr, \
        nullptr, \
        0 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::ChildStdoutData::parsingToken, \
        "parsingToken", \
        \
        false, \
        nullptr, \
        nullptr, \
        \
        true, \
        TextHelpers::AppendTxtStringField, \
        TextHelpers::TryParseTxtStringField, \
        0 \
    )

#define SR_PHASE_TIMELINE_CHILD_STDERR_SCHEMA_FIELD_TABLE(X) \
    X( \
        &SRPhaseTimelineEntrySchemaData::ChildStderrData::payloadType, \
        "payloadType", \
        \
        true, \
        TextHelpers::AppendJsonStringField, \
        TextHelpers::TryParseJsonStringField, \
        \
        true, \
        TextHelpers::AppendTxtUpperStringField, \
        TextHelpers::TryParseTxtStringField, \
        1 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::ChildStderrData::timestampUtc, \
        "tsUtc", \
        \
        true, \
        TextHelpers::AppendJsonWideStringField, \
        TextHelpers::TryParseJsonWideStringField, \
        \
        true, \
        TextHelpers::AppendTxtWideStringField, \
        TextHelpers::TryParseTxtWideStringField, \
        1 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::ChildStderrData::phase, \
        "phase", \
        \
        true, \
        TextHelpers::AppendJsonWideStringField, \
        TextHelpers::TryParseJsonWideStringField, \
        \
        true, \
        TextHelpers::AppendTxtUpperWideStringField, \
        TextHelpers::TryParseTxtWideStringField, \
        0 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::ChildStderrData::phaseOrderNo, \
        "phaseOrderNo", \
        \
        true, \
        TextHelpers::AppendJsonUInt64Field, \
        TextHelpers::TryParseJsonUInt64Field, \
        \
        true, \
        TextHelpers::AppendTxtUInt64Field, \
        TextHelpers::TryParseTxtUInt64Field, \
        0 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::ChildStderrData::eventOrderNo, \
        "eventOrderNo", \
        \
        true, \
        TextHelpers::AppendJsonUInt64Field, \
        TextHelpers::TryParseJsonUInt64Field, \
        \
        true, \
        TextHelpers::AppendTxtUInt64Field, \
        TextHelpers::TryParseTxtUInt64Field, \
        1 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::ChildStderrData::payloadDropped, \
        "payloadDropped", \
        \
        true, \
        TextHelpers::AppendJsonBoolField, \
        TextHelpers::TryParseJsonBoolField, \
        \
        true, \
        TextHelpers::AppendTxtUpperBoolField, \
        TextHelpers::TryParseTxtBoolField, \
        0 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::ChildStderrData::payloadByteCount, \
        "payloadByteCount", \
        \
        true, \
        TextHelpers::AppendJsonUInt64Field, \
        TextHelpers::TryParseJsonUInt64Field, \
        \
        true, \
        TextHelpers::AppendTxtUInt64Field, \
        TextHelpers::TryParseTxtUInt64Field, \
        1 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::ChildStderrData::payloadRepresentation, \
        "payloadRepresentation", \
        \
        true, \
        TextHelpers::AppendJsonStringField, \
        TextHelpers::TryParseJsonStringField, \
        \
        false, \
        nullptr, \
        nullptr, \
        0 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::ChildStderrData::payloadText, \
        "payloadText", \
        \
        true, \
        TextHelpers::AppendJsonStringField, \
        TextHelpers::TryParseJsonStringField, \
        \
        false, \
        nullptr, \
        nullptr, \
        0 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::ChildStderrData::payloadBase64, \
        "payloadBase64", \
        \
        true, \
        TextHelpers::AppendJsonStringField, \
        TextHelpers::TryParseJsonStringField, \
        \
        false, \
        nullptr, \
        nullptr, \
        0 \
    ) \
    X( \
        &SRPhaseTimelineEntrySchemaData::ChildStderrData::parsingToken, \
        "parsingToken", \
        \
        false, \
        nullptr, \
        nullptr, \
        \
        true, \
        TextHelpers::AppendTxtStringField, \
        TextHelpers::TryParseTxtStringField, \
        0 \
    )
