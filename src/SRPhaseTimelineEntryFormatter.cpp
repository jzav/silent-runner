#include "SRPhaseTimelineEntryFormatter.h"

#include <cstdint>
#include <string>

#include "SRPhaseTimelineEntry.h"
#include "SRPhaseTimelineEntrySchema.h"
#include "SRPhaseTimelineEntrySchemaData.h"


#include "TextHelpers.h"

namespace SR {


namespace {

// Templated helpers allow disabled schema rows to use nullptr formatters.
// if constexpr prevents instantiation of the disabled formatter call.
template <
    bool enabled,
    typename Formatter,
    typename Data,
    typename Member
>
void AppendJsonField_(
    std::string& line,
    bool& firstField,
    const char* fieldName,
    Formatter formatter,
    const Data& data,
    Member member
) {
    if constexpr (enabled) {
        if (!firstField) {
            line += ",";
        }
        formatter(line, fieldName, data.*member);
        firstField = false;
    }
}

template <
    bool enabled,
    typename Formatter,
    typename Data,
    typename Member
>
void AppendTxtField_(
    std::string& header,
    const char* fieldName,
    Formatter formatter,
    const Data& data,
    Member member
) {
    if constexpr (enabled) {
        formatter(header, fieldName, data.*member);
    }
}

std::string FormatSrDiagJsonLine_(
    const SRPhaseTimelineEntrySchemaData::SrDiagData& data
) {

    std::string line;
    line.reserve(256 + data.message.size());
    line += "{";

    bool firstField = true;

#define SR_APPEND_JSON_FIELD_( \
    member, \
    fieldName, \
    jsonEnabled, \
    jsonFormatter, \
    jsonParser, \
    txtEnabled, \
    txtFormatter, \
    txtParser \
) \
    AppendJsonField_<jsonEnabled>( \
        line, \
        firstField, \
        fieldName, \
        jsonFormatter, \
        data, \
        member \
    );


    SR_PHASE_TIMELINE_SR_DIAG_SCHEMA_FIELD_TABLE(

        SR_APPEND_JSON_FIELD_
    )

#undef SR_APPEND_JSON_FIELD_

    line += "}";
    return line;
}

std::string FormatChildStdoutJsonLine_(
    const SRPhaseTimelineEntrySchemaData::ChildStdoutData& data
) {

    std::string line;
    line.reserve(256 + data.payloadBase64.size());
    line += "{";

    bool firstField = true;

#define SR_APPEND_JSON_FIELD_( \
    member, \
    fieldName, \
    jsonEnabled, \
    jsonFormatter, \
    jsonParser, \
    txtEnabled, \
    txtFormatter, \
    txtParser \
) \
    AppendJsonField_<jsonEnabled>( \
        line, \
        firstField, \
        fieldName, \
        jsonFormatter, \
        data, \
        member \
    );


    SR_PHASE_TIMELINE_CHILD_STDOUT_SCHEMA_FIELD_TABLE(

        SR_APPEND_JSON_FIELD_
    )

#undef SR_APPEND_JSON_FIELD_

    line += "}";
    return line;
}

std::string FormatChildStderrJsonLine_(
    const SRPhaseTimelineEntrySchemaData::ChildStderrData& data
) {

    std::string line;
    line.reserve(256 + data.payloadBase64.size());
    line += "{";

    bool firstField = true;

#define SR_APPEND_JSON_FIELD_( \
    member, \
    fieldName, \
    jsonEnabled, \
    jsonFormatter, \
    jsonParser, \
    txtEnabled, \
    txtFormatter, \
    txtParser \
) \
    AppendJsonField_<jsonEnabled>( \
        line, \
        firstField, \
        fieldName, \
        jsonFormatter, \
        data, \
        member \
    );


    SR_PHASE_TIMELINE_CHILD_STDERR_SCHEMA_FIELD_TABLE(

        SR_APPEND_JSON_FIELD_
    )

#undef SR_APPEND_JSON_FIELD_

    line += "}";
    return line;
}

std::string FormatSrDiagTxtHeader_(
    const SRPhaseTimelineEntrySchemaData::SrDiagData& data
) {

    std::string header;
    header.reserve(256 + data.parsingToken.size());

#define SR_APPEND_TXT_FIELD_( \
    member, \
    fieldName, \
    jsonEnabled, \
    jsonFormatter, \
    jsonParser, \
    txtEnabled, \
    txtFormatter, \
    txtParser \
) \
    AppendTxtField_<txtEnabled>( \
        header, \
        fieldName, \
        txtFormatter, \
        data, \
        member \
    );


    SR_PHASE_TIMELINE_SR_DIAG_SCHEMA_FIELD_TABLE(

        SR_APPEND_TXT_FIELD_
    )

#undef SR_APPEND_TXT_FIELD_

    return header;
}

std::string FormatChildStderrTxtHeader_(
    const SRPhaseTimelineEntrySchemaData::ChildStderrData& data
) {
    std::string header;
    header.reserve(256 + data.parsingToken.size());

#define SR_APPEND_TXT_FIELD_( \
    member, \
    fieldName, \
    jsonEnabled, \
    jsonFormatter, \
    jsonParser, \
    txtEnabled, \
    txtFormatter, \
    txtParser \
) \
    AppendTxtField_<txtEnabled>( \
        header, \
        fieldName, \
        txtFormatter, \
        data, \
        member \
    );

    SR_PHASE_TIMELINE_CHILD_STDERR_SCHEMA_FIELD_TABLE(

        SR_APPEND_TXT_FIELD_
    )

#undef SR_APPEND_TXT_FIELD_

    return header;
}

} // namespace

std::string SRPhaseTimelineEntryFormatter::FormatSrDiagTxtHeader(
    const SrDiagEntry& entry,
    const std::string& parsingToken
) {
    SRPhaseTimelineEntrySchemaData::SrDiagData data(entry);
    data.parsingToken = parsingToken;
    return FormatSrDiagTxtHeader_(data);
}


std::string SRPhaseTimelineEntryFormatter::FormatChildStderrTxtHeader(
    const ChildStderrEntry& entry,
    const std::string& parsingToken
) {
    SRPhaseTimelineEntrySchemaData::ChildStderrData data(entry);
    data.parsingToken = parsingToken;
    return FormatChildStderrTxtHeader_(data);
}


std::string SRPhaseTimelineEntryFormatter::FormatJsonLine(
    const SrDiagEntry& entry
) {
    return FormatSrDiagJsonLine_(
        SRPhaseTimelineEntrySchemaData::SrDiagData(entry)
    );
}


std::string SRPhaseTimelineEntryFormatter::FormatJsonLine(
    const ChildStdoutEntry& entry
) {
    return FormatChildStdoutJsonLine_(
        SRPhaseTimelineEntrySchemaData::ChildStdoutData(entry)
    );

}

std::string SRPhaseTimelineEntryFormatter::FormatJsonLine(
    const ChildStderrEntry& entry
) {
    return FormatChildStderrJsonLine_(
        SRPhaseTimelineEntrySchemaData::ChildStderrData(entry)
    );
}

} // namespace SR
