#include "SRPhaseTimelineEntryJsonlParser.h"

#include <cstddef>
#include <string>
#include <utility>

#include "SRJobTypes.h"
#include "SRPhaseTimelineEntrySchema.h"

#include "TextHelpers.h"

namespace SR {
namespace {

bool TryRetrieveJsonPayloadType_(
    const std::string& line,
    JobPayloadType& payloadType
) {
    if (line.size() < 2 ||
        line.front() != '{' ||
        line.back() != '}') {
        return false;
    }

    std::size_t position = 1;
    std::string payloadTypeName;

    if (!TextHelpers::TryParseJsonStringField(
            line,
            position,
            "payloadType",
            payloadTypeName
        )) {
        return false;
    }

    return TryRetrieveJobPayloadTypeByName(
        payloadTypeName,
        payloadType
    );
}

// Templated helper allows JSON-disabled schema rows to use nullptr parsers.
// if constexpr prevents instantiation of the disabled parser call.
template <
    bool enabled,
    typename Parser,
    typename Data,
    typename Member
>
bool TryParseJsonField_(
    const std::string& line,
    std::size_t& position,
    bool& hasPreviousField,
    const char* fieldName,
    Parser parser,
    Data& data,
    Member member
) {
    if constexpr (enabled) {
        if (hasPreviousField) {
            if (position >= line.size() ||
                line[position] != ',') {
                return false;
            }

            ++position;
        }

        if (!parser(
                line,
                position,
                fieldName,
                data.*member
            )) {
            return false;
        }

        hasPreviousField = true;
    }

    return true;
}

bool IsCompleteJsonObject_(
    const std::string& line,
    std::size_t position
) noexcept {
    return
        position < line.size() &&
        line[position] == '}' &&
        position + 1 == line.size();
}

bool TryParseSrDiagJsonSchema_(
    const std::string& line,
    std::size_t position,
    SRPhaseTimelineEntrySchemaData::SrDiagData& data
) {
    bool hasPreviousField = false;

#define SR_PARSE_JSON_FIELD_( \
    member, \
    fieldName, \
    jsonEnabled, \
    jsonFormatter, \
    jsonParser, \
    txtEnabled, \
    txtFormatter, \
    txtParser, \
    txtSpacesAfter \
) \
    if (!TryParseJsonField_<jsonEnabled>( \
            line, \
            position, \
            hasPreviousField, \
            fieldName, \
            jsonParser, \
            data, \
            member \
        )) { \
        return false; \
    }

    SR_PHASE_TIMELINE_SR_DIAG_SCHEMA_FIELD_TABLE(
        SR_PARSE_JSON_FIELD_
    )

#undef SR_PARSE_JSON_FIELD_

    return IsCompleteJsonObject_(line, position);
}

bool TryParseChildStdoutJsonSchema_(
    const std::string& line,
    std::size_t position,
    SRPhaseTimelineEntrySchemaData::ChildStdoutData& data
) {
    bool hasPreviousField = false;

#define SR_PARSE_JSON_FIELD_( \
    member, \
    fieldName, \
    jsonEnabled, \
    jsonFormatter, \
    jsonParser, \
    txtEnabled, \
    txtFormatter, \
    txtParser, \
    txtSpacesAfter \
) \
    if (!TryParseJsonField_<jsonEnabled>( \
            line, \
            position, \
            hasPreviousField, \
            fieldName, \
            jsonParser, \
            data, \
            member \
        )) { \
        return false; \
    }

    SR_PHASE_TIMELINE_CHILD_STDOUT_SCHEMA_FIELD_TABLE(
        SR_PARSE_JSON_FIELD_
    )

#undef SR_PARSE_JSON_FIELD_

    return IsCompleteJsonObject_(line, position);
}

bool TryParseChildStderrJsonSchema_(
    const std::string& line,
    std::size_t position,
    SRPhaseTimelineEntrySchemaData::ChildStderrData& data
) {
    bool hasPreviousField = false;

#define SR_PARSE_JSON_FIELD_( \
    member, \
    fieldName, \
    jsonEnabled, \
    jsonFormatter, \
    jsonParser, \
    txtEnabled, \
    txtFormatter, \
    txtParser, \
    txtSpacesAfter \
) \
    if (!TryParseJsonField_<jsonEnabled>( \
            line, \
            position, \
            hasPreviousField, \
            fieldName, \
            jsonParser, \
            data, \
            member \
        )) { \
        return false; \
    }

    SR_PHASE_TIMELINE_CHILD_STDERR_SCHEMA_FIELD_TABLE(
        SR_PARSE_JSON_FIELD_
    )

#undef SR_PARSE_JSON_FIELD_

    return IsCompleteJsonObject_(line, position);
}

bool TryParseJsonSchemaByPayloadType_(
    const std::string& line,
    JobPayloadType payloadType,
    SRPhaseTimelineEntrySchemaData::SchemaDataVariant& data
) {
    switch (payloadType) {
        case JobPayloadType::SrDiag: {
            SRPhaseTimelineEntrySchemaData::SrDiagData parsedData;

            if (!TryParseSrDiagJsonSchema_(
                    line,
                    1,
                    parsedData
                )) {
                return false;
            }

            data = std::move(parsedData);
            return true;
        }

        case JobPayloadType::ChildStdout: {
            SRPhaseTimelineEntrySchemaData::ChildStdoutData parsedData;

            if (!TryParseChildStdoutJsonSchema_(
                    line,
                    1,
                    parsedData
                )) {
                return false;
            }

            data = std::move(parsedData);
            return true;
        }

        case JobPayloadType::ChildStderr: {
            SRPhaseTimelineEntrySchemaData::ChildStderrData parsedData;

            if (!TryParseChildStderrJsonSchema_(
                    line,
                    1,
                    parsedData
                )) {
                return false;
            }

            data = std::move(parsedData);
            return true;
        }
    }

    return false;
}

} // namespace

bool SRPhaseTimelineEntryJsonlParser::TryParseLine(
    const std::string& line,
    SRPhaseTimelineEntrySchemaData::SchemaDataVariant& data
) {
    if (line.size() < 2 ||
        line.front() != '{' ||
        line.back() != '}') {
        return false;
    }

    JobPayloadType payloadType;

    if (!TryRetrieveJsonPayloadType_(
            line,
            payloadType
        )) {
        return false;
    }

    return TryParseJsonSchemaByPayloadType_(
        line,
        payloadType,
        data
    );
}

} // namespace SR
