#include "SRPhaseTimelineEntryJsonlParser.h"

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>


#include "SRJobTypes.h"
#include "SRPhaseTimelineEntrySchema.h"

#include "TextHelpers.h"

namespace SR {
namespace {

bool TryRetrieveJsonPayloadType_(
    const std::string& tokenizedLine,
    std::size_t& position,
    JobPayloadType& payloadType
) {
    std::string_view payloadTypeLine;

    if (!TextHelpers::TryReadLine(
            tokenizedLine,
            position,
            payloadTypeLine
        )) {
        return false;
    }

    std::size_t fieldPosition = 0;
    std::string payloadTypeName;

    if (!TextHelpers::TryParseJsonStringField(
            payloadTypeLine,
            fieldPosition,
            "payloadType",
            payloadTypeName
        ) ||
        fieldPosition != payloadTypeLine.size()) {
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
    const std::string& tokenizedLine,
    std::size_t& position,
    const char* fieldName,
    Parser parser,
    Data& data,
    Member member
) {
    if constexpr (enabled) {
        std::string_view fieldLine;

        if (!TextHelpers::TryReadLine(
                tokenizedLine,
                position,
                fieldLine
            )) {
            return false;
        }

        std::size_t fieldPosition = 0;

        if (!parser(
                fieldLine,
                fieldPosition,
                fieldName,
                data.*member
            ) ||
            fieldPosition != fieldLine.size()) {
            return false;
        }
    }

    return true;
}

bool TryParseSrDiagJsonSchema_(
    const std::string& tokenizedLine,
    std::size_t position,
    SRPhaseTimelineEntrySchemaData::SrDiagData& data
) {
#define SR_PARSE_JSON_FIELD_( \
    member, \
    fieldName, \
    jsonEnabled, \
    jsonFormatter, \
    jsonParser, \
    txtEnabled, \
    txtFormatter, \
    txtParser \
) \
    if (!TryParseJsonField_<jsonEnabled>( \
            tokenizedLine, \
            position, \
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

    return position == tokenizedLine.size();
}

bool TryParseChildStdoutJsonSchema_(
    const std::string& tokenizedLine,
    std::size_t position,
    SRPhaseTimelineEntrySchemaData::ChildStdoutData& data
) {
#define SR_PARSE_JSON_FIELD_( \
    member, \
    fieldName, \
    jsonEnabled, \
    jsonFormatter, \
    jsonParser, \
    txtEnabled, \
    txtFormatter, \
    txtParser \
) \
    if (!TryParseJsonField_<jsonEnabled>( \
            tokenizedLine, \
            position, \
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

    return position == tokenizedLine.size();
}

bool TryParseChildStderrJsonSchema_(
    const std::string& tokenizedLine,
    std::size_t position,
    SRPhaseTimelineEntrySchemaData::ChildStderrData& data
) {
#define SR_PARSE_JSON_FIELD_( \
    member, \
    fieldName, \
    jsonEnabled, \
    jsonFormatter, \
    jsonParser, \
    txtEnabled, \
    txtFormatter, \
    txtParser \
) \
    if (!TryParseJsonField_<jsonEnabled>( \
            tokenizedLine, \
            position, \
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

    return position == tokenizedLine.size();
}


bool TryParseJsonSchemaByPayloadType_(
    const std::string& tokenizedLine,
    std::size_t position,
    JobPayloadType payloadType,
    SRPhaseTimelineEntrySchemaData::SchemaDataVariant& data
) {
    switch (payloadType) {
        case JobPayloadType::SrDiag: {
            SRPhaseTimelineEntrySchemaData::SrDiagData parsedData;

            if (!TryParseSrDiagJsonSchema_(
                    tokenizedLine,
                    position,
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
                    tokenizedLine,
                    position,
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
                    tokenizedLine,
                    position,
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


bool SRPhaseTimelineEntryParser::TryParseJsonLine(
    const std::string& line,
    SRPhaseTimelineEntrySchemaData::SchemaDataVariant& data
) {
    std::string tokenizedLine = line;

    if (!TextHelpers::TryTokenizeCanonicalJsonObject(
            tokenizedLine
        )) {
        return false;
    }

    std::size_t position = 0;
    JobPayloadType payloadType;

    if (!TryRetrieveJsonPayloadType_(
            tokenizedLine,
            position,
            payloadType
        )) {
        return false;
    }

    return TryParseJsonSchemaByPayloadType_(
        tokenizedLine,
        0,
        payloadType,
        data
    );
}


} // namespace SR
