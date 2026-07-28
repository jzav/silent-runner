#include "SRPhaseTimelineEntryTxtHeaderParser.h"

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>

#include "SRJobTypes.h"
#include "SRPhaseTimelineEntrySchema.h"

#include "TextHelpers.h"

namespace SR {
namespace {



bool TryRetrieveTxtJobPayloadTypeByName_(
    const std::string& name,
    JobPayloadType& payloadType
) {
#define SR_RETRIEVE_TXT_JOB_PAYLOAD_TYPE_(typeName, text) \
    if (name == TextHelpers::ToUpperAsciiCopy(text)) { \
        payloadType = JobPayloadType::typeName; \
        return true; \
    }

    SR_JOB_PAYLOAD_TYPE_TABLE(
        SR_RETRIEVE_TXT_JOB_PAYLOAD_TYPE_
    )

#undef SR_RETRIEVE_TXT_JOB_PAYLOAD_TYPE_

    return false;
}


bool TryRetrieveTxtPayloadType_(
    const std::string& tokenizedHeader,
    std::size_t& position,
    JobPayloadType& payloadType
) {
    std::string_view payloadTypeField;
    std::string payloadTypeName;

    if (!TextHelpers::TryReadLine(
            tokenizedHeader,
            position,
            payloadTypeField
        ) ||
        !TextHelpers::TryParseTxtStringField(
            payloadTypeField,
            "payloadType",
            payloadTypeName
        )) {
        return false;
    }

    return TryRetrieveTxtJobPayloadTypeByName_(
        payloadTypeName,
        payloadType
    );
}



// Templated helper allows TXT-disabled schema rows to use nullptr parsers.
// if constexpr prevents instantiation of the disabled parser call.
template <
    bool enabled,
    typename Parser,
    typename Data,
    typename Member
>
bool TryParseTxtField_(
    const std::string& tokenizedHeader,
    std::size_t& position,
    const char* fieldName,
    Parser parser,
    Data& data,
    Member member
) {
    if constexpr (enabled) {
        std::string_view field;

        if (!TextHelpers::TryReadLine(
                tokenizedHeader,
                position,
                field
            ) ||
            !parser(
                field,
                fieldName,
                data.*member
            )) {
            return false;
        }
    }


    return true;
}


bool TryParseSrDiagTxtSchema_(
    const std::string& tokenizedHeader,
    std::size_t position,
    SRPhaseTimelineEntrySchemaData::SrDiagData& data
) {
#define SR_PARSE_TXT_FIELD_( \
    member, \
    fieldName, \
    jsonEnabled, \
    jsonFormatter, \
    jsonParser, \
    txtEnabled, \
    txtFormatter, \
    txtParser \
) \
    if (!TryParseTxtField_<txtEnabled>( \
            tokenizedHeader, \
            position, \
            fieldName, \
            txtParser, \
            data, \
            member \
        )) { \
        return false; \
    }

    SR_PHASE_TIMELINE_SR_DIAG_SCHEMA_FIELD_TABLE(
        SR_PARSE_TXT_FIELD_
    )

#undef SR_PARSE_TXT_FIELD_

    return position == tokenizedHeader.size();
}


bool TryParseChildStderrTxtSchema_(
    const std::string& tokenizedHeader,
    std::size_t position,
    SRPhaseTimelineEntrySchemaData::ChildStderrData& data
) {
#define SR_PARSE_TXT_FIELD_( \
    member, \
    fieldName, \
    jsonEnabled, \
    jsonFormatter, \
    jsonParser, \
    txtEnabled, \
    txtFormatter, \
    txtParser \
) \
    if (!TryParseTxtField_<txtEnabled>( \
            tokenizedHeader, \
            position, \
            fieldName, \
            txtParser, \
            data, \
            member \
        )) { \
        return false; \
    }

    SR_PHASE_TIMELINE_CHILD_STDERR_SCHEMA_FIELD_TABLE(
        SR_PARSE_TXT_FIELD_
    )

#undef SR_PARSE_TXT_FIELD_

    return position == tokenizedHeader.size();
}


bool TryParseTxtSchemaByPayloadType_(
    const std::string& tokenizedHeader,
    JobPayloadType payloadType,
    SRPhaseTimelineEntrySchemaData::SchemaDataVariant& data
) {
    switch (payloadType) {
        case JobPayloadType::SrDiag: {
            SRPhaseTimelineEntrySchemaData::SrDiagData parsedData;

            if (!TryParseSrDiagTxtSchema_(
                    tokenizedHeader,
                    0,
                    parsedData
                )) {
                return false;
            }

            data = std::move(parsedData);
            return true;
        }

        case JobPayloadType::ChildStderr: {
            SRPhaseTimelineEntrySchemaData::ChildStderrData parsedData;

            if (!TryParseChildStderrTxtSchema_(
                    tokenizedHeader,
                    0,
                    parsedData
                )) {
                return false;
            }

            data = std::move(parsedData);
            return true;
        }

        case JobPayloadType::ChildStdout:
            return false;
    }

    return false;
}

} // namespace


bool SRPhaseTimelineEntryTxtHeaderParser::TryParseHeader(
    const std::string& header,
    SRPhaseTimelineEntrySchemaData::SchemaDataVariant& data
) {
    std::string tokenizedHeader = header;

    if (tokenizedHeader.size() < 2 ||
        tokenizedHeader.front() != '[' ||
        tokenizedHeader.back() != ']') {
        return false;
    }

    TextHelpers::ReplaceAll(
        tokenizedHeader,
        "][",
        "]\n["
    );

    std::size_t position = 0;
    JobPayloadType payloadType;

    if (!TryRetrieveTxtPayloadType_(
            tokenizedHeader,
            position,
            payloadType
        )) {
        return false;
    }

    return TryParseTxtSchemaByPayloadType_(
        tokenizedHeader,
        payloadType,
        data
    );
}


} // namespace SR
