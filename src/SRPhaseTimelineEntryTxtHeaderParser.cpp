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


bool TryReadTxtField_(
    std::string_view header,
    std::size_t& position,
    std::string_view& field
) noexcept {
    if (position >= header.size() ||
        header[position] != '[') {
        return false;
    }

    const std::size_t fieldEnd = header.find(']', position + 1);
    if (fieldEnd == std::string_view::npos) {
        return false;
    }

    field = header.substr(
        position,
        fieldEnd - position + 1
    );
    position = fieldEnd + 1;
    return true;
}

bool TryConsumeTxtSpaces_(
    std::string_view header,
    std::size_t& position,
    std::size_t spaceCount
) noexcept {
    if (position > header.size() ||
        header.size() - position < spaceCount) {
        return false;
    }

    for (std::size_t i = 0; i < spaceCount; ++i) {
        if (header[position + i] != ' ') {
            return false;
        }
    }

    position += spaceCount;
    return true;
}

bool TryRetrieveTxtPayloadType_(
    const std::string& header,
    JobPayloadType& payloadType
) {
    std::size_t position = 0;
    std::string_view payloadTypeField;
    std::string payloadTypeName;

    if (!TryReadTxtField_(
            header,
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
    const std::string& header,
    std::size_t& position,
    const char* fieldName,
    Parser parser,
    Data& data,
    Member member,
    std::size_t txtSpacesAfter
) {
    if constexpr (enabled) {
        std::string_view field;

        if (!TryReadTxtField_(
                header,
                position,
                field
            ) ||
            !parser(
                field,
                fieldName,
                data.*member
            ) ||
            !TryConsumeTxtSpaces_(
                header,
                position,
                txtSpacesAfter
            )) {
            return false;
        }
    }

    return true;
}


bool TryParseSrDiagTxtSchema_(
    const std::string& header,
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
    txtParser, \
    txtSpacesAfter \
) \
    if (!TryParseTxtField_<txtEnabled>( \
            header, \
            position, \
            fieldName, \
            txtParser, \
            data, \
            member, \
            txtSpacesAfter \
        )) { \
        return false; \
    }

    SR_PHASE_TIMELINE_SR_DIAG_SCHEMA_FIELD_TABLE(
        SR_PARSE_TXT_FIELD_
    )

#undef SR_PARSE_TXT_FIELD_

    return position == header.size();
}


bool TryParseChildStdoutTxtSchema_(
    const std::string& header,
    std::size_t position,
    SRPhaseTimelineEntrySchemaData::ChildStdoutData& data
) {
#define SR_PARSE_TXT_FIELD_( \
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
    if (!TryParseTxtField_<txtEnabled>( \
            header, \
            position, \
            fieldName, \
            txtParser, \
            data, \
            member, \
            txtSpacesAfter \
        )) { \
        return false; \
    }

    SR_PHASE_TIMELINE_CHILD_STDOUT_SCHEMA_FIELD_TABLE(
        SR_PARSE_TXT_FIELD_
    )

#undef SR_PARSE_TXT_FIELD_

    return position == header.size();
}

bool TryParseChildStderrTxtSchema_(
    const std::string& header,
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
    txtParser, \
    txtSpacesAfter \
) \
    if (!TryParseTxtField_<txtEnabled>( \
            header, \
            position, \
            fieldName, \
            txtParser, \
            data, \
            member, \
            txtSpacesAfter \
        )) { \
        return false; \
    }

    SR_PHASE_TIMELINE_CHILD_STDERR_SCHEMA_FIELD_TABLE(
        SR_PARSE_TXT_FIELD_
    )

#undef SR_PARSE_TXT_FIELD_

    return position == header.size();
}



bool TryParseTxtSchemaByPayloadType_(
    const std::string& header,
    JobPayloadType payloadType,
    SRPhaseTimelineEntrySchemaData::SchemaDataVariant& data
) {
    switch (payloadType) {
        case JobPayloadType::SrDiag: {
            SRPhaseTimelineEntrySchemaData::SrDiagData parsedData;

            if (!TryParseSrDiagTxtSchema_(
                    header,
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
                    header,
                    0,
                    parsedData
                )) {
                return false;
            }

            data = std::move(parsedData);
            return true;
        }

        case JobPayloadType::ChildStdout: {
            SRPhaseTimelineEntrySchemaData::ChildStdoutData parsedData;
            if (!TryParseChildStdoutTxtSchema_(
                    header,
                    0,
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


bool SRPhaseTimelineEntryTxtHeaderParser::TryParseHeader(
    const std::string& header,
    SRPhaseTimelineEntrySchemaData::SchemaDataVariant& data
) {
    if (header.size() < 2 ||
        header.front() != '[' ||
        header.back() != ']') {
        return false;
    }

    JobPayloadType payloadType;

    if (!TryRetrieveTxtPayloadType_(
            header,
            payloadType
        )) {
        return false;
    }

    return TryParseTxtSchemaByPayloadType_(
        header,
        payloadType,
        data
    );
}



} // namespace SR
