#pragma once

#include <string>

#include "SRPhaseTimelineEntrySchemaData.h"

namespace SR {


// Parses one complete canonical stderr-sr-and-child TXT segment header.
//
// Responsibilities:
// - Parse canonical [field=value] records and consume schema-defined TXT spacing.

// - Retrieve payloadType from the first field.
// - Parse the enabled TXT fields through SRPhaseTimelineEntrySchema.
// - Populate the corresponding schema data variant.
//
// Non-responsibilities:
// - Locate segment boundaries in a TXT stream.
// - Read or interpret the payload following the header.
// - Populate JSON-only payload representation fields.
// - Split payload bytes or construct replay jobs.
class SRPhaseTimelineEntryTxtHeaderParser {
public:

    // The input must contain one complete header without the terminating LF.
    static bool TryParseHeader(
        const std::string& header,
        SRPhaseTimelineEntrySchemaData::SchemaDataVariant& data
    );
};


} // namespace SR
