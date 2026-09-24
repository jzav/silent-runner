#pragma once

#include <string>

#include "SRPhaseTimelineEntrySchemaData.h"

namespace SR {

// Parses one complete canonical JSONL phase-timeline record according to
// SRPhaseTimelineEntrySchema.
//
// Responsibilities:
// - Determine the schema variant from payloadType.
// - Parse all JSON-enabled schema fields in canonical schema order.
// - Require the complete JSON object to match the selected schema.
//
// Non-responsibilities:
// - Read files or streams.
// - Decode replay payload representations.
// - Build or enqueue replay jobs.
class SRPhaseTimelineEntryJsonlParser {
public:
    static bool TryParseLine(
        const std::string& line,
        SRPhaseTimelineEntrySchemaData::SchemaDataVariant& data
    );
};

} // namespace SR
