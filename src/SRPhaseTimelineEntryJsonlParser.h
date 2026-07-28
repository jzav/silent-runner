#pragma once

#include <string>

#include "SRPhaseTimelineEntrySchemaData.h"

namespace SR {


// Parses canonical textual phase-timeline entry representations independently
// of where the source bytes were read from or how replay jobs are constructed.
//
// Responsibilities:
// - Parse one complete JSONL record into the corresponding schema data.
// - Parse mixed-stderr TXT segment headers into the corresponding schema data.
// - Maintain the parser side of the field contract defined by
//   SRPhaseTimelineEntrySchema.
//
// Non-responsibilities:
// - Read files or streams.
// - Locate TXT segment boundaries or read TXT payload bytes.
// - Decode, split, or enqueue replay payload jobs.
// - Assign synthetic event order numbers for chunked TXT replay.
//
// JSONL records contain both metadata and payload representation in one
// physical line. Mixed TXT output stores metadata in a header line followed by
// separately framed payload bytes; therefore TXT parsing intentionally stops
// at the segment header.
class SRPhaseTimelineEntryParser {
public:

    // Parses one complete canonical JSONL record and selects the
    // corresponding schema data type from the record's payloadType.
    static bool TryParseJsonLine(
        const std::string& line,
        SRPhaseTimelineEntrySchemaData::SchemaDataVariant& data
    );

    
};


} // namespace SR
