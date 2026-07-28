#pragma once

#include <string>

namespace SR {

struct SrDiagEntry;
struct ChildStdoutEntry;
struct ChildStderrEntry;


// Defines the canonical textual representation of phase-timeline entries
// independently of where the resulting bytes are written or emitted.
//
// Responsibilities:
// - Convert SrDiag, ChildStdout, and ChildStderr entries to their textual
//   representations.
// - Define JSONL field names, ordering, and value encoding.
// - Define parseable mixed-stderr TXT segment headers.
// - Maintain the TXT segment-header contract consumed by the replay reader.
//
// Non-responsibilities:
// - Decide which target or format is enabled.
// - Decide when a mixed TXT segment header is required.
// - Add separators between adjacent segments.
// - Write or emit the resulting bytes.
//
// The formatter defines individual textual records. Workers define how those
// records are framed into the output stream.
// SRPhaseTimelineEntryFormatter
//     = entry formatting

// TryWriteTxtTarget_
//     = TXT segment framing + file writing

// BuildPayloadBytes_
//     = TXT segment framing + parent payload serialization

// TryEmitParentTarget_
//     = physical parent emission
class SRPhaseTimelineEntryFormatter {
public:

    // Formats a parseable SrDiag segment header for mixed TXT output.
    // The returned string does not include the terminating LF.
    static std::string FormatSrDiagTxtHeader(
        const SrDiagEntry& entry,
        const std::string& parsingToken
    );

    // Formats a parseable ChildStderr segment header for mixed TXT output.
    // The returned string does not include the terminating LF.
    static std::string FormatChildStderrTxtHeader(
        const ChildStderrEntry& entry,
        const std::string& parsingToken
    );

    // Formats one complete JSON object without the terminating LF.
    static std::string FormatJsonLine(const SrDiagEntry& entry);
    static std::string FormatJsonLine(const ChildStdoutEntry& entry);
    static std::string FormatJsonLine(const ChildStderrEntry& entry);
};


} // namespace SR
