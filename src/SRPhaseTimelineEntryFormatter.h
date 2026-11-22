#pragma once

#include <string>
#include "SRTypes.h"


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
// - Define parseable stderr-sr-and-child TXT block headers.
// - Maintain the TXT block-header contract consumed by the replay reader.
//
// Non-responsibilities:
// - Decide which target or format is enabled.
// - Decide when a stderr-sr-and-child TXT block header is required.
// - Add separators between adjacent blocks.
// - Write or emit the resulting bytes.
//
// The formatter defines individual textual records. Workers define how those
// records are framed into the output stream.
// SRPhaseTimelineEntryFormatter
//     = entry formatting

// TryWriteTxtTarget_
//     = TXT block framing + file writing

// BuildPayloadBytes_
//     = TXT block framing + parent payload serialization

// TryEmitParentTarget_
//     = physical parent emission
class SRPhaseTimelineEntryFormatter {
public:

    // Formats a parseable SrDiag block header for stderr-sr-and-child TXT output.
    // The returned string does not include the terminating LF.
    static std::string FormatSrDiagTxtHeader(
        const SrDiagEntry& entry,
        const std::string& parsingToken,
        const std::wstring& executionId
    );

    // Formats a parseable ChildStdout block header for header-capable TXT output.
    // The returned string does not include the terminating LF.
    static std::string FormatChildStdoutTxtHeader(
        const ChildStdoutEntry& entry,
        const std::string& parsingToken,
        const std::wstring& executionId
    );

    // Formats a parseable ChildStderr block header for stderr-sr-and-child TXT output.

    // The returned string does not include the terminating LF.
    static std::string FormatChildStderrTxtHeader(
        const ChildStderrEntry& entry,
        const std::string& parsingToken,
        const std::wstring& executionId
    );

    // Formats one complete JSON object without the terminating LF.
    static std::string FormatJsonLine(
        const SrDiagEntry& entry,
        JsonlPayloadRepresentation payloadRepresentationMode,
        const std::wstring& executionId
    );
    static std::string FormatJsonLine(
        const ChildStdoutEntry& entry,
        JsonlPayloadRepresentation payloadRepresentationMode,
        const std::wstring& executionId
    );
    static std::string FormatJsonLine(
        const ChildStderrEntry& entry,
        JsonlPayloadRepresentation payloadRepresentationMode,
        const std::wstring& executionId
    );


};


} // namespace SR
