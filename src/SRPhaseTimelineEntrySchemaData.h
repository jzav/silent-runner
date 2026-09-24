#pragma once

#include <cstdint>
#include <string>
#include <variant>
#include "SRTypes.h"


namespace SR {

struct SrDiagEntry;
struct ChildStdoutEntry;
struct ChildStderrEntry;


// Defines the canonical schema data prepared from phase-timeline entries
// and consumed by phase-timeline formatters and parsers.
class SRPhaseTimelineEntrySchemaData {
public:
    struct SrDiagData {
        const SrDiagEntry* source = nullptr;
        std::string payloadType;
        std::wstring phase;
        uint64_t phaseOrderNo = 0;
        uint64_t eventOrderNo = 0;
        std::wstring timestampUtc;
        bool payloadDropped = false;
        uint64_t payloadByteCount = 0;
        std::string payloadRepresentation;
        std::wstring payloadText;
        std::string payloadBase64;
        std::wstring severity;
        std::string parsingToken;

        SrDiagData() = default;

        explicit SrDiagData(
            const SrDiagEntry& entry,
            JsonlPayloadRepresentation payloadRepresentationMode =
                JsonlPayloadRepresentation::Text
        );

    };

    struct ChildStdoutData {
        const ChildStdoutEntry* source = nullptr;
        std::string payloadType;
        std::wstring phase;
        uint64_t phaseOrderNo = 0;
        uint64_t eventOrderNo = 0;
        std::wstring timestampUtc;
        bool payloadDropped = false;
        uint64_t payloadByteCount = 0;
        std::string payloadRepresentation;
        std::string payloadText;
        std::string payloadBase64;
        std::string parsingToken;


        ChildStdoutData() = default;

        explicit ChildStdoutData(
            const ChildStdoutEntry& entry,
            JsonlPayloadRepresentation payloadRepresentationMode =
                JsonlPayloadRepresentation::Text
        );

    };

    struct ChildStderrData {
        const ChildStderrEntry* source = nullptr;
        std::string payloadType;
        std::wstring phase;
        uint64_t phaseOrderNo = 0;
        uint64_t eventOrderNo = 0;
        std::wstring timestampUtc;
        bool payloadDropped = false;
        uint64_t payloadByteCount = 0;
        std::string payloadRepresentation;
        std::string payloadText;
        std::string payloadBase64;
        std::string parsingToken;

        ChildStderrData() = default;
        explicit ChildStderrData(
            const ChildStderrEntry& entry,
            JsonlPayloadRepresentation payloadRepresentationMode =
                JsonlPayloadRepresentation::Text
        );


    };
    using SchemaDataVariant = std::variant<
        SrDiagData,
        ChildStdoutData,
        ChildStderrData
    >;
};


} // namespace SR
