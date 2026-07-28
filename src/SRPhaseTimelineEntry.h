#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <variant>


#include "SRTypes.h"
#include "SRTimelineIdentity.h"
#include "SRJobTypes.h"

namespace SR {



struct SrDiagEntry {
    static constexpr SR::JobPayloadType payloadType = SR::JobPayloadType::SrDiag;
    
    SR::TimelineEntryKey key;

    std::wstring timestampUtc;

    SR::DiagnosticSeverity severity = SR::DiagnosticSeverity::Info;
    std::wstring message;
    uint64_t payloadByteCount = 0;
    SR::ReplayPayloadStorage replayPayloadStorage =
        SR::ReplayPayloadStorage::Store;


    EventJobResults jobResults;
};

struct ChildStdoutEntry {
    static constexpr SR::JobPayloadType payloadType = SR::JobPayloadType::ChildStdout;
    
    SR::TimelineEntryKey key{ SR::LifecyclePhase::Runtime, 0, 0 };

    std::wstring timestampUtc;

    std::vector<char> bytes;
    uint64_t payloadByteCount = 0;
    SR::ReplayPayloadStorage replayPayloadStorage =
        SR::ReplayPayloadStorage::Store;


    EventJobResults jobResults;
};

struct ChildStderrEntry {
    static constexpr SR::JobPayloadType payloadType = SR::JobPayloadType::ChildStderr;
    
    SR::TimelineEntryKey key{ SR::LifecyclePhase::Runtime, 0, 0 };
    std::wstring timestampUtc;

    std::vector<char> bytes;
    uint64_t payloadByteCount = 0;
    SR::ReplayPayloadStorage replayPayloadStorage =
        SR::ReplayPayloadStorage::Store;

    EventJobResults jobResults;
};

using TimelineEntryVariant = std::variant<
    SrDiagEntry,
    ChildStdoutEntry,
    ChildStderrEntry
>;


bool IsJobResultPruneable(const EventJobResult& result) noexcept;
bool AreAllJobResultsPruneable(
    JobPayloadType payloadType,
    const EventJobResults& results
) noexcept;

} // namespace SR
