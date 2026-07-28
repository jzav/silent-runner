#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <vector>
#include <variant>
#include <utility>
#include <string>
#include <cstdint>
#include <cstddef>

#include <memory>

#include "SRRuntimeStopReason.h"
#include "SRTypes.h"
#include "SRTimelineLocationResolveBatch.h"

#include "SRPhaseTimelineEntry.h"

struct PhaseEventStamp {
    SR::LifecyclePhase phase = SR::LifecyclePhase::Runtime;
    uint32_t phaseOrderNo = static_cast<uint32_t>(SR::LifecyclePhase::Runtime);
    uint64_t eventOrderNo = 0;
    std::wstring timestampUtc;
};

// Creates a phase-local event stamp.
// eventOrderNo is the authoritative ordering key within this phase.
// timestampUtc is informational only and must not be used
// as the primary replay/reconstruction ordering source.


// Native ExecutionTimeline-owned event records.
//
// The payload record types are defined in SRPhaseTimelineEntry.h so the
// timeline, pending-job, and worker layers share one entry model.


// Phase-local timeline storage.
//
// PhaseTimeline owns phase-local storage, counters, and event stamping.
// It does not own replay/export policy and does not decide which phase
// an event belongs to. Those decisions belong to ExecutionTimeline.
// The timeline is split per lifecycle phase instead of using
// one global mixed vector so future replay, filtering,
// JSON export, and phase-scoped summaries remain possible
// without reparsing a flattened event stream.
struct PhaseTimeline {
    SR::LifecyclePhase phase = SR::LifecyclePhase::Prepare;
    uint32_t phaseOrderNo = 0;
    std::wstring name;

    std::wstring phaseStartUtc;
    std::wstring phaseEndUtc;

    uint64_t nextEventOrderNo = 0;
    PhaseEventStamp Stamp();
    
    void Reset(
        SR::LifecyclePhase phase,
        uint32_t phaseOrderNo,
        const std::wstring& name
    );
    
    void Start();
    void End();
    
    void AppendSrDiag(
        SR::DiagnosticSeverity severity,
        const std::wstring& message
    );
    
    void AppendChildStdout(
        const char* bytes,
        size_t byteCount,
        SR::ReplayPayloadStorage replayPayloadStorage
    );

    void AppendChildStderr(
        const char* bytes,
        size_t byteCount,
        SR::ReplayPayloadStorage replayPayloadStorage
    );

    void GetAllDelayed(
        const SR::GetAllDelayedFilter& filter,
        SR::JobQueueItems& delayedItems
    );


    
    SR::BufferUsage bufferUsage;

    // Phase-local mixed timeline entries.
    //
    // Each stored event keeps its concrete payload model through
    // SR::TimelineEntryVariant while sharing one event-order stream.
    std::vector<SR::TimelineEntryVariant> entries;


};
