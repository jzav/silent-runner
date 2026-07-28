#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <array>
#include <cstdint>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "SRTypes.h"
#include "SRTimelineIdentity.h"

// Shared job contract between ExecutionTimeline and worker layers.
//
// ExecutionTimeline owns job state and queue semantics.
// Workers receive PendingJobs, execute or classify them using their policy,
// and return JobResults. Workers do not own timeline state.

namespace SR {


#define SR_JOB_TARGET_TABLE(X) \
    /* Columns: name, text, stream, channel, format, worker, workerConfigIndex, headerParsingTokenEnabled */ \
    X(StdoutParent, "StdoutParent", Stdout, None, Parent, SRParentEmitWorker, 0, false) \
    X(StderrMixedParent, "StderrMixedParent", Stderr, Mixed, Parent, SRParentEmitWorker, 1, true) \
    X(StderrChildParent, "StderrChildParent", Stderr, Child, Parent, SRParentEmitWorker, 2, false) \
    X(StderrSrParent, "StderrSrParent", Stderr, Sr, Parent, SRParentEmitWorker, 3, true) \
    X(StdoutTxt, "StdoutTxt", Stdout, None, Txt, SRFileSinkWorker, 0, false) \
    X(StderrMixedTxt, "StderrMixedTxt", Stderr, Mixed, Txt, SRFileSinkWorker, 1, true) \
    X(StderrChildTxt, "StderrChildTxt", Stderr, Child, Txt, SRFileSinkWorker, 2, false) \
    X(StderrSrTxt, "StderrSrTxt", Stderr, Sr, Txt, SRFileSinkWorker, 3, true) \
    X(StdoutJsonl, "StdoutJsonl", Stdout, None, Jsonl, SRFileSinkWorker, 4, false) \
    X(StderrMixedJsonl, "StderrMixedJsonl", Stderr, Mixed, Jsonl, SRFileSinkWorker, 5, false) \
    X(StderrChildJsonl, "StderrChildJsonl", Stderr, Child, Jsonl, SRFileSinkWorker, 6, false) \
    X(StderrSrJsonl, "StderrSrJsonl", Stderr, Sr, Jsonl, SRFileSinkWorker, 7, false)




enum class JobTarget {
#define SR_X_ENUM_JOB_TARGET(name, text, stream, channel, format, worker, workerConfigIndex, headerParsingTokenEnabled) name,


    SR_JOB_TARGET_TABLE(SR_X_ENUM_JOB_TARGET)
#undef SR_X_ENUM_JOB_TARGET
};

static inline constexpr JobTarget RetrieveStderrJobTarget(
    StderrEmitSource source
) noexcept {
    switch (source) {
#define SR_X_STDERR_EMIT_SOURCE_PARENT_TARGET(name, wptr, help, target) \
        case StderrEmitSource::name: \
            return JobTarget::target;
        SR_STDERR_EMIT_SOURCE_TABLE(
            SR_X_STDERR_EMIT_SOURCE_PARENT_TARGET
        )
#undef SR_X_STDERR_EMIT_SOURCE_PARENT_TARGET
    }

    return JobTarget::StderrMixedParent;
}



static inline constexpr bool TryRetrieveStderrEmitSource(
    JobTarget target,
    StderrEmitSource& source
) noexcept {
    switch (target) {
#define SR_X_STDERR_PARENT_TARGET_EMIT_SOURCE(name, wptr, help, parentTarget) \
        case JobTarget::parentTarget: \
            source = StderrEmitSource::name; \
            return true;

        SR_STDERR_EMIT_SOURCE_TABLE(
            SR_X_STDERR_PARENT_TARGET_EMIT_SOURCE
        )

#undef SR_X_STDERR_PARENT_TARGET_EMIT_SOURCE

        default:
            return false;
    }
}

#undef SR_STDERR_EMIT_SOURCE_TABLE

static constexpr std::size_t kJobTargetCount =
    0
#define SR_X_COUNT_JOB_TARGET(name, text, stream, channel, format, worker, workerConfigIndex, headerParsingTokenEnabled) + 1


    SR_JOB_TARGET_TABLE(SR_X_COUNT_JOB_TARGET)
#undef SR_X_COUNT_JOB_TARGET
;

static inline const char* JobTargetName(JobTarget target) noexcept {
    switch (target) {
#define SR_X_JOB_TARGET_NAME(name, text, stream, channel, format, worker, workerConfigIndex, headerParsingTokenEnabled) case JobTarget::name: return text;


        SR_JOB_TARGET_TABLE(SR_X_JOB_TARGET_NAME)
#undef SR_X_JOB_TARGET_NAME
    }

    return "Unknown";
}
static inline const wchar_t* JobTargetNameToString(JobTarget target) noexcept {
    switch (target) {
#define SR_X_JOB_TARGET_NAME_TO_STRING(name, text, stream, channel, format, worker, workerConfigIndex, headerParsingTokenEnabled) case JobTarget::name: return L##text;


        SR_JOB_TARGET_TABLE(SR_X_JOB_TARGET_NAME_TO_STRING)
#undef SR_X_JOB_TARGET_NAME_TO_STRING
    }

    return L"Unknown";
}

enum class JobTargetChannel {
    None,
    Mixed,
    Child,
    Sr
};

enum class ReplayPreference : unsigned {
    None = 0,
    Priority1 = 1,
    Priority2 = 2,
    Priority3 = 3,
    Priority4 = 4,
    Priority5 = 5
};

#define SR_JOB_TARGET_FORMAT_TABLE(X) \
    X(Parent, L"parent", ReplayPreference::None) \
    X(Txt,    L"txt",    ReplayPreference::Priority2) \
    X(Jsonl,  L"jsonl",  ReplayPreference::Priority1)

enum class JobTargetFormat {
#define SR_X_ENUM_JOB_TARGET_FORMAT(name, text, replayPreference) name,
    SR_JOB_TARGET_FORMAT_TABLE(SR_X_ENUM_JOB_TARGET_FORMAT)
#undef SR_X_ENUM_JOB_TARGET_FORMAT
};

enum class JobTargetStream {
    Stdout,
    Stderr
};

#define SR_JOB_TARGET_WORKER_TABLE(X) \
    X(SRParentEmitWorker, "SRParentEmitWorker") \
    X(SRFileSinkWorker, "SRFileSinkWorker")

enum class JobTargetWorker {
#define SR_X_ENUM_JOB_TARGET_WORKER(name, text) name,
    SR_JOB_TARGET_WORKER_TABLE(SR_X_ENUM_JOB_TARGET_WORKER)
#undef SR_X_ENUM_JOB_TARGET_WORKER
};

static inline const wchar_t* JobTargetWorkerNameToString(
    JobTargetWorker worker
) noexcept {
    switch (worker) {
#define SR_X_JOB_TARGET_WORKER_NAME_TO_STRING(name, text) case JobTargetWorker::name: return L##text;
        SR_JOB_TARGET_WORKER_TABLE(SR_X_JOB_TARGET_WORKER_NAME_TO_STRING)
#undef SR_X_JOB_TARGET_WORKER_NAME_TO_STRING
    }

    return L"Unknown";
}

static inline JobTargetChannel JobTargetChannelOf(
    JobTarget target
) noexcept {
    switch (target) {
#define SR_X_JOB_TARGET_CHANNEL(name, text, stream, channel, format, worker, workerConfigIndex, headerParsingTokenEnabled) \
        case JobTarget::name: \
            return JobTargetChannel::channel;


        SR_JOB_TARGET_TABLE(SR_X_JOB_TARGET_CHANNEL)
#undef SR_X_JOB_TARGET_CHANNEL
    }

    return JobTargetChannel::None;
}

static inline JobTargetStream JobTargetStreamOf(
    JobTarget target
) noexcept {
    switch (target) {
#define SR_X_JOB_TARGET_STREAM(name, text, stream, channel, format, worker, workerConfigIndex, headerParsingTokenEnabled) \
        case JobTarget::name: \
            return JobTargetStream::stream;


        SR_JOB_TARGET_TABLE(SR_X_JOB_TARGET_STREAM)
#undef SR_X_JOB_TARGET_STREAM
    }

    return JobTargetStream::Stdout;
}
static inline JobTargetFormat JobTargetFormatOf(JobTarget target) noexcept {
    switch (target) {
#define SR_X_JOB_TARGET_FORMAT(name, text, stream, channel, format, worker, workerConfigIndex, headerParsingTokenEnabled) case JobTarget::name: return JobTargetFormat::format;


        SR_JOB_TARGET_TABLE(SR_X_JOB_TARGET_FORMAT)
#undef SR_X_JOB_TARGET_FORMAT
    }

    return JobTargetFormat::Parent;
}
static inline ReplayPreference JobTargetFormatReplayPreferenceOf(
    JobTargetFormat format
) noexcept {
    switch (format) {
#define SR_X_JOB_TARGET_FORMAT_REPLAY_PREFERENCE(name, text, replayPreference) \
        case JobTargetFormat::name: \
            return replayPreference;

        SR_JOB_TARGET_FORMAT_TABLE(
            SR_X_JOB_TARGET_FORMAT_REPLAY_PREFERENCE
        )

#undef SR_X_JOB_TARGET_FORMAT_REPLAY_PREFERENCE
    }

    return ReplayPreference::None;
}

static inline JobTargetWorker JobTargetWorkerOf(JobTarget target) noexcept {
    switch (target) {
#define SR_X_JOB_TARGET_WORKER(name, text, stream, channel, format, worker, workerConfigIndex, headerParsingTokenEnabled) case JobTarget::name: return JobTargetWorker::worker;


        SR_JOB_TARGET_TABLE(SR_X_JOB_TARGET_WORKER)
#undef SR_X_JOB_TARGET_WORKER
    }

    return JobTargetWorker::SRParentEmitWorker;
}
static inline std::size_t JobTargetWorkerConfigIndexOf(
    JobTarget target
) noexcept {
    switch (target) {
#define SR_X_JOB_TARGET_WORKER_CONFIG_INDEX(name, text, stream, channel, format, worker, workerConfigIndex, headerParsingTokenEnabled) case JobTarget::name: return workerConfigIndex;

        SR_JOB_TARGET_TABLE(SR_X_JOB_TARGET_WORKER_CONFIG_INDEX)
#undef SR_X_JOB_TARGET_WORKER_CONFIG_INDEX
    }

    return 0;
}

    static constexpr std::size_t kParentTargetConfigCount =
        0
#define SR_X_COUNT_PARENT_TARGET_CONFIG(name, text, stream, channel, format, worker, workerConfigIndex, headerParsingTokenEnabled) \
        + (SR::JobTargetWorker::worker == \
           SR::JobTargetWorker::SRParentEmitWorker ? 1u : 0u)
        SR_JOB_TARGET_TABLE(SR_X_COUNT_PARENT_TARGET_CONFIG)
#undef SR_X_COUNT_PARENT_TARGET_CONFIG
    ;
    static constexpr std::size_t kFileSinkTargetConfigCount =
        0
#define SR_X_COUNT_FILE_SINK_TARGET_CONFIG(name, text, stream, channel, format, worker, workerConfigIndex, headerParsingTokenEnabled) \
        + (SR::JobTargetWorker::worker == \
           SR::JobTargetWorker::SRFileSinkWorker ? 1u : 0u)
        SR_JOB_TARGET_TABLE(SR_X_COUNT_FILE_SINK_TARGET_CONFIG)
#undef SR_X_COUNT_FILE_SINK_TARGET_CONFIG
    ;


struct JobTargetFilter {
    std::optional<JobTarget> target;
    std::optional<std::string_view> text;
    std::optional<JobTargetStream> stream;
    std::optional<JobTargetChannel> channel;
    std::optional<JobTargetFormat> format;
    std::optional<JobTargetWorker> worker;
    std::optional<std::size_t> workerConfigIndex;

    std::optional<bool> headerParsingTokenEnabled;
};

static inline std::vector<JobTarget> RetrieveJobTargets(
    const JobTargetFilter& filter
) {
    std::vector<JobTarget> targets;

#define SR_X_RETRIEVE_JOB_TARGET( \
    tableName, \
    tableText, \
    tableStream, \
    tableChannel, \
    tableFormat, \
    tableWorker, \
    tableWorkerConfigIndex, \
    tableHeaderParsingTokenEnabled \
) \
    if ((!filter.target || *filter.target == JobTarget::tableName) && \
        (!filter.text || *filter.text == tableText) && \
        (!filter.stream || *filter.stream == JobTargetStream::tableStream) && \
        (!filter.channel || *filter.channel == JobTargetChannel::tableChannel) && \
        (!filter.format || *filter.format == JobTargetFormat::tableFormat) && \
        (!filter.worker || *filter.worker == JobTargetWorker::tableWorker) && \
        (!filter.workerConfigIndex || \
         *filter.workerConfigIndex == tableWorkerConfigIndex) && \
        (!filter.headerParsingTokenEnabled || \
         *filter.headerParsingTokenEnabled == tableHeaderParsingTokenEnabled)) { \
        targets.push_back(JobTarget::tableName); \
    }

    SR_JOB_TARGET_TABLE(SR_X_RETRIEVE_JOB_TARGET)

#undef SR_X_RETRIEVE_JOB_TARGET

    return targets;
}



#define SR_JOB_PAYLOAD_TYPE_TABLE(X) \
    X(SrDiag, "SrDiag") \
    X(ChildStdout, "ChildStdout") \
    X(ChildStderr, "ChildStderr")
    
#define SR_JOB_TARGET_PAYLOAD_TYPE_TABLE(X) \
    X(StdoutParent, ChildStdout) \
    X(StderrMixedParent, ChildStderr) \
    X(StderrMixedParent, SrDiag) \
    X(StderrChildParent, ChildStderr) \
    X(StderrSrParent, SrDiag) \
    X(StdoutTxt, ChildStdout) \
    X(StderrMixedTxt, ChildStderr) \
    X(StderrMixedTxt, SrDiag) \
    X(StderrChildTxt, ChildStderr) \
    X(StderrSrTxt, SrDiag) \
    X(StdoutJsonl, ChildStdout) \
    X(StderrMixedJsonl, ChildStderr) \
    X(StderrMixedJsonl, SrDiag) \
    X(StderrChildJsonl, ChildStderr) \
    X(StderrSrJsonl, SrDiag)

enum class JobPayloadType {
#define SR_X_ENUM_JOB_PAYLOAD_TYPE(name, text) name,
    SR_JOB_PAYLOAD_TYPE_TABLE(SR_X_ENUM_JOB_PAYLOAD_TYPE)
#undef SR_X_ENUM_JOB_PAYLOAD_TYPE
};

static inline const char* JobPayloadTypeName(JobPayloadType payloadType) noexcept {
    switch (payloadType) {
#define SR_X_JOB_PAYLOAD_TYPE_NAME(name, text) case JobPayloadType::name: return text;
        SR_JOB_PAYLOAD_TYPE_TABLE(SR_X_JOB_PAYLOAD_TYPE_NAME)
#undef SR_X_JOB_PAYLOAD_TYPE_NAME
    }

    return "Unknown";
}
static inline const wchar_t* JobPayloadTypeNameToString(JobPayloadType payloadType) noexcept {
    switch (payloadType) {
#define SR_X_JOB_PAYLOAD_TYPE_NAME_TO_STRING(name, text) case JobPayloadType::name: return L##text;
        SR_JOB_PAYLOAD_TYPE_TABLE(SR_X_JOB_PAYLOAD_TYPE_NAME_TO_STRING)
#undef SR_X_JOB_PAYLOAD_TYPE_NAME_TO_STRING
    }

    return L"Unknown";
}

static inline bool TryRetrieveJobPayloadTypeByName(
    const std::string& name,
    JobPayloadType& payloadType
) noexcept {
#define SR_X_RETRIEVE_JOB_PAYLOAD_TYPE_BY_NAME(typeName, text) \
    if (name == text) { payloadType = JobPayloadType::typeName; return true; }

    SR_JOB_PAYLOAD_TYPE_TABLE(
        SR_X_RETRIEVE_JOB_PAYLOAD_TYPE_BY_NAME
    )

#undef SR_X_RETRIEVE_JOB_PAYLOAD_TYPE_BY_NAME

    return false;
}

struct JobTargetPayloadRoute {
    JobTarget target;
    JobPayloadType payloadType;
};

static constexpr JobTargetPayloadRoute kJobTargetPayloadRoutes[] = {
#define SR_X_JOB_TARGET_PAYLOAD_ROUTE(targetName, payloadTypeName) \
    { JobTarget::targetName, JobPayloadType::payloadTypeName },
    SR_JOB_TARGET_PAYLOAD_TYPE_TABLE(SR_X_JOB_TARGET_PAYLOAD_ROUTE)
#undef SR_X_JOB_TARGET_PAYLOAD_ROUTE
};

static inline bool CanRouteJobPayloadTypeToTarget(
    JobPayloadType payloadType,
    JobTarget target
) noexcept {
    for (const JobTargetPayloadRoute& route : kJobTargetPayloadRoutes) {
        if (route.payloadType == payloadType &&
            route.target == target) {
            return true;
        }
    }

    return false;
}

static inline std::vector<JobTarget> RetrieveTargetsForPayloadType(
    JobPayloadType payloadType,
    JobTargetWorker worker
) {
    std::vector<JobTarget> targets;

    for (const JobTargetPayloadRoute& route : kJobTargetPayloadRoutes) {
        if (route.payloadType == payloadType &&
            JobTargetWorkerOf(route.target) == worker) {
            targets.push_back(route.target);
        }
    }

    return targets;
}



#define SR_JOB_STATE_TABLE(X) \
    X(Pending, "Pending", AllowedPendingTransition, false) \
    X(Delayed, "Delayed", AllowedDelayedTransition, false) \
    X(Ok, "Ok", Final, true) \
    X(Failed, "Failed", Final, false) \
    X(Suppressed, "Suppressed", Final, true) \
    X(Ignored, "Ignored", Final, true)

#define SR_PARENT_TARGET_ACTION_TABLE(X) \
    X(Emit,   std::nullopt) \
    X(Delay,  JobState::Delayed) \
    X(Ignore, JobState::Ignored)

#define SR_ALLOWED_PENDING_JOB_STATE_TRANSITIONS(X) \
    X(Delayed) \
    X(Ok) \
    X(Failed) \
    X(Suppressed) \
    X(Ignored)

#define SR_ALLOWED_DELAYED_JOB_STATE_TRANSITIONS(X) \
    X(Ok) \
    X(Failed) \
    X(Suppressed) \
    X(Ignored)

enum class JobState {
#define SR_X_ENUM_JOB_STATE(name, text, transitionPolicy, pruneable) name,
    SR_JOB_STATE_TABLE(SR_X_ENUM_JOB_STATE)
#undef SR_X_ENUM_JOB_STATE
};

static inline std::optional<JobState> RetrieveParentTargetActionJobState(
    ParentTargetAction action
) noexcept {
    switch (action) {
#define SR_X_PARENT_TARGET_ACTION_JOB_STATE(name, jobState) \
        case ParentTargetAction::name: return jobState;
        SR_PARENT_TARGET_ACTION_TABLE(
            SR_X_PARENT_TARGET_ACTION_JOB_STATE
        )
#undef SR_X_PARENT_TARGET_ACTION_JOB_STATE
    }

    return std::nullopt;
}

enum class JobStateTransitionPolicy {
    AllowedPendingTransition,
    AllowedDelayedTransition,
    Final
};

static inline const char* JobStateName(JobState state) noexcept {
    switch (state) {
#define SR_X_JOB_STATE_NAME(name, text, transitionPolicy, pruneable) case JobState::name: return text;
        SR_JOB_STATE_TABLE(SR_X_JOB_STATE_NAME)
#undef SR_X_JOB_STATE_NAME
    }

    return "Unknown";
}
static inline const wchar_t* JobStateNameToString(JobState state) noexcept {
    switch (state) {
#define SR_X_JOB_STATE_NAME_TO_STRING(name, text, transitionPolicy, pruneable) case JobState::name: return L##text;
        SR_JOB_STATE_TABLE(SR_X_JOB_STATE_NAME_TO_STRING)
#undef SR_X_JOB_STATE_NAME_TO_STRING
    }

    return L"Unknown";
}

static inline JobStateTransitionPolicy JobStateTransitionPolicyOf(JobState state) noexcept {
    switch (state) {
#define SR_X_JOB_STATE_TRANSITION_POLICY(name, text, transitionPolicy, pruneable) \
        case JobState::name: return JobStateTransitionPolicy::transitionPolicy;
        SR_JOB_STATE_TABLE(SR_X_JOB_STATE_TRANSITION_POLICY)
#undef SR_X_JOB_STATE_TRANSITION_POLICY
    }

    return JobStateTransitionPolicy::Final;
}

static inline bool IsPruneableJobState(JobState state) noexcept {
    switch (state) {
#define SR_X_JOB_STATE_PRUNEABLE(name, text, transitionPolicy, pruneable) case JobState::name: return pruneable;
        SR_JOB_STATE_TABLE(SR_X_JOB_STATE_PRUNEABLE)
#undef SR_X_JOB_STATE_PRUNEABLE
    }

    return false;
}

static inline bool IsAllowedPendingJobStateTransition(JobState to) noexcept {
    switch (to) {
#define SR_X_ALLOWED_PENDING_JOB_STATE_TRANSITION(name) case JobState::name: return true;
        SR_ALLOWED_PENDING_JOB_STATE_TRANSITIONS(SR_X_ALLOWED_PENDING_JOB_STATE_TRANSITION)
#undef SR_X_ALLOWED_PENDING_JOB_STATE_TRANSITION
    }

    return false;
}

static inline bool IsAllowedDelayedJobStateTransition(JobState to) noexcept {
    switch (to) {
#define SR_X_ALLOWED_DELAYED_JOB_STATE_TRANSITION(name) case JobState::name: return true;
        SR_ALLOWED_DELAYED_JOB_STATE_TRANSITIONS(SR_X_ALLOWED_DELAYED_JOB_STATE_TRANSITION)
#undef SR_X_ALLOWED_DELAYED_JOB_STATE_TRANSITION
    }

    return false;
}

static inline bool CanTransitionJobState(JobState from, JobState to) noexcept {
    switch (JobStateTransitionPolicyOf(from)) {
        case JobStateTransitionPolicy::AllowedPendingTransition:
            return IsAllowedPendingJobStateTransition(to);

        case JobStateTransitionPolicy::AllowedDelayedTransition:
            return IsAllowedDelayedJobStateTransition(to);

        case JobStateTransitionPolicy::Final:
            return false;
    }

    return false;
}



#define SR_JOB_ORIGIN_TABLE(X) \
    X(Timeline, L"timeline") \
    X(TxtReplay, L"txtReplay") \
    X(JsonlReplay, L"jsonlReplay")

enum class JobOrigin {
#define SR_X_JOB_ORIGIN(name, text) name,
    SR_JOB_ORIGIN_TABLE(SR_X_JOB_ORIGIN)
#undef SR_X_JOB_ORIGIN
};

inline constexpr const wchar_t* JobOriginToString(
    JobOrigin origin
) noexcept {
    switch (origin) {
#define SR_X_JOB_ORIGIN(name, text) case JobOrigin::name: return text;
        SR_JOB_ORIGIN_TABLE(SR_X_JOB_ORIGIN)
#undef SR_X_JOB_ORIGIN
    }

    return L"unknown";
}

inline constexpr bool IsFileReplayJobOrigin(
    JobOrigin origin
) noexcept {
    return
        origin == JobOrigin::TxtReplay ||
        origin == JobOrigin::JsonlReplay;
}

struct JobResultDetails {
    DWORD failedReasonGle = 0;
    std::wstring failedReasonText;
    std::wstring ignoredReasonText;
};

struct EventJobResult {
    JobTarget target = JobTarget::StdoutParent;
    JobState state = JobState::Pending;
    JobResultDetails details;
};

struct EventJobResults {
    std::array<EventJobResult, kJobTargetCount> items{{
#define SR_X_EVENT_JOB_RESULT(name, text, stream, channel, format, worker, workerConfigIndex, headerParsingTokenEnabled) EventJobResult{ JobTarget::name },
        SR_JOB_TARGET_TABLE(SR_X_EVENT_JOB_RESULT)
#undef SR_X_EVENT_JOB_RESULT
    }};

    EventJobResult& At(JobTarget target) noexcept {
        return items[static_cast<std::size_t>(target)];
    }

    const EventJobResult& At(JobTarget target) const noexcept {
        return items[static_cast<std::size_t>(target)];
    }
};
using UnobtainableJobResults = EventJobResults;

struct JobResult {
    SR::TimelineEntryKey key;
    JobOrigin origin = JobOrigin::Timeline;

    JobTarget target = JobTarget::StdoutParent;
    JobState state = JobState::Pending;

    JobResultDetails details;
};

using JobResults = std::vector<JobResult>;

} // namespace SR
