#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "SRTypes.h"
#include "SRTimelineIdentity.h"
#include "SRWorkerTypes.h"

// Shared job contract between ExecutionTimeline and worker layers.
//
// ExecutionTimeline owns job state and queue semantics.
// Workers receive PendingJobs, execute or classify them using their policy,
// and return JobResults. Workers do not own timeline state.

namespace SR {


// Persistent TXT targets use headerEnabled to select Headered (true)
// or Raw (false) presentation. JSONL targets use JSON record presentation.
#define SR_JOB_TARGET_TABLE(X) \
    /* Columns: name, text, stream, channel, format, worker, headerEnabled, acceptsSrDiagnostics, configArgument, keepLogConfigArgument, logFileStem, logFileKey, logDiagnosticText */ \
    X(StdoutParent, "StdoutParent", Stdout, None, Parent, SRParentEmitWorker, true, false, StdoutEmit, Count, nullptr, nullptr, nullptr) \
    X(StdoutParentRaw, "StdoutParentRaw", Stdout, None, Parent, SRParentEmitWorker, false, false, StdoutEmitRaw, Count, nullptr, nullptr, nullptr) \
    X(StderrChildParentRaw, "StderrChildParentRaw", Stderr, Child, Parent, SRParentEmitWorker, false, false, StderrEmitChildRaw, Count, nullptr, nullptr, nullptr) \
    X(StderrSrAndChildParent, "StderrSrAndChildParent", Stderr, SrAndChild, Parent, SRParentEmitWorker, true, true, StderrEmit, Count, nullptr, nullptr, nullptr) \
    X(StderrChildParent, "StderrChildParent", Stderr, Child, Parent, SRParentEmitWorker, true, false, StderrEmitChild, Count, nullptr, nullptr, nullptr) \
    X(StderrSrParent, "StderrSrParent", Stderr, Sr, Parent, SRParentEmitWorker, true, true, StderrEmitSr, Count, nullptr, nullptr, nullptr) \
    X(StderrSrAndChildInclStdoutParent, "StderrSrAndChildInclStdoutParent", Stderr, SrAndChildInclStdout, Parent, SRParentEmitWorker, true, true, StderrEmitInclStdout, Count, nullptr, nullptr, nullptr) \
    X(StdoutTxt, "StdoutTxt", Stdout, None, Txt, SRFileSinkWorker, true, false, StdoutDir, StdoutDirKeepLog, L"stdout", L"SILENTRUNNER_STDOUT_LOG", L"stdout log") \
    X(StdoutTxtRaw, "StdoutTxtRaw", Stdout, None, Txt, SRFileSinkWorker, false, false, StdoutDirRaw, StdoutDirKeepLog, L"stdout_raw", L"SILENTRUNNER_STDOUT_RAW_LOG", L"stdout raw log") \
    X(StderrChildTxtRaw, "StderrChildTxtRaw", Stderr, Child, Txt, SRFileSinkWorker, false, false, StderrDirChildRaw, StderrDirChildKeepLog, L"stderr_child_raw", L"SILENTRUNNER_STDERR_CHILD_RAW_LOG", L"stderr-child raw log") \
    X(StderrSrAndChildTxt, "StderrSrAndChildTxt", Stderr, SrAndChild, Txt, SRFileSinkWorker, true, true, StderrDir, StderrDirKeepLog, L"stderr", L"SILENTRUNNER_STDERR_LOG", L"stderr-sr-and-child log") \
    X(StderrChildTxt, "StderrChildTxt", Stderr, Child, Txt, SRFileSinkWorker, true, false, StderrDirChild, StderrDirChildKeepLog, L"stderr_child", L"SILENTRUNNER_STDERR_CHILD_LOG", L"stderr-child log") \
    X(StderrSrTxt, "StderrSrTxt", Stderr, Sr, Txt, SRFileSinkWorker, true, true, StderrDirSr, StderrDirSrKeepLog, L"stderr_sr", L"SILENTRUNNER_STDERR_SR_LOG", L"stderr-sr log") \
    X(StderrSrAndChildInclStdoutTxt, "StderrSrAndChildInclStdoutTxt", Stderr, SrAndChildInclStdout, Txt, SRFileSinkWorker, true, true, StderrDirInclStdout, StderrDirInclStdoutKeepLog, L"stderr_incl_stdout", L"SILENTRUNNER_STDERR_INCL_STDOUT_LOG", L"stderr-sr-and-child-incl-stdout log") \
    X(StdoutJsonl, "StdoutJsonl", Stdout, None, Jsonl, SRFileSinkWorker, false, false, StdoutDirJsonl, StdoutDirKeepLog, L"stdout", L"SILENTRUNNER_STDOUT_JSONL_LOG", L"stdout JSONL log") \
    X(StderrSrAndChildJsonl, "StderrSrAndChildJsonl", Stderr, SrAndChild, Jsonl, SRFileSinkWorker, false, true, StderrDirJsonl, StderrDirKeepLog, L"stderr", L"SILENTRUNNER_STDERR_JSONL_LOG", L"stderr-sr-and-child JSONL log") \
    X(StderrChildJsonl, "StderrChildJsonl", Stderr, Child, Jsonl, SRFileSinkWorker, false, false, StderrDirChildJsonl, StderrDirChildKeepLog, L"stderr_child", L"SILENTRUNNER_STDERR_CHILD_JSONL_LOG", L"stderr-child JSONL log") \
    X(StderrSrJsonl, "StderrSrJsonl", Stderr, Sr, Jsonl, SRFileSinkWorker, false, true, StderrDirSrJsonl, StderrDirSrKeepLog, L"stderr_sr", L"SILENTRUNNER_STDERR_SR_JSONL_LOG", L"stderr-sr JSONL log") \
    X(StderrSrAndChildInclStdoutJsonl, "StderrSrAndChildInclStdoutJsonl", Stderr, SrAndChildInclStdout, Jsonl, SRFileSinkWorker, false, true, StderrDirInclStdoutJsonl, StderrDirInclStdoutKeepLog, L"stderr_incl_stdout", L"SILENTRUNNER_STDERR_INCL_STDOUT_JSONL_LOG", L"stderr-sr-and-child-incl-stdout JSONL log")




enum class JobTarget {
#define SR_X_ENUM_JOB_TARGET(name, text, stream, channel, format, worker, headerEnabled, acceptsSrDiagnostics, configArgument, keepLogConfigArgument, logFileStem, logFileKey, logDiagnosticText) name,


    SR_JOB_TARGET_TABLE(SR_X_ENUM_JOB_TARGET)
#undef SR_X_ENUM_JOB_TARGET
};

struct GetAllDelayedFilter {
    JobTarget target;
};

static constexpr std::size_t kJobTargetCount =
    0
#define SR_X_COUNT_JOB_TARGET(name, text, stream, channel, format, worker, headerEnabled, acceptsSrDiagnostics, configArgument, keepLogConfigArgument, logFileStem, logFileKey, logDiagnosticText) + 1


    SR_JOB_TARGET_TABLE(SR_X_COUNT_JOB_TARGET)
#undef SR_X_COUNT_JOB_TARGET
;

struct TargetLogConfig {
    bool directoryRequested = false;
    std::wstring directory;
    KeepLogMode keepLogMode = KeepLogMode::Always;
};
struct TargetLogConfigs {
    TargetLogConfig& For(
        JobTarget target
    ) noexcept {
        return byTarget_[static_cast<std::size_t>(target)];
    }
    const TargetLogConfig& For(
        JobTarget target
    ) const noexcept {
        return byTarget_[static_cast<std::size_t>(target)];
    }
private:
    std::array<TargetLogConfig, kJobTargetCount> byTarget_{};
};

struct SRTargetLogFilesConfig {
    TargetLogConfigs targetLogConfigs;
};


static inline const wchar_t* JobTargetNameToString(JobTarget target) noexcept {
    switch (target) {
#define SR_X_JOB_TARGET_NAME_TO_STRING(name, text, stream, channel, format, worker, headerEnabled, acceptsSrDiagnostics, configArgument, keepLogConfigArgument, logFileStem, logFileKey, logDiagnosticText) case JobTarget::name: return L##text;


        SR_JOB_TARGET_TABLE(SR_X_JOB_TARGET_NAME_TO_STRING)
#undef SR_X_JOB_TARGET_NAME_TO_STRING
    }

    return L"Unknown";
}

enum class JobTargetChannel {
    None,
    SrAndChild,
    SrAndChildInclStdout,
    Child,
    Sr
};

static inline constexpr JobTargetChannel JobTargetChannelOf(
    JobTarget target
) noexcept {
    switch (target) {
#define SR_X_JOB_TARGET_CHANNEL(name, text, stream, channel, format, worker, headerEnabled, acceptsSrDiagnostics, configArgument, keepLogConfigArgument, logFileStem, logFileKey, logDiagnosticText) \
        case JobTarget::name: return JobTargetChannel::channel;
        SR_JOB_TARGET_TABLE(SR_X_JOB_TARGET_CHANNEL)
#undef SR_X_JOB_TARGET_CHANNEL
    }
    return JobTargetChannel::None;
}
#define SR_JOB_TARGET_FORMAT_TABLE(X) \
    X(Parent, L"parent") \
    X(Txt,    L"txt") \
    X(Jsonl,  L"jsonl")

enum class JobTargetFormat {
#define SR_X_ENUM_JOB_TARGET_FORMAT(name, text) name,
    SR_JOB_TARGET_FORMAT_TABLE(SR_X_ENUM_JOB_TARGET_FORMAT)
#undef SR_X_ENUM_JOB_TARGET_FORMAT
};

enum class JobTargetStream {
    Stdout,
    Stderr
};



static inline JobTargetFormat JobTargetFormatOf(
    JobTarget target
) noexcept {
    switch (target) {
#define SR_X_JOB_TARGET_FORMAT(name, text, stream, channel, format, worker, headerEnabled, acceptsSrDiagnostics, configArgument, keepLogConfigArgument, logFileStem, logFileKey, logDiagnosticText) \
        case JobTarget::name: \
            return JobTargetFormat::format;
        SR_JOB_TARGET_TABLE(SR_X_JOB_TARGET_FORMAT)
#undef SR_X_JOB_TARGET_FORMAT
    }
    return JobTargetFormat::Parent;
}

static inline JobTargetWorker JobTargetWorkerOf(JobTarget target) noexcept {
    switch (target) {
#define SR_X_JOB_TARGET_WORKER(name, text, stream, channel, format, worker, headerEnabled, acceptsSrDiagnostics, configArgument, keepLogConfigArgument, logFileStem, logFileKey, logDiagnosticText) case JobTarget::name: return JobTargetWorker::worker;


        SR_JOB_TARGET_TABLE(SR_X_JOB_TARGET_WORKER)
#undef SR_X_JOB_TARGET_WORKER
    }

    return JobTargetWorker::SRParentEmitWorker;
}
static constexpr std::size_t kInvalidJobTargetWorkerConfigIndex =
    static_cast<std::size_t>(-1);

template <JobTargetWorker Worker>
static constexpr std::size_t JobTargetCountForWorker() noexcept {
    return
        0
#define SR_X_COUNT_JOB_TARGET_FOR_WORKER(name, text, stream, channel, format, worker, headerEnabled, acceptsSrDiagnostics, configArgument, keepLogConfigArgument, logFileStem, logFileKey, logDiagnosticText) \
        + (JobTargetWorker::worker == Worker ? 1u : 0u)
        SR_JOB_TARGET_TABLE(SR_X_COUNT_JOB_TARGET_FOR_WORKER)
#undef SR_X_COUNT_JOB_TARGET_FOR_WORKER
    ;
}

struct ConfigArgumentId {
    std::string_view value{};
};

struct WorkerTargetLayoutEntry {
    JobTarget target{};
    std::string_view text{};
    JobTargetStream stream = JobTargetStream::Stdout;
    JobTargetChannel channel = JobTargetChannel::None;
    JobTargetFormat format = JobTargetFormat::Parent;
    JobTargetWorker worker = JobTargetWorker::SRParentEmitWorker;
    bool headerEnabled = false;
    bool acceptsSrDiagnostics = false;
    ConfigArgumentId configArgument{};
    ConfigArgumentId keepLogConfigArgument{};
    const wchar_t* logFileStem = nullptr;
    const wchar_t* logFileKey = nullptr;
    const wchar_t* logDiagnosticText = nullptr;
};


template <JobTargetWorker Worker>
struct WorkerTargetLayout {
    static constexpr std::size_t kTargetCount =
        JobTargetCountForWorker<Worker>();

    std::array<
        WorkerTargetLayoutEntry,
        kTargetCount
    > targets{};
    std::array<std::size_t, kJobTargetCount> configIndexByTarget{};

    constexpr std::size_t ConfigIndexOf(
        JobTarget target
    ) const noexcept {
        return configIndexByTarget[
            static_cast<std::size_t>(target)
        ];
    }
};

template <JobTargetWorker Worker>
static constexpr WorkerTargetLayout<Worker>
BuildWorkerTargetLayout() noexcept {
    WorkerTargetLayout<Worker> layout{};

    for (std::size_t i = 0; i < kJobTargetCount; ++i) {
        layout.configIndexByTarget[i] =
            kInvalidJobTargetWorkerConfigIndex;
    }

    std::size_t workerConfigIndex = 0;

#define SR_X_BUILD_WORKER_TARGET_LAYOUT(name, text, stream, channel, format, worker, headerEnabled, acceptsSrDiagnostics, configArgument, keepLogConfigArgument, logFileStem, logFileKey, logDiagnosticText) \
    if (JobTargetWorker::worker == Worker) { \
        layout.targets[workerConfigIndex] = WorkerTargetLayoutEntry{ \
            JobTarget::name, \
            text, \
            JobTargetStream::stream, \
            JobTargetChannel::channel, \
            JobTargetFormat::format, \
            JobTargetWorker::worker, \
            headerEnabled, \
            acceptsSrDiagnostics, \
            ConfigArgumentId{#configArgument}, \
            ConfigArgumentId{#keepLogConfigArgument}, \
            logFileStem, \
            logFileKey, \
            logDiagnosticText \
        }; \
        layout.configIndexByTarget[static_cast<std::size_t>(JobTarget::name)] = workerConfigIndex; \
        ++workerConfigIndex; \
    }

    SR_JOB_TARGET_TABLE(SR_X_BUILD_WORKER_TARGET_LAYOUT)

#undef SR_X_BUILD_WORKER_TARGET_LAYOUT

    return layout;
}

using ParentEmitWorkerTargetLayout =
    WorkerTargetLayout<JobTargetWorker::SRParentEmitWorker>;

using FileSinkWorkerTargetLayout =
    WorkerTargetLayout<JobTargetWorker::SRFileSinkWorker>;

static constexpr std::size_t kParentTargetConfigCount =
    ParentEmitWorkerTargetLayout::kTargetCount;

static constexpr std::size_t kFileSinkTargetConfigCount =
    FileSinkWorkerTargetLayout::kTargetCount;

static constexpr ParentEmitWorkerTargetLayout
    kParentEmitWorkerTargetLayout =
        BuildWorkerTargetLayout<
            JobTargetWorker::SRParentEmitWorker
        >();

static constexpr FileSinkWorkerTargetLayout
    kFileSinkWorkerTargetLayout =
        BuildWorkerTargetLayout<
            JobTargetWorker::SRFileSinkWorker
        >();


struct JobTargetFilter {
    std::vector<JobTarget> targets;
    std::optional<std::string_view> text;
    std::optional<JobTargetStream> stream;
    std::optional<JobTargetChannel> channel;
    std::optional<JobTargetFormat> format;
    std::optional<JobTargetWorker> worker;

    std::optional<bool> headerEnabled;
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
    tableHeaderEnabled, \
    tableAcceptsSrDiagnostics, \
    tableConfigArgument, \
    tableKeepLogConfigArgument, \
    tableLogFileStem, \
    tableLogKey, \
    tableLogDiagnosticText \
) \
    if ((filter.targets.empty() || std::find(filter.targets.begin(), filter.targets.end(), JobTarget::tableName) != filter.targets.end()) && \
        (!filter.text || *filter.text == tableText) && \
        (!filter.stream || *filter.stream == JobTargetStream::tableStream) && \
        (!filter.channel || *filter.channel == JobTargetChannel::tableChannel) && \
        (!filter.format || *filter.format == JobTargetFormat::tableFormat) && \
        (!filter.worker || *filter.worker == JobTargetWorker::tableWorker) && \
        (!filter.headerEnabled || \
         *filter.headerEnabled == tableHeaderEnabled)) { \
        targets.push_back(JobTarget::tableName); \
    }

    SR_JOB_TARGET_TABLE(SR_X_RETRIEVE_JOB_TARGET)

#undef SR_X_RETRIEVE_JOB_TARGET

    return targets;
}



#define SR_JOB_PAYLOAD_TYPE_TABLE(X) \
    X(SrDiag, "SrDiagEvent") \
    X(ChildStdout, "ChildStdout") \
    X(ChildStderr, "ChildStderr")
    
#define SR_JOB_TARGET_PAYLOAD_TYPE_TABLE(X) \
    X(StdoutParent, ChildStdout) \
    X(StdoutParentRaw, ChildStdout) \
    X(StderrSrAndChildParent, ChildStderr) \
    X(StderrSrAndChildParent, SrDiag) \
    X(StderrChildParent, ChildStderr) \
    X(StderrChildParentRaw, ChildStderr) \
    X(StderrSrParent, SrDiag) \
    X(StderrSrAndChildInclStdoutParent, ChildStdout) \
    X(StderrSrAndChildInclStdoutParent, ChildStderr) \
    X(StderrSrAndChildInclStdoutParent, SrDiag) \
    X(StdoutTxt, ChildStdout) \
    X(StdoutTxtRaw, ChildStdout) \
    X(StderrSrAndChildTxt, ChildStderr) \
    X(StderrSrAndChildTxt, SrDiag) \
    X(StderrChildTxt, ChildStderr) \
    X(StderrChildTxtRaw, ChildStderr) \
    X(StderrSrTxt, SrDiag) \
    X(StderrSrAndChildInclStdoutTxt, ChildStdout) \
    X(StderrSrAndChildInclStdoutTxt, ChildStderr) \
    X(StderrSrAndChildInclStdoutTxt, SrDiag) \
    X(StdoutJsonl, ChildStdout) \
    X(StderrSrAndChildJsonl, ChildStderr) \
    X(StderrSrAndChildJsonl, SrDiag) \
    X(StderrChildJsonl, ChildStderr) \
    X(StderrSrJsonl, SrDiag) \
    X(StderrSrAndChildInclStdoutJsonl, ChildStdout) \
    X(StderrSrAndChildInclStdoutJsonl, ChildStderr) \
    X(StderrSrAndChildInclStdoutJsonl, SrDiag)

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
#define SR_X_EVENT_JOB_RESULT(name, text, stream, channel, format, worker, headerEnabled, acceptsSrDiagnostics, configArgument, keepLogConfigArgument, logFileStem, logFileKey, logDiagnosticText) EventJobResult{ JobTarget::name },

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
