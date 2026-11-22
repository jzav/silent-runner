
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "SRTypes.h"
#include "SRJobTypes.h"
#include "SRParentEmitPolicyTypes.h"


namespace SR {

// =============================================================================
// Config argument classification
// =============================================================================
enum class ConfigArgumentTopic {
    Diagnostics,
    ProcessEnvironment,
    ExecutionId,
    ParentEmission,
    ChildEventSeparation,
    PersistentLogging,
    LogRetention,
    Buffering,
    PostExecutionHooks,
    ExecutionMode,
    Help
};

enum class ConfigArgumentParsingMode {
    Flag,
    Value,
    ChildCommand
};

} // namespace SR


// =============================================================================
// Config value types
// =============================================================================

// Columns: value type ID, C++ type, value type text, value resolver.

#define SR_CONFIG_VALUE_TYPE_TABLE(X) \
    X(Bool,                     bool,                         L"bool",                         ResolveBool) \
    X(WString,                  std::wstring,                 L"std::wstring",                 ResolveWString) \
    X(UInt32,                   uint32_t,                     L"uint32_t",                     ResolveUInt32) \
    X(UInt64,                   uint64_t,                     L"uint64_t",                     ResolveUInt64) \
    X(ChildEventFraming,        SR::ChildEventFraming,        L"SR::ChildEventFraming",        ResolveChildEventFraming) \
    X(JsonlPayloadRepresentation, SR::JsonlPayloadRepresentation, L"SR::JsonlPayloadRepresentation", ResolveJsonlPayloadRepresentation) \
    X(IdSuffixMode,             SR::IdSuffixMode,             L"SR::IdSuffixMode",             ResolveIdSuffixMode) \
    X(EmitMode,                 SR::EmitMode,                 L"SR::EmitMode",                 ResolveEmitMode) \
    X(KeepLogMode,              SR::KeepLogMode,              L"SR::KeepLogMode",              ResolveKeepLogMode) \
    X(ExecutionMode,            SR::ExecutionMode,            L"SR::ExecutionMode",            ResolveExecutionMode)



namespace SR {
enum class ConfigValueType {
#define SR_X_CONFIG_VALUE_TYPE_ENUM(id, valueType, valueTypeText, resolver) id,

    SR_CONFIG_VALUE_TYPE_TABLE(SR_X_CONFIG_VALUE_TYPE_ENUM)
#undef SR_X_CONFIG_VALUE_TYPE_ENUM
    Count
};

// Resolver declarations and runtime dispatch by config value type.

struct ConfigArgumentData;

namespace Resolution {

#define SR_X_CONFIG_VALUE_RESOLVER_DECLARATION(id, valueType, valueTypeText, resolver) \
    bool resolver(const ConfigArgumentData& configArgument, valueType& value, std::wstring& err);

    SR_CONFIG_VALUE_TYPE_TABLE(SR_X_CONFIG_VALUE_RESOLVER_DECLARATION)
#undef SR_X_CONFIG_VALUE_RESOLVER_DECLARATION

} // namespace Resolution

}


// =============================================================================
// Config arguments
// =============================================================================

// Columns: argument ID, ID text, CLI spelling, alias, topic, parsing mode, value type ID.

#define SR_CONFIG_ARGUMENT_TABLE(X) \
    X(Debug,                           L"Debug",                           L"--debug",                            nullptr,  Diagnostics,         Flag,         Bool) \
    X(Verbose,                         L"Verbose",                         L"--verbose",                          nullptr,  Diagnostics,         Flag,         Bool) \
    X(ProbeDir,                        L"ProbeDir",                        L"--probe-dir",                       nullptr,  Diagnostics,         Value,        WString) \
    X(Cwd,                             L"Cwd",                             L"--cwd",                             nullptr,  ProcessEnvironment,  Value,        WString) \
    X(InheritStdin,                     L"InheritStdin",                     L"--inherit-stdin",                    nullptr,  ProcessEnvironment,  Flag,         Bool) \
    X(Utf8,                            L"Utf8",                            L"--utf8",                            L"--utf-8", ProcessEnvironment,  Flag,         Bool) \
    X(TimeoutMs,                        L"TimeoutMs",                        L"--timeout-ms",                       nullptr,  ProcessEnvironment,  Value,        UInt32) \
    X(AbortOnRuntimeFailure,             L"AbortOnRuntimeFailure",             L"--abort-on-runtime-failure",        nullptr,  ProcessEnvironment,  Flag,         Bool) \
    X(IdPrefix,                         L"IdPrefix",                         L"--id-prefix",                        nullptr,  ExecutionId,         Value,        WString) \
    X(IdBase,                           L"IdBase",                           L"--id-base",                          nullptr,  ExecutionId,         Value,        WString) \
    X(IdSuffix,                         L"IdSuffix",                         L"--id-suffix",                        nullptr,  ExecutionId,         Value,        IdSuffixMode) \
    X(StdoutEventFraming,                L"StdoutEventFraming",                L"--stdout-event-framing",                nullptr,  ChildEventSeparation, Value, ChildEventFraming) \
    X(StdoutEventNewlineMaxBytes,        L"StdoutEventNewlineMaxBytes",        L"--stdout-event-newline-max-bytes",      nullptr,  ChildEventSeparation, Value, UInt64) \
    X(StderrChildEventFraming,           L"StderrChildEventFraming",           L"--stderr-child-event-framing",          nullptr,  ChildEventSeparation, Value, ChildEventFraming) \
    X(StderrChildEventNewlineMaxBytes,   L"StderrChildEventNewlineMaxBytes",   L"--stderr-child-event-newline-max-bytes", nullptr, ChildEventSeparation, Value, UInt64) \
    X(StdoutEmit,                       L"StdoutEmit",                       L"--stdout-emit",                       nullptr,  ParentEmission,      Value,        EmitMode) \
    X(StdoutEmitRaw,                    L"StdoutEmitRaw",                    L"--stdout-emit-raw",                   nullptr,  ParentEmission,      Value,        EmitMode) \
    X(StderrEmit,                       L"StderrEmit",                       L"--stderr-emit",                       nullptr,  ParentEmission,      Value,        EmitMode) \
    X(StderrEmitChild,                   L"StderrEmitChild",                   L"--stderr-emit-child",                 nullptr,  ParentEmission,      Value,        EmitMode) \
    X(StderrEmitChildRaw,               L"StderrEmitChildRaw",               L"--stderr-emit-child-raw",             nullptr,  ParentEmission,      Value,        EmitMode) \
    X(StderrEmitSr,                      L"StderrEmitSr",                      L"--stderr-emit-sr",                    nullptr,  ParentEmission,      Value,        EmitMode) \
    X(StderrEmitInclStdout,               L"StderrEmitInclStdout",               L"--stderr-emit-incl-stdout",            nullptr,  ParentEmission,      Value,        EmitMode) \
    X(StdoutDir,                        L"StdoutDir",                        L"--stdout-dir",                       nullptr,  PersistentLogging,   Value,        WString) \
    X(StdoutDirRaw,                     L"StdoutDirRaw",                     L"--stdout-dir-raw",                    nullptr,  PersistentLogging,   Value,        WString) \
    X(StdoutDirJsonl,                    L"StdoutDirJsonl",                    L"--stdout-dir-jsonl",                 nullptr,  PersistentLogging,   Value,        WString) \
    X(StderrDir,                        L"StderrDir",                        L"--stderr-dir",                       nullptr,  PersistentLogging,   Value,        WString) \
    X(StderrDirJsonl,                    L"StderrDirJsonl",                    L"--stderr-dir-jsonl",                 nullptr,  PersistentLogging,   Value,        WString) \
    X(StderrDirChild,                    L"StderrDirChild",                    L"--stderr-dir-child",                 nullptr,  PersistentLogging,   Value,        WString) \
    X(StderrDirChildRaw,                L"StderrDirChildRaw",                L"--stderr-dir-child-raw",              nullptr,  PersistentLogging,   Value,        WString) \
    X(StderrDirChildJsonl,                L"StderrDirChildJsonl",                L"--stderr-dir-child-jsonl",            nullptr,  PersistentLogging,   Value,        WString) \
    X(StderrDirSr,                       L"StderrDirSr",                       L"--stderr-dir-sr",                    nullptr,  PersistentLogging,   Value,        WString) \
    X(StderrDirSrJsonl,                   L"StderrDirSrJsonl",                   L"--stderr-dir-sr-jsonl",               nullptr,  PersistentLogging,   Value,        WString) \
    X(StderrDirInclStdout,                L"StderrDirInclStdout",                L"--stderr-dir-incl-stdout",             nullptr,  PersistentLogging,   Value,        WString) \
    X(StderrDirInclStdoutJsonl,            L"StderrDirInclStdoutJsonl",            L"--stderr-dir-incl-stdout-jsonl",       nullptr,  PersistentLogging,   Value,        WString) \
    X(JsonlPayloadRepresentation,           L"JsonlPayloadRepresentation",           L"--jsonl-payload-representation",        nullptr,  PersistentLogging,   Value,        JsonlPayloadRepresentation) \
    X(StdoutDirKeepLog,                   L"StdoutDirKeepLog",                   L"--stdout-dir-keep-log",               nullptr,  LogRetention,        Value,        KeepLogMode) \
    X(StderrDirKeepLog,                   L"StderrDirKeepLog",                   L"--stderr-dir-keep-log",               nullptr,  LogRetention,        Value,        KeepLogMode) \
    X(StderrDirChildKeepLog,               L"StderrDirChildKeepLog",               L"--stderr-dir-child-keep-log",         nullptr,  LogRetention,        Value,        KeepLogMode) \
    X(StderrDirSrKeepLog,                  L"StderrDirSrKeepLog",                  L"--stderr-dir-sr-keep-log",            nullptr,  LogRetention,        Value,        KeepLogMode) \
    X(StderrDirInclStdoutKeepLog,           L"StderrDirInclStdoutKeepLog",           L"--stderr-dir-incl-stdout-keep-log",    nullptr,  LogRetention,        Value,        KeepLogMode) \
    X(StdoutMaxBufferBytes,                L"StdoutMaxBufferBytes",                L"--stdout-max-buffer-bytes",           nullptr,  Buffering,           Value,        UInt64) \
    X(StderrMaxBufferBytes,                L"StderrMaxBufferBytes",                L"--stderr-max-buffer-bytes",           nullptr,  Buffering,           Value,        UInt64) \
    X(StdTotalMaxBufferBytes,              L"StdTotalMaxBufferBytes",              L"--std-total-max-buffer-bytes",        nullptr,  Buffering,           Value,        UInt64) \
    X(RunOnSuccess,                      L"RunOnSuccess",                      L"--run-on-success",                   nullptr,  PostExecutionHooks,  Value,        WString) \
    X(RunOnFailure,                      L"RunOnFailure",                      L"--run-on-failure",                   nullptr,  PostExecutionHooks,  Value,        WString) \
    X(CommandString,                        L"CommandString",                        L"-c",                                L"/c",      ExecutionMode,        ChildCommand, ExecutionMode) \
    X(Help,                              L"Help",                              L"--help",                             nullptr,  Help,                Flag,         Bool)

namespace SR {

enum class ConfigArgument {
#define SR_X_CONFIG_ARGUMENT_ENUM(id, idText, spelling, alias, topic, parsingMode, valueTypeId) id,
    SR_CONFIG_ARGUMENT_TABLE(SR_X_CONFIG_ARGUMENT_ENUM)
#undef SR_X_CONFIG_ARGUMENT_ENUM
    Count
};

static constexpr std::size_t kConfigArgumentCount =
    static_cast<std::size_t>(ConfigArgument::Count);

// Resolve an argument ID from the job-target layout to its typed enum.
static inline constexpr ConfigArgument ResolveConfigArgument(
    ConfigArgumentId id
) noexcept {
#define SR_X_RESOLVE_CONFIG_ARGUMENT(name, idText, spelling, alias, topic, parsingMode, valueTypeId) \
    if (id.value == #name) return ConfigArgument::name;
    SR_CONFIG_ARGUMENT_TABLE(SR_X_RESOLVE_CONFIG_ARGUMENT)
#undef SR_X_RESOLVE_CONFIG_ARGUMENT
    return ConfigArgument::Count;
}


} // namespace SR


// =============================================================================
// Config owners
// =============================================================================

// Columns: owner ID, config member, owner type.

#define SR_CONFIG_OWNER_TABLE(X) \
    X(SRWorkerCommonPolicy,   workerCommonPolicy,   Class) \
    X(SRFileSinkWorker,       fileSinkWorker,       Class) \
    X(SRTargetLogFiles,       targetLogFiles,       Class) \
    X(SRLifecycleDiagnostics, lifecycleDiagnostics, Class) \
    X(SRParentEmitPolicy,     parentEmitPolicy,     Class) \
    X(SRBufferLimiter,        bufferLimiter,        Class) \
    X(SRTimeLimiter,          timeLimiter,          Class) \
    X(SRRuntimeCoordinator,  runtimeCoordinator,  Class) \
    X(ExecutionTimeline,      executionTimeline,    Class) \
    X(PrepareRuntime,         prepareRuntime,       Function) \
    X(ExecuteChildProcess,   executeChildProcess, Function) \
    X(FinalizeExecution,      finalizeExecution,    Function)

namespace SR {

enum class ConfigOwnerType {
    Class,
    Function,
    Namespace
};

enum class ConfigOwner {
#define SR_X_CONFIG_OWNER_ENUM(id, member, type) id,
    SR_CONFIG_OWNER_TABLE(SR_X_CONFIG_OWNER_ENUM)
#undef SR_X_CONFIG_OWNER_ENUM
};

} // namespace SR


// =============================================================================
// Argument-to-owner mapping
// =============================================================================

// Columns: argument ID, owner ID, owner field.

#define SR_CONFIG_ARGUMENT_OWNER_TABLE(X) \
    X(Debug,                        SRLifecycleDiagnostics, debug) \
    X(Debug,                        ExecuteChildProcess,   debug) \
    X(Verbose,                      ExecuteChildProcess,   verbose) \
    X(Verbose,                      SRLifecycleDiagnostics, verbose) \
    X(Verbose,                      ExecutionTimeline,      verbose) \
    X(Verbose,                      FinalizeExecution,      verbose) \
    X(ProbeDir,                     PrepareRuntime,        probeDir) \
    X(Cwd,                          PrepareRuntime,        cwd) \
    X(Cwd,                          FinalizeExecution,      cwd) \
    X(Cwd,                          ExecuteChildProcess,   cwd) \
    X(Utf8,                         ExecuteChildProcess,   utf8) \
    X(InheritStdin,                  ExecuteChildProcess,   inheritStdin) \
    X(Utf8,                         PrepareRuntime,        utf8) \
    X(TimeoutMs,                     SRTimeLimiter,          timeoutMs) \
    X(AbortOnRuntimeFailure,            SRRuntimeCoordinator, abortOnRuntimeFailure) \
    X(IdPrefix,                      SRWorkerCommonPolicy,  idPrefix) \
    X(IdBase,                        SRWorkerCommonPolicy,  idBase) \
    X(IdSuffix,                      SRWorkerCommonPolicy,  idSuffix) \
    X(StdoutEventFraming,               ExecuteChildProcess,   stdoutEventFraming) \
    X(StdoutEventNewlineMaxBytes,       ExecuteChildProcess,   stdoutEventNewlineMaxBytes) \
    X(StderrChildEventFraming,          ExecuteChildProcess,   stderrChildEventFraming) \
    X(StderrChildEventNewlineMaxBytes,  ExecuteChildProcess,   stderrChildEventNewlineMaxBytes) \
    X(StdoutDir,                     PrepareRuntime,        stdoutDir) \
    X(StdoutDirJsonl,                 PrepareRuntime,        stdoutDirJsonl) \
    X(StderrDir,                     PrepareRuntime,        stderrDir) \
    X(StderrDirJsonl,                 PrepareRuntime,        stderrDirJsonl) \
    X(StderrDirChild,                 PrepareRuntime,        stderrDirChild) \
    X(StderrDirChildJsonl,             PrepareRuntime,        stderrDirChildJsonl) \
    X(StderrDirSr,                    PrepareRuntime,        stderrDirSr) \
    X(StderrDirSrJsonl,                PrepareRuntime,        stderrDirSrJsonl) \
    X(StderrDirInclStdout,             PrepareRuntime,        stderrDirInclStdout) \
    X(StderrDirInclStdoutJsonl,         PrepareRuntime,        stderrDirInclStdoutJsonl) \
    X(JsonlPayloadRepresentation,        SRFileSinkWorker,         jsonlPayloadRepresentation) \
    X(JsonlPayloadRepresentation,      ExecuteChildProcess,   jsonlPayloadRepresentation) \
    X(StdoutMaxBufferBytes,             SRBufferLimiter,        stdoutMaxBufferBytes) \
    X(StdoutMaxBufferBytes,             PrepareRuntime,         stdoutMaxBufferBytes) \
    X(StdoutMaxBufferBytes,             ExecuteChildProcess,   stdoutMaxBufferBytes) \
    X(StderrMaxBufferBytes,             SRBufferLimiter,        stderrMaxBufferBytes) \
    X(StderrMaxBufferBytes,             PrepareRuntime,         stderrMaxBufferBytes) \
    X(StderrMaxBufferBytes,             ExecuteChildProcess,   stderrMaxBufferBytes) \
    X(StdTotalMaxBufferBytes,            SRBufferLimiter,        stdTotalMaxBufferBytes) \
    X(StdTotalMaxBufferBytes,            PrepareRuntime,         stdTotalMaxBufferBytes) \
    X(StdTotalMaxBufferBytes,        ExecuteChildProcess,   stdTotalMaxBufferBytes) \
    X(RunOnSuccess,                    PrepareRuntime,        runOnSuccessPath) \
    X(RunOnSuccess,                ExecuteChildProcess,   runOnSuccessPath) \
    X(RunOnFailure,                    PrepareRuntime,        runOnFailurePath) \
    X(RunOnFailure,                ExecuteChildProcess,   runOnFailurePath) \
    X(RunOnSuccess,                    FinalizeExecution,      runOnSuccessPath) \
    X(RunOnFailure,                    FinalizeExecution,      runOnFailurePath) \
    X(CommandString,                      PrepareRuntime,        executionMode) \
    X(CommandString,                    ExecuteChildProcess,   executionMode)

// =============================================================================
// Derived config values
// =============================================================================
//
// Columns: derived value ID, C++ type, field.

#define SR_CONFIG_DERIVED_VALUE_TABLE(X) \
    X(StdoutParentTarget, SR::JobTarget, stdoutParentTarget) \
    X(StderrParentTarget, SR::JobTarget, stderrParentTarget) \
    X(StdoutEmitMode, SR::EmitMode, stdoutEmitMode) \
    X(StderrEmitMode, SR::EmitMode, stderrEmitMode) \
    X(ArgVector,             std::vector<std::wstring>, argVector) \
    X(ChildArgsStartIndex,   int,                       childArgsStartIndex) \
    X(NeedsParsingToken,     bool,                      needsParsingToken) \
    X(TargetLogConfigs,         SR::TargetLogConfigs,        targetLogConfigs) \
    X(StdoutTxtHeaderGranularity,    SR::ChildTxtHeaderGranularity, stdoutTxtHeaderGranularity) \
    X(StderrChildTxtHeaderGranularity, SR::ChildTxtHeaderGranularity, stderrChildTxtHeaderGranularity)


// Columns: derived value ID, owner ID.
#define SR_CONFIG_DERIVED_VALUE_OWNER_TABLE(X) \
    X(StdoutParentTarget, SRParentEmitPolicy) \
    X(StderrParentTarget, SRParentEmitPolicy) \
    X(StdoutEmitMode, SRParentEmitPolicy) \
    X(StderrEmitMode, SRParentEmitPolicy) \
    X(ArgVector,             PrepareRuntime) \
    X(ChildArgsStartIndex,   PrepareRuntime) \
    X(NeedsParsingToken,       SRWorkerCommonPolicy) \
    X(TargetLogConfigs,         SRTargetLogFiles) \
    X(StdoutTxtHeaderGranularity,      SRWorkerCommonPolicy) \
    X(StdoutTxtHeaderGranularity,      FinalizeExecution) \
    X(StderrChildTxtHeaderGranularity, SRWorkerCommonPolicy) \
    X(StderrChildTxtHeaderGranularity, FinalizeExecution)






namespace SR {

    
// =============================================================================
// Resolved value types
// =============================================================================

// Value type ID -> C++ type.
#define SR_X_CONFIG_VALUE_TYPE_ALIAS(id, valueType, valueTypeText, resolver) \
    using ConfigValueType_##id = valueType;

SR_CONFIG_VALUE_TYPE_TABLE(SR_X_CONFIG_VALUE_TYPE_ALIAS)

#undef SR_X_CONFIG_VALUE_TYPE_ALIAS


// Variant capable of storing every resolved config argument value.
using ConfigArgumentTypedValue = std::variant<
    std::monostate
#define SR_X_CONFIG_TYPED_VALUE_TYPE(id, valueType, valueTypeText, resolver) \
    , valueType

    SR_CONFIG_VALUE_TYPE_TABLE(SR_X_CONFIG_TYPED_VALUE_TYPE)

#undef SR_X_CONFIG_TYPED_VALUE_TYPE
>;

static_assert(
    std::variant_size_v<ConfigArgumentTypedValue> ==
    static_cast<std::size_t>(ConfigValueType::Count) + 1
);


struct ConfigArgumentData {
    const wchar_t* id;
    const wchar_t* spelling;
    const wchar_t* alias;
    ConfigArgumentTopic topic;
    ConfigArgumentParsingMode parsingMode;
    ConfigValueType valueType;

    std::wstring optionValue{};
    bool optionValueSpecified = false;
    std::wstring parsingError{};
    ConfigArgumentTypedValue typedValue{};
};

static inline std::array<ConfigArgumentData, kConfigArgumentCount>
MakeConfigArgumentData() {
    return {{
#define SR_X_CONFIG_ARGUMENT_DATA(id, idText, spelling, alias, topic, parsingMode, valueTypeId) \
        { \
            idText, \
            spelling, \
            alias, \
            ConfigArgumentTopic::topic, \
            ConfigArgumentParsingMode::parsingMode, \
            ConfigValueType::valueTypeId \
        },

        SR_CONFIG_ARGUMENT_TABLE(SR_X_CONFIG_ARGUMENT_DATA)
#undef SR_X_CONFIG_ARGUMENT_DATA
    }};
}

static inline bool ResolveConfigValue(
    ConfigArgumentData& configArgument,
    std::wstring& err
) {

    switch (configArgument.valueType) {
#define SR_X_RESOLVE_CONFIG_VALUE(id, valueType, valueTypeText, resolver) \
        case ConfigValueType::id: { \
            valueType value{}; \
            if (!Resolution::resolver(configArgument, value, err)) { \
                return false; \
            } \
            configArgument.typedValue = std::move(value); \
            return true; \
        }


        SR_CONFIG_VALUE_TYPE_TABLE(SR_X_RESOLVE_CONFIG_VALUE)
#undef SR_X_RESOLVE_CONFIG_VALUE
    }

    return false;

}


// Argument ID -> resolved C++ type.
#define SR_X_CONFIG_ARGUMENT_VALUE_TYPE_ALIAS(id, idText, spelling, alias, topic, parsingMode, valueTypeId) \
    using ConfigArgumentValueType_##id = ConfigValueType_##valueTypeId;

    SR_CONFIG_ARGUMENT_TABLE(SR_X_CONFIG_ARGUMENT_VALUE_TYPE_ALIAS)

#undef SR_X_CONFIG_ARGUMENT_VALUE_TYPE_ALIAS



// Argument ID -> C++ type for compile-time typed access.
template <ConfigArgument argument>
struct ConfigArgumentValueTypeOf;

#define SR_X_CONFIG_ARGUMENT_VALUE_TYPE_TRAIT(id, idText, spelling, alias, topic, parsingMode, valueTypeId) \
    template <> struct ConfigArgumentValueTypeOf<ConfigArgument::id> { \
        using type = ConfigArgumentValueType_##id; \
    };

SR_CONFIG_ARGUMENT_TABLE(SR_X_CONFIG_ARGUMENT_VALUE_TYPE_TRAIT)
#undef SR_X_CONFIG_ARGUMENT_VALUE_TYPE_TRAIT

class ConfigArguments {
public:
    void Init() {
        arguments_ = MakeConfigArgumentData();
    }

    ConfigArgumentData& GetData(ConfigArgument argument) {
        return arguments_[static_cast<std::size_t>(argument)];
    }

    const ConfigArgumentData& GetData(ConfigArgument argument) const {
        return arguments_[static_cast<std::size_t>(argument)];
    }

    bool IsSpecified(ConfigArgument argument) const {
        return GetData(argument).optionValueSpecified;
    }

    template <typename T>
    void CopyValue(ConfigArgument argument, T& destination) const {
        destination = std::get<T>(GetData(argument).typedValue);
    }

    template <typename T>
    void SetValue(ConfigArgument argument, T&& value) {
        GetData(argument).typedValue = std::forward<T>(value);
    }

    template <ConfigArgument argument>
    const typename ConfigArgumentValueTypeOf<argument>::type& GetValue() const {
        using ValueType = typename ConfigArgumentValueTypeOf<argument>::type;
        return std::get<ValueType>(GetData(argument).typedValue);
    }

    auto begin() noexcept { return arguments_.begin(); }
    auto end() noexcept { return arguments_.end(); }
    auto begin() const noexcept { return arguments_.begin(); }
    auto end() const noexcept { return arguments_.end(); }

private:
    using Storage = std::array<ConfigArgumentData, kConfigArgumentCount>;
    Storage arguments_{};
};
// Values derived from resolved arguments and retained by SRConfigsBuilder.
struct ConfigDerivedValues {
#define SR_X_CONFIG_DERIVED_VALUE_FIELD(id, valueType, field) \
    std::optional<valueType> field{};


    SR_CONFIG_DERIVED_VALUE_TABLE(SR_X_CONFIG_DERIVED_VALUE_FIELD)
#undef SR_X_CONFIG_DERIVED_VALUE_FIELD
};


// =============================================================================
// Owner field projection
// =============================================================================

// Materialize an argument field only for the owner mapped to that argument.
#define SR_X_CONFIG_OWNER_FIELD(argument, owner, field) \
    template <ConfigOwner TargetOwner> \
    struct ConfigOwnerField_##argument##_##owner {}; \
    template <> \
    struct ConfigOwnerField_##argument##_##owner<ConfigOwner::owner> { \
        ConfigArgumentValueType_##argument field{}; \
    };

SR_CONFIG_ARGUMENT_OWNER_TABLE(SR_X_CONFIG_OWNER_FIELD)

#undef SR_X_CONFIG_OWNER_FIELD

// Materialize each derived value field once.
#define SR_X_CONFIG_DERIVED_VALUE_FIELD_TYPE(id, valueType, field) \
    struct ConfigDerivedValueField_##id { \
        valueType field{}; \
    };

SR_CONFIG_DERIVED_VALUE_TABLE(SR_X_CONFIG_DERIVED_VALUE_FIELD_TYPE)

#undef SR_X_CONFIG_DERIVED_VALUE_FIELD_TYPE


// Materialize a derived field only for the owner mapped to that value.
#define SR_X_CONFIG_DERIVED_OWNER_FIELD(derivedValue, owner) \
    template <ConfigOwner TargetOwner> \
    struct ConfigDerivedOwnerField_##derivedValue##_##owner {}; \
    template <> \
    struct ConfigDerivedOwnerField_##derivedValue##_##owner<ConfigOwner::owner> \
        : ConfigDerivedValueField_##derivedValue {};

SR_CONFIG_DERIVED_VALUE_OWNER_TABLE(SR_X_CONFIG_DERIVED_OWNER_FIELD)

#undef SR_X_CONFIG_DERIVED_OWNER_FIELD



// Aggregate all mapped argument and derived fields for one owner.

struct ConfigForOwnerEmptyBase {};

template <ConfigOwner Owner>
struct ConfigForOwner
    : ConfigForOwnerEmptyBase
#define SR_X_CONFIG_OWNER_FIELD_BASE(argument, owner, field) \
    , ConfigOwnerField_##argument##_##owner<Owner>

    SR_CONFIG_ARGUMENT_OWNER_TABLE(SR_X_CONFIG_OWNER_FIELD_BASE)

#undef SR_X_CONFIG_OWNER_FIELD_BASE

#define SR_X_CONFIG_DERIVED_OWNER_FIELD_BASE(derivedValue, owner) \
    , ConfigDerivedOwnerField_##derivedValue##_##owner<Owner>

    SR_CONFIG_DERIVED_VALUE_OWNER_TABLE(SR_X_CONFIG_DERIVED_OWNER_FIELD_BASE)

#undef SR_X_CONFIG_DERIVED_OWNER_FIELD_BASE

{};








// Complete set of consumer configs.
struct SRConfigs {
#define SR_X_CONFIG_MEMBER(owner, member, type) \
    owner##Config member;

    SR_CONFIG_OWNER_TABLE(SR_X_CONFIG_MEMBER)

#undef SR_X_CONFIG_MEMBER
};


// Retrieve the concrete consumer config for a compile-time owner ID.
template <ConfigOwner Owner>
struct ConfigOwnerAccessor;

#define SR_X_CONFIG_OWNER_ACCESSOR(owner, member, type) \
    template <> \
    struct ConfigOwnerAccessor<ConfigOwner::owner> { \
        static owner##Config& Retrieve(SRConfigs& configs) noexcept { \
            return configs.member; \
        } \
    };

SR_CONFIG_OWNER_TABLE(SR_X_CONFIG_OWNER_ACCESSOR)
#undef SR_X_CONFIG_OWNER_ACCESSOR


template <ConfigOwner Owner>
static inline auto& RetrieveConfigForOwner(
    SRConfigs& configs
) noexcept {
    return ConfigOwnerAccessor<Owner>::Retrieve(configs);
}


static inline void BuildConsumerConfigsHelper(
    const ConfigArguments& configArguments,
    SRConfigs& configs
) {
#define SR_X_BUILD_CONSUMER_CONFIG(argument, owner, field) \
    configArguments.CopyValue( \
        ConfigArgument::argument, \
        RetrieveConfigForOwner<ConfigOwner::owner>(configs).field \
    );

    SR_CONFIG_ARGUMENT_OWNER_TABLE(SR_X_BUILD_CONSUMER_CONFIG)
#undef SR_X_BUILD_CONSUMER_CONFIG
}

#define SR_X_APPEND_DERIVED_VALUE_HELPER(id, valueType, field) \
    template <typename Config> \
    static inline void AppendDerivedValue_##id( \
        const ConfigDerivedValues& derivedValues, \
        Config& config \
    ) { \
        if (derivedValues.field) { \
            config.field = *derivedValues.field; \
        } \
    }

SR_CONFIG_DERIVED_VALUE_TABLE(SR_X_APPEND_DERIVED_VALUE_HELPER)
#undef SR_X_APPEND_DERIVED_VALUE_HELPER


static inline void AppendDerivedValuesHelper(
    const ConfigDerivedValues& derivedValues,
    SRConfigs& configs
) {
#define SR_X_APPEND_DERIVED_TO_CONSUMER_CONFIG(derivedValue, owner) \
    AppendDerivedValue_##derivedValue( \
        derivedValues, \
        RetrieveConfigForOwner<ConfigOwner::owner>(configs) \
    );

    SR_CONFIG_DERIVED_VALUE_OWNER_TABLE(SR_X_APPEND_DERIVED_TO_CONSUMER_CONFIG)
#undef SR_X_APPEND_DERIVED_TO_CONSUMER_CONFIG
}



} // namespace SR
