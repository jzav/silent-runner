
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
    X(JsonlPayloadPresentation, SR::JsonlPayloadPresentation, L"SR::JsonlPayloadPresentation", ResolveJsonlPayloadPresentation) \
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
    X(IdPrefix,                         L"IdPrefix",                         L"--id-prefix",                        nullptr,  ExecutionId,         Value,        WString) \
    X(IdBase,                           L"IdBase",                           L"--id-base",                          nullptr,  ExecutionId,         Value,        WString) \
    X(IdSuffix,                         L"IdSuffix",                         L"--id-suffix",                        nullptr,  ExecutionId,         Value,        IdSuffixMode) \
    X(StdoutEventFraming,                L"StdoutEventFraming",                L"--stdout-event-framing",                nullptr,  ChildEventSeparation, Value, ChildEventFraming) \
    X(StdoutEventNewlineMaxBytes,        L"StdoutEventNewlineMaxBytes",        L"--stdout-event-newline-max-bytes",      nullptr,  ChildEventSeparation, Value, UInt64) \
    X(StderrChildEventFraming,           L"StderrChildEventFraming",           L"--stderr-child-event-framing",          nullptr,  ChildEventSeparation, Value, ChildEventFraming) \
    X(StderrChildEventNewlineMaxBytes,   L"StderrChildEventNewlineMaxBytes",   L"--stderr-child-event-newline-max-bytes", nullptr, ChildEventSeparation, Value, UInt64) \
    X(StdoutEmit,                       L"StdoutEmit",                       L"--stdout-emit",                       nullptr,  ParentEmission,      Value,        EmitMode) \
    X(StderrEmit,                       L"StderrEmit",                       L"--stderr-emit",                       nullptr,  ParentEmission,      Value,        EmitMode) \
    X(StderrEmitChild,                   L"StderrEmitChild",                   L"--stderr-emit-child",                 nullptr,  ParentEmission,      Value,        EmitMode) \
    X(StderrEmitSr,                      L"StderrEmitSr",                      L"--stderr-emit-sr",                    nullptr,  ParentEmission,      Value,        EmitMode) \
    X(StderrEmitInclStdout,               L"StderrEmitInclStdout",               L"--stderr-emit-incl-stdout",            nullptr,  ParentEmission,      Value,        EmitMode) \
    X(StdoutDir,                        L"StdoutDir",                        L"--stdout-dir",                       nullptr,  PersistentLogging,   Value,        WString) \
    X(StdoutDirJsonl,                    L"StdoutDirJsonl",                    L"--stdout-dir-jsonl",                 nullptr,  PersistentLogging,   Value,        WString) \
    X(StderrDir,                        L"StderrDir",                        L"--stderr-dir",                       nullptr,  PersistentLogging,   Value,        WString) \
    X(StderrDirJsonl,                    L"StderrDirJsonl",                    L"--stderr-dir-jsonl",                 nullptr,  PersistentLogging,   Value,        WString) \
    X(StderrDirChild,                    L"StderrDirChild",                    L"--stderr-dir-child",                 nullptr,  PersistentLogging,   Value,        WString) \
    X(StderrDirChildJsonl,                L"StderrDirChildJsonl",                L"--stderr-dir-child-jsonl",            nullptr,  PersistentLogging,   Value,        WString) \
    X(StderrDirSr,                       L"StderrDirSr",                       L"--stderr-dir-sr",                    nullptr,  PersistentLogging,   Value,        WString) \
    X(StderrDirSrJsonl,                   L"StderrDirSrJsonl",                   L"--stderr-dir-sr-jsonl",               nullptr,  PersistentLogging,   Value,        WString) \
    X(StderrDirInclStdout,                L"StderrDirInclStdout",                L"--stderr-dir-incl-stdout",             nullptr,  PersistentLogging,   Value,        WString) \
    X(StderrDirInclStdoutJsonl,            L"StderrDirInclStdoutJsonl",            L"--stderr-dir-incl-stdout-jsonl",       nullptr,  PersistentLogging,   Value,        WString) \
    X(JsonlPayloadPresentation,           L"JsonlPayloadPresentation",           L"--jsonl-payload-presentation",        nullptr,  PersistentLogging,   Value,        JsonlPayloadPresentation) \
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
    X(RawCommand,                        L"RawCommand",                        L"-c",                                L"/c",      ExecutionMode,        ChildCommand, ExecutionMode) \
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

} // namespace SR


// =============================================================================
// Config owners
// =============================================================================

// Columns: owner ID, config member, owner type.

#define SR_CONFIG_OWNER_TABLE(X) \
    X(SRWorkerCommonPolicy,   workerCommonPolicy,   Class) \
    X(SRFileSinkWorker,       fileSinkWorker,       Class) \
    X(SRLifecycleDiagnostics, lifecycleDiagnostics, Class) \
    X(SRParentEmitPolicy,     parentEmitPolicy,     Class) \
    X(SRBufferLimiter,        bufferLimiter,        Class) \
    X(ExecutionTimeline,      executionTimeline,    Class) \
    X(PrepareRuntime,         prepareRuntime,       Function) \
    X(RunHiddenWithRouting,   runHiddenWithRouting, Function) \
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
    X(Debug,                        RunHiddenWithRouting,   debug) \
    X(Verbose,                      SRLifecycleDiagnostics, verbose) \
    X(Verbose,                      ExecutionTimeline,      verbose) \
    X(Verbose,                      FinalizeExecution,      verbose) \
    X(ProbeDir,                     PrepareRuntime,        probeDir) \
    X(Cwd,                          PrepareRuntime,        cwd) \
    X(Cwd,                          FinalizeExecution,      cwd) \
    X(Cwd,                          RunHiddenWithRouting,   cwd) \
    X(InheritStdin,                  RunHiddenWithRouting,   inheritStdin) \
    X(Utf8,                         PrepareRuntime,        utf8) \
    X(TimeoutMs,                     RunHiddenWithRouting,   timeoutMs) \
    X(IdPrefix,                      PrepareRuntime,        idPrefix) \
    X(IdPrefix,                      RunHiddenWithRouting,   idPrefix) \
    X(IdBase,                        PrepareRuntime,        idBase) \
    X(IdBase,                        RunHiddenWithRouting,   idBase) \
    X(IdSuffix,                      PrepareRuntime,        idSuffix) \
    X(StdoutEventFraming,               RunHiddenWithRouting,   stdoutEventFraming) \
    X(StdoutEventNewlineMaxBytes,       RunHiddenWithRouting,   stdoutEventNewlineMaxBytes) \
    X(StderrChildEventFraming,          RunHiddenWithRouting,   stderrChildEventFraming) \
    X(StderrChildEventNewlineMaxBytes,  RunHiddenWithRouting,   stderrChildEventNewlineMaxBytes) \
    X(StdoutEmit,                    SRParentEmitPolicy,     stdoutEmit) \
    X(StdoutDir,                     PrepareRuntime,        stdoutDir) \
    X(StdoutDir,                     SRParentEmitPolicy,     stdoutDir) \
    X(StdoutDirJsonl,                 PrepareRuntime,        stdoutDirJsonl) \
    X(StdoutDirJsonl,                 SRParentEmitPolicy,     stdoutDirJsonl) \
    X(StderrDir,                     PrepareRuntime,        stderrDir) \
    X(StderrDir,                     SRParentEmitPolicy,     stderrDir) \
    X(StderrDirJsonl,                 PrepareRuntime,        stderrDirJsonl) \
    X(StderrDirJsonl,                 SRParentEmitPolicy,     stderrDirJsonl) \
    X(StderrDirChild,                 PrepareRuntime,        stderrDirChild) \
    X(StderrDirChild,                 SRParentEmitPolicy,     stderrDirChild) \
    X(StderrDirChildJsonl,             PrepareRuntime,        stderrDirChildJsonl) \
    X(StderrDirChildJsonl,             SRParentEmitPolicy,     stderrDirChildJsonl) \
    X(StderrDirSr,                    PrepareRuntime,        stderrDirSr) \
    X(StderrDirSr,                    SRParentEmitPolicy,     stderrDirSr) \
    X(StderrDirSrJsonl,                PrepareRuntime,        stderrDirSrJsonl) \
    X(StderrDirSrJsonl,                SRParentEmitPolicy,     stderrDirSrJsonl) \
    X(StderrDirInclStdout,             PrepareRuntime,        stderrDirInclStdout) \
    X(StderrDirInclStdout,             SRParentEmitPolicy,     stderrDirInclStdout) \
    X(StderrDirInclStdoutJsonl,         PrepareRuntime,        stderrDirInclStdoutJsonl) \
    X(StderrDirInclStdoutJsonl,         SRParentEmitPolicy,     stderrDirInclStdoutJsonl) \
    X(JsonlPayloadPresentation,        SRFileSinkWorker,         jsonlPayloadPresentation) \
    X(StdoutDirKeepLog,                FinalizeExecution,      stdoutDirKeepLog) \
    X(StderrDirKeepLog,                FinalizeExecution,      stderrDirKeepLog) \
    X(StderrDirChildKeepLog,            FinalizeExecution,      stderrDirChildKeepLog) \
    X(StderrDirSrKeepLog,               FinalizeExecution,      stderrDirSrKeepLog) \
    X(StderrDirInclStdoutKeepLog,        FinalizeExecution,      stderrDirInclStdoutKeepLog) \
    X(StdoutMaxBufferBytes,             SRBufferLimiter,        stdoutMaxBufferBytes) \
    X(StdoutMaxBufferBytes,             PrepareRuntime,         stdoutMaxBufferBytes) \
    X(StderrMaxBufferBytes,             SRBufferLimiter,        stderrMaxBufferBytes) \
    X(StderrMaxBufferBytes,             PrepareRuntime,         stderrMaxBufferBytes) \
    X(StdTotalMaxBufferBytes,            SRBufferLimiter,        stdTotalMaxBufferBytes) \
    X(StdTotalMaxBufferBytes,            PrepareRuntime,         stdTotalMaxBufferBytes) \
    X(RunOnSuccess,                    PrepareRuntime,        runOnSuccessPath) \
    X(RunOnFailure,                    PrepareRuntime,        runOnFailurePath) \
    X(RunOnSuccess,                    FinalizeExecution,      runOnSuccessPath) \
    X(RunOnFailure,                    FinalizeExecution,      runOnFailurePath) \
    X(RawCommand,                      PrepareRuntime,        executionMode) \
    X(RawCommand,                    RunHiddenWithRouting,   executionMode)

// =============================================================================
// Derived config values
// =============================================================================
//
// Columns: derived value ID, C++ type, field.

#define SR_CONFIG_DERIVED_VALUE_TABLE(X) \
    X(StderrEmit,            SR::EmitMode,              stderrEmit) \
    X(StderrEmitSource,      SR::StderrEmitSource,      stderrEmitSource) \
    X(ArgVector,             std::vector<std::wstring>, argVector) \
    X(ChildArgsStartIndex,   int,                       childArgsStartIndex) \
    X(GeneratedSuffix,       std::wstring,              generatedSuffix) \
    X(EffectiveIdSuffixMode, SR::IdSuffixMode,          effectiveIdSuffixMode) \
    X(UseDefaultSuffixMode,  bool,                      useDefaultSuffixMode) \
    X(ExecutionId,           std::wstring,              executionId) \
    X(NeedsParsingToken,     bool,                      needsParsingToken) \
    X(StdoutPresentation,    SR::ChildOutputPresentation, stdoutPresentation) \
    X(StderrChildPresentation, SR::ChildOutputPresentation, stderrChildPresentation)


// Columns: derived value ID, owner ID.
#define SR_CONFIG_DERIVED_VALUE_OWNER_TABLE(X) \
    X(StderrEmit,            SRParentEmitPolicy) \
    X(StderrEmitSource,      SRParentEmitPolicy) \
    X(ArgVector,             PrepareRuntime) \
    X(ChildArgsStartIndex,   PrepareRuntime) \
    X(GeneratedSuffix,       PrepareRuntime) \
    X(GeneratedSuffix,       RunHiddenWithRouting) \
    X(EffectiveIdSuffixMode, PrepareRuntime) \
    X(EffectiveIdSuffixMode, RunHiddenWithRouting) \
    X(UseDefaultSuffixMode,  PrepareRuntime) \
    X(UseDefaultSuffixMode,  RunHiddenWithRouting) \
    X(ExecutionId,           PrepareRuntime) \
    X(ExecutionId,           RunHiddenWithRouting) \
    X(ExecutionId,           FinalizeExecution) \
    X(NeedsParsingToken,       SRWorkerCommonPolicy) \
    X(StdoutPresentation,      SRWorkerCommonPolicy) \
    X(StdoutPresentation,      FinalizeExecution) \
    X(StderrChildPresentation, SRWorkerCommonPolicy) \
    X(StderrChildPresentation, FinalizeExecution)





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


// =============================================================================
// Consumer config types
// =============================================================================

// Materialize one concrete config type per owner.
#define SR_X_CONFIG_STRUCT(owner, member, type) \
    struct owner##Config : ConfigForOwner<ConfigOwner::owner> {};

SR_CONFIG_OWNER_TABLE(SR_X_CONFIG_STRUCT)

#undef SR_X_CONFIG_STRUCT


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
    const std::array<ConfigArgumentData, kConfigArgumentCount>& configArguments,
    SRConfigs& configs
) {
#define SR_X_BUILD_CONSUMER_CONFIG(argument, owner, field) \
    RetrieveConfigForOwner<ConfigOwner::owner>(configs).field = \
        std::get<ConfigArgumentValueType_##argument>( \
            configArguments[ \
                static_cast<std::size_t>(ConfigArgument::argument) \
            ].typedValue \
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
