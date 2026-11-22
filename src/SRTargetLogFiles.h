#pragma once

#include <array>
#include <cstddef>
#include <string>
#include <optional>
#include <vector>

#include "LogWriter.h"
#include "SRJobTypes.h"
#include "SRTypes.h"

struct TargetLogFile {
    std::wstring path;
    bool created = false;
    LogWriter::FileWriter writer;
};

struct TargetLogFiles {
    SR::JobTarget target{};
    SR::TargetLogConfig config;
    TargetLogFile running;
    TargetLogFile success;
    TargetLogFile failure;
};
struct TargetLogBinding {
    SR::JobTarget target{};
    bool enabled = false;
    LogWriter::FileWriter* writer = nullptr;
};
struct TargetLogPathBinding {
    SR::JobTarget target{};
    bool created = false;
    const std::wstring* path = nullptr;
    SR::KeepLogMode keepLogMode{};
};
enum class TargetLogFileSlot {
    Running,
    Success,
    Failure
};

enum class LogCreationFailureReason {
    None,
    ExpandDirectoryFailed,
    ResolveDirectoryFailed,
    ExistingPath,
    DuplicatePath,
    EnsureDirectoryFailed,
    CreateRunningFileFailed
};

struct LogCreationFailure {
    LogCreationFailureReason reason =
        LogCreationFailureReason::None;

    SR::JobTarget target{};
    TargetLogFileSlot slot = TargetLogFileSlot::Running;

    SR::JobTarget conflictingTarget{};
    TargetLogFileSlot conflictingSlot =
        TargetLogFileSlot::Running;

    DWORD gle = 0;
    std::wstring missingVariable;
};
struct LogWriterFailure {
    SR::JobTarget target{};
    DWORD gle = 0;
};
enum class TargetLogFinalizationAction {
    None,
    Rename,
    Delete
};
struct TargetLogFinalizationResult {
    SR::JobTarget target{};
    TargetLogFinalizationAction action =
        TargetLogFinalizationAction::None;
    bool succeeded = false;
    DWORD gle = 0;
    std::wstring runningPath;
    std::wstring finalPath;
};
class SRTargetLogFiles {
public:
    void Init(
        const SR::FileSinkWorkerTargetLayout& targetLayout,
        const SR::SRTargetLogFilesConfig& config
    );

    bool ResolveDirectories(
        LogCreationFailure* failure = nullptr
    );
    void BuildLogPaths(
        const std::wstring& executionId
    );
    bool ValidateLogPaths(
        LogCreationFailure* failure = nullptr
    ) const;
    bool PrepareRunningLogs(
        LogCreationFailure* failure = nullptr
    );
    std::array<bool, SR::kJobTargetCount>
    BuildReplaySourceAvailability() const noexcept;

    TargetLogFiles& Target(
        SR::JobTarget target
    ) noexcept;
    const TargetLogFiles& Target(
        SR::JobTarget target
    ) const noexcept;
    std::vector<TargetLogPathBinding> BuildRunningPathBindings(
        const SR::JobTargetFilter& filter
    ) const;
    std::vector<TargetLogPathBinding> GetFinalLogPaths() const;
    std::vector<TargetLogBinding> BuildRunningBindings(
        const SR::JobTargetFilter& filter
    );
    std::vector<TargetLogBinding> BuildFinalBindings(
        const SR::JobTargetFilter& filter,
        bool success
    );
    bool FinalizeRunningLogs(
        bool success,
        std::vector<TargetLogFinalizationResult>& results
    );
    bool FlushRunningWriters(
        const SR::JobTargetFilter& filter,
        LogWriterFailure* failure = nullptr
    );
    bool CloseRunningWriters(
        const SR::JobTargetFilter& filter,
        LogWriterFailure* failure = nullptr
    );
    bool ReopenFinalWriters(
        const SR::JobTargetFilter& filter,
        bool success,
        LogWriterFailure* failure = nullptr
    );
    bool CloseFinalWriters(
        const SR::JobTargetFilter& filter,
        bool success,
        LogWriterFailure* failure = nullptr
    );
private:
    std::vector<std::size_t> SelectTargetConfigIndices_(
        const SR::JobTargetFilter& filter
    ) const;
    TargetLogFile& LogFileForSlot_(
        TargetLogFiles& targetLogFiles,
        TargetLogFileSlot slot
    ) noexcept;
    static bool ShouldKeep_(
        SR::KeepLogMode mode,
        bool success
    ) noexcept;
    std::vector<TargetLogBinding> BuildBindings_(
        const SR::JobTargetFilter& filter,
        TargetLogFileSlot slot
    );
    bool FlushWriters_(
        const SR::JobTargetFilter& filter,
        TargetLogFileSlot slot,
        LogWriterFailure* failure
    );
    bool ReopenWriters_(
        const SR::JobTargetFilter& filter,
        TargetLogFileSlot slot,
        LogWriterFailure* failure
    );
    bool CloseWriters_(
        const SR::JobTargetFilter& filter,
        TargetLogFileSlot slot,
        LogWriterFailure* failure
    );
    SR::FileSinkWorkerTargetLayout targetLayout_{};
    std::array<
        TargetLogFiles,
        SR::kFileSinkTargetConfigCount
    > targets_{};
    std::optional<bool> finalizationSuccess_;
};
