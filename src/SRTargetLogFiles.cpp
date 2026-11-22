#include "SRTargetLogFiles.h"
#include "FileHelpers.h"
#include "TextHelpers.h"
#include <utility>

void SRTargetLogFiles::Init(
    const SR::FileSinkWorkerTargetLayout& targetLayout,
    const SR::SRTargetLogFilesConfig& config
) {
    targetLayout_ = targetLayout;
    finalizationSuccess_.reset();
    for (std::size_t i = 0; i < targets_.size(); ++i) {
        const SR::JobTarget target =
            targetLayout_.targets[i].target;
        targets_[i].target = target;
        targets_[i].config =
            config.targetLogConfigs.For(target);
    }
}

bool SRTargetLogFiles::ResolveDirectories(
    LogCreationFailure* failure
) {
    if (failure) {
        *failure = {};
    }

    for (auto& targetLogFiles : targets_) {
        if (!targetLogFiles.config.directoryRequested) {
            continue;
        }

        std::wstring expandedDirectory;
        std::wstring missingVariable;
        DWORD gle = 0;

        const bool expansionSucceeded =
            FileHelpers::TryExpandEnvironmentVariables(
                targetLogFiles.config.directory,
                expandedDirectory,
                missingVariable,
                &gle
            );

        if (!expansionSucceeded || expandedDirectory.empty()) {
            if (failure) {
                failure->reason =
                    LogCreationFailureReason::ExpandDirectoryFailed;
                failure->target = targetLogFiles.target;
                failure->gle = gle;
                failure->missingVariable = std::move(missingVariable);
            }
            return false;
        }

        std::wstring resolvedDirectory;
        if (!FileHelpers::TryResolveFullPath(
                expandedDirectory,
                resolvedDirectory,
                &gle
            )) {
            if (failure) {
                failure->reason =
                    LogCreationFailureReason::ResolveDirectoryFailed;
                failure->target = targetLogFiles.target;
                failure->gle = gle;
            }
            return false;
        }

        targetLogFiles.config.directory =
            std::move(resolvedDirectory);
    }

    return true;
}
void SRTargetLogFiles::BuildLogPaths(
    const std::wstring& executionId
) {
    for (std::size_t i = 0; i < targets_.size(); ++i) {
        auto& targetLogFiles = targets_[i];
        const auto& layout = targetLayout_.targets[i];

        targetLogFiles.running.path.clear();
        targetLogFiles.success.path.clear();
        targetLogFiles.failure.path.clear();

        if (!targetLogFiles.config.directoryRequested) {
            continue;
        }

        const std::wstring prefix =
            executionId + L"_" + layout.logFileStem;

        const wchar_t* extension =
            layout.format == SR::JobTargetFormat::Jsonl
                ? L".jsonl"
                : L".log";

        auto buildPath = [&](const wchar_t* state) {
            return FileHelpers::JoinPath(
                targetLogFiles.config.directory,
                prefix + L"_" + state + extension
            );
        };

        targetLogFiles.running.path = buildPath(L"running");
        targetLogFiles.success.path = buildPath(L"success");
        targetLogFiles.failure.path = buildPath(L"failure");
    }
}
bool SRTargetLogFiles::ValidateLogPaths(
    LogCreationFailure* failure
) const {
    if (failure) {
        *failure = {};
    }

    struct PathEntry {
        SR::JobTarget target;
        TargetLogFileSlot slot;
        const std::wstring* path;
    };

    std::vector<PathEntry> paths;
    paths.reserve(targets_.size() * 3);

    for (const auto& targetLogFiles : targets_) {
        if (!targetLogFiles.config.directoryRequested) {
            continue;
        }

        paths.push_back({
            targetLogFiles.target,
            TargetLogFileSlot::Running,
            &targetLogFiles.running.path
        });
        paths.push_back({
            targetLogFiles.target,
            TargetLogFileSlot::Success,
            &targetLogFiles.success.path
        });
        paths.push_back({
            targetLogFiles.target,
            TargetLogFileSlot::Failure,
            &targetLogFiles.failure.path
        });
    }

    for (std::size_t i = 0; i < paths.size(); ++i) {
        for (std::size_t j = 0; j < i; ++j) {
            if (!TextHelpers::EqualsOrdinalIgnoreCase(
                    *paths[i].path,
                    *paths[j].path
                )) {
                continue;
            }

            if (failure) {
                failure->reason =
                    LogCreationFailureReason::DuplicatePath;
                failure->target = paths[i].target;
                failure->slot = paths[i].slot;
                failure->conflictingTarget = paths[j].target;
                failure->conflictingSlot = paths[j].slot;
            }
            return false;
        }

        const DWORD attributes =
            GetFileAttributesW(paths[i].path->c_str());

        if (attributes != INVALID_FILE_ATTRIBUTES) {
            if (failure) {
                failure->reason =
                    LogCreationFailureReason::ExistingPath;
                failure->target = paths[i].target;
                failure->slot = paths[i].slot;
            }
            return false;
        }

        const DWORD gle = GetLastError();
        if (gle != ERROR_FILE_NOT_FOUND &&
            gle != ERROR_PATH_NOT_FOUND) {
            if (failure) {
                failure->reason =
                    LogCreationFailureReason::ExistingPath;
                failure->target = paths[i].target;
                failure->slot = paths[i].slot;
                failure->gle = gle;
            }
            return false;
        }
    }

    return true;
}
bool SRTargetLogFiles::PrepareRunningLogs(
    LogCreationFailure* failure
) {
    if (failure) {
        *failure = {};
    }

    for (auto& targetLogFiles : targets_) {
        if (!targetLogFiles.config.directoryRequested) {
            continue;
        }

        DWORD gle = 0;

        if (!FileHelpers::EnsureDirExists(
                targetLogFiles.config.directory,
                &gle
            )) {
            if (failure) {
                failure->reason =
                    LogCreationFailureReason::EnsureDirectoryFailed;
                failure->target = targetLogFiles.target;
                failure->slot = TargetLogFileSlot::Running;
                failure->gle = gle;
            }
            return false;
        }

        if (!targetLogFiles.running.writer.CreateNewFile(
                targetLogFiles.running.path,
                &gle
            )) {
            if (failure) {
                failure->reason =
                    LogCreationFailureReason::CreateRunningFileFailed;
                failure->target = targetLogFiles.target;
                failure->slot = TargetLogFileSlot::Running;
                failure->gle = gle;
            }
            return false;
        }

        targetLogFiles.running.created = true;
    }

    return true;
}
std::array<bool, SR::kJobTargetCount>
SRTargetLogFiles::BuildReplaySourceAvailability() const noexcept {
    std::array<bool, SR::kJobTargetCount> configuredByTarget{};
    for (const auto& targetLogFiles : targets_) {
        configuredByTarget[
            static_cast<std::size_t>(targetLogFiles.target)
        ] = targetLogFiles.config.directoryRequested;
    }
    return configuredByTarget;
}




TargetLogFiles& SRTargetLogFiles::Target(
    SR::JobTarget target
) noexcept {
    return targets_[targetLayout_.ConfigIndexOf(target)];
}
const TargetLogFiles& SRTargetLogFiles::Target(
    SR::JobTarget target
) const noexcept {
    return targets_[targetLayout_.ConfigIndexOf(target)];
}
std::vector<std::size_t> SRTargetLogFiles::SelectTargetConfigIndices_(
    const SR::JobTargetFilter& filter
) const {
    const auto selectedTargets = SR::RetrieveJobTargets(filter);
    std::vector<std::size_t> configIndices;
    configIndices.reserve(selectedTargets.size());
    for (const SR::JobTarget target : selectedTargets) {
        const std::size_t configIndex =
            targetLayout_.ConfigIndexOf(target);
        if (configIndex == SR::kInvalidJobTargetWorkerConfigIndex) {
            continue;
        }
        configIndices.push_back(configIndex);
    }
    return configIndices;
}
std::vector<TargetLogPathBinding> SRTargetLogFiles::BuildRunningPathBindings(
    const SR::JobTargetFilter& filter
) const {
    const auto configIndices =
        SelectTargetConfigIndices_(filter);
    std::vector<TargetLogPathBinding> bindings;
    bindings.reserve(configIndices.size());
    for (const std::size_t configIndex : configIndices) {
        const TargetLogFiles& targetLogFiles =
            targets_[configIndex];
        bindings.push_back(TargetLogPathBinding{
            targetLogFiles.target,
            targetLogFiles.running.created,
            &targetLogFiles.running.path,
            targetLogFiles.config.keepLogMode
        });
    }
    return bindings;
}
std::vector<TargetLogPathBinding> SRTargetLogFiles::GetFinalLogPaths() const {
    std::vector<TargetLogPathBinding> bindings;
    if (!finalizationSuccess_.has_value()) {
        return bindings;
    }

    bindings.reserve(targets_.size());
    for (const TargetLogFiles& targetLogFiles : targets_) {
        const TargetLogFile& logFile =
            *finalizationSuccess_
                ? targetLogFiles.success
                : targetLogFiles.failure;

        bindings.push_back(TargetLogPathBinding{
            targetLogFiles.target,
            logFile.created,
            &logFile.path,
            targetLogFiles.config.keepLogMode
        });
    }

    return bindings;
}
std::vector<TargetLogBinding> SRTargetLogFiles::BuildRunningBindings(
    const SR::JobTargetFilter& filter
) {
    return BuildBindings_(
        filter,
        TargetLogFileSlot::Running
    );
}
std::vector<TargetLogBinding> SRTargetLogFiles::BuildFinalBindings(
    const SR::JobTargetFilter& filter,
    bool success
) {
    return BuildBindings_(
        filter,
        success
            ? TargetLogFileSlot::Success
            : TargetLogFileSlot::Failure
    );
}
TargetLogFile& SRTargetLogFiles::LogFileForSlot_(
    TargetLogFiles& targetLogFiles,
    TargetLogFileSlot slot
) noexcept {
    switch (slot) {
        case TargetLogFileSlot::Running:
            return targetLogFiles.running;
        case TargetLogFileSlot::Success:
            return targetLogFiles.success;
        case TargetLogFileSlot::Failure:
            return targetLogFiles.failure;
    }
    return targetLogFiles.running;
}
bool SRTargetLogFiles::ShouldKeep_(
    SR::KeepLogMode mode,
    bool success
) noexcept {
    switch (mode) {
        case SR::KeepLogMode::Always:
            return true;
        case SR::KeepLogMode::Success:
            return success;
        case SR::KeepLogMode::Failure:
            return !success;
    }
    return true;
}
bool SRTargetLogFiles::FinalizeRunningLogs(
    bool success,
    std::vector<TargetLogFinalizationResult>& results
) {
    finalizationSuccess_ = success;
    results.clear();
    bool allSucceeded = true;
    for (TargetLogFiles& targetLogFiles : targets_) {
        if (!targetLogFiles.running.created) {
            continue;
        }
        TargetLogFinalizationResult result;
        result.target = targetLogFiles.target;
        result.runningPath = targetLogFiles.running.path;
        const bool keep =
            ShouldKeep_(
                targetLogFiles.config.keepLogMode,
                success
            );
        DWORD gle = 0;
        if (keep) {
            TargetLogFile& finalLogFile =
                LogFileForSlot_(
                    targetLogFiles,
                    success
                        ? TargetLogFileSlot::Success
                        : TargetLogFileSlot::Failure
                );
            result.action =
                TargetLogFinalizationAction::Rename;
            result.finalPath = finalLogFile.path;
            result.succeeded =
                LogWriter::TryRenameLogFile(
                    targetLogFiles.running.path,
                    finalLogFile.path,
                    &gle
                );
            if (result.succeeded) {
                targetLogFiles.running.created = false;
                finalLogFile.created = true;
            }
        } else {
            result.action =
                TargetLogFinalizationAction::Delete;
            result.succeeded =
                LogWriter::TryDeleteLogFile(
                    targetLogFiles.running.path,
                    &gle
                );
            if (result.succeeded) {
                targetLogFiles.running.created = false;
            }
        }
        result.gle = gle;
        if (!result.succeeded) {
            allSucceeded = false;
        }
        results.push_back(result);
    }
    return allSucceeded;
}
bool SRTargetLogFiles::FlushRunningWriters(
    const SR::JobTargetFilter& filter,
    LogWriterFailure* failure
) {
    return FlushWriters_(
        filter,
        TargetLogFileSlot::Running,
        failure
    );
}
bool SRTargetLogFiles::CloseRunningWriters(
    const SR::JobTargetFilter& filter,
    LogWriterFailure* failure
) {
    return CloseWriters_(
        filter,
        TargetLogFileSlot::Running,
        failure
    );
}
bool SRTargetLogFiles::ReopenFinalWriters(
    const SR::JobTargetFilter& filter,
    bool success,
    LogWriterFailure* failure
) {
    return ReopenWriters_(
        filter,
        success
            ? TargetLogFileSlot::Success
            : TargetLogFileSlot::Failure,
        failure
    );
}
bool SRTargetLogFiles::CloseFinalWriters(
    const SR::JobTargetFilter& filter,
    bool success,
    LogWriterFailure* failure
) {
    return CloseWriters_(
        filter,
        success
            ? TargetLogFileSlot::Success
            : TargetLogFileSlot::Failure,
        failure
    );
}
bool SRTargetLogFiles::FlushWriters_(
    const SR::JobTargetFilter& filter,
    TargetLogFileSlot slot,
    LogWriterFailure* failure
) {
    if (failure) {
        *failure = LogWriterFailure{};
    }
    const auto configIndices =
        SelectTargetConfigIndices_(filter);
    for (const std::size_t configIndex : configIndices) {
        TargetLogFiles& targetLogFiles =
            targets_[configIndex];
        TargetLogFile& logFile =
            LogFileForSlot_(targetLogFiles, slot);
        if (!logFile.writer.IsOpen()) {
            continue;
        }
        DWORD gle = 0;
        if (!logFile.writer.Flush(&gle)) {
            if (failure) {
                failure->target = targetLogFiles.target;
                failure->gle = gle;
            }
            return false;
        }
    }
    return true;
}
bool SRTargetLogFiles::ReopenWriters_(
    const SR::JobTargetFilter& filter,
    TargetLogFileSlot slot,
    LogWriterFailure* failure
) {
    if (failure) {
        *failure = LogWriterFailure{};
    }
    const auto configIndices =
        SelectTargetConfigIndices_(filter);
    bool success = true;
    for (const std::size_t configIndex : configIndices) {
        TargetLogFiles& targetLogFiles =
            targets_[configIndex];
        TargetLogFile& logFile =
            LogFileForSlot_(targetLogFiles, slot);
        if (!logFile.created || logFile.writer.IsOpen()) {
            continue;
        }
        DWORD gle = 0;
        if (!logFile.writer.OpenAppendFile(logFile.path, &gle)) {
            if (success && failure) {
                failure->target = targetLogFiles.target;
                failure->gle = gle;
            }
            success = false;
        }
    }
    return success;
}
bool SRTargetLogFiles::CloseWriters_(
    const SR::JobTargetFilter& filter,
    TargetLogFileSlot slot,
    LogWriterFailure* failure
) {
    if (failure) {
        *failure = LogWriterFailure{};
    }
    const auto configIndices =
        SelectTargetConfigIndices_(filter);
    bool success = true;
    for (const std::size_t configIndex : configIndices) {
        TargetLogFiles& targetLogFiles =
            targets_[configIndex];
        TargetLogFile& logFile =
            LogFileForSlot_(targetLogFiles, slot);
        if (!logFile.writer.IsOpen()) {
            continue;
        }
        DWORD gle = 0;
        if (!logFile.writer.Close(&gle)) {
            if (success && failure) {
                failure->target = targetLogFiles.target;
                failure->gle = gle;
            }
            success = false;
        }
    }
    return success;
}
std::vector<TargetLogBinding> SRTargetLogFiles::BuildBindings_(
    const SR::JobTargetFilter& filter,
    TargetLogFileSlot slot
) {
    const auto configIndices =
        SelectTargetConfigIndices_(filter);
    std::vector<TargetLogBinding> bindings;
    bindings.reserve(configIndices.size());
    for (const std::size_t configIndex : configIndices) {
        TargetLogFiles& targetLogFiles =
            targets_[configIndex];
        TargetLogFile& logFile =
            LogFileForSlot_(targetLogFiles, slot);
        const bool enabled =
            logFile.created &&
            logFile.writer.IsOpen();
        bindings.push_back(TargetLogBinding{
            targetLogFiles.target,
            enabled,
            enabled ? &logFile.writer : nullptr
        });
    }
    return bindings;
}
