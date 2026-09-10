#pragma once

#include <atomic>

#include "SRJobTypes.h"
#include "SRTypes.h"
#include "SRConfigsBuilderTypes.h"

// Shared runtime policy for parent stdout/stderr delivery.
//
// This object keeps parent emit/replay policy as two explicit configuration
// categories:
//
// - EmitModeConfig: runtime/finalize mutable parent emit modes.
//
// - EmitSourceConfig: source selection plus replayable persistent source
//   availability derived from the generated SRParentEmitPolicyConfig.
//   The persistent source topology is static for a prepared run; the selected
//   stderr source is runtime/finalize mutable but belongs to source selection.
//
// Derived queries are computed from the current EmitSourceConfig +
// EmitModeConfig combination. They are not stored as independent state, which
// prevents stale need*ReplayBuffer or active stderr source aggregates after
// runtime updates.
class SRParentEmitPolicy {
public:
    SRParentEmitPolicy() = default;

    SRParentEmitPolicy(const SRParentEmitPolicy&) = delete;
    SRParentEmitPolicy& operator=(const SRParentEmitPolicy&) = delete;

    bool Init(
        const SR::SRParentEmitPolicyConfig& config
    ) noexcept {
        SetStdoutEmitMode(config.stdoutEmit);
        SetStderrEmitMode(config.stderrEmit);
        SetStderrEmitSource(config.stderrEmitSource);

        emitSourceConfig_.hasReplayablePersistentStdoutTxtSource =
            !config.stdoutDir.empty();
        emitSourceConfig_.hasReplayablePersistentStdoutJsonlSource =
            !config.stdoutDirJsonl.empty();

        emitSourceConfig_.hasReplayablePersistentStderrSrAndChildTxtSource =
            !config.stderrDir.empty();
        emitSourceConfig_.hasReplayablePersistentStderrSrAndChildJsonlSource =
            !config.stderrDirJsonl.empty();
        emitSourceConfig_.hasReplayablePersistentStderrChildTxtSource =
            !config.stderrDirChild.empty();
        emitSourceConfig_.hasReplayablePersistentStderrChildJsonlSource =
            !config.stderrDirChildJsonl.empty();
        emitSourceConfig_.hasReplayablePersistentStderrSrTxtSource =
            !config.stderrDirSr.empty();
        emitSourceConfig_.hasReplayablePersistentStderrSrJsonlSource =
            !config.stderrDirSrJsonl.empty();
        emitSourceConfig_.hasReplayablePersistentStderrSrAndChildInclStdoutTxtSource =
            !config.stderrDirInclStdout.empty();
        emitSourceConfig_.hasReplayablePersistentStderrSrAndChildInclStdoutJsonlSource =
            !config.stderrDirInclStdoutJsonl.empty();

        return true;
    }

    void SetStdoutEmitMode(SR::EmitMode mode) noexcept {
        emitModeConfig_.stdoutEmitMode.store(
            mode,
            std::memory_order_relaxed
        );
    }

    void SetStderrEmitMode(SR::EmitMode mode) noexcept {
        emitModeConfig_.stderrEmitMode.store(
            mode,
            std::memory_order_relaxed
        );
    }

    void SetStderrEmitSource(SR::StderrEmitSource source) noexcept {
        emitSourceConfig_.stderrEmitSource.store(
            source,
            std::memory_order_relaxed
        );
    }
    SR::EmitMode StdoutEmitMode() const noexcept {
        return RetrieveStdoutEmitMode_();
    }
    
    SR::EmitMode StderrEmitMode() const noexcept {
        return RetrieveStderrEmitMode_();
    }
    SR::StderrEmitSource StderrEmitSource() const noexcept {
        return RetrieveStderrEmitSource_();
    }

    SR::EmitMode RetrieveTargetEmitMode(
        SR::JobTarget target
    ) const noexcept {
        if (target == SR::JobTarget::StdoutParent) {
            return RetrieveStdoutEmitMode_();
        }

        const SR::StderrEmitSource stderrEmitSource = RetrieveStderrEmitSource_();

        const SR::JobTarget stderrJobTarget = SR::RetrieveStderrJobTarget(stderrEmitSource);

        if (target == stderrJobTarget) {
            return RetrieveStderrEmitMode_();
        }

        return SR::EmitMode::Never;
    }

    bool HasPersistentReplaySource(SR::JobTarget target) const noexcept {
        switch (target) {
            case SR::JobTarget::StdoutParent:
                return HasReplayablePersistentStdoutSource_();

            case SR::JobTarget::StderrSrAndChildParent:
                return HasReplayablePersistentStderrSrAndChildSource_();

            case SR::JobTarget::StderrChildParent:
                return HasReplayablePersistentStderrChildSource_();

            case SR::JobTarget::StderrSrParent:
                return HasReplayablePersistentStderrSrSource_();
            case SR::JobTarget::StderrSrAndChildInclStdoutParent:
                return HasReplayablePersistentStderrSrAndChildInclStdoutSource_();


            default:
                return false;
        }
    }

    struct ParentTargetJobStateDecision {
        std::optional<SR::JobState> state;
        std::wstring ignoredReasonText;
    };

    ParentTargetJobStateDecision RetrieveParentTargetJobStateDecision(
        SR::JobTarget target
    ) const noexcept {
        ParentTargetJobStateDecision decision;

        const SR::EmitMode emitMode =
            RetrieveTargetEmitMode(target);

        const bool hasPersistentReplaySource =
            HasPersistentReplaySource(target);

        const SR::ParentTargetAction action =
            SR::RetrieveParentTargetAction(
                emitMode,
                hasPersistentReplaySource
            );

        decision.state =
            SR::RetrieveParentTargetActionJobState(
                action
            );

        if (!decision.state ||
            *decision.state != SR::JobState::Ignored) {
            return decision;
        }

        if (emitMode == SR::EmitMode::Never) {
            decision.ignoredReasonText =
                L"Parent target disabled by emit policy";
        } else if (hasPersistentReplaySource) {
            decision.ignoredReasonText =
                L"Persistent replay source available";
        } else {
            decision.ignoredReasonText =
                L"Parent target ignored";
        }

        return decision;
    }


    bool NeedsStdoutReplayBuffer() const noexcept {
        return
            IsBufferedEmitMode(RetrieveStdoutEmitMode_()) &&
            !HasReplayablePersistentStdoutSource_();
    }

    bool NeedsStderrReplayBuffer() const noexcept {
        return
            IsBufferedEmitMode(RetrieveStderrEmitMode_()) &&
            !HasActiveStderrPersistentReplaySource_();
    }
    bool NeedsStderrInclStdoutReplayBuffer() const noexcept {
        return
            RetrieveStderrEmitSource_() ==
                SR::StderrEmitSource::SrAndChildInclStdout &&
            NeedsStderrReplayBuffer();
    }


    static bool IsBufferedEmitMode(SR::EmitMode mode) noexcept {
        return
            mode == SR::EmitMode::End ||
            mode == SR::EmitMode::Success ||
            mode == SR::EmitMode::Failure;
    }

private:
    struct EmitModeConfig {
        // Parent emit modes may change during finalize replay.
        std::atomic<SR::EmitMode> stdoutEmitMode{SR::EmitMode::Stream};
        std::atomic<SR::EmitMode> stderrEmitMode{SR::EmitMode::Stream};
    };

    struct EmitSourceConfig {
        // The selected stderr source is runtime/finalize mutable, but it belongs
        // to source selection rather than emit timing.
        std::atomic<SR::StderrEmitSource> stderrEmitSource{
            SR::StderrEmitSource::SrAndChild
        };

// Replayable persistent source topology is derived from the generated
// config during Init() and is not changed during a prepared run.

        bool hasReplayablePersistentStdoutTxtSource = false;
        bool hasReplayablePersistentStdoutJsonlSource = false;

        bool hasReplayablePersistentStderrSrAndChildTxtSource = false;
        bool hasReplayablePersistentStderrSrAndChildJsonlSource = false;
        bool hasReplayablePersistentStderrChildTxtSource = false;
        bool hasReplayablePersistentStderrChildJsonlSource = false;
        bool hasReplayablePersistentStderrSrTxtSource = false;
        bool hasReplayablePersistentStderrSrJsonlSource = false;
        bool hasReplayablePersistentStderrSrAndChildInclStdoutTxtSource = false;
        bool hasReplayablePersistentStderrSrAndChildInclStdoutJsonlSource = false;

    };

    SR::EmitMode RetrieveStdoutEmitMode_() const noexcept {
        return emitModeConfig_.stdoutEmitMode.load(std::memory_order_relaxed);
    }

    SR::EmitMode RetrieveStderrEmitMode_() const noexcept {
        return emitModeConfig_.stderrEmitMode.load(std::memory_order_relaxed);
    }

    SR::StderrEmitSource RetrieveStderrEmitSource_() const noexcept {
        return emitSourceConfig_.stderrEmitSource.load(std::memory_order_relaxed);
    }

    bool HasReplayablePersistentStdoutSource_() const noexcept {
        return
            emitSourceConfig_.hasReplayablePersistentStdoutTxtSource ||
            emitSourceConfig_.hasReplayablePersistentStdoutJsonlSource;
    }

    bool HasReplayablePersistentStderrSrAndChildSource_() const noexcept {
        return
            emitSourceConfig_.hasReplayablePersistentStderrSrAndChildTxtSource ||
            emitSourceConfig_.hasReplayablePersistentStderrSrAndChildJsonlSource;
    }

    bool HasReplayablePersistentStderrChildSource_() const noexcept {
        return
            emitSourceConfig_.hasReplayablePersistentStderrChildTxtSource ||
            emitSourceConfig_.hasReplayablePersistentStderrChildJsonlSource;
    }

    bool HasReplayablePersistentStderrSrSource_() const noexcept {
        return
            emitSourceConfig_.hasReplayablePersistentStderrSrTxtSource ||
            emitSourceConfig_.hasReplayablePersistentStderrSrJsonlSource;
    }
    bool HasReplayablePersistentStderrSrAndChildInclStdoutSource_() const noexcept {
        return
            emitSourceConfig_.hasReplayablePersistentStderrSrAndChildInclStdoutTxtSource ||
            emitSourceConfig_.hasReplayablePersistentStderrSrAndChildInclStdoutJsonlSource;
    }


    bool HasActiveStderrPersistentReplaySource_() const noexcept {
        switch (RetrieveStderrEmitSource_()) {
            case SR::StderrEmitSource::SrAndChild:
                return HasReplayablePersistentStderrSrAndChildSource_();

            case SR::StderrEmitSource::Child:
                return HasReplayablePersistentStderrChildSource_();

            case SR::StderrEmitSource::Sr:
                return HasReplayablePersistentStderrSrSource_();
            case SR::StderrEmitSource::SrAndChildInclStdout:
                return HasReplayablePersistentStderrSrAndChildInclStdoutSource_();


            default:
                return false;
        }
    }

    EmitModeConfig emitModeConfig_;
    EmitSourceConfig emitSourceConfig_;
};
