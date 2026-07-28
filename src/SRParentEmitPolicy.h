#pragma once

#include <atomic>

#include "SRJobTypes.h"
#include "SRTypes.h"

// Shared runtime policy for parent stdout/stderr delivery.
//
// This object keeps parent emit/replay policy as two explicit configuration
// categories:
//
// - EmitModeConfig: runtime/finalize mutable parent emit modes.
//
// - EmitSourceConfig: source selection plus replayable persistent source
//   availability copied from finalized SR::Options after
//   ArgumentParser::FinalizeReplayPolicyOptions().
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

    bool Init() noexcept {
        emitModeConfig_.stdoutEmitMode.store(
            SR::EmitMode::Stream,
            std::memory_order_relaxed
        );
        emitModeConfig_.stderrEmitMode.store(
            SR::EmitMode::Stream,
            std::memory_order_relaxed
        );

        emitSourceConfig_.stderrEmitSource.store(
            SR::StderrEmitSource::Mixed,
            std::memory_order_relaxed
        );
        emitSourceConfig_.hasReplayablePersistentStdoutTxtSource = false;
        emitSourceConfig_.hasReplayablePersistentStdoutJsonlSource = false;
        
        emitSourceConfig_.hasReplayablePersistentStderrMixedTxtSource = false;
        emitSourceConfig_.hasReplayablePersistentStderrMixedJsonlSource = false;
        emitSourceConfig_.hasReplayablePersistentStderrChildTxtSource = false;
        emitSourceConfig_.hasReplayablePersistentStderrChildJsonlSource = false;
        emitSourceConfig_.hasReplayablePersistentStderrSrTxtSource = false;
        emitSourceConfig_.hasReplayablePersistentStderrSrJsonlSource = false;
        return true;
    }

    void SetFromFinalizedOptions(const SR::Options& opt) noexcept {
        emitSourceConfig_.hasReplayablePersistentStdoutTxtSource =
            opt.hasReplayablePersistentStdoutTxtSource;
        emitSourceConfig_.hasReplayablePersistentStdoutJsonlSource =
            opt.hasReplayablePersistentStdoutJsonlSource;

        emitSourceConfig_.hasReplayablePersistentStderrMixedTxtSource =
            opt.hasReplayablePersistentStderrMixedTxtSource;
        emitSourceConfig_.hasReplayablePersistentStderrMixedJsonlSource =
            opt.hasReplayablePersistentStderrMixedJsonlSource;
        emitSourceConfig_.hasReplayablePersistentStderrChildTxtSource =
            opt.hasReplayablePersistentStderrChildTxtSource;
        emitSourceConfig_.hasReplayablePersistentStderrChildJsonlSource =
            opt.hasReplayablePersistentStderrChildJsonlSource;
        emitSourceConfig_.hasReplayablePersistentStderrSrTxtSource =
            opt.hasReplayablePersistentStderrSrTxtSource;
        emitSourceConfig_.hasReplayablePersistentStderrSrJsonlSource =
            opt.hasReplayablePersistentStderrSrJsonlSource;

        SetStdoutEmitMode(opt.stdoutEmit);
        SetStderrEmitMode(opt.stderrEmit);
        SetStderrEmitSource(opt.stderrEmitSource);
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

            case SR::JobTarget::StderrMixedParent:
                return HasReplayablePersistentStderrMixedSource_();

            case SR::JobTarget::StderrChildParent:
                return HasReplayablePersistentStderrChildSource_();

            case SR::JobTarget::StderrSrParent:
                return HasReplayablePersistentStderrSrSource_();

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
            SR::StderrEmitSource::Mixed
        };

        // Replayable persistent source topology is copied from finalized
        // options and is not changed during a prepared run.
        bool hasReplayablePersistentStdoutTxtSource = false;
        bool hasReplayablePersistentStdoutJsonlSource = false;

        bool hasReplayablePersistentStderrMixedTxtSource = false;
        bool hasReplayablePersistentStderrMixedJsonlSource = false;
        bool hasReplayablePersistentStderrChildTxtSource = false;
        bool hasReplayablePersistentStderrChildJsonlSource = false;
        bool hasReplayablePersistentStderrSrTxtSource = false;
        bool hasReplayablePersistentStderrSrJsonlSource = false;
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

    bool HasReplayablePersistentStderrMixedSource_() const noexcept {
        return
            emitSourceConfig_.hasReplayablePersistentStderrMixedTxtSource ||
            emitSourceConfig_.hasReplayablePersistentStderrMixedJsonlSource;
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

    bool HasActiveStderrPersistentReplaySource_() const noexcept {
        switch (RetrieveStderrEmitSource_()) {
            case SR::StderrEmitSource::Mixed:
                return HasReplayablePersistentStderrMixedSource_();

            case SR::StderrEmitSource::Child:
                return HasReplayablePersistentStderrChildSource_();

            case SR::StderrEmitSource::SilentRunner:
                return HasReplayablePersistentStderrSrSource_();

            default:
                return false;
        }
    }

    EmitModeConfig emitModeConfig_;
    EmitSourceConfig emitSourceConfig_;
};
