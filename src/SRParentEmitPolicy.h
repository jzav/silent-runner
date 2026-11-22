#pragma once

#include <atomic>
#include <array>

#include "SRJobTypes.h"
#include "SRTypes.h"
#include "SRParentEmitPolicyTypes.h"

// Shared runtime policy for parent stdout/stderr delivery.
//
// This object keeps parent emit/replay policy as two explicit configuration
// categories:
//
// - EmitModeConfig: runtime/finalize mutable parent emit modes.
//
// - ReplaySourceConfig: static replay-source layout and configured-source
//   availability prepared at Init().
//
// Derived queries use the selected parent targets, current emit modes,
// and replay-source availability without duplicating aggregate state.
class SRParentEmitPolicy {
public:
    SRParentEmitPolicy() = default;

    SRParentEmitPolicy(const SRParentEmitPolicy&) = delete;
    SRParentEmitPolicy& operator=(const SRParentEmitPolicy&) = delete;

    bool Init(
        const SR::SRParentEmitPolicyConfig& config,
        const std::array<bool, SR::kJobTargetCount>&
            persistentReplaySourceConfiguredByTarget,
        const SR::ParentReplaySourceLayout& replaySourceLayout
    ) noexcept {
        stdoutParentTarget_ = config.stdoutParentTarget;
        stderrParentTarget_ = config.stderrParentTarget;
        SetStdoutEmitMode(config.stdoutEmitMode);
        SetStderrEmitMode(config.stderrEmitMode);
        replaySourceConfig_.replaySourceLayout = replaySourceLayout;
        replaySourceConfig_.persistentReplaySourceConfiguredByTarget =
            persistentReplaySourceConfiguredByTarget;
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

    SR::EmitMode StdoutEmitMode() const noexcept {
        return RetrieveStdoutEmitMode_();
    }
    
    SR::EmitMode StderrEmitMode() const noexcept {
        return RetrieveStderrEmitMode_();
    }

    SR::JobTarget StdoutParentTarget() const noexcept {
        return stdoutParentTarget_;
    }

    SR::JobTarget StderrParentTarget() const noexcept {
        return stderrParentTarget_;
    }

    SR::EmitMode RetrieveTargetEmitMode(
        SR::JobTarget target
    ) const noexcept {
        if (target == stdoutParentTarget_) {
            return RetrieveStdoutEmitMode_();
        }

        if (target == stderrParentTarget_) {
            return RetrieveStderrEmitMode_();
        }

        return SR::EmitMode::Never;
    }

    bool HasPersistentReplaySource(SR::JobTarget target) const noexcept {
        for (const auto& source : replaySourceConfig_.replaySourceLayout.entries) {
            if (source.parentTarget != target) {
                continue;
            }
            if (replaySourceConfig_.persistentReplaySourceConfiguredByTarget[
                    static_cast<std::size_t>(source.sourceTarget)
                ]) {
                return true;
            }
        }
        return false;
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
            !HasPersistentReplaySource(stdoutParentTarget_);
    }

    bool NeedsStderrReplayBuffer() const noexcept {
        return
            IsBufferedEmitMode(RetrieveStderrEmitMode_()) &&
            !HasPersistentReplaySource(stderrParentTarget_);
    }

    bool NeedsStderrInclStdoutReplayBuffer() const noexcept {
        return
            stderrParentTarget_ ==
                SR::JobTarget::StderrSrAndChildInclStdoutParent &&
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

    struct ReplaySourceConfig {
        // Replay topology and configured-source availability are prepared
        // during Init() and remain static for the prepared run.
        SR::ParentReplaySourceLayout replaySourceLayout{};
        std::array<
            bool,
            SR::kJobTargetCount
        > persistentReplaySourceConfiguredByTarget{};
    };

    SR::EmitMode RetrieveStdoutEmitMode_() const noexcept {
        return emitModeConfig_.stdoutEmitMode.load(std::memory_order_relaxed);
    }

    SR::EmitMode RetrieveStderrEmitMode_() const noexcept {
        return emitModeConfig_.stderrEmitMode.load(std::memory_order_relaxed);
    }



    SR::JobTarget stdoutParentTarget_ = SR::JobTarget::StdoutParent;
    SR::JobTarget stderrParentTarget_ =
        SR::JobTarget::StderrSrAndChildParent;
    EmitModeConfig emitModeConfig_;
    ReplaySourceConfig replaySourceConfig_;
};
