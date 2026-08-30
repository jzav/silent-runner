#include "SRParentReplayRouter.h"

#include "SRExecutionTimeline.h"
#include "SRLifecycleDiagnostics.h"
#include "SRReplayJsonlToParent.h"
#include "SRReplayTxtToParent.h"

namespace {


void SelectPersistentReplaySource_(
    const std::wstring& txtPath,
    const std::wstring& jsonlPath,
    SR::ParentReplayParameterSet& parameters
) noexcept {
    if (!jsonlPath.empty()) {
        parameters.source = SR::ParentReplaySource::Jsonl;
        parameters.path = jsonlPath;
        return;
    }

    if (!txtPath.empty()) {
        parameters.source = SR::ParentReplaySource::Txt;
        parameters.path = txtPath;
        return;
    }

    parameters.source = SR::ParentReplaySource::None;
    parameters.path.clear();
}

bool HasReplaySource_(
    const SR::ParentReplayParameterSet& parameters,
    SR::ParentReplaySource source
) noexcept {
    return parameters.source == source;
}

bool HasReplaySource_(
    const SR::ParentReplayParameters& parameters,
    SR::ParentReplaySource source
) noexcept {
    return
        HasReplaySource_(
            parameters.stdoutParentReplayParameters,
            source
        ) ||
        HasReplaySource_(
            parameters.stderrParentReplayParameters,
            source
        );
}


const wchar_t* ParentReplaySourceToString_(
    SR::ParentReplaySource source
) noexcept {
    switch (source) {
        case SR::ParentReplaySource::None:
            return L"None";
        case SR::ParentReplaySource::Timeline:
            return L"Timeline";
        case SR::ParentReplaySource::Txt:
            return L"Txt";
        case SR::ParentReplaySource::Jsonl:
            return L"Jsonl";
    }

    return L"Unknown";
}

std::wstring FormatReplayParameterSet_(
    const wchar_t* streamName,
    const SR::ParentReplayParameterSet& parameters
) {
    std::wstring out = streamName;
    out += L"={target=";
    out += SR::JobTargetNameToString(parameters.target);
    out += L" source=";
    out += ParentReplaySourceToString_(parameters.source);
    out += L" path=";
    out += parameters.path.empty() ? L"<none>" : parameters.path;
    out += L"}";
    return out;
}
} // namespace

bool SRParentReplayRouter::Init(
    SRLifecycleDiagnostics& lifecycleDiag
) noexcept {
    lifecycleDiag_ = &lifecycleDiag;
    executionTimeline_ = nullptr;
    replayTxtToParent_ = nullptr;
    replayJsonlToParent_ = nullptr;
    return true;
}


void SRParentReplayRouter::SetExecutionTimeline(
    ExecutionTimeline& executionTimeline
) noexcept {
    executionTimeline_ = &executionTimeline;
}

void SRParentReplayRouter::SetReplayTxtToParent(
    SRReplayTxtToParent& replayTxtToParent
) noexcept {
    replayTxtToParent_ = &replayTxtToParent;
}

void SRParentReplayRouter::SetReplayJsonlToParent(
    SRReplayJsonlToParent& replayJsonlToParent
) noexcept {
    replayJsonlToParent_ = &replayJsonlToParent;
}

bool SRParentReplayRouter::ReplayToParent(
    const SR::ParentReplayPolicySnapshot& policySnapshot,
    bool executionSucceeded,
    const SR::LogPaths& logPaths
) {
    if (!lifecycleDiag_) {
        return false;
    }

    lifecycleDiag_->ProbeLine(
        std::wstring(L"[PARENT-REPLAY] Replay starts; executionSucceeded=") +
        (executionSucceeded ? L"true" : L"false")
    );

    lifecycleDiag_->ProbeLine(
        std::wstring(L"[PARENT-REPLAY] Dependencies; executionTimeline=") +
        (executionTimeline_ ? L"set" : L"null") +
        L" replayTxtToParent=" +
        (replayTxtToParent_ ? L"set" : L"null") +
        L" replayJsonlToParent=" +
        (replayJsonlToParent_ ? L"set" : L"null")
    );

    SR::ParentReplayParameters parameters;

    if (!BuildReplayParameters_(
            policySnapshot,
            executionSucceeded,
            logPaths,
            parameters
        )) {
        lifecycleDiag_->ProbeLine(
            L"[PARENT-REPLAY] Failed to build replay parameters"
        );
        lifecycleDiag_->ProbeLine(
            L"[PARENT-REPLAY] BuildReplayParameters_ returned false"
        );
        return false;
    }

    const std::wstring replayPlan =
        FormatReplayParameterSet_(
            L"stdout",
            parameters.stdoutParentReplayParameters
        ) +
        L" " +
        FormatReplayParameterSet_(
            L"stderr",
            parameters.stderrParentReplayParameters
        );

    lifecycleDiag_->ProbeLine(
        L"[PARENT-REPLAY] Replay plan; " + replayPlan
    );

    bool succeeded = true;

    if (HasReplaySource_(
            parameters,
            SR::ParentReplaySource::Timeline
        )) {
        lifecycleDiag_->ProbeLine(
            L"[PARENT-REPLAY] Dispatching timeline replay"
        );

        bool timelineSucceeded = false;
        if (!executionTimeline_) {
            lifecycleDiag_->ProbeLine(
                L"[PARENT-REPLAY] Timeline replay dependency is missing"
            );
        } else {
            timelineSucceeded = ReplayTimeline_(parameters);
        }

        lifecycleDiag_->ProbeLine(
            std::wstring(L"[PARENT-REPLAY] Timeline replay finished; result=") +
            (timelineSucceeded ? L"ok" : L"failed")
        );
        succeeded = timelineSucceeded && succeeded;
    }

    if (HasReplaySource_(
            parameters,
            SR::ParentReplaySource::Jsonl
        )) {
        lifecycleDiag_->ProbeLine(
            L"[PARENT-REPLAY] Dispatching JSONL replay"
        );

        bool jsonlSucceeded = false;
        if (!replayJsonlToParent_) {
            lifecycleDiag_->ProbeLine(
                L"[PARENT-REPLAY] JSONL replay dependency is missing"
            );
        } else {
            jsonlSucceeded =
                replayJsonlToParent_->ReplayToParent(parameters);
        }

        lifecycleDiag_->ProbeLine(
            std::wstring(L"[PARENT-REPLAY] JSONL replay finished; result=") +
            (jsonlSucceeded ? L"ok" : L"failed")
        );
        succeeded = jsonlSucceeded && succeeded;
    }

    if (HasReplaySource_(
            parameters,
            SR::ParentReplaySource::Txt
        )) {
        lifecycleDiag_->ProbeLine(
            L"[PARENT-REPLAY] Dispatching TXT replay"
        );

        bool txtSucceeded = false;
        if (!replayTxtToParent_) {
            lifecycleDiag_->ProbeLine(
                L"[PARENT-REPLAY] TXT replay dependency is missing"
            );
        } else {
            txtSucceeded =
                replayTxtToParent_->ReplayToParent(parameters);
        }

        lifecycleDiag_->ProbeLine(
            std::wstring(L"[PARENT-REPLAY] TXT replay finished; result=") +
            (txtSucceeded ? L"ok" : L"failed")
        );
        succeeded = txtSucceeded && succeeded;
    }

    lifecycleDiag_->DebugLine(
        std::wstring(L"[PARENT-REPLAY] Replay completed with result ") +
        (succeeded ? L"ok" : L"failed") +
        L" using plan: " +
        replayPlan
    );
    lifecycleDiag_->ProbeLine(
        std::wstring(L"[PARENT-REPLAY] Replay ends; result=") +
        (succeeded ? L"ok" : L"failed")
    );
    lifecycleDiag_->ProbeLine(
        std::wstring(L"[PARENT-REPLAY] ReplayToParent leave; result=") +
        (succeeded ? L"ok" : L"failed")
    );

    return succeeded;
}

bool SRParentReplayRouter::BuildReplayParameters_(
    const SR::ParentReplayPolicySnapshot& policySnapshot,
    bool executionSucceeded,
    const SR::LogPaths& logPaths,
    SR::ParentReplayParameters& parameters
) const noexcept {

    parameters = SR::ParentReplayParameters{};

    const SR::LogPathSet& replayLogPaths =
        logPaths.running;

    return
        BuildStdoutReplayParameters_(
            policySnapshot,
            executionSucceeded,
            replayLogPaths,
            parameters.stdoutParentReplayParameters
        ) &&
        BuildStderrReplayParameters_(
            policySnapshot,
            executionSucceeded,
            replayLogPaths,
            parameters.stderrParentReplayParameters
        );
}

bool SRParentReplayRouter::BuildStdoutReplayParameters_(
    const SR::ParentReplayPolicySnapshot& policySnapshot,
    bool executionSucceeded,
    const SR::LogPathSet& logPaths,
    SR::ParentReplayParameterSet& parameters
) const noexcept {
    parameters = SR::ParentReplayParameterSet{};
    parameters.target = SR::JobTarget::StdoutParent;

    const SR::EmitMode emitMode =
        policySnapshot.stdoutEmitMode;
    const bool shouldReplay =
        SR::ShouldReplayForExecutionResult(
            emitMode,
            executionSucceeded
        );


    if (lifecycleDiag_) {
        lifecycleDiag_->ProbeLine(
            std::wstring(L"[PARENT-REPLAY] Stdout decision; emitMode=") +
            SR::EmitModeToString(emitMode) +
            L" executionSucceeded=" +
            (executionSucceeded ? L"true" : L"false") +
            L" shouldReplay=" +
            (shouldReplay ? L"true" : L"false") +
            L" needsReplayBuffer=" +
            (policySnapshot.needsStdoutReplayBuffer ? L"true" : L"false")
        );
        lifecycleDiag_->ProbeLine(
            std::wstring(L"[PARENT-REPLAY] BuildStdoutReplayParameters_; txtPath=") +
            (logPaths.stdoutTxt.empty() ? L"<none>" : logPaths.stdoutTxt) +
            L" jsonlPath=" +
            (logPaths.stdoutJsonl.empty() ? L"<none>" : logPaths.stdoutJsonl)
        );
    }

    if (!shouldReplay) {
        return true;
    }

    if (policySnapshot.needsStdoutReplayBuffer) {
        parameters.source = SR::ParentReplaySource::Timeline;
    } else {
        SelectPersistentReplaySource_(
            logPaths.stdoutTxt,
            logPaths.stdoutJsonl,
            parameters
        );
    }

    if (lifecycleDiag_) {
        lifecycleDiag_->ProbeLine(
            L"[PARENT-REPLAY] Stdout source selected; " +
            FormatReplayParameterSet_(L"stdout", parameters)
        );
    }

    return parameters.source != SR::ParentReplaySource::None;
}

bool SRParentReplayRouter::BuildStderrReplayParameters_(
    const SR::ParentReplayPolicySnapshot& policySnapshot,
    bool executionSucceeded,
    const SR::LogPathSet& logPaths,
    SR::ParentReplayParameterSet& parameters
) const noexcept {
    parameters = SR::ParentReplayParameterSet{};

    parameters.target =
        SR::RetrieveStderrJobTarget(
            policySnapshot.stderrEmitSource
        );
    const SR::EmitMode emitMode =
        policySnapshot.stderrEmitMode;
    const bool shouldReplay =
        SR::ShouldReplayForExecutionResult(
            emitMode,
            executionSucceeded
        );


    if (lifecycleDiag_) {
        lifecycleDiag_->ProbeLine(
            std::wstring(L"[PARENT-REPLAY] Stderr decision; emitMode=") +
            SR::EmitModeToString(emitMode) +
            L" emitSource=" +
            SR::StderrEmitSourceToString(policySnapshot.stderrEmitSource) +
            L" executionSucceeded=" +
            (executionSucceeded ? L"true" : L"false") +
            L" shouldReplay=" +
            (shouldReplay ? L"true" : L"false") +
            L" needsReplayBuffer=" +
            (policySnapshot.needsStderrReplayBuffer ? L"true" : L"false")
        );
    }

    if (!shouldReplay) {
        return true;
    }

    if (policySnapshot.needsStderrReplayBuffer) {
        parameters.source = SR::ParentReplaySource::Timeline;
    } else {
        switch (parameters.target) {
            case SR::JobTarget::StderrSrAndChildParent:
                SelectPersistentReplaySource_(
                    logPaths.stderrSrAndChildTxt,
                    logPaths.stderrSrAndChildJsonl,
                    parameters
                );
                break;

            case SR::JobTarget::StderrChildParent:
                SelectPersistentReplaySource_(
                    logPaths.stderrChildTxt,
                    logPaths.stderrChildJsonl,
                    parameters
                );
                break;

            case SR::JobTarget::StderrSrParent:
                SelectPersistentReplaySource_(
                    logPaths.stderrSrTxt,
                    logPaths.stderrSrJsonl,
                    parameters
                );
                break;
            case SR::JobTarget::StderrSrAndChildInclStdoutParent:
                SelectPersistentReplaySource_(
                    logPaths.stderrSrAndChildInclStdoutTxt,
                    logPaths.stderrSrAndChildInclStdoutJsonl,
                    parameters
                );
                break;


            default:
                if (lifecycleDiag_) {
                    lifecycleDiag_->ProbeLine(
                        L"[PARENT-REPLAY] BuildStderrReplayParameters_ invalid target"
                    );
                }
                return false;
        }
    }

    if (lifecycleDiag_) {
        lifecycleDiag_->ProbeLine(

            L"[PARENT-REPLAY] Stderr source selected; " +
            FormatReplayParameterSet_(L"stderr", parameters)
        );
        lifecycleDiag_->ProbeLine(
            L"[PARENT-REPLAY] BuildStderrReplayParameters_ leave; " +
            FormatReplayParameterSet_(L"stderr", parameters)
        );
    }

    return parameters.source != SR::ParentReplaySource::None;
}

bool SRParentReplayRouter::ReplayTimeline_(
    const SR::ParentReplayParameters& parameters
) {
    return executionTimeline_->ReplayToParent(parameters);
}
