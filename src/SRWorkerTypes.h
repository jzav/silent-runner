#pragma once

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace SR {
enum class JobTarget;

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

struct FileSinkWorkerFailureState {
    struct TargetFailure {
        JobTarget target{};
        bool suppressed = false;
        uint32_t gle = 0;
        std::wstring reason;
    };
    std::vector<TargetFailure> targets;
};

struct ParentEmitWorkerFailureState {
    struct StreamFailure {
        bool suppressed = false;
        uint32_t gle = 0;
        std::wstring reason;
    };

    StreamFailure workerStdoutFailure;
    StreamFailure workerStderrFailure;
};

using WorkerOperationalFailureState = std::variant<
    std::monostate,
    FileSinkWorkerFailureState,
    ParentEmitWorkerFailureState
>;

} // namespace SR
