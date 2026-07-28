#include "SRReplayJsonlToParent.h"

#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "LogReader.h"
#include "SRReplayJobsBatch.h"
#include "SRJobsExchange.h"
#include "SRLifecycleDiagnostics.h"
#include "SRPendingJobTypes.h"
#include "SRPhaseTimelineEntryJsonlParser.h"

namespace {

struct ReplayBatchContext {
    SRReplayJobsBatch jobsBatch;
    bool allPendingJobsEnqueued = true;
};

struct JsonlReplayContext {
    ReplayBatchContext batch;
    bool parseSucceeded = true;
};


int Base64Value_(char ch) noexcept {
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '+') return 62;
    if (ch == '/') return 63;
    return -1;
}

bool DecodeBase64_(
    const std::string& encoded,
    std::vector<char>& decoded
) {
    decoded.clear();

    if (encoded.size() % 4 != 0) {
        return false;
    }

    decoded.reserve((encoded.size() / 4) * 3);

    for (std::size_t i = 0; i < encoded.size(); i += 4) {
        const char c0 = encoded[i];
        const char c1 = encoded[i + 1];
        const char c2 = encoded[i + 2];
        const char c3 = encoded[i + 3];

        const int v0 = Base64Value_(c0);
        const int v1 = Base64Value_(c1);
        const int v2 = c2 == '=' ? 0 : Base64Value_(c2);
        const int v3 = c3 == '=' ? 0 : Base64Value_(c3);

        if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0) {
            return false;
        }

        const uint32_t block =
            (static_cast<uint32_t>(v0) << 18) |
            (static_cast<uint32_t>(v1) << 12) |
            (static_cast<uint32_t>(v2) << 6) |
            static_cast<uint32_t>(v3);

        decoded.push_back(
            static_cast<char>((block >> 16) & 0xff)
        );

        if (c2 != '=') {
            decoded.push_back(
                static_cast<char>((block >> 8) & 0xff)
            );
        }

        if (c3 != '=') {
            decoded.push_back(
                static_cast<char>(block & 0xff)
            );
        }

        if ((c2 == '=' && c3 != '=') ||
            (c2 == '=' && i + 4 != encoded.size()) ||
            (c3 == '=' && i + 4 != encoded.size())) {
            return false;
        }
    }

    return true;
}


bool TryBuildPendingJobKey_(
    const std::wstring& phaseText,
    uint64_t phaseOrderNo,
    uint64_t eventOrderNo,
    SR::TimelineEntryKey& key
) noexcept {
    if (phaseOrderNo >
        static_cast<uint64_t>(
            std::numeric_limits<uint32_t>::max()
        )) {
        return false;
    }

    SR::LifecyclePhase phase;

    if (!SR::TryParseLifecyclePhase(
            phaseText,
            phase
        )) {
        return false;
    }

    key.phase = phase;
    key.phaseOrderNo =
        static_cast<uint32_t>(phaseOrderNo);
    key.eventOrderNo = eventOrderNo;
    return true;
}

SR::ReplayPayloadStorage ReplayPayloadStorageFromSchemaData_(
    bool payloadDropped
) noexcept {
    return payloadDropped
        ? SR::ReplayPayloadStorage::DroppedByBufferLimit
        : SR::ReplayPayloadStorage::NotNeeded;
}

bool TryBuildPendingJob_(
    const SR::SRPhaseTimelineEntrySchemaData::SrDiagData& data,
    SR::PendingJob& job
) {
    SR::TimelineEntryKey key;
    SR::DiagnosticSeverity severity;

    if (!TryBuildPendingJobKey_(
            data.phase,
            data.phaseOrderNo,
            data.eventOrderNo,
            key
        ) ||
        !SR::TryParseDiagnosticSeverity(
            data.severity,
            severity
        )) {
        return false;
    }

    job = SR::PendingJob{};
    job.key = key;
    job.payloadType = SR::JobPayloadType::SrDiag;

    job.srDiag.key = key;
    job.srDiag.timestampUtc = data.timestampUtc;
    job.srDiag.severity = severity;
    job.srDiag.message = data.message;
    job.srDiag.payloadByteCount = data.payloadByteCount;
    job.srDiag.replayPayloadStorage =
        ReplayPayloadStorageFromSchemaData_(
            data.payloadDropped
        );

    return true;
}

bool TryBuildPendingJob_(
    const SR::SRPhaseTimelineEntrySchemaData::ChildStdoutData& data,
    SR::PendingJob& job
) {
    SR::TimelineEntryKey key;
    std::vector<char> bytes;

    if (!TryBuildPendingJobKey_(
            data.phase,
            data.phaseOrderNo,
            data.eventOrderNo,
            key
        )) {
        return false;
    }

    if (!data.payloadDropped &&
        (!DecodeBase64_(
                data.payloadBase64,
                bytes
            ) ||
         data.payloadByteCount !=
            static_cast<uint64_t>(bytes.size()))) {
        return false;
    }

    job = SR::PendingJob{};
    job.key = key;
    job.payloadType = SR::JobPayloadType::ChildStdout;

    job.childStdout.key = key;
    job.childStdout.timestampUtc = data.timestampUtc;
    job.childStdout.bytes = std::move(bytes);
    job.childStdout.payloadByteCount =
        data.payloadByteCount;
    job.childStdout.replayPayloadStorage =
        ReplayPayloadStorageFromSchemaData_(
            data.payloadDropped
        );

    return true;
}

bool TryBuildPendingJob_(
    const SR::SRPhaseTimelineEntrySchemaData::ChildStderrData& data,
    SR::PendingJob& job
) {
    SR::TimelineEntryKey key;
    std::vector<char> bytes;

    if (!TryBuildPendingJobKey_(
            data.phase,
            data.phaseOrderNo,
            data.eventOrderNo,
            key
        )) {
        return false;
    }

    if (!data.payloadDropped &&
        (!DecodeBase64_(
                data.payloadBase64,
                bytes
            ) ||
         data.payloadByteCount !=
            static_cast<uint64_t>(bytes.size()))) {
        return false;
    }

    job = SR::PendingJob{};
    job.key = key;
    job.payloadType = SR::JobPayloadType::ChildStderr;

    job.childStderr.key = key;
    job.childStderr.timestampUtc = data.timestampUtc;
    job.childStderr.bytes = std::move(bytes);
    job.childStderr.payloadByteCount =
        data.payloadByteCount;
    job.childStderr.replayPayloadStorage =
        ReplayPayloadStorageFromSchemaData_(
            data.payloadDropped
        );

    return true;
}

bool TryBuildPendingJob_(
    const SR::SRPhaseTimelineEntrySchemaData::SchemaDataVariant& data,
    SR::PendingJob& job
) {
    return std::visit(
        [&job](const auto& concreteData) {
            return TryBuildPendingJob_(
                concreteData,
                job
            );
        },
        data
    );
}



bool ReplayLine_(
    void* context,
    const std::string& line
) {
    JsonlReplayContext* replay =
        static_cast<JsonlReplayContext*>(context);

    if (!replay) {
        return false;
    }

    if (line.empty()) {
        return true;
    }

    SR::SRPhaseTimelineEntrySchemaData::SchemaDataVariant schemaData;

    if (!SR::SRPhaseTimelineEntryParser::TryParseJsonLine(
            line,
            schemaData
        )) {
        replay->parseSucceeded = false;
        return false;
    }

    SR::PendingJob job;

    if (!TryBuildPendingJob_(
            schemaData,
            job
        )) {
        replay->parseSucceeded = false;
        return false;
    }

    job.origin = SR::JobOrigin::JsonlReplay;

    replay->batch.allPendingJobsEnqueued =
        replay->batch.jobsBatch.Add(std::move(job));
    return replay->batch.allPendingJobsEnqueued;

}

} // namespace

bool SRReplayJsonlToParent::Init(
    SRLifecycleDiagnostics* diagnostics
) noexcept {
    jobsExchange_ = nullptr;
    diagnostics_ = diagnostics;
    return true;
}

void SRReplayJsonlToParent::SetJobsExchange(
    SRJobsExchange& jobsExchange
) noexcept {
    jobsExchange_ = &jobsExchange;
}

bool SRReplayJsonlToParent::ReplayToParent(
    const SR::ParentReplayParameters& parameters
) {
    if (!jobsExchange_) {
        if (diagnostics_) {
            diagnostics_->ErrorLine(
                L"SRReplayJsonlToParent has no jobs exchange"
            );
        }
        return false;
    }

    bool succeeded = true;

    if (parameters.stdoutParentReplayParameters.source == SR::ParentReplaySource::Jsonl) {
        succeeded =
            ReplayByParameterSet_(parameters.stdoutParentReplayParameters) &&
            succeeded;
    }

    if (parameters.stderrParentReplayParameters.source == SR::ParentReplaySource::Jsonl) {
        succeeded =
            ReplayByParameterSet_(parameters.stderrParentReplayParameters) &&
            succeeded;
    }

    return succeeded;
}

bool SRReplayJsonlToParent::ReplayByParameterSet_(
    const SR::ParentReplayParameterSet& parameters
) {
    if (parameters.path.empty()) {
        if (diagnostics_) {
            diagnostics_->ErrorLine(
                L"JSONL parent replay path is empty"
            );
        }
        return false;
    }

    LogReader::FileReader reader;
    DWORD gle = 0;

    if (!reader.OpenExistingFile(parameters.path, &gle)) {
        if (diagnostics_) {
            diagnostics_->ErrorLine(
                L"Failed to open JSONL replay source: " +
                parameters.path +
                L" GLE=" +
                std::to_wstring(gle)
            );
        }
        return false;
    }

    JsonlReplayContext context;
    if (!context.batch.jobsBatch.Init(

            *jobsExchange_,
            parameters.target
        )) {
        if (diagnostics_) {
            diagnostics_->ErrorLine(
                L"Failed to initialize JSONL replay jobs batch"
            );
        }
        return false;
    }

    const LogReader::ReadResult readResult =
        reader.ReadLines(
            1u << 15,
            &ReplayLine_,
            &context,
            &gle
        );

    reader.Close();

    if (readResult == LogReader::ReadResult::IoFailed) {
        if (diagnostics_) {
            diagnostics_->ErrorLine(
                L"Failed to read JSONL replay source: " +
                parameters.path +
                L" GLE=" +
                std::to_wstring(gle)
            );
        }
        return false;
    }

    if (!context.parseSucceeded) {
        if (diagnostics_) {
            diagnostics_->ErrorLine(
                L"Failed to parse JSONL replay source: " +
                parameters.path
            );
        }
        return false;
    }

    if (readResult == LogReader::ReadResult::CallbackStopped ||
        !context.batch.allPendingJobsEnqueued) {

        if (diagnostics_) {
            diagnostics_->ErrorLine(
                L"Failed to enqueue JSONL replay job: " +
                parameters.path
            );
        }
        return false;
    }

    if (!context.batch.jobsBatch.Flush()) {
        if (diagnostics_) {
            diagnostics_->ErrorLine(
                L"Failed to flush JSONL replay jobs: " +
                parameters.path
            );
        }
        return false;
    }
    return true;
}
