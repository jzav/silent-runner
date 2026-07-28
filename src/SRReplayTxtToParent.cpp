#include "SRReplayTxtToParent.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "FileHelpers.h"
#include "LogReader.h"
#include "SRReplayJobsBatch.h"
#include "SRJobsExchange.h"
#include "SRLifecycleDiagnostics.h"
#include "SRPendingJobTypes.h"
#include "SRPhaseTimelineEntryTxtHeaderParser.h"
#include "TextHelpers.h"


namespace {

constexpr DWORD kReplayBufferSize = 1u << 16;
constexpr char kLf = '\n';
constexpr char kHeaderPrefix[] = "[payloadType=";

struct ReplayBatchContext {
    SRReplayJobsBatch jobsBatch;
    bool allPendingJobsEnqueued = true;
};

struct PlainTxtReplayContext {
    ReplayBatchContext batch;
    SR::JobPayloadType payloadType = SR::JobPayloadType::ChildStdout;
    uint64_t nextEventOrderNo = 0;
};


bool ReplayPlainChunk_(
    void* context,
    const char* data,
    std::size_t size
) {
    PlainTxtReplayContext* replay =
        static_cast<PlainTxtReplayContext*>(context);

    if (!replay ||
        !data ||
        size == 0) {
        return false;
    }

    SR::PendingJob job;
    job.origin = SR::JobOrigin::TxtReplay;
    job.key.phase = static_cast<SR::LifecyclePhase>(0);
    job.key.phaseOrderNo = 0;
    job.key.eventOrderNo = replay->nextEventOrderNo++;
    job.payloadType = replay->payloadType;

    if (replay->payloadType == SR::JobPayloadType::ChildStdout) {
        job.childStdout.key = job.key;
        job.childStdout.bytes.assign(data, data + size);
        job.childStdout.payloadByteCount =
            static_cast<uint64_t>(size);
        job.childStdout.replayPayloadStorage =
            SR::ReplayPayloadStorage::NotNeeded;
    } else if (replay->payloadType == SR::JobPayloadType::ChildStderr) {
        job.childStderr.key = job.key;
        job.childStderr.bytes.assign(data, data + size);
        job.childStderr.payloadByteCount =
            static_cast<uint64_t>(size);
        job.childStderr.replayPayloadStorage =
            SR::ReplayPayloadStorage::NotNeeded;
    } else {
        return false;
    }

    replay->batch.allPendingJobsEnqueued =
        replay->batch.jobsBatch.Add(std::move(job));
    return replay->batch.allPendingJobsEnqueued;
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
    if (!SR::TryParseLifecyclePhaseUppercase(
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

} // namespace


struct SRReplayTxtToParent::SegmentReplayContext {
    SR::SRPhaseTimelineEntrySchemaData::SchemaDataVariant schemaData;
    uint64_t nextEventOrderNo = 0;
    bool headerParsingSucceeded = true;
};

struct SRReplayTxtToParent::ReplayBatchContext {
    SRReplayJobsBatch jobsBatch;
    bool allPendingJobsEnqueued = true;
};


bool SRReplayTxtToParent::Init(
    SRLifecycleDiagnostics* diagnostics,
    const std::string& parsingToken,
    std::size_t pendingJobPayloadSize
) noexcept {
    jobsExchange_ = nullptr;
    diagnostics_ = diagnostics;

    currentBuffer_.clear();
    nextBuffer_.clear();

    parsingToken_ = parsingToken;
    parsingTokenSuffix_ =
        "[parsingToken=" +
        parsingToken_ +
        "]";

    pendingJobPayloadSize_ = pendingJobPayloadSize;

    return
        !parsingToken_.empty() &&
        pendingJobPayloadSize_ != 0;
}

void SRReplayTxtToParent::SetJobsExchange(
    SRJobsExchange& jobsExchange
) noexcept {
    jobsExchange_ = &jobsExchange;
}

SRReplayTxtToParent::TxtReplayMode
SRReplayTxtToParent::DetermineTxtReplayMode_(
    SR::JobTarget target
) {
    SR::JobTargetFilter filter;
    filter.format = SR::JobTargetFormat::Parent;
    filter.headerParsingTokenEnabled = true;

    for (const SR::JobTarget headeredTarget :
         SR::RetrieveJobTargets(filter)) {
        if (headeredTarget == target) {
            return TxtReplayMode::Headered;
        }
    }

    return TxtReplayMode::Plain;
}

bool SRReplayTxtToParent::ReplayByParameterSet_(
    const SR::ParentReplayParameterSet& parameters,
    SR::JobPayloadType plainPayloadType
) {
    if (DetermineTxtReplayMode_(parameters.target) ==
        TxtReplayMode::Headered) {
        return ReplayHeaderedTxt_(parameters);
    }

    return ReplayPlainTxt_(
        parameters,
        plainPayloadType
    );
}

bool SRReplayTxtToParent::ReplayToParent(
    const SR::ParentReplayParameters& parameters
) {
    if (!jobsExchange_) {
        if (diagnostics_) {
            diagnostics_->ErrorLine(
                L"SRReplayTxtToParent has no jobs exchange"
            );
        }
        return false;
    }

    bool succeeded = true;

    if (parameters.stdoutParentReplayParameters.source ==
        SR::ParentReplaySource::Txt) {
        succeeded =
            ReplayByParameterSet_(
                parameters.stdoutParentReplayParameters,
                SR::JobPayloadType::ChildStdout
            ) &&
            succeeded;
    }

    if (parameters.stderrParentReplayParameters.source ==
        SR::ParentReplaySource::Txt) {
        succeeded =
            ReplayByParameterSet_(
                parameters.stderrParentReplayParameters,
                SR::JobPayloadType::ChildStderr
            ) &&
            succeeded;
    }

    return succeeded;
}

bool SRReplayTxtToParent::ReplayPlainTxt_(
    const SR::ParentReplayParameterSet& parameters,
    SR::JobPayloadType payloadType
) {
    if (parameters.path.empty()) {
        if (diagnostics_) {
            diagnostics_->ErrorLine(
                L"TXT parent replay path is empty"
            );
        }
        return false;
    }

    if (!SR::CanRouteJobPayloadTypeToTarget(
            payloadType,
            parameters.target
        )) {
        if (diagnostics_) {
            diagnostics_->ErrorLine(
                L"TXT parent replay payload type cannot be routed to target"
            );
        }
        return false;
    }

    LogReader::FileReader reader;
    DWORD gle = 0;

    if (!reader.OpenExistingFile(parameters.path, &gle)) {
        if (diagnostics_) {
            diagnostics_->ErrorLine(
                L"Failed to open TXT replay source: " +
                parameters.path +
                L" GLE=" +
                std::to_wstring(gle)
            );
        }
        return false;
    }

    PlainTxtReplayContext context;
    if (!context.batch.jobsBatch.Init(
            *jobsExchange_,
            parameters.target
        )) {
        if (diagnostics_) {
            diagnostics_->ErrorLine(
                L"Failed to initialize TXT replay jobs batch"
            );
        }
        return false;
    }
    context.payloadType = payloadType;

    const LogReader::ReadResult readResult =
        reader.ReadChunks(
            static_cast<DWORD>(pendingJobPayloadSize_),
            &ReplayPlainChunk_,
            &context,
            &gle
        );

    reader.Close();

    if (readResult == LogReader::ReadResult::IoFailed) {
        if (diagnostics_) {
            diagnostics_->ErrorLine(
                L"Failed to read TXT replay source: " +
                parameters.path +
                L" GLE=" +
                std::to_wstring(gle)
            );
        }
        return false;
    }

    if (readResult == LogReader::ReadResult::CallbackStopped ||
        !context.batch.allPendingJobsEnqueued) {
        if (diagnostics_) {
            diagnostics_->ErrorLine(
                L"Failed to enqueue TXT replay job: " +
                parameters.path
            );
        }
        return false;
    }

    if (!context.batch.jobsBatch.Flush()) {
        if (diagnostics_) {
            diagnostics_->ErrorLine(
                L"Failed to flush TXT replay jobs: " +
                parameters.path
            );
        }
        return false;
    }

    return true;
}

bool SRReplayTxtToParent::FillNextBuffer_(
    LogReader::FileReader& reader,
    DWORD* outGle
) {
    nextBuffer_.resize(kReplayBufferSize);

    DWORD bytesRead = 0;
    if (!reader.Read(
            nextBuffer_.data(),
            kReplayBufferSize,
            bytesRead,
            outGle
        )) {
        nextBuffer_.clear();
        return false;
    }

    nextBuffer_.resize(
        static_cast<std::size_t>(bytesRead)
    );
    return true;
}

void SRReplayTxtToParent::SwapBuffers_() noexcept {
    currentBuffer_.swap(nextBuffer_);
    nextBuffer_.clear();
}

SRReplayTxtToParent::HeaderResult
SRReplayTxtToParent::CheckHeader_(
    const std::vector<char>& buffer,
    std::size_t headerPosition,
    HeaderCheckMode mode
) {
    if (mode == HeaderCheckMode::Start) {
        candidateHeader_.clear();
    }

    while (headerPosition < buffer.size()) {
        const char ch = buffer[headerPosition];

        if (ch == kLf) {
            ++headerPosition;

            const bool header =
                TextHelpers::StartsWith(
                    candidateHeader_,
                    kHeaderPrefix
                ) &&
                TextHelpers::EndsWith(
                    candidateHeader_,
                    parsingTokenSuffix_
                );


            if (!header) {
                return {
                    HeaderResultState::NotHeader,
                    0
                };
            }

            return {
                HeaderResultState::Header,
                headerPosition
            };
        }

        candidateHeader_.push_back(ch);

        const std::size_t prefixIndex =
            candidateHeader_.size() - 1;

        if (prefixIndex <
                sizeof(kHeaderPrefix) - 1 &&
            candidateHeader_[prefixIndex] !=
                kHeaderPrefix[prefixIndex]) {
            return {
                HeaderResultState::NotHeader,
                0
            };
        }

        ++headerPosition;
    }

    if (mode == HeaderCheckMode::Continue) {
        return {
            HeaderResultState::NotHeader,
            0
        };
    }

    return {
        HeaderResultState::NeedsNext,
        headerPosition
    };
}

bool SRReplayTxtToParent::TryParseCandidateHeader_(
    SR::JobTarget target,
    SegmentReplayContext& context
) {
    SR::SRPhaseTimelineEntrySchemaData::SchemaDataVariant schemaData;
    if (diagnostics_) {
        diagnostics_->ProbeLine(
            std::wstring(L"Parsing TXT replay header; target=") +
            SR::JobTargetNameToString(target) +
            L"; candidateHeaderBytes=" +
            std::to_wstring(candidateHeader_.size()) +
            L"; candidateHeader=" +
            FileHelpers::Utf8ToWide(candidateHeader_)
        );
    }

    if (!SR::SRPhaseTimelineEntryTxtHeaderParser::TryParseHeader(
            candidateHeader_,
            schemaData
        )) {
        if (diagnostics_) {
            diagnostics_->ErrorLine(
                std::wstring(L"Failed to parse TXT replay candidate header; reason=header-schema-parser") +
                L"; target=" +
                SR::JobTargetNameToString(target) +
                L"; candidateHeaderBytes=" +
                std::to_wstring(candidateHeader_.size()) +
                L"; candidateHeader=" +
                FileHelpers::Utf8ToWide(candidateHeader_)
            );
        }
        context.headerParsingSucceeded = false;
        return false;
    }

    const bool valid = std::visit(
        [this, target](const auto& data) -> bool {
            using Data = std::decay_t<decltype(data)>;

            if constexpr (
                std::is_same_v<
                    Data,
                    SR::SRPhaseTimelineEntrySchemaData::ChildStdoutData
                >
            ) {
                if (diagnostics_) {
                    diagnostics_->ErrorLine(
                        std::wstring(L"Failed to validate TXT replay candidate header; reason=child-stdout-not-supported") +
                        L"; target=" +
                        SR::JobTargetNameToString(target)
                    );
                }
                return false;
            } else {
                SR::TimelineEntryKey key;

                if (!TryBuildPendingJobKey_(
                        data.phase,
                        data.phaseOrderNo,
                        data.eventOrderNo,
                        key
                    )) {
                    if (diagnostics_) {
                        diagnostics_->ErrorLine(
                            std::wstring(L"Failed to validate TXT replay candidate header; reason=pending-job-key") +
                            L"; phase=" +
                            data.phase +
                            L"; phaseOrderNo=" +
                            std::to_wstring(data.phaseOrderNo) +
                            L"; eventOrderNo=" +
                            std::to_wstring(data.eventOrderNo)
                        );
                    }
                    return false;
                }

                if (data.parsingToken != parsingToken_) {
                    if (diagnostics_) {
                        diagnostics_->ErrorLine(
                            std::wstring(L"Failed to validate TXT replay candidate header; reason=parsing-token-mismatch") +
                            L"; expectedParsingToken=" +
                            FileHelpers::Utf8ToWide(parsingToken_) +
                            L"; actualParsingToken=" +
                            FileHelpers::Utf8ToWide(data.parsingToken)
                        );
                    }
                    return false;
                }

                if (diagnostics_) {
                    diagnostics_->ProbeLine(
                        L"Validated TXT replay header identity; phase=" +
                        data.phase +
                        L"; phaseOrderNo=" +
                        std::to_wstring(data.phaseOrderNo) +
                        L"; eventOrderNo=" +
                        std::to_wstring(data.eventOrderNo)
                    );
                }

                if constexpr (
                    std::is_same_v<
                        Data,
                        SR::SRPhaseTimelineEntrySchemaData::SrDiagData
                    >
                ) {
                    SR::DiagnosticSeverity severity;

                    return
                        SR::TryParseDiagnosticSeverityUppercase(
                            data.severity,
                            severity
                        ) &&
                        SR::CanRouteJobPayloadTypeToTarget(
                            SR::JobPayloadType::SrDiag,
                            target
                        );
                } else {
                    return SR::CanRouteJobPayloadTypeToTarget(
                        SR::JobPayloadType::ChildStderr,
                        target
                    );
                }
            }
        },
        schemaData
    );

    if (!valid) {
        context.headerParsingSucceeded = false;
        return false;
    }

    context.nextEventOrderNo = std::visit(
        [](const auto& data) {
            return data.eventOrderNo;
        },
        schemaData
    );
    context.schemaData = std::move(schemaData);
    context.headerParsingSucceeded = true;
    return true;
}

bool SRReplayTxtToParent::TryBuildPendingJob_(
    SegmentReplayContext& segmentContext,
    std::vector<char>& pendingPayloadBuffer,
    SR::PendingJob& job
) {
    return std::visit(
        [&](const auto& data) -> bool {
            using Data = std::decay_t<decltype(data)>;

            if constexpr (
                std::is_same_v<
                    Data,
                    SR::SRPhaseTimelineEntrySchemaData::ChildStdoutData
                >
            ) {
                return false;
            } else {
                SR::TimelineEntryKey key;
                if (!TryBuildPendingJobKey_(
                        data.phase,
                        data.phaseOrderNo,
                        segmentContext.nextEventOrderNo++,
                        key
                    )) {
                    return false;
                }

                job = SR::PendingJob{};
                job.origin = SR::JobOrigin::TxtReplay;
                job.key = key;

                const SR::ReplayPayloadStorage replayPayloadStorage =
                    ReplayPayloadStorageFromSchemaData_(
                        data.payloadDropped
                    );

                if constexpr (
                    std::is_same_v<
                        Data,
                        SR::SRPhaseTimelineEntrySchemaData::SrDiagData
                    >
                ) {
                    SR::DiagnosticSeverity severity;
                    if (!SR::TryParseDiagnosticSeverityUppercase(
                            data.severity,
                            severity
                        )) {
                        return false;
                    }

                    const std::size_t messageSize =
                        pendingPayloadBuffer.size();

                    job.payloadType = SR::JobPayloadType::SrDiag;
                    job.srDiag.key = key;
                    job.srDiag.timestampUtc = data.timestampUtc;
                    job.srDiag.severity = severity;
                    job.srDiag.message = FileHelpers::Utf8ToWide(
                        std::string(
                            pendingPayloadBuffer.begin(),
                            pendingPayloadBuffer.end()
                        )
                    );
                    job.srDiag.payloadByteCount =
                        data.payloadDropped
                            ? data.payloadByteCount
                            : static_cast<uint64_t>(messageSize);
                    job.srDiag.replayPayloadStorage =
                        replayPayloadStorage;
                } else {
                    job.payloadType = SR::JobPayloadType::ChildStderr;
                    job.childStderr.key = key;
                    job.childStderr.timestampUtc = data.timestampUtc;
                    job.childStderr.bytes =
                        std::move(pendingPayloadBuffer);
                    job.childStderr.payloadByteCount =
                        data.payloadDropped
                            ? data.payloadByteCount
                            : static_cast<uint64_t>(
                                job.childStderr.bytes.size()
                            );
                    job.childStderr.replayPayloadStorage =
                        replayPayloadStorage;
                }

                return true;
            }
        },
        segmentContext.schemaData
    );
}


bool SRReplayTxtToParent::FlushPendingPayload_(
    SegmentReplayContext& segmentContext,
    ReplayBatchContext& batchContext,
    std::vector<char>& pendingPayloadBuffer
) {
    const bool skipEmptyPayload = std::visit(
        [&](const auto& data) -> bool {
            return
                pendingPayloadBuffer.empty() &&
                !data.payloadDropped;
        },
        segmentContext.schemaData
    );

    if (skipEmptyPayload) {
        return true;
    }

    SR::PendingJob job;
    if (!TryBuildPendingJob_(
            segmentContext,
            pendingPayloadBuffer,
            job
        )) {
        return false;
    }

    pendingPayloadBuffer.clear();

    batchContext.allPendingJobsEnqueued =
        batchContext.jobsBatch.Add(std::move(job));
    return batchContext.allPendingJobsEnqueued;
}

SRReplayTxtToParent::ChunkResult
SRReplayTxtToParent::ChunkUntilSeparator_(
    SegmentReplayContext& segmentContext,
    ReplayBatchContext& batchContext,
    std::vector<char>& pendingPayloadBuffer,
    HeaderResult& nextHeaderResult

) {
    std::size_t payloadPosition =
        nextHeaderResult.position;

    const bool chunkedSegment =
        std::holds_alternative<
            SR::SRPhaseTimelineEntrySchemaData::ChildStderrData
        >(segmentContext.schemaData) ||
        std::holds_alternative<
            SR::SRPhaseTimelineEntrySchemaData::SrDiagData
        >(segmentContext.schemaData);

    // CheckHeader_() starts at the LF which terminated the previous payload
    // line. If that candidate was rejected, the LF belongs to the current
    // payload and must be consumed before searching for the next separator.
    if (nextHeaderResult.state ==
            HeaderResultState::NotHeader &&
        payloadPosition < currentBuffer_.size() &&
        currentBuffer_[payloadPosition] == kLf) {
        pendingPayloadBuffer.push_back(kLf);
        ++payloadPosition;

        if (chunkedSegment &&
            pendingPayloadBuffer.size() ==
                pendingJobPayloadSize_ &&
            !FlushPendingPayload_(
                segmentContext,
                batchContext,
                pendingPayloadBuffer
            )) {
            return {
                ChunkResultState::BufferExhausted,
                payloadPosition
            };
        }
    }

    const auto findSeparator =
        [&](std::size_t position) -> ChunkResult {
            std::size_t nextLfPosition = position;

            while (nextLfPosition < currentBuffer_.size()) {
                if (currentBuffer_[nextLfPosition] == kLf) {
                    return {
                        ChunkResultState::LfFound,
                        nextLfPosition
                    };
                }

                ++nextLfPosition;
            }

            return {
                ChunkResultState::BufferExhausted,
                nextLfPosition
            };
        };

    const ChunkResult separatorResult =
        findSeparator(payloadPosition);

    const std::size_t endPosition = separatorResult.position;
    std::size_t startPosition = payloadPosition;

    while (startPosition < endPosition) {
        if (chunkedSegment) {
            const std::size_t remainingCapacity =
                pendingJobPayloadSize_ -
                pendingPayloadBuffer.size();

            const std::size_t copySize = std::min(
                remainingCapacity,
                endPosition - startPosition
            );

            pendingPayloadBuffer.insert(
                pendingPayloadBuffer.end(),
                currentBuffer_.begin() +
                    static_cast<std::ptrdiff_t>(startPosition),
                currentBuffer_.begin() +
                    static_cast<std::ptrdiff_t>(
                        startPosition + copySize
                    )
            );

            startPosition += copySize;

            if (pendingPayloadBuffer.size() ==
                pendingJobPayloadSize_) {
                if (!FlushPendingPayload_(
                        segmentContext,
                        batchContext,
                        pendingPayloadBuffer
                    )) {
                    return {
                        ChunkResultState::BufferExhausted,
                        startPosition
                    };
                }
            }
        }
    }

    return separatorResult;
}

bool SRReplayTxtToParent::ReplayHeaderedTxt_(
    const SR::ParentReplayParameterSet& parameters
) {
    if (parameters.path.empty()) {
        if (diagnostics_) {
            diagnostics_->ErrorLine(
                L"TXT parent replay path is empty"
            );
        }
        return false;
    }

    LogReader::FileReader reader;
    DWORD gle = 0;

    if (!reader.OpenExistingFile(
            parameters.path,
            &gle
        )) {
        if (diagnostics_) {
            diagnostics_->ErrorLine(
                L"Failed to open TXT replay source: " +
                parameters.path +
                L" GLE=" +
                std::to_wstring(gle)
            );
        }
        return false;
    }

    SegmentReplayContext segmentContext;
    ReplayBatchContext batchContext;
    std::vector<char> pendingPayloadBuffer;

    if (!batchContext.jobsBatch.Init(
            *jobsExchange_,
            parameters.target
        )) {
        if (diagnostics_) {
            diagnostics_->ErrorLine(
                L"Failed to initialize TXT replay jobs batch"
            );
        }
        return false;
    }

    currentBuffer_.clear();
    nextBuffer_.clear();

    if (!FillNextBuffer_(reader, &gle)) {
        reader.Close();
        if (diagnostics_) {
            diagnostics_->ErrorLine(
                L"Failed to read TXT replay source: " +
                parameters.path +
                L" GLE=" +
                std::to_wstring(gle)
            );
        }
        return false;
    }

    SwapBuffers_();

    if (!FillNextBuffer_(reader, &gle)) {
        reader.Close();
        if (diagnostics_) {
            diagnostics_->ErrorLine(
                L"Failed to read TXT replay source: " +
                parameters.path +
                L" GLE=" +
                std::to_wstring(gle)
            );
        }
        return false;
    }

    if (currentBuffer_.empty()) {
        reader.Close();
        if (diagnostics_) {
            diagnostics_->ErrorLine(
                L"Failed to parse TXT replay source: " +
                parameters.path +
                L"; reason=empty-source" +
                L"; currentBufferBytes=" +
                std::to_wstring(currentBuffer_.size()) +
                L"; nextBufferBytes=" +
                std::to_wstring(nextBuffer_.size())
            );
        }
        return false;
    }

    HeaderResult nextHeaderResult = CheckHeader_(
        currentBuffer_,
        0,
        HeaderCheckMode::Start
    );

    if (nextHeaderResult.state != HeaderResultState::Header ||
        !TryParseCandidateHeader_(
            parameters.target,
            segmentContext
        )) {
        reader.Close();
        if (diagnostics_) {
            diagnostics_->ErrorLine(
                L"Failed to parse TXT replay source: " +
                parameters.path +
                L"; reason=initial-header" +
                L"; headerState=" +
                std::to_wstring(
                    static_cast<unsigned>(
                        nextHeaderResult.state
                    )
                ) +
                L"; headerNextPosition=" +
                std::to_wstring(nextHeaderResult.position) +
                L"; candidateHeaderBytes=" +
                std::to_wstring(candidateHeader_.size()) +
                L"; currentBufferBytes=" +
                std::to_wstring(currentBuffer_.size()) +
                L"; nextBufferBytes=" +
                std::to_wstring(nextBuffer_.size()) +
                L"; candidateHeader=" +
                FileHelpers::Utf8ToWide(candidateHeader_)
            );
        }
        return false;
    }


    while (true) {
        const ChunkResult chunkResult = ChunkUntilSeparator_(
            segmentContext,
            batchContext,
            pendingPayloadBuffer,
            nextHeaderResult
        );

        if (!batchContext.allPendingJobsEnqueued) {
            reader.Close();
            if (diagnostics_) {
                diagnostics_->ErrorLine(
                    L"Failed to enqueue TXT replay job: " +
                    parameters.path
                );
            }
            return false;
        }

        if (chunkResult.state ==
            ChunkResultState::BufferExhausted) {
            if (nextBuffer_.empty()) {
                break;
            }

            SwapBuffers_();
            nextHeaderResult = {
                HeaderResultState::Header,
                0
            };


            if (!FillNextBuffer_(reader, &gle)) {
                reader.Close();
                if (diagnostics_) {
                    diagnostics_->ErrorLine(
                        L"Failed to read TXT replay source: " +
                        parameters.path +
                        L" GLE=" +
                        std::to_wstring(gle)
                    );
                }
                return false;
            }

            continue;
        }

        nextHeaderResult = CheckHeader_(

            currentBuffer_,
            chunkResult.position + 1,

            HeaderCheckMode::Start
        );

        const bool headerContinuesInNextBuffer =
            nextHeaderResult.state ==
                HeaderResultState::NeedsNext;

        if (headerContinuesInNextBuffer) {
            nextHeaderResult = CheckHeader_(
                nextBuffer_,
                0,
                HeaderCheckMode::Continue
            );
        }

        if (headerContinuesInNextBuffer &&
            nextBuffer_.empty() &&
            nextHeaderResult.state ==
                HeaderResultState::NeedsNext) {
            continue;
        }

        if (nextHeaderResult.state ==
            HeaderResultState::NotHeader) {
            nextHeaderResult.position =
                chunkResult.position;

            continue;
        }

        SegmentReplayContext nextSegmentContext;

        if (!TryParseCandidateHeader_(
                parameters.target,
                nextSegmentContext
            )) {
            segmentContext.headerParsingSucceeded = false;
            break;
        }


        if (!FlushPendingPayload_(
                segmentContext,
                batchContext,
                pendingPayloadBuffer
            )) {
            reader.Close();
            if (diagnostics_) {
                diagnostics_->ErrorLine(
                    L"Failed to enqueue TXT replay job: " +
                    parameters.path
                );
            }
            return false;
        }
        if (headerContinuesInNextBuffer) {
            SwapBuffers_();

            if (!FillNextBuffer_(reader, &gle)) {
                reader.Close();
                if (diagnostics_) {
                    diagnostics_->ErrorLine(
                        L"Failed to read TXT replay source: " +
                        parameters.path +
                        L" GLE=" +
                        std::to_wstring(gle)
                    );
                }
                return false;
            }
        }

        segmentContext = std::move(nextSegmentContext);
    }

    if (pendingPayloadBuffer.size() == 1 && pendingPayloadBuffer.front() == '\n') {
        pendingPayloadBuffer.clear();
    } else {
        if (!FlushPendingPayload_(
            segmentContext,
            batchContext,
            pendingPayloadBuffer
        )) {
            reader.Close();
            if (diagnostics_) {
                diagnostics_->ErrorLine(
                    L"Failed to enqueue TXT replay job: " +
                    parameters.path
                );
            }
            return false;
        }
    }

    reader.Close();

    if (!segmentContext.headerParsingSucceeded) {
        if (diagnostics_) {
            diagnostics_->ErrorLine(
                L"Failed to parse TXT replay source: " +
                parameters.path +
                L"; reason=segment-header" +
                L"; nextEventOrderNo=" +
                std::to_wstring(segmentContext.nextEventOrderNo) +
                L"; candidateHeaderBytes=" +
                std::to_wstring(candidateHeader_.size()) +
                L"; currentBufferBytes=" +
                std::to_wstring(currentBuffer_.size()) +
                L"; nextBufferBytes=" +
                std::to_wstring(nextBuffer_.size()) +
                L"; candidateHeader=" +
                FileHelpers::Utf8ToWide(candidateHeader_)
            );
        }
        return false;
    }

    if (!batchContext.allPendingJobsEnqueued) {
        if (diagnostics_) {
            diagnostics_->ErrorLine(
                L"Failed to enqueue TXT replay job: " +
                parameters.path
            );
        }
        return false;
    }

    if (!batchContext.jobsBatch.Flush()) {
        if (diagnostics_) {
            diagnostics_->ErrorLine(
                L"Failed to flush TXT replay jobs: " +
                parameters.path
            );
        }
        return false;
    }

    return true;
}
