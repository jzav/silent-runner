#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstddef>
#include <string>
#include <vector>

#include "SRParentReplayTypes.h"
#include "SRPendingJobTypes.h"

namespace LogReader {
class FileReader;
}

class SRJobsExchange;
class SRLifecycleDiagnostics;

class SRReplayTxtToParent {
public:
    SRReplayTxtToParent() = default;

    SRReplayTxtToParent(const SRReplayTxtToParent&) = delete;
    SRReplayTxtToParent& operator=(const SRReplayTxtToParent&) = delete;

    bool Init(
        SRLifecycleDiagnostics* diagnostics,
        const std::string& parsingToken,
        std::size_t pendingJobPayloadSize
    ) noexcept;

    void SetJobsExchange(SRJobsExchange& jobsExchange) noexcept;

    bool ReplayToParent(
        const SR::ParentReplayParameters& parameters
    );

private:
    enum class TxtReplayMode {
        Plain,
        Headered
    };
    enum class ChunkResultState {
        LfFound,
        BufferExhausted
    };

    struct ChunkResult {
        ChunkResultState state = ChunkResultState::BufferExhausted;
        std::size_t position = 0;
    };

    enum class HeaderCheckMode {
        Start,
        Continue
    };

    enum class HeaderResultState {
        Header,
        NotHeader,
        NeedsNext
    };

    struct HeaderResult {
        HeaderResultState state = HeaderResultState::NotHeader;
        std::size_t position = 0;
    };

    struct SegmentReplayContext;
    struct ReplayBatchContext;

    static TxtReplayMode DetermineTxtReplayMode_(
        SR::JobTarget target
    );

    bool ReplayByParameterSet_(
        const SR::ParentReplayParameterSet& parameters,
        SR::JobPayloadType plainPayloadType
    );

    bool ReplayPlainTxt_(
        const SR::ParentReplayParameterSet& parameters,
        SR::JobPayloadType payloadType
    );

    bool ReplayHeaderedTxt_(
        const SR::ParentReplayParameterSet& parameters
    );

    bool FillNextBuffer_(
        LogReader::FileReader& reader,
        DWORD* outGle
    );

    void SwapBuffers_() noexcept;

    bool TryBuildPendingJob_(
        SegmentReplayContext& segmentContext,
        std::vector<char>& pendingPayloadBuffer,
        SR::PendingJob& job
    );

    bool FlushPendingPayload_(
        SegmentReplayContext& segmentContext,
        ReplayBatchContext& batchContext,
        std::vector<char>& pendingPayloadBuffer
    );

    ChunkResult ChunkUntilSeparator_(
        SegmentReplayContext& segmentContext,
        ReplayBatchContext& batchContext,
        std::vector<char>& pendingPayloadBuffer,
        HeaderResult& nextHeaderResult

    );


    HeaderResult CheckHeader_(
        const std::vector<char>& buffer,
        std::size_t headerPosition,
        HeaderCheckMode mode
    );

    bool TryParseCandidateHeader_(
        SR::JobTarget target,
        SegmentReplayContext& context
    );

    SRJobsExchange* jobsExchange_ = nullptr; // non-owning
    SRLifecycleDiagnostics* diagnostics_ = nullptr; // non-owning

    std::vector<char> currentBuffer_;
    std::vector<char> nextBuffer_;
    std::string candidateHeader_;
    std::string parsingToken_;
    std::string parsingTokenSuffix_;
    std::size_t pendingJobPayloadSize_ = 0;

};
