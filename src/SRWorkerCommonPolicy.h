#pragma once

#include <string>
#include <vector>


#include "SRTypes.h"
#include "SRJobTypes.h"

// Common configuration shared by multiple workers.
//
// The parsing token is generated during initialization when required by
// the finalized command-line options. The token remains immutable for
// the lifetime of the process.
class SRWorkerCommonPolicy {
public:
    SRWorkerCommonPolicy() = default;

    SRWorkerCommonPolicy(const SRWorkerCommonPolicy&) = delete;
    SRWorkerCommonPolicy& operator=(const SRWorkerCommonPolicy&) = delete;
    SRWorkerCommonPolicy(SRWorkerCommonPolicy&&) = delete;
    SRWorkerCommonPolicy& operator=(SRWorkerCommonPolicy&&) = delete;

    bool Init(
        const SR::Options& opt
    ) noexcept;

    bool NeedsParsingToken() const noexcept;

    const std::string& ParsingToken() const noexcept;

    const std::vector<SR::JobTarget>&
    FileSinkParsingTokenTargets() const noexcept;

    const std::vector<SR::JobTarget>&
    ParentParsingTokenTargets() const noexcept;


private:
    bool needsParsingToken_ = false;
    std::string parsingToken_;
    std::vector<SR::JobTarget> fileSinkParsingTokenTargets_;
    std::vector<SR::JobTarget> parentParsingTokenTargets_;

};
