#pragma once

#include <string>
#include <vector>

#include "LogWriter.h"
#include "HandleHelpers.h"
#include "SRTypes.h"
#include "SRConfigsBuilderTypes.h"

class SRLifecycleDiagnostics;
class SRParentEmitPolicy;
class SRFileSinkWorker;

struct SRLogFileWriters {
    LogWriter::FileWriter stdoutLogWriter;
    LogWriter::FileWriter stderrLogWriter;
    LogWriter::FileWriter stderrChildLogWriter;
    LogWriter::FileWriter stderrSrLogWriter;
    LogWriter::FileWriter stderrSrAndChildInclStdoutLogWriter;
    LogWriter::FileWriter stdoutJsonlWriter;
    LogWriter::FileWriter stderrJsonlWriter;
    LogWriter::FileWriter stderrChildJsonlWriter;
    LogWriter::FileWriter stderrSrJsonlWriter;
    LogWriter::FileWriter stderrSrAndChildInclStdoutJsonlWriter;
};

struct SRLogFiles {
    SR::LogPaths paths;
    SR::LogFileCreationResults creationResults;
    SRLogFileWriters writers;
};

struct SRPrepareResult {
    bool ok = false;
    int earlyExitCode = 255;

    std::wstring fullCmdLineForCreateProcess;
    HandleHelpers::StdHandleWriteProbeResult stdoutStdHandleProbe;
    HandleHelpers::StdHandleWriteProbeResult stderrStdHandleProbe;

    std::wstring specialCharactersDebugMessage;
    std::vector<std::wstring> unboundedReplayBufferDebugMessages;
    SRLogFiles logFiles;
};

void PrepareRuntime(
    SR::SRConfigs& configs,
    SRFileSinkWorker& fileSinkWorker,

    const SRParentEmitPolicy& parentEmitPolicy,
    SRLifecycleDiagnostics& lifecycleDiag,
    SRPrepareResult& result
);
