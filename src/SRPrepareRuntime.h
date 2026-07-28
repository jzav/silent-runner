#pragma once

#include <memory>
#include <string>

#include "LogWriter.h"
#include "HandleHelpers.h"
#include "SRFileSinkWorker.h"
#include "SRJobsExchange.h"
#include "SRParentEmitWorker.h"
#include "SRTypes.h"
#include "SRWorkerSupervisor.h"

class SRLifecycleDiagnostics;

struct SRPreparedRuntime {
    std::wstring fullCmdLineForCreateProcess;
    std::wstring executionId;
    std::wstring generatedSuffix;
    SR::IdSuffixMode effectiveIdSuffixMode = SR::IdSuffixMode::None;
    bool useDefaultSuffixMode = false;


    std::wstring stdoutRunningName;
    std::wstring stderrRunningName;
    std::wstring stdoutSuccessName;
    std::wstring stdoutFailureName;
    std::wstring stderrSuccessName;
    std::wstring stderrFailureName;
    std::wstring stderrChildRunningName;
    std::wstring stderrChildSuccessName;
    std::wstring stderrChildFailureName;
    std::wstring stderrSrRunningName;
    std::wstring stderrSrSuccessName;
    std::wstring stderrSrFailureName;
    std::wstring stdoutJsonlRunningName;
    std::wstring stderrJsonlRunningName;
    std::wstring stdoutJsonlSuccessName;
    std::wstring stdoutJsonlFailureName;
    std::wstring stderrJsonlSuccessName;
    std::wstring stderrJsonlFailureName;
    std::wstring stderrChildJsonlRunningName;
    std::wstring stderrChildJsonlSuccessName;
    std::wstring stderrChildJsonlFailureName;
    std::wstring stderrSrJsonlRunningName;
    std::wstring stderrSrJsonlSuccessName;
    std::wstring stderrSrJsonlFailureName;
    std::wstring probeLogName;


    std::wstring probeLogPath;


    LogWriter::FileWriter stdoutLogWriter;
    LogWriter::FileWriter stderrLogWriter;
    LogWriter::FileWriter stderrChildLogWriter;
    LogWriter::FileWriter stderrSrLogWriter;
    LogWriter::FileWriter stdoutJsonlWriter;
    LogWriter::FileWriter stderrJsonlWriter;
    LogWriter::FileWriter stderrChildJsonlWriter;
    LogWriter::FileWriter stderrSrJsonlWriter;
    HandleHelpers::StdHandleWriteProbeResult stdoutStdHandleProbe;
    HandleHelpers::StdHandleWriteProbeResult stderrStdHandleProbe;

    std::unique_ptr<SR::SRWorkerSupervisor> workerSupervisor;
    std::unique_ptr<SRFileSinkWorker> fileSinkWorker;
    std::unique_ptr<SRParentEmitWorker> parentEmitWorker;
    std::unique_ptr<SRJobsExchange> jobsExchange;

};

struct SRPrepareResult {
    bool ok = false;
    int earlyExitCode = 255;
    SRPreparedRuntime prepared;
};

void PrepareRuntime(
    const SR::Options& opt,
    SRLifecycleDiagnostics& lifecycleDiag,
    SR::LogPaths& logPaths,
    SRPrepareResult& result
);
