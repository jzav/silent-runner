#pragma once

#include <memory>

#include "SRFileSinkWorker.h"
#include "SRJobsExchange.h"
#include "SRParentEmitWorker.h"
#include "SRWorkerSupervisor.h"

struct SRWorkers {
    std::unique_ptr<SR::SRWorkerSupervisor> supervisor;
    std::unique_ptr<SRFileSinkWorker> fileSink;
    std::unique_ptr<SRParentEmitWorker> parentEmit;
    std::unique_ptr<SRJobsExchange> jobsExchange;
};
