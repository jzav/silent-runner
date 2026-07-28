#include "SRExecutionTimelineDiagnostics.h"
#include "SRPendingJobDiagnostics.h"
#include "TextHelpers.h"


namespace SR {

namespace {

void AppendTimelineEntryKey_(
    std::wstring& out,
    const TimelineEntryKey& key
) {
    out += LifecyclePhaseShortNameToString(key.phase);
    out += L":";
    out += std::to_wstring(key.phaseOrderNo);
    out += L":";
    out += std::to_wstring(key.eventOrderNo);
}

template <typename KeyVector>
void AppendKeyListLine_(
    std::wstring& out,
    const wchar_t* label,
    const KeyVector& keys
) {
    out += label;
    out += L"_";
    out += std::to_wstring(keys.size());
    out += L"=[";

    bool first = true;
    for (const auto& key : keys) {
        if (!first) {
            out += L",";
        }

        AppendTimelineEntryKey_(out, key);
        first = false;
    }

    out += L"]\n";
}
void AppendWorkerFailureListLine_(
    std::wstring& out,
    const WorkerFailureRecords& records
) {
    out += L"workerFailures_";
    out += std::to_wstring(records.size());
    out += L"=[";

    if (records.empty()) {
        out += L"]\n";
        return;
    }

    out += L"\n";

    for (std::size_t i = 0; i < records.size(); ++i) {
        const WorkerFailureRecord& record = records[i];

        out += L"  ";
        out += JobTargetWorkerNameToString(record.worker);
        out += L":";

        if (!record.failureText.empty()) {
            out += record.failureText;
        } else {
            out += L"(none)";
        }

        if (i + 1 < records.size()) {
            out += L",";
        }

        out += L"\n";
    }

    out += L"]\n";
}
void AppendCompletedResultItem_(
    std::wstring& out,
    const TimelineEntryKey& key,
    JobTarget target
) {
    AppendTimelineEntryKey_(out, key);
    out += L":";
    out += JobTargetNameToString(target);
}

template <typename ItemVector>
void AppendCompletedResultItemListLine_(
    std::wstring& out,
    const wchar_t* label,
    const ItemVector& items
) {
    out += label;
    out += L"_";
    out += std::to_wstring(items.size());
    out += L"=[";

    bool first = true;
    for (const auto& item : items) {
        if (!first) {
            out += L",";
        }

        AppendCompletedResultItem_(out, item.key, item.target);
        first = false;
    }

    out += L"]\n";
}



void AppendReasonedItem_(
    std::wstring& out,
    const CompletedResultNotAppliedItem& item
) {
    AppendCompletedResultItem_(out, item.key, item.target);
    out += L"_";
    out += CompletedResultNotAppliedReasonToString(item.reason);
}

void AppendReasonedItem_(
    std::wstring& out,
    const PendingJobBuildFailedItem& item
) {
    AppendTimelineEntryKey_(out, item.key);
    out += L"_";
    out += PendingJobBuildFailedReasonToString(item.reason);
}

void AppendReasonedItem_(
    std::wstring& out,
    const PendingJobNotEnqueuedItem& item
) {
    AppendTimelineEntryKey_(out, item.key);
    out += L"_";
    out += PendingJobNotEnqueuedReasonToString(item.reason);
}

void AppendReasonedItem_(
    std::wstring& out,
    const PruneSkippedItem& item
) {
    AppendTimelineEntryKey_(out, item.key);
    out += L"_";
    out += PruneSkippedReasonToString(item.reason);
}

void AppendReasonedItem_(
    std::wstring& out,
    const PruneFailedItem& item
) {
    AppendTimelineEntryKey_(out, item.key);
    out += L"_";
    out += PruneFailedReasonToString(item.reason);
}

template <typename ItemVector>
void AppendReasonedListLine_(
    std::wstring& out,
    const wchar_t* label,
    const ItemVector& items
) {
    out += label;
    out += L"_";
    out += std::to_wstring(items.size());
    out += L"=[";

    bool first = true;
    for (const auto& item : items) {
        if (!first) {
            out += L",";
        }

        AppendReasonedItem_(out, item);
        first = false;
    }

    out += L"]\n";
}

} // namespace


std::wstring FormatEventSummary(
    const EventSummary& eventSummary
) {
    std::wstring out;

    out += L"EventSummary=[";
    AppendTimelineEntryKey_(out, eventSummary.eventKey);
    out += L"] result=";
    out += EventResultToString(eventSummary.result);

    if (eventSummary.failedStep && *eventSummary.failedStep) {
        out += L" failedStep=";
        out += eventSummary.failedStep;
    }

    out += L"\n";
    out += L"legend=[phaseName:phaseOrderNo:eventOrderNo] P=Prepare R=Runtime\n";
    out += L"Results\n";
    AppendCompletedResultItemListLine_(
        out,
        L"completedResultsTaken",
        eventSummary.completedResultsTaken
    );
    AppendCompletedResultItemListLine_(
        out,
        L"completedResultsApplied",
        eventSummary.completedResultsApplied
    );
    AppendReasonedListLine_(
        out,
        L"completedResultsNotApplied",
        eventSummary.completedResultsNotApplied
    );

    out += L"Jobs\n";
    AppendKeyListLine_(
        out,
        L"jobQueueRetrieved",
        eventSummary.jobQueueRetrieved
    );
    AppendKeyListLine_(
        out,
        L"pendingJobsBuilt",
        eventSummary.pendingJobsBuilt
    );
    AppendReasonedListLine_(
        out,
        L"pendingJobsBuildFailed",
        eventSummary.pendingJobsBuildFailed
    );
    AppendKeyListLine_(
        out,
        L"pendingJobsEnqueued",
        eventSummary.pendingJobsEnqueued
    );
    AppendReasonedListLine_(
        out,
        L"pendingJobsNotEnqueued",
        eventSummary.pendingJobsNotEnqueued
    );

    if (!eventSummary.workerSummaries.pendingJobsEnqueueSummaries.empty() ||
        !eventSummary.workerSummaries.pendingJobSummaries.empty()) {
        auto appendWorkerSummaries = [&](
            JobTargetWorker worker,
            const wchar_t* title
        ) {
            bool hasAny = false;

            for (const auto& summary :
                  eventSummary.workerSummaries.pendingJobsEnqueueSummaries) {
                if (summary.worker == worker) {
                    hasAny = true;
                    break;
                }
            }

            if (!hasAny) {
                for (const auto& summary :
                      eventSummary.workerSummaries.pendingJobSummaries) {
                    if (summary.worker == worker) {
                        hasAny = true;
                        break;
                    }
                }
            }

            if (!hasAny) {
                return;
            }

            out += title;
            out += L"\n";

            WorkerPendingJobsEnqueueSummary enqueueSummary;
            enqueueSummary.worker = worker;
            for (const auto& summary :
                  eventSummary.workerSummaries.pendingJobsEnqueueSummaries) {
                if (summary.worker == worker) {
                    enqueueSummary.jobsReceived.insert(
                        enqueueSummary.jobsReceived.end(),
                        summary.jobsReceived.begin(),
                        summary.jobsReceived.end()
                    );
                    enqueueSummary.jobsAccepted.insert(
                        enqueueSummary.jobsAccepted.end(),
                        summary.jobsAccepted.begin(),
                        summary.jobsAccepted.end()
                    );
                    enqueueSummary.jobsRejected.insert(
                        enqueueSummary.jobsRejected.end(),
                        summary.jobsRejected.begin(),
                        summary.jobsRejected.end()
                    );
                }
            }
            if (!enqueueSummary.jobsReceived.empty() ||
                !enqueueSummary.jobsAccepted.empty() ||
                !enqueueSummary.jobsRejected.empty()) {
                out += FormatWorkerPendingJobsEnqueueSummary(enqueueSummary);
            }

            for (const auto& summary :
                  eventSummary.workerSummaries.pendingJobSummaries) {
                if (summary.worker == worker) {
                    out += FormatWorkerPendingJobSummary(summary);
                    out += L"\n";
                }
            }
        };

        appendWorkerSummaries(
            JobTargetWorker::SRFileSinkWorker,
            L"FileSinkWorker"
        );
        appendWorkerSummaries(
            JobTargetWorker::SRParentEmitWorker,
            L"ParentEmitWorker"
        );
    }
    
    out += L"PruningCompleted\n";
    AppendKeyListLine_(
        out,
        L"pruned",
        eventSummary.completedPruning.pruned
    );
    AppendReasonedListLine_(
        out,
        L"pruneSkipped",
        eventSummary.completedPruning.pruneSkipped
    );
    AppendReasonedListLine_(
        out,
        L"pruneFailed",
        eventSummary.completedPruning.pruneFailed
    );

    out += L"PruningUnobtainable\n";
    AppendWorkerFailureListLine_(
        out,
        eventSummary.unobtainablePruning.workerFailures
    );
    AppendCompletedResultItemListLine_(
        out,
        L"unobtainableTargets",
        eventSummary.unobtainablePruning.unobtainableTargets
    );
    AppendKeyListLine_(
        out,
        L"pruned",
        eventSummary.unobtainablePruning.pruning.pruned
    );
    AppendReasonedListLine_(
        out,
        L"pruneSkipped",
        eventSummary.unobtainablePruning.pruning.pruneSkipped
    );
    AppendReasonedListLine_(
        out,
        L"pruneFailed",
        eventSummary.unobtainablePruning.pruning.pruneFailed
    );

    if (!out.empty() && out.back() == L'\n') {
        out.pop_back();
    }

    return out;
}
std::wstring FormatFinalEventSummary(
    const EventSummary& eventSummary
) {
    std::wstring out = FormatEventSummary(eventSummary);
    const std::wstring prefix = L"EventSummary=[";
    if (!TextHelpers::StartsWith(out, prefix)) {
        return out;
    }

    const std::size_t begin = prefix.size();
    const std::size_t end = out.find(L']', begin);
    if (end == std::wstring::npos) {
        return out;
    }

    out.replace(begin, end - begin, L"Final");
    return out;
}


} // namespace SR
