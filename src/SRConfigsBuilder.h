#pragma once

#include <array>
#include <string>

#include "SRConfigsBuilderTypes.h"


namespace SR {

class SRConfigsBuilder {
public:
    SRConfigs configs{};
    bool helpRequested = false;
    std::wstring err{};

    void Init(
        const FileSinkWorkerTargetLayout& fileSinkTargetLayout,
        const ParentEmitWorkerTargetLayout& parentEmitTargetLayout
    );
    bool Build(
        int argc,
        wchar_t** argv
    );

private:
    struct WorkerTargetConfigEntry {
        const WorkerTargetLayoutEntry* source = nullptr;
        ConfigArgument configArgument = ConfigArgument::Count;
        ConfigArgument keepLogConfigArgument = ConfigArgument::Count;

        WorkerTargetConfigEntry() = default;
        explicit WorkerTargetConfigEntry(
            const WorkerTargetLayoutEntry& entry
        );
    };

    template <typename Layout>
    struct WorkerTargetConfigs {
        std::array<
            WorkerTargetConfigEntry,
            Layout::kTargetCount
        > targets{};

        WorkerTargetConfigs() = default;

        explicit WorkerTargetConfigs(const Layout& layout) {
            for (std::size_t i = 0; i < targets.size(); ++i) {
                targets[i] = WorkerTargetConfigEntry(
                    layout.targets[i]
                );
            }
        }
    };

    void ParseArguments(
        int argc,
        wchar_t** argv
    );

    bool ValidateParsedArguments();
    bool ResolveArguments();
    bool ValidateResolvedArguments();
    void DeriveValues();
    void SetErrorIfNone(
        const std::wstring& fallbackError
    );


    void BuildConsumerConfigs();
    void AppendDerivedValues();

    WorkerTargetConfigs<FileSinkWorkerTargetLayout>
        fileSinkWorkerTargetConfigs_{};

    WorkerTargetConfigs<ParentEmitWorkerTargetLayout>
        parentEmitWorkerTargetConfigs_{};
    ConfigArguments configArguments_{};
    ConfigDerivedValues derivedValues_{};

    std::wstring unknownArgumentParsingError_;
};


} // namespace SR
