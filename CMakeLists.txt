cmake_minimum_required(VERSION 3.21)

# Match the existing release script: -O2, with no implicit -DNDEBUG.
# An explicitly supplied CMAKE_CXX_FLAGS_RELEASE still takes precedence.
if(NOT DEFINED CMAKE_CXX_FLAGS_RELEASE)
    set(CMAKE_CXX_FLAGS_RELEASE "-O2" CACHE STRING "C++ flags for Release builds")
endif()

project(SilentRunner LANGUAGES CXX)

if(NOT MINGW OR NOT CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    message(FATAL_ERROR "SilentRunner currently requires a MinGW-w64 GNU g++ toolchain.")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "SilentRunner requires a 64-bit MinGW-w64 toolchain.")
endif()

if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build configuration" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        Debug Release RelWithDebInfo MinSizeRel)
endif()

# Keep the source list explicit. Add new implementation files here.
# WIN32 selects the Windows subsystem (equivalent to -mwindows).
add_executable(SilentRunner WIN32
    src/ErrorHelpers.cpp
    src/FileHelpers.cpp
    src/HandleHelpers.cpp
    src/HelpGenerator.cpp
    src/TextHelpers.cpp
    src/ChildStdReader.cpp
    src/JobController.cpp
    src/LogWriter.cpp
    src/LogReader.cpp
    src/ParentStdEmitter.cpp
    src/ProcessHelpers.cpp
    src/SRConfigsBuilder.cpp
    src/SRChildCmdBuilder.cpp
    src/SRThreading.cpp
    src/SRUnobtainableResults.cpp
    src/SRLogGatewayDiagnostics.cpp
    src/SRBufferLimiter.cpp
    src/SRLogGatewayStderr.cpp
    src/SRLogGatewayStdout.cpp
    src/SRJobsExchange.cpp
    src/SRWorkerCommonPolicy.cpp
    src/SRWorkerSupervisor.cpp
    src/SRFileSinkWorker.cpp
    src/SRParentEmitWorker.cpp
    src/SRParentReplayRouter.cpp
    src/SRReplayJsonlToParent.cpp
    src/SRReplayTxtToParent.cpp
    src/SRReplayJobsBatch.cpp
    src/SRTimelineLocationResolveBatch.cpp
    src/SRPendingJobDiagnostics.cpp
    src/SRPhaseTimelineEntryFormatter.cpp
    src/SRPhaseTimelineEntryJsonlParser.cpp
    src/SRPhaseTimelineEntryTxtHeaderParser.cpp
    src/SRPhaseTimelineEntrySchemaData.cpp
    src/SRPhaseTimelineEntry.cpp
    src/SRPhaseTimeline.cpp
    src/SRExecutionTimeline.cpp
    src/SRExecutionTimelineDiagnostics.cpp
    src/SRLifecycleDiagnostics.cpp
    src/SRLifecycleFinalizeExecution.cpp
    src/SRMain.cpp
    src/SRPrepareRuntime.cpp
    src/SRRuntime.cpp
    src/SRRuntimeStopReason.cpp
    src/SRRunHook.cpp
)

set_target_properties(SilentRunner PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)

# -municode defines UNICODE during compilation and selects Unicode startup
# during linking, matching the original single g++ invocation.
target_compile_options(SilentRunner PRIVATE -municode)
target_link_options(SilentRunner PRIVATE
    -municode
    -static-libgcc
    -static-libstdc++
    "$<$<CONFIG:Release>:-s>"
)
target_link_libraries(SilentRunner PRIVATE bcrypt)

# Tests are registered here but are executed separately by ctest.
# tests/CMakeLists.txt must support the SilentRunner target in integrated mode.
# Configuring tests/ directly retains the external SILENTRUNNER_EXE mode.
include(CTest)
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
