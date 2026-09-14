include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Keeps the outer execution successful while a detached hook's nested SilentRunner returns 254 because no diagnostic channel is available.")

set(marker_file "${SR_TEST_ROOT}/hook-nested-no-diagnostic-channel.txt")
file(TO_NATIVE_PATH "${SILENTRUNNER_EXE}" nested_sr_exe)

sr_run(r
    ENV "SR_TEST_NESTED_EXE=${nested_sr_exe}"
    ARGS --run-on-success hook-nested-no-diagnostic-channel.cmd "${SR_OK}"
)

sr_assert_exit(r 0)
sr_assert_stdout_contains(r "${SR_TEST_CHILD_STDOUT_MARKER}")

# The hook is detached; its result is published only after the file is complete.
sr_wait_for_path("${marker_file}")
sr_assert_file_equals("${marker_file}" "${SR_TEST_EXIT_NO_DIAGNOSTIC_CHANNEL}\n")
