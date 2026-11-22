include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Returns exit code 255 without starting the child when --stdout-dir points to an existing regular file, preserving its contents.")

set(log_path "${SR_TEST_ROOT}/logs")
set(sentinel "SRTEST_LOG_DIRECTORY_FILE_SENTINEL")
file(WRITE "${log_path}" "${sentinel}")

sr_run(r ARGS
    --id-base ctest-stdout-dir-points-to-file
    --stdout-dir "${log_path}"
    "${SR_OK}"
)

sr_assert_exit(r "${SR_TEST_EXIT_INTERNAL}")
sr_assert_stdout_not_contains(r "${SR_TEST_CHILD_STDOUT_MARKER}")
sr_assert_file_equals("${log_path}" "${sentinel}")
