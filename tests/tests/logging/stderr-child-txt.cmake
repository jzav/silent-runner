include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Writes child stderr to a failure TXT log.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-stderr-child")
set(expected_log "${log_dir}/${execution_id}_stderr_child_failure.log")

sr_run(
    r
    ARGS
        --id-base "${execution_id}"
        --stderr-dir-child "${log_dir}"
        "${SR_FAIL}"
)

sr_assert_exit(r "${SR_TEST_FAIL_CMD_EXIT_CODE}")
sr_assert_file_contains("${expected_log}" "${SR_TEST_CHILD_STDERR_MARKER}")
sr_assert_directory_file_count("${log_dir}" 1)
