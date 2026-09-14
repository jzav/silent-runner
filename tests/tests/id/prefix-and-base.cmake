include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Combines --id-prefix and --id-base in prefix_base order with one underscore and no implicit suffix.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(expected_log "${log_dir}/ctest_composed_stdout_success.log")

sr_run(r ARGS
    --id-prefix ctest
    --id-base composed
    --stdout-dir "${log_dir}"
    --stdout-emit never
    "${SR_STDOUT_CMD}"
)

sr_assert_exit(r 0)
sr_assert_file_contains("${expected_log}" "${SR_TEST_CHILD_STDOUT_MARKER}")
sr_assert_directory_file_count("${log_dir}" 1)
