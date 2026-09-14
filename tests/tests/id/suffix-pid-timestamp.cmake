include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Builds a PID+timestamp execution ID suffix and matching log filename.")
set(log_dir "${SR_TEST_ROOT}/logs")
sr_run(r ARGS --id-suffix "pid+timestamp" --stdout-dir "${log_dir}" --stdout-emit never "${SR_STDOUT_CMD}")
sr_assert_exit(r 0)
sr_assert_single_file_name_matches(
    "${log_dir}"
    "^pid[0-9]+_[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]_[0-9][0-9]-[0-9][0-9]-[0-9][0-9]Z_stdout_success\\.log$"
)
