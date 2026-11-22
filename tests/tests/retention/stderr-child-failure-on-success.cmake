include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Removes all three child stderr log presentations on success under failure-only retention.")
set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-ret-stderr-child-failure-success")
set(expected_log "${log_dir}/${execution_id}_stderr_child_success.log")
set(expected_jsonl_log "${log_dir}/${execution_id}_stderr_child_success.jsonl")
set(expected_raw_log "${log_dir}/${execution_id}_stderr_child_raw_success.log")
sr_run(r ARGS
    --id-base "${execution_id}"
    --stderr-dir-child "${log_dir}"
    --stderr-dir-child-jsonl "${log_dir}"
    --stderr-dir-child-raw "${log_dir}"
    --stderr-dir-child-keep-log failure
    "${SR_STDERR_CMD}"
)
sr_assert_exit(r 0)
sr_assert_path_not_exists("${expected_log}")
sr_assert_path_not_exists("${expected_jsonl_log}")
sr_assert_path_not_exists("${expected_raw_log}")
sr_assert_directory_file_count("${log_dir}" 0)
