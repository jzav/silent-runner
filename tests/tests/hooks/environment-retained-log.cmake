include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Exposes all retained TXT and JSONL log paths to the hook environment.")
set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-hook-log")
set(expected_stdout_log "${log_dir}/${execution_id}_stdout_success.log")
set(expected_stdout_jsonl_log "${log_dir}/${execution_id}_stdout_success.jsonl")
set(expected_stderr_log "${log_dir}/${execution_id}_stderr_success.log")
set(expected_stderr_jsonl_log "${log_dir}/${execution_id}_stderr_success.jsonl")
set(expected_stderr_child_log "${log_dir}/${execution_id}_stderr_child_success.log")
set(expected_stderr_child_jsonl_log "${log_dir}/${execution_id}_stderr_child_success.jsonl")
set(expected_stderr_sr_log "${log_dir}/${execution_id}_stderr_sr_success.log")
set(expected_stderr_sr_jsonl_log "${log_dir}/${execution_id}_stderr_sr_success.jsonl")
set(expected_stderr_incl_stdout_log "${log_dir}/${execution_id}_stderr_incl_stdout_success.log")
set(expected_stderr_incl_stdout_jsonl_log "${log_dir}/${execution_id}_stderr_incl_stdout_success.jsonl")
foreach(path_var IN ITEMS
    expected_stdout_log
    expected_stdout_jsonl_log
    expected_stderr_log
    expected_stderr_jsonl_log
    expected_stderr_child_log
    expected_stderr_child_jsonl_log
    expected_stderr_sr_log
    expected_stderr_sr_jsonl_log
    expected_stderr_incl_stdout_log
    expected_stderr_incl_stdout_jsonl_log
)
    cmake_path(NATIVE_PATH ${path_var} NORMALIZE ${path_var}_native)
endforeach()
sr_run(r ARGS
    --id-base "${execution_id}"
    --stdout-dir "${log_dir}"
    --stdout-dir-jsonl "${log_dir}"
    --stderr-dir "${log_dir}"
    --stderr-dir-jsonl "${log_dir}"
    --stderr-dir-child "${log_dir}"
    --stderr-dir-child-jsonl "${log_dir}"
    --stderr-dir-sr "${log_dir}"
    --stderr-dir-sr-jsonl "${log_dir}"
    --stderr-dir-incl-stdout "${log_dir}"
    --stderr-dir-incl-stdout-jsonl "${log_dir}"
    --stdout-dir-keep-log always
    --stdout-emit never
    --run-on-success hook-env.cmd
    "${SR_BOTH_CMD}"
)
sr_assert_exit(r 0)
set(env_file "${SR_TEST_ROOT}/hook-env.txt")
sr_wait_for_path("${env_file}")
sr_assert_file_contains("${env_file}" "STDOUT_LOG=[${expected_stdout_log_native}]")
sr_assert_file_contains("${env_file}" "STDOUT_JSONL_LOG=[${expected_stdout_jsonl_log_native}]")
sr_assert_file_contains("${env_file}" "STDERR_LOG=[${expected_stderr_log_native}]")
sr_assert_file_contains("${env_file}" "STDERR_JSONL_LOG=[${expected_stderr_jsonl_log_native}]")
sr_assert_file_contains("${env_file}" "STDERR_CHILD_LOG=[${expected_stderr_child_log_native}]")
sr_assert_file_contains("${env_file}" "STDERR_CHILD_JSONL_LOG=[${expected_stderr_child_jsonl_log_native}]")
sr_assert_file_contains("${env_file}" "STDERR_SR_LOG=[${expected_stderr_sr_log_native}]")
sr_assert_file_contains("${env_file}" "STDERR_SR_JSONL_LOG=[${expected_stderr_sr_jsonl_log_native}]")
sr_assert_file_contains("${env_file}" "STDERR_INCL_STDOUT_LOG=[${expected_stderr_incl_stdout_log_native}]")
sr_assert_file_contains("${env_file}" "STDERR_INCL_STDOUT_JSONL_LOG=[${expected_stderr_incl_stdout_jsonl_log_native}]")
