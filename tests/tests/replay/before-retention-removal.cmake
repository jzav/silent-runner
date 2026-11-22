include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Replays from the running persistent stdout source before success causes failure-only retention to remove that log.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-replay-before-retention-removal")

set(expected_running_log
    "${log_dir}/${execution_id}_stdout_running.jsonl"
)
set(expected_success_log
    "${log_dir}/${execution_id}_stdout_success.jsonl"
)

cmake_path(
    NATIVE_PATH expected_running_log
    NORMALIZE expected_running_log_native
)

sr_run(r ARGS
    --debug
    --id-base "${execution_id}"
    --stdout-dir-jsonl "${log_dir}"
    --stdout-dir-keep-log failure
    --stdout-emit end
    --stderr-emit-sr stream
    "${SR_STDOUT_CMD}"
)

sr_assert_exit(r 0)

sr_assert_stderr_contains(
    r
    "[PARENT-REPLAY] Replay completed with result ok using plan: "
)
sr_assert_stderr_contains(
    r
    "stdout={target=StdoutParent source=Jsonl path=${expected_running_log_native}}"
)

sr_assert_stdout_txt_header(r "CHILDSTDOUT")
sr_assert_stdout_occurrence_count(
    r
    "${SR_TEST_CHILD_STDOUT_MARKER}"
    1
)

# Replay consumed the *_running source successfully, but failure-only retention
# must remove it after replay because this execution succeeded.
sr_assert_path_not_exists("${expected_running_log}")
sr_assert_path_not_exists("${expected_success_log}")
sr_assert_directory_file_count("${log_dir}" 0)

# Raw replay must consume its running TXT source before success removes it.
set(raw_log_dir "${SR_TEST_ROOT}/raw-logs")
set(raw_execution_id "ctest-raw-replay-before-retention-removal")
set(raw_running_log
    "${raw_log_dir}/${raw_execution_id}_stdout_raw_running.log"
)
set(raw_final_log
    "${raw_log_dir}/${raw_execution_id}_stdout_raw_success.log"
)
set(raw_output "${SR_TEST_ROOT}/raw-replay-output.bin")
set(raw_expected "${SR_TEST_ROOT}/raw-replay-expected.bin")
sr_write_crlf_terminated_fixture("${raw_expected}" "${SR_TEST_CHILD_STDOUT_MARKER}")
cmake_path(NATIVE_PATH raw_running_log NORMALIZE raw_running_log_native)

sr_run(raw OUTPUT_FILE "${raw_output}" ARGS
    --debug
    --id-base "${raw_execution_id}"
    --stdout-dir-raw "${raw_log_dir}"
    --stdout-dir-keep-log failure
    --stdout-emit-raw end
    --stderr-emit-sr stream
    "${SR_STDOUT_CMD}"
)
sr_assert_exit(raw 0)
sr_assert_stderr_contains(raw
    "stdout={target=StdoutParentRaw source=Txt path=${raw_running_log_native}}"
)
sr_assert_files_equal_bytes("${raw_output}" "${raw_expected}")
sr_assert_path_not_exists("${raw_running_log}")
sr_assert_path_not_exists("${raw_final_log}")
sr_assert_directory_file_count("${raw_log_dir}" 0)
