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
