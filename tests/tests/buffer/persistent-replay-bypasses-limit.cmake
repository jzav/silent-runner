include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Bypasses RAM replay-buffer limits when stdout End replay can use a persistent JSONL source.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-buffer-persistent-replay-bypass")

set(expected_log
    "${log_dir}/${execution_id}_stdout_success.jsonl"
)
set(expected_running_log
    "${log_dir}/${execution_id}_stdout_running.jsonl"
)

set(expected_payload
    "${SR_TEST_CHILD_STDOUT_MARKER}\r\n"
)

cmake_path(
    NATIVE_PATH expected_running_log
    NORMALIZE expected_running_log_native
)

sr_run(r ARGS
    --debug
    --id-base "${execution_id}"
    --stdout-dir-jsonl "${log_dir}"
    --stdout-emit end
    --stdout-max-buffer-bytes 1
    --std-total-max-buffer-bytes 1
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
sr_assert_stderr_not_contains(
    r
    "Fatal runtime stop: Buffer limit exceeded"
)

sr_assert_stdout_txt_header(r "CHILDSTDOUT")
sr_assert_stdout_occurrence_count(
    r
    "${SR_TEST_CHILD_STDOUT_MARKER}"
    1
)

sr_assert_file_not_empty("${expected_log}")
sr_assert_jsonl_default_text_payload(
    "${expected_log}"
    "ChildStdout"
    "${expected_payload}"
)

sr_assert_directory_file_count("${log_dir}" 1)
