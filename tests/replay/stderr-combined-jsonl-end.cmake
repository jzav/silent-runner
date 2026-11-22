include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Replays combined SilentRunner diagnostics and child stderr from the persistent combined-stderr JSONL source in End mode.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-replay-stderr-combined-jsonl-end")

set(expected_log
    "${log_dir}/${execution_id}_stderr_success.jsonl"
)
set(expected_running_log
    "${log_dir}/${execution_id}_stderr_running.jsonl"
)

set(expected_stderr_payload
    "${SR_TEST_CHILD_STDERR_MARKER}\r\n"
)

cmake_path(
    NATIVE_PATH expected_running_log
    NORMALIZE expected_running_log_native
)

sr_run(r ARGS
    --debug
    --id-base "${execution_id}"
    --stderr-dir-jsonl "${log_dir}"
    --stdout-emit never
    --stderr-emit end
    "${SR_BOTH_CMD}"
)

sr_assert_exit(r 0)

sr_assert_stderr_contains(
    r
    "[PARENT-REPLAY] Replay completed with result ok using plan: "
)
sr_assert_stderr_contains(
    r
    "stderr={target=StderrSrAndChildParent source=Jsonl path=${expected_running_log_native}}"
)

sr_assert_stdout_empty(r)

sr_assert_stderr_txt_header(r "SRDIAGEVENT")
sr_assert_stderr_txt_header(r "CHILDSTDERR")
sr_assert_stderr_contains(r "fullCmdLine=")
sr_assert_stderr_occurrence_count(
    r
    "${SR_TEST_CHILD_STDERR_MARKER}"
    1
)
sr_assert_stderr_not_contains(
    r
    "${SR_TEST_CHILD_STDOUT_MARKER}"
)

sr_assert_file_not_empty("${expected_log}")
sr_assert_jsonl_default_text_payload(
    "${expected_log}"
    "ChildStderr"
    "${expected_stderr_payload}"
)
sr_assert_jsonl_default_text_records(
    "${expected_log}"
    "SrDiagEvent"
)
sr_assert_file_not_contains(
    "${expected_log}"
    "${SR_TEST_CHILD_STDOUT_JSONL_PREFIX}"
)

sr_assert_directory_file_count("${log_dir}" 1)
