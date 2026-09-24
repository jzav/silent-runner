include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Keeps stdout Timeline replay when only an unrelated stderr-child persistent log source exists.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-replay-unrelated-log-keeps-timeline")

set(expected_child_log
    "${log_dir}/${execution_id}_stderr_child_success.jsonl"
)
set(expected_stderr_payload
    "${SR_TEST_CHILD_STDERR_MARKER}\r\n"
)

sr_run(r ARGS
    --debug
    --id-base "${execution_id}"
    --stderr-dir-child-jsonl "${log_dir}"
    --stdout-emit end
    --stderr-emit-sr stream
    "${SR_BOTH_CMD}"
)

sr_assert_exit(r 0)

sr_assert_stderr_contains(
    r
    "[PARENT-REPLAY] Replay completed with result ok using plan: "
)
sr_assert_stderr_contains(
    r
    "stdout={target=StdoutParent source=Timeline path=<none>}"
)

sr_assert_stdout_txt_header(r "CHILDSTDOUT")
sr_assert_stdout_occurrence_count(
    r
    "${SR_TEST_CHILD_STDOUT_MARKER}"
    1
)
sr_assert_stdout_not_contains(
    r
    "${SR_TEST_CHILD_STDERR_MARKER}"
)

sr_assert_file_not_empty("${expected_child_log}")
sr_assert_jsonl_default_text_payload(
    "${expected_child_log}"
    "ChildStderr"
    "${expected_stderr_payload}"
)

sr_assert_directory_file_count("${log_dir}" 1)
