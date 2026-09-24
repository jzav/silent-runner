include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Keeps persistent replay subject to success and failure result gating when a replayable log source exists.")

# Failure-only emission must not replay after a successful execution even though
# a persistent JSONL source exists and is retained.
set(success_log_dir "${SR_TEST_ROOT}/success-logs")
set(success_execution_id "ctest-replay-gating-failure-on-success")
set(success_final_log
    "${success_log_dir}/${success_execution_id}_stdout_success.jsonl"
)
set(expected_success_payload
    "${SR_TEST_CHILD_STDOUT_MARKER}\r\n"
)

sr_run(success_case ARGS
    --debug
    --id-base "${success_execution_id}"
    --stdout-dir-jsonl "${success_log_dir}"
    --stdout-emit failure
    --stderr-emit-sr stream
    "${SR_STDOUT_CMD}"
)

sr_assert_exit(success_case 0)
sr_assert_stdout_empty(success_case)
sr_assert_stderr_not_contains(
    success_case
    "[PARENT-REPLAY] Replay completed with result"
)

sr_assert_file_not_empty("${success_final_log}")
sr_assert_jsonl_default_text_payload(
    "${success_final_log}"
    "ChildStdout"
    "${expected_success_payload}"
)
sr_assert_directory_file_count("${success_log_dir}" 1)

# Success-only emission must likewise not replay after a failed execution.
set(failure_log_dir "${SR_TEST_ROOT}/failure-logs")
set(failure_execution_id "ctest-replay-gating-success-on-failure")
set(failure_final_log
    "${failure_log_dir}/${failure_execution_id}_stdout_failure.jsonl"
)
set(expected_failure_payload
    "${SR_TEST_CHILD_STDOUT_MARKER}\r\n"
)

sr_run(failure_case ARGS
    --debug
    --id-base "${failure_execution_id}"
    --stdout-dir-jsonl "${failure_log_dir}"
    --stdout-emit success
    --stderr-emit-sr stream
    "${SR_FAIL}"
)

sr_assert_exit(
    failure_case
    "${SR_TEST_FAIL_CMD_EXIT_CODE}"
)
sr_assert_stdout_empty(failure_case)
sr_assert_stderr_not_contains(
    failure_case
    "[PARENT-REPLAY] Replay completed with result"
)

sr_assert_file_not_empty("${failure_final_log}")
sr_assert_jsonl_default_text_payload(
    "${failure_final_log}"
    "ChildStdout"
    "${expected_failure_payload}"
)
sr_assert_directory_file_count("${failure_log_dir}" 1)
