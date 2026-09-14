include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Verifies persistent Txt replay provenance and parent payload for stdout-txt-success.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-replay-stdout-txt-success")
set(expected_log "${log_dir}/${execution_id}_stdout_success.log")

sr_run(r ARGS
    --debug
    --id-base "${execution_id}"
    --stdout-dir "${log_dir}"
    --stdout-emit success
    --stderr-emit-sr stream
    "${SR_STDOUT_CMD}"
)
sr_assert_exit(r 0)

# The normal debug completion line identifies the selected parent target/source.
# Checking only payload or log existence would also allow timeline replay.
sr_assert_stderr_contains(r "[PARENT-REPLAY] Replay completed with result ok using plan: ")
sr_assert_stderr_contains(r "stdout={target=StdoutParent source=Txt path=")

sr_assert_stdout_contains(r "${SR_TEST_CHILD_STDOUT_MARKER}")
sr_assert_stdout_not_contains(r "${SR_TEST_SRDIAG_TXT_PREFIX}")
sr_assert_stderr_not_contains(r "${SR_TEST_CHILD_STDOUT_MARKER}")

sr_assert_file_not_empty("${expected_log}")
sr_assert_file_contains("${expected_log}" "${SR_TEST_CHILD_STDOUT_MARKER}")
sr_assert_directory_file_count("${log_dir}" 1)
