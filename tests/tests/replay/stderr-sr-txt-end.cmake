include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Verifies persistent Txt replay provenance and parent payload for stderr-sr-txt-end.")

# Based on the anchored snapshot 2026-09-13_12-13-32.
set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-replay-stderr-sr-txt-end")
set(expected_log "${log_dir}/${execution_id}_stderr_sr_success.log")

sr_run(r ARGS
    --debug
    --id-base "${execution_id}"
    --stderr-dir-sr "${log_dir}"
    --stdout-emit never
    --stderr-emit-sr end
    "${SR_BOTH_CMD}"
)
sr_assert_exit(r 0)

# The normal debug completion line identifies the selected parent target/source.
# Checking only payload or log existence would also allow timeline replay.
sr_assert_stderr_contains(r "[PARENT-REPLAY] Replay completed with result ok using plan: ")
sr_assert_stderr_contains(r "stderr={target=StderrSrParent source=Txt path=")

sr_assert_stdout_empty(r)
# This diagnostic predates replay; the completion diagnostic alone is insufficient.
sr_assert_stderr_contains(r "fullCmdLine=")
sr_assert_stderr_contains(r "${SR_TEST_SRDIAG_TXT_PREFIX}")
sr_assert_stderr_not_contains(r "${SR_TEST_CHILD_STDOUT_MARKER}")
sr_assert_stderr_not_contains(r "${SR_TEST_CHILD_STDERR_MARKER}")

sr_assert_file_not_empty("${expected_log}")
sr_assert_file_contains("${expected_log}" "${SR_TEST_SRDIAG_TXT_PREFIX}")
sr_assert_directory_file_count("${log_dir}" 1)
