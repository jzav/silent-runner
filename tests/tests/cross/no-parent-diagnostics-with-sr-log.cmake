include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Keeps SR diagnostics out of a child-only parent stderr view while an SR-only persistent log provides the diagnostic channel.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-cross-no-parent-diagnostics-with-sr-log")
set(expected_log
    "${log_dir}/${execution_id}_stderr_sr_success.log"
)

sr_run(r ARGS
    --debug
    --id-base "${execution_id}"
    --stdout-emit never
    --stderr-dir-sr "${log_dir}"
    --stderr-emit-child stream
    "${SR_BOTH_CMD}"
)

sr_assert_exit(r 0)

sr_assert_stdout_empty(r)

sr_assert_stderr_txt_header(
    r
    "CHILDSTDERR"
)
sr_assert_stderr_occurrence_count(
    r
    "${SR_TEST_CHILD_STDERR_MARKER}"
    1
)
sr_assert_stderr_not_contains(
    r
    "${SR_TEST_SRDIAG_TXT_PREFIX}"
)
sr_assert_stderr_not_contains(
    r
    "fullCmdLine="
)

sr_assert_file_not_empty("${expected_log}")
sr_assert_file_txt_header(
    "${expected_log}"
    "SRDIAGEVENT"
)
sr_assert_file_contains(
    "${expected_log}"
    "fullCmdLine="
)
sr_assert_file_not_contains(
    "${expected_log}"
    "${SR_TEST_CHILD_STDERR_MARKER}"
)

sr_assert_directory_file_count("${log_dir}" 1)
