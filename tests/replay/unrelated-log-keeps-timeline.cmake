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
# Headered TXT and JSONL logs are not compatible sources for Raw parent
# replay; both Raw parent streams must therefore use the timeline.
set(raw_log_dir "${SR_TEST_ROOT}/raw-incompatible-logs")
set(raw_diag_dir "${SR_TEST_ROOT}/raw-incompatible-diag")
set(raw_execution_id "ctest-replay-raw-incompatible-sources")
set(raw_diag_log
    "${raw_diag_dir}/${raw_execution_id}_stderr_sr_success.log"
)
set(raw_stdout_output "${SR_TEST_ROOT}/raw-timeline-stdout.bin")
set(raw_stderr_output "${SR_TEST_ROOT}/raw-timeline-stderr.bin")
set(raw_stdout_expected "${SR_TEST_ROOT}/raw-timeline-stdout-expected.bin")
set(raw_stderr_expected "${SR_TEST_ROOT}/raw-timeline-stderr-expected.bin")
sr_write_crlf_terminated_fixture(
    "${raw_stdout_expected}" "${SR_TEST_CHILD_STDOUT_MARKER}"
)
sr_write_crlf_terminated_fixture(
    "${raw_stderr_expected}" "${SR_TEST_CHILD_STDERR_MARKER}"
)

sr_run(raw OUTPUT_FILE "${raw_stdout_output}" ERROR_FILE "${raw_stderr_output}" ARGS
    --debug
    --id-base "${raw_execution_id}"
    --stdout-dir "${raw_log_dir}"
    --stdout-dir-jsonl "${raw_log_dir}"
    --stderr-dir-child "${raw_log_dir}"
    --stderr-dir-child-jsonl "${raw_log_dir}"
    --stderr-dir-sr "${raw_diag_dir}"
    --stdout-emit-raw end
    --stderr-emit-child-raw end
    "${SR_BOTH_CMD}"
)
sr_assert_exit(raw 0)
sr_assert_files_equal_bytes("${raw_stdout_output}" "${raw_stdout_expected}")
sr_assert_files_equal_bytes("${raw_stderr_output}" "${raw_stderr_expected}")
sr_assert_file_contains("${raw_diag_log}"
    "stdout={target=StdoutParentRaw source=Timeline path=<none>}"
)
sr_assert_file_contains("${raw_diag_log}"
    "stderr={target=StderrChildParentRaw source=Timeline path=<none>}"
)
sr_assert_directory_file_count("${raw_log_dir}" 4)
sr_assert_directory_file_count("${raw_diag_dir}" 1)

# The reverse mismatch also matters: a Headered parent must not replay
# from a Raw TXT log (which has no event headers).
set(reverse_log_dir "${SR_TEST_ROOT}/headered-incompatible-logs")
set(reverse_execution_id "ctest-replay-headered-incompatible-raw")
set(reverse_raw_log
    "${reverse_log_dir}/${reverse_execution_id}_stdout_raw_success.log"
)
set(reverse_expected "${SR_TEST_ROOT}/reverse-raw-expected.bin")
sr_write_crlf_terminated_fixture(
    "${reverse_expected}" "${SR_TEST_CHILD_STDOUT_MARKER}"
)

sr_run(reverse ARGS
    --debug
    --id-base "${reverse_execution_id}"
    --stdout-dir-raw "${reverse_log_dir}"
    --stdout-emit end
    --stderr-emit-sr stream
    "${SR_STDOUT_CMD}"
)
sr_assert_exit(reverse 0)
sr_assert_stderr_contains(reverse
    "stdout={target=StdoutParent source=Timeline path=<none>}"
)
sr_assert_stdout_txt_header(reverse "CHILDSTDOUT")
sr_assert_stdout_occurrence_count(reverse "${SR_TEST_CHILD_STDOUT_MARKER}" 1)
sr_assert_files_equal_bytes("${reverse_raw_log}" "${reverse_expected}")
sr_assert_directory_file_count("${reverse_log_dir}" 1)
