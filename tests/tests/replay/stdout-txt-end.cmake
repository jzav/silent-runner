include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Verifies persistent Txt replay provenance, headered output, and non-duplicated parent payload for stdout-txt-end.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-replay-stdout-txt-end")
set(expected_log "${log_dir}/${execution_id}_stdout_success.log")
set(expected_running_log "${log_dir}/${execution_id}_stdout_running.log")
cmake_path(NATIVE_PATH expected_running_log NORMALIZE expected_running_log_native)

sr_run(r ARGS
    --debug
    --id-base "${execution_id}"
    --stdout-dir "${log_dir}"
    --stdout-emit end
    --stderr-emit-sr stream
    "${SR_STDOUT_CMD}"
)
sr_assert_exit(r 0)

sr_assert_stderr_contains(r "[PARENT-REPLAY] Replay completed with result ok using plan: ")
sr_assert_stderr_contains(r "stdout={target=StdoutParent source=Txt path=${expected_running_log_native}}")

sr_assert_stdout_txt_header(r "CHILDSTDOUT")
sr_assert_stdout_occurrence_count(r "${SR_TEST_CHILD_STDOUT_MARKER}" 1)
sr_assert_stdout_not_contains(r "${SR_TEST_SRDIAG_TXT_PREFIX}")
sr_assert_stderr_not_contains(r "${SR_TEST_CHILD_STDOUT_MARKER}")

sr_assert_file_not_empty("${expected_log}")
sr_assert_file_txt_header("${expected_log}" "CHILDSTDOUT")
sr_assert_file_occurrence_count("${expected_log}" "${SR_TEST_CHILD_STDOUT_MARKER}" 1)
sr_assert_directory_file_count("${log_dir}" 1)
# Raw parent replay must select Raw TXT even when Headered TXT and JSONL
# logs from the same stream are available.
set(raw_log_dir "${SR_TEST_ROOT}/raw-logs")
set(raw_execution_id "ctest-replay-stdout-raw-txt-end")
set(raw_final_log "${raw_log_dir}/${raw_execution_id}_stdout_raw_success.log")
set(raw_running_log "${raw_log_dir}/${raw_execution_id}_stdout_raw_running.log")
set(raw_output "${SR_TEST_ROOT}/stdout-raw-replay.bin")
set(raw_expected "${SR_TEST_ROOT}/stdout-raw-expected.bin")

sr_write_crlf_terminated_fixture("${raw_expected}" "${SR_TEST_CHILD_STDOUT_MARKER}")
cmake_path(NATIVE_PATH raw_running_log NORMALIZE raw_running_log_native)

sr_run(raw OUTPUT_FILE "${raw_output}" ARGS
    --debug
    --id-base "${raw_execution_id}"
    --stdout-dir-raw "${raw_log_dir}"
    --stdout-dir "${raw_log_dir}"
    --stdout-dir-jsonl "${raw_log_dir}"
    --stdout-emit-raw end
    --stderr-emit-sr stream
    "${SR_STDOUT_CMD}"
)
sr_assert_exit(raw 0)
sr_assert_stderr_contains(raw
    "stdout={target=StdoutParentRaw source=Txt path=${raw_running_log_native}}"
)
sr_assert_files_equal_bytes("${raw_output}" "${raw_expected}")
sr_assert_files_equal_bytes("${raw_final_log}" "${raw_expected}")
sr_assert_file_txt_header(
    "${raw_log_dir}/${raw_execution_id}_stdout_success.log" "CHILDSTDOUT"
)
sr_assert_file_not_empty(
    "${raw_log_dir}/${raw_execution_id}_stdout_success.jsonl"
)
sr_assert_directory_file_count("${raw_log_dir}" 3)
