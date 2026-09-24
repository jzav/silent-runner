include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Creates and validates all ten persistent log destinations in parallel for one failed execution.")
set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-all-logs")
set(expected_stdout_payload "${SR_TEST_CHILD_STDOUT_MARKER}\r\n")
set(expected_stderr_payload "${SR_TEST_CHILD_STDERR_MARKER}\r\n")
set(stdout_txt "${log_dir}/${execution_id}_stdout_failure.log")
set(stdout_jsonl "${log_dir}/${execution_id}_stdout_failure.jsonl")
set(stderr_txt "${log_dir}/${execution_id}_stderr_failure.log")
set(stderr_jsonl "${log_dir}/${execution_id}_stderr_failure.jsonl")
set(stderr_child_txt "${log_dir}/${execution_id}_stderr_child_failure.log")
set(stderr_child_jsonl "${log_dir}/${execution_id}_stderr_child_failure.jsonl")
set(stderr_sr_txt "${log_dir}/${execution_id}_stderr_sr_failure.log")
set(stderr_sr_jsonl "${log_dir}/${execution_id}_stderr_sr_failure.jsonl")
set(stderr_incl_stdout_txt "${log_dir}/${execution_id}_stderr_incl_stdout_failure.log")
set(stderr_incl_stdout_jsonl "${log_dir}/${execution_id}_stderr_incl_stdout_failure.jsonl")
sr_run(r ARGS
    --debug
    --id-base "${execution_id}"
    --stdout-dir "${log_dir}"
    --stdout-dir-jsonl "${log_dir}"
    --stderr-dir "${log_dir}"
    --stderr-dir-jsonl "${log_dir}"
    --stderr-dir-child "${log_dir}"
    --stderr-dir-child-jsonl "${log_dir}"
    --stderr-dir-sr "${log_dir}"
    --stderr-dir-sr-jsonl "${log_dir}"
    --stderr-dir-incl-stdout "${log_dir}"
    --stderr-dir-incl-stdout-jsonl "${log_dir}"
    "${SR_FAIL}"
)
sr_assert_exit(r "${SR_TEST_FAIL_CMD_EXIT_CODE}")
sr_assert_directory_file_count("${log_dir}" 10)
sr_assert_file_txt_header("${stdout_txt}" "CHILDSTDOUT")
sr_assert_file_occurrence_count("${stdout_txt}" "${SR_TEST_CHILD_STDOUT_MARKER}" 1)
sr_assert_file_not_contains("${stdout_txt}" "${SR_TEST_CHILD_STDERR_MARKER}")
sr_assert_file_not_contains("${stdout_txt}" "${SR_TEST_SRDIAG_TXT_PREFIX}")

sr_assert_jsonl_default_text_payload("${stdout_jsonl}" "ChildStdout" "${expected_stdout_payload}")
sr_assert_file_not_contains("${stdout_jsonl}" "${SR_TEST_CHILD_STDERR_JSONL_PREFIX}")
sr_assert_file_not_contains("${stdout_jsonl}" "${SR_TEST_SRDIAG_JSONL_PREFIX}")

sr_assert_file_txt_header("${stderr_txt}" "CHILDSTDERR")
sr_assert_file_txt_header("${stderr_txt}" "SRDIAGEVENT")
sr_assert_file_occurrence_count("${stderr_txt}" "${SR_TEST_CHILD_STDERR_MARKER}" 1)
sr_assert_file_not_contains("${stderr_txt}" "${SR_TEST_CHILD_STDOUT_MARKER}")

sr_assert_jsonl_default_text_payload("${stderr_jsonl}" "ChildStderr" "${expected_stderr_payload}")
sr_assert_jsonl_default_text_records("${stderr_jsonl}" "SrDiagEvent")
sr_assert_file_not_contains("${stderr_jsonl}" "${SR_TEST_CHILD_STDOUT_JSONL_PREFIX}")

sr_assert_file_txt_header("${stderr_child_txt}" "CHILDSTDERR")
sr_assert_file_occurrence_count("${stderr_child_txt}" "${SR_TEST_CHILD_STDERR_MARKER}" 1)
sr_assert_file_not_contains("${stderr_child_txt}" "${SR_TEST_CHILD_STDOUT_MARKER}")
sr_assert_file_not_contains("${stderr_child_txt}" "${SR_TEST_SRDIAG_TXT_PREFIX}")

sr_assert_jsonl_default_text_payload("${stderr_child_jsonl}" "ChildStderr" "${expected_stderr_payload}")
sr_assert_file_not_contains("${stderr_child_jsonl}" "${SR_TEST_CHILD_STDOUT_JSONL_PREFIX}")
sr_assert_file_not_contains("${stderr_child_jsonl}" "${SR_TEST_SRDIAG_JSONL_PREFIX}")

sr_assert_file_txt_header("${stderr_sr_txt}" "SRDIAGEVENT")
sr_assert_file_not_contains("${stderr_sr_txt}" "${SR_TEST_CHILD_STDOUT_MARKER}")
sr_assert_file_not_contains("${stderr_sr_txt}" "${SR_TEST_CHILD_STDERR_MARKER}")

sr_assert_jsonl_default_text_records("${stderr_sr_jsonl}" "SrDiagEvent")
sr_assert_file_not_contains("${stderr_sr_jsonl}" "${SR_TEST_CHILD_STDOUT_JSONL_PREFIX}")
sr_assert_file_not_contains("${stderr_sr_jsonl}" "${SR_TEST_CHILD_STDERR_JSONL_PREFIX}")

sr_assert_file_txt_header("${stderr_incl_stdout_txt}" "SRDIAGEVENT")
sr_assert_file_txt_header("${stderr_incl_stdout_txt}" "CHILDSTDOUT")
sr_assert_file_txt_header("${stderr_incl_stdout_txt}" "CHILDSTDERR")
sr_assert_file_occurrence_count("${stderr_incl_stdout_txt}" "${SR_TEST_CHILD_STDOUT_MARKER}" 1)
sr_assert_file_occurrence_count("${stderr_incl_stdout_txt}" "${SR_TEST_CHILD_STDERR_MARKER}" 1)

sr_assert_jsonl_default_text_payload("${stderr_incl_stdout_jsonl}" "ChildStdout" "${expected_stdout_payload}")
sr_assert_jsonl_default_text_payload("${stderr_incl_stdout_jsonl}" "ChildStderr" "${expected_stderr_payload}")
sr_assert_jsonl_default_text_records("${stderr_incl_stdout_jsonl}" "SrDiagEvent")
