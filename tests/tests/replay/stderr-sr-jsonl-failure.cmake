include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Verifies persistent Jsonl replay provenance, default text SR diagnostics, and early failure diagnostics for stderr-sr-jsonl-failure.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-replay-stderr-sr-jsonl-failure")
set(expected_log "${log_dir}/${execution_id}_stderr_sr_failure.jsonl")
set(expected_running_log "${log_dir}/${execution_id}_stderr_sr_running.jsonl")
cmake_path(NATIVE_PATH expected_running_log NORMALIZE expected_running_log_native)

sr_run(r ARGS
    --debug
    --id-base "${execution_id}"
    --stderr-dir-sr-jsonl "${log_dir}"
    --stdout-emit never
    --stderr-emit-sr failure
    "${SR_FAIL}"
)
sr_assert_exit(r "${SR_TEST_FAIL_CMD_EXIT_CODE}")

sr_assert_stderr_contains(r "[PARENT-REPLAY] Replay completed with result ok using plan: ")
sr_assert_stderr_contains(r "stderr={target=StderrSrParent source=Jsonl path=${expected_running_log_native}}")

sr_assert_stdout_empty(r)
sr_assert_stderr_txt_header(r "SRDIAGEVENT")
sr_assert_stderr_contains(r "fullCmdLine=")
sr_assert_stderr_contains(r "${SR_TEST_SRDIAG_TXT_PREFIX}")
sr_assert_stderr_not_contains(r "${SR_TEST_CHILD_STDOUT_MARKER}")
sr_assert_stderr_not_contains(r "${SR_TEST_CHILD_STDERR_MARKER}")

sr_assert_file_not_empty("${expected_log}")
sr_assert_jsonl_default_text_records("${expected_log}" "SrDiagEvent")
sr_assert_file_contains("${expected_log}" "fullCmdLine=")
sr_assert_directory_file_count("${log_dir}" 1)
