include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Verifies persistent Txt replay provenance and early SR diagnostics for stderr-sr-txt-end.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-replay-stderr-sr-txt-end")
set(expected_log "${log_dir}/${execution_id}_stderr_sr_success.log")
set(expected_running_log "${log_dir}/${execution_id}_stderr_sr_running.log")
cmake_path(NATIVE_PATH expected_running_log NORMALIZE expected_running_log_native)

sr_run(r ARGS
    --debug
    --id-base "${execution_id}"
    --stderr-dir-sr "${log_dir}"
    --stdout-emit never
    --stderr-emit-sr end
    "${SR_BOTH_CMD}"
)
sr_assert_exit(r 0)

sr_assert_stderr_contains(r "[PARENT-REPLAY] Replay completed with result ok using plan: ")
sr_assert_stderr_contains(r "stderr={target=StderrSrParent source=Txt path=${expected_running_log_native}}")

sr_assert_stdout_empty(r)
sr_assert_stderr_txt_header(r "SRDIAGEVENT")
sr_assert_stderr_contains(r "fullCmdLine=")
sr_assert_stderr_contains(r "${SR_TEST_SRDIAG_TXT_PREFIX}")
sr_assert_stderr_not_contains(r "${SR_TEST_CHILD_STDOUT_MARKER}")
sr_assert_stderr_not_contains(r "${SR_TEST_CHILD_STDERR_MARKER}")

sr_assert_file_not_empty("${expected_log}")
sr_assert_file_txt_header("${expected_log}" "SRDIAGEVENT")
sr_assert_file_contains("${expected_log}" "fullCmdLine=")
sr_assert_directory_file_count("${log_dir}" 1)
