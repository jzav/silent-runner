include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Replays child-only stderr from its persistent TXT source in End mode.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(diag_dir "${SR_TEST_ROOT}/diag")

set(execution_id "ctest-replay-stderr-child-txt-end")

set(expected_diag_log
    "${diag_dir}/${execution_id}_stderr_sr_success.log"
)


set(expected_log
    "${log_dir}/${execution_id}_stderr_child_success.log"
)
set(expected_running_log
    "${log_dir}/${execution_id}_stderr_child_running.log"
)

cmake_path(
    NATIVE_PATH expected_running_log
    NORMALIZE expected_running_log_native
)

sr_run(r ARGS
    --debug
    --id-base "${execution_id}"
    --stderr-dir-child "${log_dir}"
    --stderr-dir-sr "${diag_dir}"

    --stdout-emit never
    --stderr-emit-child end
    "${SR_BOTH_CMD}"
)

sr_assert_exit(r 0)

sr_assert_file_not_empty("${expected_diag_log}")
sr_assert_file_txt_header(
    "${expected_diag_log}"
    "SRDIAGEVENT"
)
sr_assert_file_contains(
    "${expected_diag_log}"
    "[PARENT-REPLAY] Replay completed with result ok using plan: "
)
sr_assert_file_contains(
    "${expected_diag_log}"
    "stderr={target=StderrChildParent source=Txt path=${expected_running_log_native}}"
)


sr_assert_stdout_empty(r)
sr_assert_stderr_txt_header(r "CHILDSTDERR")
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
    "${SR_TEST_CHILD_STDOUT_MARKER}"
)

sr_assert_file_not_empty("${expected_log}")
sr_assert_file_txt_header(
    "${expected_log}"
    "CHILDSTDERR"
)
sr_assert_file_occurrence_count(
    "${expected_log}"
    "${SR_TEST_CHILD_STDERR_MARKER}"
    1
)
sr_assert_file_not_contains(
    "${expected_log}"
    "${SR_TEST_CHILD_STDOUT_MARKER}"
)

sr_assert_directory_file_count("${log_dir}" 1)
sr_assert_directory_file_count("${diag_dir}" 1)
# Raw child-stderr replay uses only its Raw TXT source, while diagnostics
# remain confined to the separate SR-only log.
set(raw_log_dir "${SR_TEST_ROOT}/raw-logs")
set(raw_diag_dir "${SR_TEST_ROOT}/raw-diag")
set(raw_execution_id "ctest-replay-stderr-child-raw-txt-end")
set(raw_final_log
    "${raw_log_dir}/${raw_execution_id}_stderr_child_raw_success.log"
)
set(raw_running_log
    "${raw_log_dir}/${raw_execution_id}_stderr_child_raw_running.log"
)
set(raw_diag_log
    "${raw_diag_dir}/${raw_execution_id}_stderr_sr_success.log"
)
set(raw_output "${SR_TEST_ROOT}/stderr-child-raw-replay.bin")
set(raw_expected "${SR_TEST_ROOT}/stderr-child-raw-expected.bin")

sr_write_crlf_terminated_fixture("${raw_expected}" "${SR_TEST_CHILD_STDERR_MARKER}")
cmake_path(NATIVE_PATH raw_running_log NORMALIZE raw_running_log_native)

sr_run(raw ERROR_FILE "${raw_output}" ARGS
    --debug
    --id-base "${raw_execution_id}"
    --stdout-emit never
    --stderr-emit-child-raw end
    --stderr-dir-child-raw "${raw_log_dir}"
    --stderr-dir-sr "${raw_diag_dir}"
    "${SR_BOTH_CMD}"
)
sr_assert_exit(raw 0)
sr_assert_stdout_empty(raw)
sr_assert_files_equal_bytes("${raw_output}" "${raw_expected}")
sr_assert_files_equal_bytes("${raw_final_log}" "${raw_expected}")
sr_assert_file_contains("${raw_diag_log}"
    "stderr={target=StderrChildParentRaw source=Txt path=${raw_running_log_native}}"
)
sr_assert_directory_file_count("${raw_log_dir}" 1)
sr_assert_directory_file_count("${raw_diag_dir}" 1)
