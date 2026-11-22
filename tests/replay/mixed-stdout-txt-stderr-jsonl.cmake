include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Selects stdout TXT and stderr-child JSONL persistent replay sources independently in the same execution.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(diag_dir "${SR_TEST_ROOT}/diag")

set(execution_id "ctest-replay-mixed-stdout-txt-stderr-jsonl")

set(expected_diag_log
    "${diag_dir}/${execution_id}_stderr_sr_success.log"
)


set(expected_stdout_log
    "${log_dir}/${execution_id}_stdout_success.log"
)
set(expected_stdout_running_log
    "${log_dir}/${execution_id}_stdout_running.log"
)

set(expected_stderr_log
    "${log_dir}/${execution_id}_stderr_child_success.jsonl"
)
set(expected_stderr_running_log
    "${log_dir}/${execution_id}_stderr_child_running.jsonl"
)

set(expected_stderr_payload
    "${SR_TEST_CHILD_STDERR_MARKER}\r\n"
)

cmake_path(
    NATIVE_PATH expected_stdout_running_log
    NORMALIZE expected_stdout_running_log_native
)
cmake_path(
    NATIVE_PATH expected_stderr_running_log
    NORMALIZE expected_stderr_running_log_native
)

sr_run(r ARGS
    --debug
    --id-base "${execution_id}"
    --stdout-dir "${log_dir}"
    --stderr-dir-child-jsonl "${log_dir}"
    --stderr-dir-sr "${diag_dir}"

    --stdout-emit end
    --stderr-emit-child end
    "${SR_BOTH_CMD}"
)

sr_assert_exit(r 0)

sr_assert_file_not_empty("${expected_diag_log}")
sr_assert_file_contains(
    "${expected_diag_log}"
    "[PARENT-REPLAY] Replay completed with result ok using plan: "
)
sr_assert_file_contains(
    "${expected_diag_log}"
    "stdout={target=StdoutParent source=Txt path=${expected_stdout_running_log_native}}"
)
sr_assert_file_contains(
    "${expected_diag_log}"
    "stderr={target=StderrChildParent source=Jsonl path=${expected_stderr_running_log_native}}"
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


sr_assert_file_not_empty("${expected_stdout_log}")
sr_assert_file_txt_header(
    "${expected_stdout_log}"
    "CHILDSTDOUT"
)
sr_assert_file_occurrence_count(
    "${expected_stdout_log}"
    "${SR_TEST_CHILD_STDOUT_MARKER}"
    1
)

sr_assert_file_not_empty("${expected_stderr_log}")
sr_assert_jsonl_default_text_payload(
    "${expected_stderr_log}"
    "ChildStderr"
    "${expected_stderr_payload}"
)

sr_assert_directory_file_count("${log_dir}" 2)
sr_assert_directory_file_count("${diag_dir}" 1)
