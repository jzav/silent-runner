include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Aborts a buffered child-stderr execution with exit 125 when the per-stream stderr buffer limit is exceeded.")

set(diag_dir "${SR_TEST_ROOT}/diag")
set(execution_id "ctest-buffer-stderr-limit")
set(expected_diag_log
    "${diag_dir}/${execution_id}_stderr_sr_failure.log"
)

sr_run(r ARGS
    --id-base "${execution_id}"
    --stdout-emit never
    --stderr-emit-child end
    --stderr-max-buffer-bytes 1
    --stderr-dir-sr "${diag_dir}"
    "${SR_SLEEP_OUTPUT}"
)

sr_assert_exit(r "${SR_TEST_EXIT_BUFFER_LIMIT}")

sr_assert_stdout_empty(r)
sr_assert_stderr_occurrence_count(
    r
    "[payloadType=CHILDSTDERR]"
    1
)
sr_assert_stderr_occurrence_count(
    r
    "[payloadDropped=TRUE][payloadByteCount=23]"
    1
)
sr_assert_stderr_not_contains(
    r
    "STDERR_BEFORE_TIMEOUT"
)
sr_assert_stderr_not_contains(
    r
    "${SR_TEST_SRDIAG_TXT_PREFIX}"
)



sr_assert_file_not_empty("${expected_diag_log}")
sr_assert_file_txt_header(
    "${expected_diag_log}"
    "SRDIAGEVENT"
)
sr_assert_file_contains(
    "${expected_diag_log}"
    "Fatal runtime stop: Buffer limit exceeded; first_hit=stderr stdout_max=0 stderr_max=1 total_max=0 action=abort"
)

sr_assert_directory_file_count("${diag_dir}" 1)
