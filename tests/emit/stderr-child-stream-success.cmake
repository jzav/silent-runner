include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Emits child stderr in Headered and Raw stream presentation without SR diagnostics.")
sr_run(r ARGS --stderr-emit-child stream --stderr-dir-sr "${SR_TEST_ROOT}/sr-diag" "${SR_BOTH_CMD}")
sr_assert_exit(r 0)
sr_assert_stderr_txt_header(r "CHILDSTDERR")
sr_assert_stderr_occurrence_count(r "${SR_TEST_CHILD_STDERR_MARKER}" 1)
sr_assert_stderr_not_contains(r "${SR_TEST_CHILD_STDOUT_MARKER}")
sr_assert_stderr_not_contains(r "${SR_TEST_SRDIAG_TXT_PREFIX}")
set(expected_raw "${SR_TEST_ROOT}/expected-stderr-raw.bin")
set(actual_raw "${SR_TEST_ROOT}/actual-stderr-raw.bin")
sr_write_crlf_terminated_fixture("${expected_raw}" "${SR_TEST_CHILD_STDERR_MARKER}")
sr_run(raw ERROR_FILE "${actual_raw}" ARGS
    --stderr-emit-child-raw stream
    --stderr-dir-sr "${SR_TEST_ROOT}/sr-raw-diag"
    "${SR_BOTH_CMD}"
)
sr_assert_exit(raw 0)
sr_assert_files_equal_bytes("${actual_raw}" "${expected_raw}")
