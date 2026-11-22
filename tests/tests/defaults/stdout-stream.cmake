include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Streams headered child stdout to parent stdout by default.")
sr_run(r ARGS "${SR_STDOUT_CMD}")
sr_assert_exit(r 0)
sr_assert_stdout_txt_header(r "CHILDSTDOUT")
sr_assert_stdout_occurrence_count(r "${SR_TEST_CHILD_STDOUT_MARKER}" 1)
sr_assert_stdout_not_contains(r "${SR_TEST_CHILD_STDERR_MARKER}")
sr_assert_stdout_not_contains(r "${SR_TEST_SRDIAG_TXT_PREFIX}")

# Verify that a redirected stdout file receives the original child bytes.
set(expected_raw "${SR_TEST_ROOT}/expected-stdout-raw.bin")
set(redirected_raw "${SR_TEST_ROOT}/redirected-stdout-raw.bin")
sr_write_crlf_terminated_fixture("${expected_raw}" "${SR_TEST_CHILD_STDOUT_MARKER}")

sr_run(redirected OUTPUT_FILE "${redirected_raw}" ARGS
    --stdout-emit-raw stream
    --stderr-emit never
    "${SR_STDOUT_CMD}"
)
sr_assert_exit(redirected 0)
sr_assert_files_equal_bytes("${redirected_raw}" "${expected_raw}")

# Verify that stdout reaches a downstream process through a pipe.
set(piped_raw "${SR_TEST_ROOT}/piped-stdout-raw.bin")

execute_process(
    COMMAND "${SILENTRUNNER_EXE}"
        --stdout-emit-raw stream
        --stderr-emit never
        "${SR_STDOUT_CMD}"
    COMMAND findstr "/C:${SR_TEST_CHILD_STDOUT_MARKER}"
    WORKING_DIRECTORY "${SR_TEST_ROOT}"
    OUTPUT_FILE "${piped_raw}"
    RESULTS_VARIABLE pipe_results
)

if(NOT pipe_results STREQUAL "0;0")
    message(FATAL_ERROR "Stdout pipeline failed: ${pipe_results}")
endif()

sr_assert_file_contains("${piped_raw}" "${SR_TEST_CHILD_STDOUT_MARKER}")
