include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Preserves and replays child stdout and stderr produced before a timeout in failure emit mode.")
sr_run(r ARGS --timeout-ms 1500 --stdout-emit failure --stderr-emit failure "${SR_SLEEP_OUTPUT}")
sr_assert_exit(r "${SR_TEST_EXIT_TIMEOUT}")
sr_assert_stdout_contains(r "BEFORE_TIMEOUT")
sr_assert_stderr_contains(r "STDERR_BEFORE_TIMEOUT")
# On timeout, failure-only Raw replay must return the already emitted child
# bytes, both from the timeline and from persistent Raw TXT log sources.
set(raw_stdout_expected "${SR_TEST_ROOT}/raw-timeout-stdout-expected.bin")
set(raw_stderr_expected "${SR_TEST_ROOT}/raw-timeout-stderr-expected.bin")
sr_write_crlf_terminated_fixture("${raw_stdout_expected}" "BEFORE_TIMEOUT")
sr_write_crlf_terminated_fixture("${raw_stderr_expected}" "STDERR_BEFORE_TIMEOUT")
foreach(raw_source IN ITEMS timeline txt)
    set(raw_execution_id "ctest-timeout-raw-${raw_source}")
    set(raw_stdout_output "${SR_TEST_ROOT}/timeout-stdout-${raw_source}.bin")
    set(raw_stderr_output "${SR_TEST_ROOT}/timeout-stderr-${raw_source}.bin")
    set(raw_log_dir "${SR_TEST_ROOT}/timeout-logs-${raw_source}")
    set(raw_diag_dir "${SR_TEST_ROOT}/timeout-diag-${raw_source}")
    set(raw_log_options)
    if(raw_source STREQUAL "txt")
        list(APPEND raw_log_options
            --stdout-dir-raw "${raw_log_dir}"
            --stderr-dir-child-raw "${raw_log_dir}"
        )
    endif()
    sr_run(raw
        OUTPUT_FILE "${raw_stdout_output}"
        ERROR_FILE "${raw_stderr_output}"
        ARGS
            --id-base "${raw_execution_id}"
            --timeout-ms 1500
            --stdout-emit-raw failure
            --stderr-emit-child-raw failure
            --stderr-dir-sr "${raw_diag_dir}"
            ${raw_log_options}
            "${SR_SLEEP_OUTPUT}"
    )
    sr_assert_exit(raw "${SR_TEST_EXIT_TIMEOUT}")
    sr_assert_files_equal_bytes("${raw_stdout_output}" "${raw_stdout_expected}")
    sr_assert_files_equal_bytes("${raw_stderr_output}" "${raw_stderr_expected}")
    sr_assert_directory_file_count("${raw_diag_dir}" 1)
    if(raw_source STREQUAL "txt")
        set(raw_stdout_log "${raw_log_dir}/${raw_execution_id}_stdout_raw_failure.log")
        set(raw_stderr_log "${raw_log_dir}/${raw_execution_id}_stderr_child_raw_failure.log")
        sr_assert_files_equal_bytes("${raw_stdout_log}" "${raw_stdout_expected}")
        sr_assert_files_equal_bytes("${raw_stderr_log}" "${raw_stderr_expected}")
        sr_assert_directory_file_count("${raw_log_dir}" 2)
    endif()
endforeach()
