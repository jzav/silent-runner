include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Emits child stdout in end mode when the child succeeds.")
sr_run(r ARGS --stdout-emit end "${SR_STDOUT_CMD}")
sr_assert_exit(r 0)
sr_assert_stdout_contains(r "${SR_TEST_CHILD_STDOUT_MARKER}")
# A silent child produces empty Raw parent streams and empty Raw TXT logs.
# Check both immediate and delayed modes without depending on text capture.
set(raw_quiet_child "${SR_TEST_ROOT}/raw-empty.cmd")
file(WRITE "${raw_quiet_child}" "@echo off\r\nexit /b 0\r\n")
foreach(raw_mode IN ITEMS stream end)
    set(raw_execution_id "ctest-empty-raw-${raw_mode}")
    set(raw_stdout_output "${SR_TEST_ROOT}/empty-stdout-${raw_mode}.bin")
    set(raw_stderr_output "${SR_TEST_ROOT}/empty-stderr-${raw_mode}.bin")
    set(raw_log_dir "${SR_TEST_ROOT}/empty-logs-${raw_mode}")
    set(raw_diag_dir "${SR_TEST_ROOT}/empty-diag-${raw_mode}")
    sr_run(raw
        OUTPUT_FILE "${raw_stdout_output}"
        ERROR_FILE "${raw_stderr_output}"
        ARGS
            --id-base "${raw_execution_id}"
            --stdout-emit-raw "${raw_mode}"
            --stderr-emit-child-raw "${raw_mode}"
            --stdout-dir-raw "${raw_log_dir}"
            --stderr-dir-child-raw "${raw_log_dir}"
            --stderr-dir-sr "${raw_diag_dir}"
            "${raw_quiet_child}"
    )
    sr_assert_exit(raw 0)
    sr_assert_file_hex("${raw_stdout_output}" "")
    sr_assert_file_hex("${raw_stderr_output}" "")
    sr_assert_file_hex("${raw_log_dir}/${raw_execution_id}_stdout_raw_success.log" "")
    sr_assert_file_hex("${raw_log_dir}/${raw_execution_id}_stderr_child_raw_success.log" "")
    sr_assert_directory_file_count("${raw_log_dir}" 2)
    sr_assert_directory_file_count("${raw_diag_dir}" 1)
endforeach()
