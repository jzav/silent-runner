include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init()
set(log_dir "${SR_TEST_ROOT}/logs")
set(expected_log "${log_dir}/ctest-timeout_stdout_failure.log")
sr_run(r ARGS
    --id-base ctest-timeout
    --timeout-ms 100
    --stdout-dir "${log_dir}"
    --stdout-dir-keep-log failure
    --stdout-emit never
    "${SR_SLEEP_OUTPUT}"
)
sr_assert_exit(r "${SR_TEST_EXIT_TIMEOUT}")
sr_assert_file_contains("${expected_log}" "BEFORE_TIMEOUT")
