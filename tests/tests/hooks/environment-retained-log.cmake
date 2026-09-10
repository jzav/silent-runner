include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init()
set(log_dir "${SR_TEST_ROOT}/logs")
set(expected_log "${log_dir}/ctest-hook-log_stdout_success.log")
cmake_path(NATIVE_PATH expected_log NORMALIZE expected_log_native)
sr_run(r ARGS
    --id-base ctest-hook-log
    --stdout-dir "${log_dir}"
    --stdout-dir-keep-log always
    --stdout-emit never
    --run-on-success hook-env.cmd
    "${SR_STDOUT_CMD}"
)
sr_assert_exit(r 0)
set(env_file "${SR_TEST_ROOT}/hook-env.txt")
sr_wait_for_path("${env_file}")
sr_assert_file_contains("${env_file}" "STDOUT_LOG=[${expected_log_native}]")
