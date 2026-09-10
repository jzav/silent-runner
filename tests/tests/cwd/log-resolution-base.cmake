include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init()
file(MAKE_DIRECTORY "${SR_TEST_ROOT}/childcwd")
set(expected_log "${SR_TEST_ROOT}/logs/ctest-cwd-log_stdout_success.log")
set(wrong_log "${SR_TEST_ROOT}/childcwd/logs/ctest-cwd-log_stdout_success.log")
sr_run(r ARGS
    --cwd childcwd
    --id-base ctest-cwd-log
    --stdout-dir logs
    --stdout-emit never
    "${SR_STDOUT_CMD}"
)
sr_assert_exit(r 0)
sr_assert_path_exists("${expected_log}")
sr_assert_path_not_exists("${wrong_log}")
