include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Combines a successful execution, success-only log retention, and the success hook.")
set(log_dir "${SR_TEST_ROOT}/logs")
sr_run(r ARGS
    --id-base cross-success
    --stdout-dir "${log_dir}"
    --stdout-dir-keep-log success
    --stdout-emit never
    --run-on-success success-hook.cmd
    "${SR_STDOUT_CMD}"
)
sr_assert_exit(r 0)
sr_assert_path_exists("${log_dir}/cross-success_stdout_success.log")
sr_wait_for_path("${SR_TEST_ROOT}/success.marker")
