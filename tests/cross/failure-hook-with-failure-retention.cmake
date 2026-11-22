include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Combines a failed execution, failure-only log retention, and the failure hook.")
set(log_dir "${SR_TEST_ROOT}/logs")
sr_run(r ARGS
    --id-base cross-failure
    --stdout-dir "${log_dir}"
    --stdout-dir-keep-log failure
    --stdout-emit never
    --run-on-failure failure-hook.cmd
    "${SR_FAIL}"
)
sr_assert_exit(r "${SR_TEST_FAIL_CMD_EXIT_CODE}")
sr_assert_path_exists("${log_dir}/cross-failure_stdout_failure.log")
sr_wait_for_path("${SR_TEST_ROOT}/failure.marker")
