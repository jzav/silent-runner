include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Runs child commands without a diagnostic channel and supports completely silent execution.")

sr_run(r ARGS --stderr-emit never "${SR_OK}")

sr_assert_exit(r 0)
sr_assert_stdout_contains(r "${SR_TEST_CHILD_STDOUT_MARKER}")
sr_assert_stderr_empty(r)

sr_run(silent_ok ARGS --stdout-emit never --stderr-emit never "${SR_OK}")
sr_assert_exit(silent_ok 0)
sr_assert_stdout_empty(silent_ok)
sr_assert_stderr_empty(silent_ok)

sr_run(silent_fail ARGS --stdout-emit never --stderr-emit never "${SR_FAIL}")
sr_assert_exit(silent_fail "${SR_TEST_FAIL_CMD_EXIT_CODE}")
sr_assert_stdout_empty(silent_fail)
sr_assert_stderr_empty(silent_fail)
