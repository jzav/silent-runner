include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Terminates with exit code 254 before starting the child when no SilentRunner diagnostic channel is available.")

sr_run(r ARGS --stderr-emit never "${SR_OK}")

sr_assert_exit(r "${SR_TEST_EXIT_NO_DIAGNOSTIC_CHANNEL}")
sr_assert_stdout_not_contains(r "${SR_TEST_CHILD_STDOUT_MARKER}")
