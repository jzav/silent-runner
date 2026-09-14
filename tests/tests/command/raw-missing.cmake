include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Rejects raw mode when the command string is missing.")
sr_run(r ARGS -c)
sr_assert_exit(r "${SR_TEST_EXIT_CLI_ERROR}")
