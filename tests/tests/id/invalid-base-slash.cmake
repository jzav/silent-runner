include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init()
sr_run(r ARGS --id-base "bad/value" "${SR_OK}")
sr_assert_exit(r "${SR_TEST_EXIT_CLI_ERROR}")
