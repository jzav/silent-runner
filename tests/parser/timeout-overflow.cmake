include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Rejects a --timeout-ms value above the uint32 range.")
sr_run(r ARGS --timeout-ms 4294967296 "${SR_OK}")
sr_assert_exit(r "${SR_TEST_EXIT_CLI_ERROR}")
