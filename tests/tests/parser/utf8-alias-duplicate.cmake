include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Treats --utf8 and --utf-8 as the same option for duplicate detection.")
sr_run(r ARGS --utf8 --utf-8 "${SR_OK}")
sr_assert_exit(r "${SR_TEST_EXIT_CLI_ERROR}")
