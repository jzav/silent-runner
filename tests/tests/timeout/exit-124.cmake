include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init()
sr_run(r ARGS --timeout-ms 100 "${SR_SLEEP}")
sr_assert_exit(r "${SR_TEST_EXIT_TIMEOUT}")
