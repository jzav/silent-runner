include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Accepts UINT32_MAX as the --timeout-ms value.")
sr_run(r ARGS --timeout-ms 4294967295 "${SR_OK}")
sr_assert_exit(r 0)
