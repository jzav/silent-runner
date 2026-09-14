include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Lets a child that completes before the timeout return normally.")
sr_run(r ARGS --timeout-ms 5000 "${SR_OK}")
sr_assert_exit(r 0)
