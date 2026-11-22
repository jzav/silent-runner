include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Accepts SilentRunner option names case-insensitively.")
sr_run(r ARGS --DeBuG "${SR_OK}")
sr_assert_exit(r 0)
