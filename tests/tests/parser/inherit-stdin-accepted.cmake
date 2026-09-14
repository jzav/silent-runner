include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Accepts the --inherit-stdin flag.")
sr_run(r ARGS --inherit-stdin "${SR_OK}")
sr_assert_exit(r 0)
