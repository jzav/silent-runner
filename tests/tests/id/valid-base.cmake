include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init()
sr_run(r ARGS --id-base "abc-DEF_123." "${SR_OK}")
sr_assert_exit(r 0)

