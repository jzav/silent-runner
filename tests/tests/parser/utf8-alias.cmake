include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Accepts --utf-8 as an alias of --utf8.")
sr_run(r ARGS --utf-8 "${SR_OK}")
sr_assert_exit(r 0)
