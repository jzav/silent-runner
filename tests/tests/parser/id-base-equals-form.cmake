include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Accepts the --id-base=value form.")
sr_run(r ARGS --id-base=ctest-equals "${SR_OK}")
sr_assert_exit(r 0)
