include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Accepts UINT64_MAX for --stdout-max-buffer-bytes.")
sr_run(r ARGS --stdout-max-buffer-bytes 18446744073709551615 "${SR_OK}")
sr_assert_exit(r 0)
