include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Rejects a --stdout-max-buffer-bytes value above UINT64_MAX.")
sr_run(r ARGS --stdout-max-buffer-bytes 18446744073709551616 "${SR_OK}")
sr_assert_exit(r "${SR_TEST_EXIT_CLI_ERROR}")
