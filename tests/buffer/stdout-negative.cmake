include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Rejects a negative --stdout-max-buffer-bytes value.")
sr_run(r ARGS --stdout-max-buffer-bytes -1 "${SR_OK}")
sr_assert_exit(r "${SR_TEST_EXIT_CLI_ERROR}")
