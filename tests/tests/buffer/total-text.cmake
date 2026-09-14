include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Rejects a non-numeric --std-total-max-buffer-bytes value.")
sr_run(r ARGS --std-total-max-buffer-bytes abc "${SR_OK}")
sr_assert_exit(r "${SR_TEST_EXIT_CLI_ERROR}")
