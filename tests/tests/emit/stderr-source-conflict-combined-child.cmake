include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Rejects simultaneous combined and child-only stderr parent emission sources.")
sr_run(r ARGS --stderr-emit stream --stderr-emit-child stream "${SR_OK}")
sr_assert_exit(r "${SR_TEST_EXIT_CLI_ERROR}")
