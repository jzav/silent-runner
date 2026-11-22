include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Rejects combined and child-only stderr sources even when the combined source is explicitly set to never.")
sr_run(r ARGS --stderr-emit never --stderr-emit-child stream "${SR_OK}")
sr_assert_exit(r "${SR_TEST_EXIT_CLI_ERROR}")
