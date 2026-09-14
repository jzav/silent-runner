include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Rejects an invalid question-mark character in --stderr-dir-child.")
sr_run(r ARGS --stderr-dir-child "bad?path" "${SR_OK}")
sr_assert_exit(r "${SR_TEST_EXIT_CLI_ERROR}")
