include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Rejects extra arguments after the single raw command string.")
sr_run(r ARGS -c "echo FIRST" unexpected-extra-argv)
sr_assert_exit(r "${SR_TEST_EXIT_CLI_ERROR}")
