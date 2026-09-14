include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Returns exit code 255 without starting the child when inherited ComSpec points to a nonexistent executable, instead of using the fallback.")

set(invalid_comspec "${SR_TEST_ROOT}/missing-cmd.exe")
sr_assert_path_not_exists("${invalid_comspec}")

sr_run(r ENV "ComSpec=${invalid_comspec}" ARGS "${SR_OK}")

sr_assert_exit(r "${SR_TEST_EXIT_INTERNAL}")
sr_assert_stdout_not_contains(r "${SR_TEST_CHILD_STDOUT_MARKER}")
