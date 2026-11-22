include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Runs a relative failure hook after a failed child execution and rejects invalid ComSpec before hook launch.")

sr_run(r ARGS --run-on-failure failure-hook.cmd "${SR_FAIL}")
sr_assert_exit(r "${SR_TEST_FAIL_CMD_EXIT_CODE}")
set(marker "${SR_TEST_ROOT}/failure.marker")
sr_wait_for_path("${marker}")

file(REMOVE "${marker}")
# Invalid ComSpec fails during Prepare, before child or hook launch.
sr_run(
    invalid_comspec
    ENV "ComSpec=${SR_TEST_ROOT}/missing-comspec.exe"
    ARGS --run-on-failure failure-hook.cmd "${SR_OK}"
)
sr_assert_exit(invalid_comspec "${SR_TEST_EXIT_INTERNAL}")
sr_assert_stdout_not_contains(invalid_comspec "${SR_TEST_CHILD_STDOUT_MARKER}")
sr_assert_path_not_exists("${marker}")
# An expanded failure hook must still run for a nonzero child exit code.
sr_run(expanded_failure_hook ENV "SR_D4_FAILURE_HOOK=failure-hook.cmd"
    ARGS --run-on-failure "%SR_D4_FAILURE_HOOK%" "${SR_FAIL}")
sr_assert_exit(expanded_failure_hook "${SR_TEST_FAIL_CMD_EXIT_CODE}")
sr_wait_for_path("${marker}")
