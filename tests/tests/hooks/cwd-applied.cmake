include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Validates --cwd and hook working directory, including one-pass environment expansion.")
file(MAKE_DIRECTORY "${SR_TEST_ROOT}/hook-workdir")
sr_run(r ARGS --cwd hook-workdir --run-on-success hook-cwd.cmd "${SR_OK}")
sr_assert_exit(r 0)
set(result_file "${SR_TEST_ROOT}/hook-cwd.txt")
sr_wait_for_path("${result_file}")
set(expected "${SR_TEST_ROOT}/hook-workdir")
cmake_path(NATIVE_PATH expected NORMALIZE expected_native)
sr_assert_file_contains("${result_file}" "CWD=[${expected_native}]")
# Expand a relative cwd supplied through an environment variable.
sr_run(expanded_cwd ENV "SR_D4_CWD=hook-workdir" ARGS --cwd "%SR_D4_CWD%" "${SR_PRINT_CWD}")
sr_assert_exit(expanded_cwd 0)
sr_assert_stdout_contains(expanded_cwd "${expected_native}")
# A variable introduced by expansion must remain literal, not expand again.
set(literal_cwd "${SR_TEST_ROOT}/%SR_D4_CWD%")
file(MAKE_DIRECTORY "${literal_cwd}")
cmake_path(NATIVE_PATH literal_cwd NORMALIZE literal_cwd_native)
sr_run(nonrecursive_cwd
    ENV "SR_D4_CWD=hook-workdir" "SR_D4_NESTED_CWD=%SR_D4_CWD%"
    ARGS --cwd "%SR_D4_NESTED_CWD%" "${SR_PRINT_CWD}"
)
sr_assert_exit(nonrecursive_cwd 0)
sr_assert_stdout_contains(nonrecursive_cwd "${literal_cwd_native}")
# Undefined and empty path variables are configuration errors.
sr_run(undefined_cwd UNSET_ENV SR_D4_MISSING_CWD ARGS --cwd "%SR_D4_MISSING_CWD%" "${SR_OK}")
sr_assert_exit(undefined_cwd "${SR_TEST_EXIT_CLI_ERROR}")
sr_assert_stdout_not_contains(undefined_cwd "${SR_TEST_CHILD_STDOUT_MARKER}")
sr_run(empty_cwd ENV "SR_D4_EMPTY_CWD=" ARGS --cwd "%SR_D4_EMPTY_CWD%" "${SR_OK}")
sr_assert_exit(empty_cwd "${SR_TEST_EXIT_CLI_ERROR}")
