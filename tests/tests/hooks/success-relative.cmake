include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Runs relative and expanded success hooks and validates both hook paths before execution.")
sr_run(r ARGS --run-on-success success-hook.cmd "${SR_OK}")
sr_assert_exit(r 0)
set(marker "${SR_TEST_ROOT}/success.marker")
sr_wait_for_path("${marker}")
# Expand the selected success-hook path during Prepare.
file(REMOVE "${marker}")
sr_run(expanded_hook ENV "SR_D4_HOOK=success-hook.cmd"
    ARGS --run-on-success "%SR_D4_HOOK%" "${SR_OK}")
sr_assert_exit(expanded_hook 0)
sr_wait_for_path("${marker}")
# Both hook paths must validate, even when the child would succeed.
file(REMOVE "${marker}")
sr_run(unselected_undefined_hook
    UNSET_ENV SR_D4_MISSING_HOOK
    ARGS --run-on-success success-hook.cmd --run-on-failure "%SR_D4_MISSING_HOOK%" "${SR_OK}"
)
sr_assert_exit(unselected_undefined_hook "${SR_TEST_EXIT_CLI_ERROR}")
sr_assert_path_not_exists("${marker}")
# Nested variables are not expanded during Prepare.
sr_run(nonrecursive_hook
    ENV "SR_D4_HOOK=success-hook.cmd" "SR_D4_NESTED_HOOK=%SR_D4_HOOK%"
    ARGS --run-on-success "%SR_D4_NESTED_HOOK%" "${SR_OK}"
)
sr_assert_exit(nonrecursive_hook "${SR_TEST_EXIT_CLI_ERROR}")
sr_run(empty_hook ENV "SR_D4_EMPTY_HOOK="
    ARGS --run-on-success "%SR_D4_EMPTY_HOOK%" "${SR_OK}")
sr_assert_exit(empty_hook "${SR_TEST_EXIT_CLI_ERROR}")
