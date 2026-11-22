include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Rejects invalid, undefined, and recursively referenced ComSpec values before child startup.")

set(invalid_comspec "${SR_TEST_ROOT}/missing-cmd.exe")
sr_assert_path_not_exists("${invalid_comspec}")

sr_run(r ENV "ComSpec=${invalid_comspec}" ARGS "${SR_OK}")

sr_assert_exit(r "${SR_TEST_EXIT_INTERNAL}")
sr_assert_stdout_not_contains(r "${SR_TEST_CHILD_STDOUT_MARKER}")
# Undefined ComSpec variables are errors, never fallback requests.
sr_run(undefined
    ENV "ComSpec=%SR_D4_MISSING_COMSPEC%"
    UNSET_ENV SR_D4_MISSING_COMSPEC
    ARGS "${SR_OK}"
)
sr_assert_exit(undefined "${SR_TEST_EXIT_INTERNAL}")
sr_assert_stdout_not_contains(undefined "${SR_TEST_CHILD_STDOUT_MARKER}")
# ComSpec expansion must not recursively resolve a second variable.
sr_run(nonrecursive
    ENV "SR_D4_COMSPEC_INNER=${invalid_comspec}"
        "SR_D4_COMSPEC_OUTER=%SR_D4_COMSPEC_INNER%"
        "ComSpec=%SR_D4_COMSPEC_OUTER%"
    ARGS "${SR_OK}"
)
sr_assert_exit(nonrecursive "${SR_TEST_EXIT_INTERNAL}")
sr_assert_stdout_not_contains(nonrecursive "${SR_TEST_CHILD_STDOUT_MARKER}")
# A bad ComSpec must fail before log directory creation.
sr_run(no_log_side_effect
    ENV "ComSpec=${invalid_comspec}"
    ARGS --stdout-dir not-created "${SR_OK}"
)
sr_assert_exit(no_log_side_effect "${SR_TEST_EXIT_INTERNAL}")
sr_assert_path_not_exists("${SR_TEST_ROOT}/not-created")
