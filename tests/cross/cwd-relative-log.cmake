include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Resolves relative and environment-expanded log directories independently of --cwd.")
file(MAKE_DIRECTORY "${SR_TEST_ROOT}/childcwd")
sr_run(r ARGS --cwd childcwd --id-base cross-cwd-log --stdout-dir logs --stdout-emit never "${SR_STDOUT_CMD}")
sr_assert_exit(r 0)
sr_assert_path_exists("${SR_TEST_ROOT}/logs/cross-cwd-log_stdout_success.log")
sr_assert_path_not_exists("${SR_TEST_ROOT}/childcwd/logs/cross-cwd-log_stdout_success.log")
# Expand multiple log targets into one directory.
sr_run(expanded_logs
    ENV "SR_D4_LOG_DIR=expanded-logs"
    ARGS --id-base d4-expanded-logs --stdout-dir "%SR_D4_LOG_DIR%"
        --stdout-dir-jsonl "%SR_D4_LOG_DIR%" "${SR_STDOUT_CMD}"
)
sr_assert_exit(expanded_logs 0)
sr_assert_path_exists("${SR_TEST_ROOT}/expanded-logs/d4-expanded-logs_stdout_success.log")
sr_assert_path_exists("${SR_TEST_ROOT}/expanded-logs/d4-expanded-logs_stdout_success.jsonl")
# Percent signs in different original path components must not form a variable.
sr_run(unpaired_percent
    ARGS --id-base d4-percent-components --stdout-dir "part%/tail%" "${SR_STDOUT_CMD}"
)
sr_assert_exit(unpaired_percent 0)
sr_assert_path_exists("${SR_TEST_ROOT}/part%/tail%/d4-percent-components_stdout_success.log")
# Invalid expansion must fail before a child starts or directories are created.
sr_run(undefined_log
    UNSET_ENV SR_D4_MISSING_LOG_DIR
    ARGS --stdout-dir "%SR_D4_MISSING_LOG_DIR%" "${SR_STDOUT_CMD}"
)
sr_assert_exit(undefined_log "${SR_TEST_EXIT_CLI_ERROR}")
sr_assert_stdout_not_contains(undefined_log "${SR_TEST_CHILD_STDOUT_MARKER}")
sr_run(empty_log ENV "SR_D4_EMPTY_LOG_DIR="
    ARGS --stdout-dir "%SR_D4_EMPTY_LOG_DIR%" "${SR_OK}")
sr_assert_exit(empty_log "${SR_TEST_EXIT_CLI_ERROR}")
