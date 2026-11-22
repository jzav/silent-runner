include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Preserves quoted child arguments and delegates environment-variable expansion to cmd.exe.")
sr_run(r ARGS "${SR_ECHO_ARGS}" "hello world" second)
sr_assert_exit(r 0)
sr_assert_stdout_contains(r "ARG1=[hello world]")
sr_assert_stdout_contains(r "ARG2=[second]")
sr_run(expanded_argument
    ENV "SR_D4_ARGUMENT=hello world"
    ARGS "${SR_ECHO_ARGS}" "%SR_D4_ARGUMENT%" second
)
sr_assert_exit(expanded_argument 0)
# cmd.exe expands the unquoted reference after SilentRunner builds the command.
# Spaces introduced by expansion split the value into separate arguments.
sr_assert_stdout_contains(expanded_argument "ARG1=[hello]")
sr_assert_stdout_contains(expanded_argument "ARG2=[world]")
sr_assert_stdout_contains(expanded_argument "ARG3=[second]")
