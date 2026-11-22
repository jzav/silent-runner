include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Executes -c command strings with cmd.exe environment-variable substitution.")
sr_run(r ARGS -c "echo RAW_COMMAND_OK")
sr_assert_exit(r 0)
sr_assert_stdout_contains(r "RAW_COMMAND_OK")
sr_run(expanded_command ENV "SR_D4_RAW_VALUE=RAW_COMMAND_EXPANDED"
    ARGS -c "echo %SR_D4_RAW_VALUE%")
sr_assert_exit(expanded_command 0)
sr_assert_stdout_contains(expanded_command "RAW_COMMAND_EXPANDED")
sr_run(undefined_command UNSET_ENV SR_D4_UNDEFINED_RAW
    ARGS -c "echo BEFORE%SR_D4_UNDEFINED_RAW%AFTER")
sr_assert_exit(undefined_command 0)
# cmd.exe leaves this undefined reference literal in a direct -c command.
sr_assert_stdout_contains(undefined_command "BEFORE%SR_D4_UNDEFINED_RAW%AFTER")
