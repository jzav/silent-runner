include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Runs scripts with spaces, including a child path expanded by cmd.exe.")
set(dir "${SR_TEST_ROOT}/scripts with spaces")
file(MAKE_DIRECTORY "${dir}")
file(COPY "${SR_OK}" DESTINATION "${dir}")
set(script "${dir}/ok.cmd")
sr_run(r ARGS "${script}")
sr_assert_exit(r 0)
sr_assert_stdout_contains(r "${SR_TEST_CHILD_STDOUT_MARKER}")
# SilentRunner preserves the %VAR% reference in Script/Executable mode.
sr_run(expanded_script
    ENV "SR_D4_SCRIPT_DIR=${dir}"
    ARGS "%SR_D4_SCRIPT_DIR%/ok.cmd"
)
sr_assert_exit(expanded_script 0)
sr_assert_stdout_contains(expanded_script "${SR_TEST_CHILD_STDOUT_MARKER}")
