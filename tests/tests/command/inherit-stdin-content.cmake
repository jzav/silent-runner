include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Passes parent stdin content to the child only with --inherit-stdin while the default child stdin remains NUL.")

set(input_file "${SR_TEST_ROOT}/stdin-content.txt")
set(child_cmd "${SR_TEST_ROOT}/stdin-reader.cmd")

sr_write_crlf_terminated_fixture(
    "${input_file}"
    "N6_STDIN_CONTENT"
)

file(WRITE
    "${child_cmd}"
    "@echo off\r\n"
    "set \"line=\"\r\n"
    "set /p \"line=\"\r\n"
    "echo STDIN=[%line%]\r\n"
    "exit /b 0\r\n"
)

sr_run(default_case
    INPUT_FILE "${input_file}"
    ARGS
        --stdout-emit stream
        "${child_cmd}"
)

sr_assert_exit(default_case 0)
sr_assert_stdout_contains(
    default_case
    "STDIN=[]"
)
sr_assert_stdout_not_contains(
    default_case
    "N6_STDIN_CONTENT"
)

sr_run(inherit_case
    INPUT_FILE "${input_file}"
    ARGS
        --inherit-stdin
        --stdout-emit stream
        "${child_cmd}"
)

sr_assert_exit(inherit_case 0)
sr_assert_stdout_contains(
    inherit_case
    "STDIN=[N6_STDIN_CONTENT]"
)
