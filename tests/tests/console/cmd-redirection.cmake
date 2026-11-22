include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Preserves CMD stdout/stderr redirection and stream merging.")

# Use the actual CMD interpreter to exercise shell redirection operators.
if(DEFINED ENV{ComSpec} AND NOT "$ENV{ComSpec}" STREQUAL "")
    set(cmd_exe "$ENV{ComSpec}")
else()
    set(cmd_exe "C:/Windows/System32/cmd.exe")
endif()

set(stdout_path "${SR_TEST_ROOT}/cmd-stdout.bin")
set(stderr_path "${SR_TEST_ROOT}/cmd-stderr.bin")
set(combined_path "${SR_TEST_ROOT}/cmd-combined.bin")
set(expected_stdout "${SR_TEST_ROOT}/expected-stdout.bin")
set(expected_stderr "${SR_TEST_ROOT}/expected-stderr.bin")

sr_write_crlf_terminated_fixture("${expected_stdout}" "${SR_TEST_CHILD_STDOUT_MARKER}")
sr_write_crlf_terminated_fixture("${expected_stderr}" "${SR_TEST_CHILD_STDERR_MARKER}")

file(TO_NATIVE_PATH "${SILENTRUNNER_EXE}" sr_exe_native)
file(TO_NATIVE_PATH "${SR_BOTH_CMD}" child_native)
file(TO_NATIVE_PATH "${stdout_path}" stdout_native)
file(TO_NATIVE_PATH "${stderr_path}" stderr_native)
file(TO_NATIVE_PATH "${combined_path}" combined_native)

# Keep the CMD operators outside the quoted SilentRunner arguments.
set(batch_path "${SR_TEST_ROOT}/cmd-redirection.cmd")
file(WRITE "${batch_path}"
    "@echo off\r\n"
    "\"${sr_exe_native}\" --stdout-emit-raw stream --stderr-emit-child-raw stream \"${child_native}\" > \"${stdout_native}\" 2> \"${stderr_native}\"\r\n"
    "if errorlevel 1 exit /b 10\r\n"
    "\"${sr_exe_native}\" --stdout-emit-raw stream --stderr-emit-child-raw stream \"${child_native}\" > \"${combined_native}\" 2>&1\r\n"
    "if errorlevel 1 exit /b 11\r\n"
    "exit /b 0\r\n"
)

file(TO_NATIVE_PATH "${batch_path}" batch_native)
execute_process(
    COMMAND "${cmd_exe}" /d /c "${batch_native}"
    WORKING_DIRECTORY "${SR_TEST_ROOT}"
    RESULT_VARIABLE cmd_result
    OUTPUT_VARIABLE cmd_stdout
    ERROR_VARIABLE cmd_stderr
)

if(NOT "${cmd_result}" STREQUAL "0")
    message(FATAL_ERROR
        "CMD redirection script failed (exit=${cmd_result}).\n"
        "stdout: ${cmd_stdout}\n"
        "stderr: ${cmd_stderr}"
    )
endif()

# Independent redirections must preserve each child's bytes exactly.
sr_assert_files_equal_bytes("${stdout_path}" "${expected_stdout}")
sr_assert_files_equal_bytes("${stderr_path}" "${expected_stderr}")

# With 2>&1 both streams must reach the same file; ordering is not assumed.
sr_assert_file_contains("${combined_path}" "${SR_TEST_CHILD_STDOUT_MARKER}")
sr_assert_file_contains("${combined_path}" "${SR_TEST_CHILD_STDERR_MARKER}")
