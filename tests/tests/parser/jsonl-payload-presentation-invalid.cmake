include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Rejects an unknown JSONL payload presentation before the child process is started.")

set(marker "${SR_TEST_ROOT}/child-ran.marker")
set(child_cmd "${SR_TEST_ROOT}/jsonl-presentation-invalid-child.cmd")

file(WRITE
    "${child_cmd}"
    "@echo off\r\n> \"%~dp0child-ran.marker\" echo ran\r\nexit /b 0\r\n"
)

sr_run(r ARGS
    --jsonl-payload-presentation invalid-presentation
    "${child_cmd}"
)

sr_assert_exit(r "${SR_TEST_EXIT_CLI_ERROR}")
sr_assert_stdout_empty(r)
sr_assert_stderr_contains(
    r
    "Invalid value for --jsonl-payload-presentation. Allowed values:"
)
sr_assert_stderr_contains(r "text")
sr_assert_stderr_contains(r "base64")
sr_assert_stderr_contains(r "text+base64")
sr_assert_stderr_contains(r "base64+text")
sr_assert_path_not_exists("${marker}")
