include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Rejects unknown stdout and stderr-child event framing values with option-specific diagnostics.")

foreach(option IN ITEMS
    --stdout-event-framing
    --stderr-child-event-framing
)
    sr_run(r ARGS
        "${option}" invalid-framing
        "${SR_OK}"
    )

    sr_assert_exit(r "${SR_TEST_EXIT_CLI_ERROR}")
    sr_assert_stdout_empty(r)
    sr_assert_stderr_contains(
        r
        "Invalid value for ${option}. Allowed values:"
    )
    sr_assert_stderr_contains(r "chunk")
    sr_assert_stderr_contains(r "lf")
    sr_assert_stderr_contains(r "newline")
    sr_assert_stderr_contains(r "crlf")
endforeach()
