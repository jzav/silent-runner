include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Validates stdout event newline maximum byte-count boundaries.")

function(assert_stdout_newline_max_accepted value)
    sr_run(r ARGS
        --debug
        --stderr-emit-sr stream
        --stdout-event-framing lf
        --stdout-event-newline-max-bytes "${value}"
        "${SR_OK}"
    )

    sr_assert_exit(r 0)
    sr_assert_stderr_contains(
        r
        "STDOUT_EVENT_FRAMING=lf STDOUT_EVENT_NEWLINE_MAX_BYTES=${value}"
    )
endfunction()

function(assert_stdout_newline_max_rejected value expected_error)
    sr_run(r ARGS
        --stdout-event-framing lf
        --stdout-event-newline-max-bytes "${value}"
        "${SR_OK}"
    )

    sr_assert_exit(r "${SR_TEST_EXIT_CLI_ERROR}")
    sr_assert_stdout_empty(r)
    sr_assert_stderr_contains(r "${expected_error}")
endfunction()

assert_stdout_newline_max_accepted("1")
assert_stdout_newline_max_accepted("18446744073709551615")

assert_stdout_newline_max_rejected(
    "0"
    "Invalid value for --stdout-event-newline-max-bytes: must be greater than 0"
)

assert_stdout_newline_max_rejected(
    "-1"
    "Invalid value for --stdout-event-newline-max-bytes"
)

assert_stdout_newline_max_rejected(
    "not-a-number"
    "Invalid value for --stdout-event-newline-max-bytes"
)

assert_stdout_newline_max_rejected(
    "18446744073709551616"
    "Invalid value for --stdout-event-newline-max-bytes"
)
