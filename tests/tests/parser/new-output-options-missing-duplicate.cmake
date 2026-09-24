include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Reports missing values and duplicate assignments for every new framing and JSONL representation option.")

function(assert_missing_value option)
    sr_run(r ARGS "${option}")

    sr_assert_exit(r "${SR_TEST_EXIT_CLI_ERROR}")
    sr_assert_stdout_empty(r)
    sr_assert_stderr_contains(
        r
        "Missing value for ${option}"
    )
endfunction()

function(assert_duplicate option)
    sr_run(r ARGS
        ${ARGN}
        "${SR_OK}"
    )

    sr_assert_exit(r "${SR_TEST_EXIT_CLI_ERROR}")
    sr_assert_stdout_empty(r)
    sr_assert_stderr_contains(
        r
        "Duplicate ${option}"
    )
endfunction()

foreach(option IN ITEMS
    --stdout-event-framing
    --stdout-event-newline-max-bytes
    --stderr-child-event-framing
    --stderr-child-event-newline-max-bytes
    --jsonl-payload-representation
)
    assert_missing_value("${option}")
endforeach()

assert_duplicate(
    "--stdout-event-framing"
    --stdout-event-framing lf
    --stdout-event-framing crlf
)

assert_duplicate(
    "--stdout-event-newline-max-bytes"
    --stdout-event-framing lf
    --stdout-event-newline-max-bytes 1
    --stdout-event-newline-max-bytes 2
)

assert_duplicate(
    "--stderr-child-event-framing"
    --stderr-child-event-framing lf
    --stderr-child-event-framing crlf
)

assert_duplicate(
    "--stderr-child-event-newline-max-bytes"
    --stderr-child-event-framing lf
    --stderr-child-event-newline-max-bytes 1
    --stderr-child-event-newline-max-bytes 2
)

assert_duplicate(
    "--jsonl-payload-representation"
    --jsonl-payload-representation text
    --jsonl-payload-representation base64
)
