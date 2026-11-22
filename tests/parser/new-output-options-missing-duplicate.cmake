include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Checks missing and duplicate framing, JSONL, and Raw options, plus mutually exclusive Raw stdout emission.")

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
    --stdout-emit-raw
    --stderr-emit-child-raw
    --stdout-dir-raw
    --stderr-dir-child-raw
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
foreach(raw_option IN ITEMS --stdout-emit-raw --stderr-emit-child-raw)
    assert_duplicate(
        "${raw_option}"
        "${raw_option}" stream
        "${raw_option}" end
    )
endforeach()
foreach(raw_option IN ITEMS --stdout-dir-raw --stderr-dir-child-raw)
    assert_duplicate(
        "${raw_option}"
        "${raw_option}" first
        "${raw_option}" second
    )
endforeach()
# A Raw stdout target cannot coexist with a Headered stdout target,
# regardless of argument order or whether one emitter is disabled.
sr_run(raw_first ARGS --stdout-emit-raw never --stdout-emit stream "${SR_OK}")
sr_assert_exit(raw_first "${SR_TEST_EXIT_CLI_ERROR}")
sr_assert_stdout_empty(raw_first)
sr_assert_stderr_contains(raw_first
    "Mutually exclusive options: --stdout-emit and --stdout-emit-raw"
)
sr_run(headered_first ARGS --stdout-emit stream --stdout-emit-raw never "${SR_OK}")
sr_assert_exit(headered_first "${SR_TEST_EXIT_CLI_ERROR}")
sr_assert_stdout_empty(headered_first)
sr_assert_stderr_contains(headered_first
    "Mutually exclusive options: --stdout-emit and --stdout-emit-raw"
)
