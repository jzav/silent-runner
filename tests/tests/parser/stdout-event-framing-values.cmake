include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Accepts all stdout event framing spellings and resolves them to the expected runtime configuration.")

function(assert_stdout_framing expected_framing expected_max_bytes)
    sr_run(r ARGS
        --debug
        --stderr-emit-sr stream
        ${ARGN}
        "${SR_OK}"
    )

    sr_assert_exit(r 0)
    sr_assert_stderr_contains(
        r
        "STDOUT_EVENT_FRAMING=${expected_framing} STDOUT_EVENT_NEWLINE_MAX_BYTES=${expected_max_bytes}"
    )

    # Setting stdout framing must not modify the independent stderr framing.
    sr_assert_stderr_contains(
        r
        "STDERR_CHILD_EVENT_FRAMING=chunk STDERR_CHILD_EVENT_NEWLINE_MAX_BYTES=0"
    )
endfunction()

assert_stdout_framing(
    "chunk"
    "0"
    --stdout-event-framing chunk
)

assert_stdout_framing(
    "lf"
    "524288"
    --stdout-event-framing lf
)

assert_stdout_framing(
    "lf"
    "524288"
    --stdout-event-framing newline
)

assert_stdout_framing(
    "crlf"
    "524288"
    --stdout-event-framing crlf
)

assert_stdout_framing(
    "crlf"
    "524288"
    --STDOUT-EVENT-FRAMING CrLf
)

assert_stdout_framing(
    "lf"
    "524288"
    "--stdout-event-framing=NeWlInE"
)
