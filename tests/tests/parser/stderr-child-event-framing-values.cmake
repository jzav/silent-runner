include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Accepts all stderr-child event framing spellings and resolves them without modifying stdout framing.")

function(assert_stderr_child_framing expected_framing expected_max_bytes)
    sr_run(r ARGS
        --debug
        --stderr-emit-sr stream
        ${ARGN}
        "${SR_OK}"
    )

    sr_assert_exit(r 0)
    sr_assert_stderr_contains(
        r
        "STDERR_CHILD_EVENT_FRAMING=${expected_framing} STDERR_CHILD_EVENT_NEWLINE_MAX_BYTES=${expected_max_bytes}"
    )

    # The stderr-child option must not accidentally populate stdout framing.
    sr_assert_stderr_contains(
        r
        "STDOUT_EVENT_FRAMING=chunk STDOUT_EVENT_NEWLINE_MAX_BYTES=0"
    )
endfunction()

assert_stderr_child_framing(
    "chunk"
    "0"
    --stderr-child-event-framing chunk
)

assert_stderr_child_framing(
    "lf"
    "524288"
    --stderr-child-event-framing lf
)

assert_stderr_child_framing(
    "lf"
    "524288"
    --stderr-child-event-framing newline
)

assert_stderr_child_framing(
    "crlf"
    "524288"
    --stderr-child-event-framing crlf
)

assert_stderr_child_framing(
    "crlf"
    "524288"
    --STDERR-CHILD-EVENT-FRAMING CrLf
)

assert_stderr_child_framing(
    "lf"
    "524288"
    "--stderr-child-event-framing=NeWlInE"
)
