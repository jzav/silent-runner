include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Requires each newline maximum to use a non-chunk framing mode for the same stream and keeps argument order irrelevant.")

function(assert_requires_framing expected_error)
    sr_run(r ARGS
        ${ARGN}
        "${SR_OK}"
    )

    sr_assert_exit(r "${SR_TEST_EXIT_CLI_ERROR}")
    sr_assert_stdout_empty(r)
    sr_assert_stderr_contains(r "${expected_error}")
endfunction()

set(stdout_requires_error
    "--stdout-event-newline-max-bytes requires --stdout-event-framing to be lf, newline, or crlf"
)

set(stderr_requires_error
    "--stderr-child-event-newline-max-bytes requires --stderr-child-event-framing to be lf, newline, or crlf"
)

# A maximum without an explicit event framing still sees the default chunk mode.
assert_requires_framing(
    "${stdout_requires_error}"
    --stdout-event-newline-max-bytes 7
)

assert_requires_framing(
    "${stderr_requires_error}"
    --stderr-child-event-newline-max-bytes 9
)

# Explicit chunk is equally invalid.
assert_requires_framing(
    "${stdout_requires_error}"
    --stdout-event-framing chunk
    --stdout-event-newline-max-bytes 7
)

assert_requires_framing(
    "${stderr_requires_error}"
    --stderr-child-event-framing chunk
    --stderr-child-event-newline-max-bytes 9
)

# Framing the opposite stream must not satisfy the dependency.
assert_requires_framing(
    "${stdout_requires_error}"
    --stderr-child-event-framing lf
    --stdout-event-newline-max-bytes 7
)

assert_requires_framing(
    "${stderr_requires_error}"
    --stdout-event-framing lf
    --stderr-child-event-newline-max-bytes 9
)

# Valid framing/max pairs resolve identically regardless of CLI order.
sr_run(a ARGS
    --debug
    --stderr-emit-sr stream
    --stdout-event-framing lf
    --stdout-event-newline-max-bytes 7
    --stderr-child-event-framing crlf
    --stderr-child-event-newline-max-bytes 9
    "${SR_OK}"
)

sr_assert_exit(a 0)
sr_assert_stderr_contains(
    a
    "STDOUT_EVENT_FRAMING=lf STDOUT_EVENT_NEWLINE_MAX_BYTES=7"
)
sr_assert_stderr_contains(
    a
    "STDERR_CHILD_EVENT_FRAMING=crlf STDERR_CHILD_EVENT_NEWLINE_MAX_BYTES=9"
)

sr_run(b ARGS
    --debug
    --stderr-emit-sr stream
    --stderr-child-event-newline-max-bytes 9
    --stderr-child-event-framing crlf
    --stdout-event-newline-max-bytes 7
    --stdout-event-framing lf
    "${SR_OK}"
)

sr_assert_exit(b 0)
sr_assert_stderr_contains(
    b
    "STDOUT_EVENT_FRAMING=lf STDOUT_EVENT_NEWLINE_MAX_BYTES=7"
)
sr_assert_stderr_contains(
    b
    "STDERR_CHILD_EVENT_FRAMING=crlf STDERR_CHILD_EVENT_NEWLINE_MAX_BYTES=9"
)
