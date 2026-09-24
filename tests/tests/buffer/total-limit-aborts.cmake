include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Aborts a buffered stdout execution with exit 125 when only the shared total buffer limit is exceeded.")

sr_run(r ARGS
    --stdout-emit end
    --std-total-max-buffer-bytes 1
    --stderr-emit-sr stream
    "${SR_SLEEP_OUTPUT}"
)

sr_assert_exit(r "${SR_TEST_EXIT_BUFFER_LIMIT}")

sr_assert_stdout_occurrence_count(
    r
    "[payloadType=CHILDSTDOUT]"
    1
)
sr_assert_stdout_occurrence_count(
    r
    "[payloadDropped=TRUE][payloadByteCount=16]"
    1
)
sr_assert_stdout_not_contains(
    r
    "BEFORE_TIMEOUT"
)

sr_assert_stderr_contains(
    r
    "Fatal runtime stop: Buffer limit exceeded; first_hit=stdout stdout_max=0 stderr_max=0 total_max=1 action=abort"
)

sr_assert_stderr_not_contains(
    r
    "${SR_TEST_CHILD_STDERR_MARKER}"
)
