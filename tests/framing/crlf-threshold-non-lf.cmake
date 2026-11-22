include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Emits at the configured CRLF threshold when a threshold-ending CR is followed by a non-LF byte.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-framing-crlf-threshold-non-lf")
set(expected_log
    "${log_dir}/${execution_id}_stdout_success.jsonl"
)

set(payload_file "${SR_TEST_ROOT}/threshold-non-lf.bin")
set(child_cmd "${SR_TEST_ROOT}/threshold-non-lf.cmd")

string(ASCII 13 cr)

# Exact bytes:
#   41 42 43 0d 58 5a
#
# At threshold 4, ABC<CR> is held for one byte. X proves that the CR is not the
# start of CRLF, so ABC<CR> is emitted at four bytes and X begins the next event.
#
# There is no LF in this fixture, so file(WRITE) cannot perform newline
# translation and the lone CR remains byte-exact.
file(WRITE "${payload_file}" "ABC${cr}XZ")

sr_assert_file_hex(
    "${payload_file}"
    "4142430d585a"
)

sr_write_type_emitter_cmd("${child_cmd}" "${payload_file}" stdout)


sr_run(r ARGS
    --id-base "${execution_id}"
    --stdout-dir-jsonl "${log_dir}"
    --stdout-event-framing crlf
    --stdout-event-newline-max-bytes 4
    --stdout-emit never
    --stderr-emit-sr stream
    "${child_cmd}"
)

sr_assert_exit(r 0)
sr_assert_stdout_empty(r)
sr_assert_directory_file_count("${log_dir}" 1)

sr_assert_jsonl_text_event_sequence(
    "${expected_log}"
    "ChildStdout"
    "ABC${cr}"
    "XZ"
)
