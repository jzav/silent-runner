include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Allows one byte beyond the CRLF newline threshold when the threshold byte is CR and the next byte is LF.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-framing-crlf-threshold-extra")
set(expected_log
    "${log_dir}/${execution_id}_stdout_success.jsonl"
)

set(payload_file "${SR_TEST_ROOT}/threshold-extra.bin")
set(crlf_part "${SR_TEST_ROOT}/threshold-extra-crlf.bin")
set(tail_part "${SR_TEST_ROOT}/threshold-extra-tail.bin")
set(child_cmd "${SR_TEST_ROOT}/threshold-extra.cmd")

string(ASCII 10 lf)
string(ASCII 13 cr)

# Exact bytes:
#   41 42 43 0d 0a 5a
#
# At threshold 4, ABC<CR> is held until the following byte resolves whether the
# CR begins a delimiter. LF completes CRLF, so the event is five bytes.
sr_write_crlf_terminated_fixture("${crlf_part}" "ABC")
file(WRITE "${tail_part}" "Z")

sr_concat_files(
    "${payload_file}"
    "${crlf_part}"
    "${tail_part}"
)

sr_assert_file_hex(
    "${payload_file}"
    "4142430d0a5a"
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
    "ABC${cr}${lf}"
    "Z"
)
