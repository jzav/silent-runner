include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Treats only an exact CRLF pair as a delimiter under CRLF framing while lone LF and lone CR remain payload bytes.")


set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-framing-crlf-exact")
set(expected_log
    "${log_dir}/${execution_id}_stdout_success.jsonl"
)

set(payload_file "${SR_TEST_ROOT}/crlf-exact.bin")
set(lf_part "${SR_TEST_ROOT}/crlf-exact-lf.bin")
set(lone_cr_part "${SR_TEST_ROOT}/crlf-exact-lone-cr.bin")
set(crlf_part "${SR_TEST_ROOT}/crlf-exact-crlf.bin")
set(tail_part "${SR_TEST_ROOT}/crlf-exact-tail.bin")
set(child_cmd "${SR_TEST_ROOT}/crlf-exact.cmd")

string(ASCII 10 lf)
string(ASCII 13 cr)

# Exact bytes:
#   41 0a 42 0d 43 0d 0a 44
#   A  LF B  CR C  CR LF D
#
# Only CR LF is a delimiter. The earlier LF and CR must stay in the event.
sr_write_lf_terminated_fixture("${lf_part}" "A")
file(WRITE "${lone_cr_part}" "B${cr}")
sr_write_crlf_terminated_fixture("${crlf_part}" "C")
file(WRITE "${tail_part}" "D")

sr_concat_files(
    "${payload_file}"
    "${lf_part}"
    "${lone_cr_part}"
    "${crlf_part}"
    "${tail_part}"
)

sr_assert_file_hex(
    "${payload_file}"
    "410a420d430d0a44"
)

sr_write_type_emitter_cmd("${child_cmd}" "${payload_file}" stdout)


sr_run(r ARGS
    --id-base "${execution_id}"
    --stdout-dir-jsonl "${log_dir}"
    --stdout-event-framing crlf
    --stdout-event-newline-max-bytes 64
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
    "A${lf}B${cr}C${cr}${lf}"
    "D"
)
