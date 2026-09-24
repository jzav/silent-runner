include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Emits one parseable CHILDSTDOUT TXT header for every LF-framed child stdout event.")

set(payload_file "${SR_TEST_ROOT}/emit-lf-events.bin")
set(first_part "${SR_TEST_ROOT}/emit-lf-first.bin")
set(second_part "${SR_TEST_ROOT}/emit-lf-second.bin")
set(child_cmd "${SR_TEST_ROOT}/emit-lf-events.cmd")

string(ASCII 10 lf)

sr_write_lf_terminated_fixture("${first_part}" "N4_EMIT_ONE")
sr_write_lf_terminated_fixture("${second_part}" "N4_EMIT_TWO")

sr_concat_files(
    "${payload_file}"
    "${first_part}"
    "${second_part}"
)

sr_assert_file_hex(
    "${payload_file}"
    "4e345f454d49545f4f4e450a4e345f454d49545f54574f0a"
)

sr_write_type_emitter_cmd(
    "${child_cmd}"
    "${payload_file}"
    stdout
)

sr_run(r ARGS
    --stdout-event-framing lf
    --stdout-event-newline-max-bytes 64
    --stdout-emit stream
    --stderr-emit-sr stream
    "${child_cmd}"
)

sr_assert_exit(r 0)
sr_assert_stdout_txt_header(r "CHILDSTDOUT")
sr_assert_stdout_occurrence_count(
    r
    "[payloadType=CHILDSTDOUT]"
    2
)
sr_assert_stdout_occurrence_count(
    r
    "[payloadByteCount=12]"
    2
)
sr_assert_stdout_occurrence_count(r "N4_EMIT_ONE" 1)
sr_assert_stdout_occurrence_count(r "N4_EMIT_TWO" 1)

sr_assert_stderr_not_contains(r "N4_EMIT_ONE")
sr_assert_stderr_not_contains(r "N4_EMIT_TWO")
