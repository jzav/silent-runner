include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Frames child stdout into one JSONL event per LF-delimited payload.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-framing-stdout-lf")
set(expected_log
    "${log_dir}/${execution_id}_stdout_success.jsonl"
)

set(payload_file "${SR_TEST_ROOT}/stdout-lf.bin")
set(first_part "${SR_TEST_ROOT}/stdout-lf-first.bin")
set(second_part "${SR_TEST_ROOT}/stdout-lf-second.bin")
set(child_cmd "${SR_TEST_ROOT}/stdout-lf.cmd")

string(ASCII 10 lf)

sr_write_lf_terminated_fixture("${first_part}" "A")
sr_write_lf_terminated_fixture("${second_part}" "B")

sr_concat_files(
    "${payload_file}"
    "${first_part}"
    "${second_part}"
)

sr_assert_file_hex(
    "${payload_file}"
    "410a420a"
)

sr_write_type_emitter_cmd("${child_cmd}" "${payload_file}" stdout)



sr_run(r ARGS
    --id-base "${execution_id}"
    --stdout-dir-jsonl "${log_dir}"
    --stdout-event-framing lf
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
    "A${lf}"
    "B${lf}"
)
