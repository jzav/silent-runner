include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Frames child stderr into one child-only JSONL event per LF-delimited payload.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-framing-stderr-child-lf")
set(expected_log
    "${log_dir}/${execution_id}_stderr_child_success.jsonl"
)

set(payload_file "${SR_TEST_ROOT}/stderr-lf.bin")
set(first_part "${SR_TEST_ROOT}/stderr-lf-first.bin")
set(second_part "${SR_TEST_ROOT}/stderr-lf-second.bin")
set(child_cmd "${SR_TEST_ROOT}/stderr-lf.cmd")

string(ASCII 10 lf)

sr_write_lf_terminated_fixture("${first_part}" "E1")
sr_write_lf_terminated_fixture("${second_part}" "E2")

sr_concat_files(
    "${payload_file}"
    "${first_part}"
    "${second_part}"
)

sr_assert_file_hex(
    "${payload_file}"
    "45310a45320a"
)

sr_write_type_emitter_cmd("${child_cmd}" "${payload_file}" stderr)

sr_run(r ARGS
    --id-base "${execution_id}"
    --stderr-dir-child-jsonl "${log_dir}"
    --stderr-child-event-framing lf
    --stderr-child-event-newline-max-bytes 64
    --stderr-emit-sr stream
    "${child_cmd}"
)

sr_assert_exit(r 0)
sr_assert_stdout_empty(r)
sr_assert_directory_file_count("${log_dir}" 1)

sr_assert_jsonl_text_event_sequence(
    "${expected_log}"
    "ChildStderr"
    "E1${lf}"
    "E2${lf}"
)
