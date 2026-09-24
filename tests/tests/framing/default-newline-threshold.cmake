include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Applies the default 512 KiB newline-framing threshold at runtime when no explicit newline-max-bytes value is supplied.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-framing-default-threshold")
set(expected_log
    "${log_dir}/${execution_id}_stdout_success.jsonl"
)

set(payload_file "${SR_TEST_ROOT}/default-threshold.bin")
set(child_cmd "${SR_TEST_ROOT}/default-threshold.cmd")

# No delimiter: the default threshold must emit the first 524288 bytes and EOF
# must flush the remaining byte as a second event.
string(REPEAT "A" 524289 payload)
file(WRITE "${payload_file}" "${payload}")

string(SUBSTRING "${payload}" 0 524288 expected_first)
string(SUBSTRING "${payload}" 524288 1 expected_tail)

sr_write_type_emitter_cmd("${child_cmd}" "${payload_file}" stdout)

sr_run(r ARGS
    --id-base "${execution_id}"
    --stdout-dir-jsonl "${log_dir}"
    --stdout-event-framing lf
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
    "${expected_first}"
    "${expected_tail}"
)
