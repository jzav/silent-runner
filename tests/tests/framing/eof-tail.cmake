include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Flushes a final unterminated child stdout event at EOF for both LF and CRLF framing.")

set(payload_file "${SR_TEST_ROOT}/eof-tail.bin")
set(child_cmd "${SR_TEST_ROOT}/eof-tail.cmd")

file(WRITE "${payload_file}" "TAIL")
sr_write_type_emitter_cmd("${child_cmd}" "${payload_file}" stdout)

foreach(framing IN ITEMS lf crlf)
    set(log_dir "${SR_TEST_ROOT}/logs-${framing}")
    set(execution_id "ctest-framing-eof-tail-${framing}")
    set(expected_log
        "${log_dir}/${execution_id}_stdout_success.jsonl"
    )

    sr_run(r ARGS
        --id-base "${execution_id}"
        --stdout-dir-jsonl "${log_dir}"
        --stdout-event-framing "${framing}"
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
        "TAIL"
    )
endforeach()
