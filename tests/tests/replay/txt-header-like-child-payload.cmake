include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Keeps a header-like LF line inside one CRLF-framed TXT child event as payload and replays the event byte-exactly.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-replay-txt-header-like-child-payload")
set(expected_log
    "${log_dir}/${execution_id}_stdout_success.log"
)
set(expected_running_log
    "${log_dir}/${execution_id}_stdout_running.log"
)

cmake_path(
    NATIVE_PATH expected_running_log
    NORMALIZE expected_running_log_native
)

set(payload_file "${SR_TEST_ROOT}/header-like-payload.bin")
set(fake_header_part "${SR_TEST_ROOT}/header-like-prefix.bin")
set(tail_part "${SR_TEST_ROOT}/header-like-tail.bin")
set(child_cmd "${SR_TEST_ROOT}/header-like-payload.cmd")
set(parent_stdout_file "${SR_TEST_ROOT}/parent-stdout.bin")

sr_write_lf_terminated_fixture(
    "${fake_header_part}"
    "[payloadType=CHILDSTDOUT] [tsUtc=2000-01-01_00-00-00Z] [phase=RUNTIME][phaseOrderNo=1][eventOrderNo=999] [payloadDropped=FALSE][payloadByteCount=1] [parsingToken=deadbeef]"
)

sr_write_crlf_terminated_fixture(
    "${tail_part}"
    "N4_HEADER_LIKE_TAIL"
)

sr_concat_files(
    "${payload_file}"
    "${fake_header_part}"
    "${tail_part}"
)

file(SIZE "${payload_file}" payload_size)
if(NOT payload_size EQUAL 193)
    message(FATAL_ERROR
        "Header-like payload fixture construction failed: expected 193 bytes, got ${payload_size}."
    )
endif()

sr_write_type_emitter_cmd(
    "${child_cmd}"
    "${payload_file}"
    stdout
)

sr_run(
    r
    OUTPUT_FILE "${parent_stdout_file}"
    ARGS
        --debug
        --id-base "${execution_id}"
        --stdout-dir "${log_dir}"
        --stdout-event-framing crlf
        --stdout-event-newline-max-bytes 4096
        --stdout-emit end
        --stderr-emit-sr stream
        "${child_cmd}"
)

sr_assert_exit(r 0)

sr_assert_stderr_contains(
    r
    "[PARENT-REPLAY] Replay completed with result ok using plan: "
)
sr_assert_stderr_contains(
    r
    "stdout={target=StdoutParent source=Txt path=${expected_running_log_native}}"
)

sr_assert_single_txt_output_payload_equals_file(
    "${expected_log}"
    "${payload_file}"
    "CHILDSTDOUT"
)

sr_assert_single_txt_output_payload_equals_file(
    "${parent_stdout_file}"
    "${payload_file}"
    "CHILDSTDOUT"
)

sr_assert_file_occurrence_count(
    "${expected_log}"
    "[payloadType=CHILDSTDOUT]"
    2
)
sr_assert_file_occurrence_count(
    "${parent_stdout_file}"
    "[payloadType=CHILDSTDOUT]"
    2
)

sr_assert_directory_file_count("${log_dir}" 1)
