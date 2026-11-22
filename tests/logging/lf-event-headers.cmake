include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Writes one parseable CHILDSTDOUT TXT header for every LF-framed child stdout event.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-logging-lf-event-headers")
set(expected_log
    "${log_dir}/${execution_id}_stdout_success.log"
)

set(payload_file "${SR_TEST_ROOT}/logging-lf-events.bin")
set(first_part "${SR_TEST_ROOT}/logging-lf-first.bin")
set(second_part "${SR_TEST_ROOT}/logging-lf-second.bin")
set(child_cmd "${SR_TEST_ROOT}/logging-lf-events.cmd")

string(ASCII 10 lf)

sr_write_lf_terminated_fixture("${first_part}" "N4_LOG_ONE")
sr_write_lf_terminated_fixture("${second_part}" "N4_LOG_TWO")

sr_concat_files(
    "${payload_file}"
    "${first_part}"
    "${second_part}"
)

sr_assert_file_hex(
    "${payload_file}"
    "4e345f4c4f475f4f4e450a4e345f4c4f475f54574f0a"
)

sr_write_type_emitter_cmd(
    "${child_cmd}"
    "${payload_file}"
    stdout
)

sr_run(r ARGS
    --id-base "${execution_id}"
    --stdout-dir "${log_dir}"
    --stdout-event-framing lf
    --stdout-event-newline-max-bytes 64
    --stdout-emit never
    --stderr-emit-sr stream
    "${child_cmd}"
)

sr_assert_exit(r 0)
sr_assert_stdout_empty(r)

sr_assert_file_not_empty("${expected_log}")
sr_assert_file_txt_header("${expected_log}" "CHILDSTDOUT")
sr_assert_file_occurrence_count(
    "${expected_log}"
    "[payloadType=CHILDSTDOUT]"
    2
)
sr_assert_file_occurrence_count(
    "${expected_log}"
    "[payloadByteCount=11]"
    2
)
# Each LF-framed header identifies the execution before its phase.
file(STRINGS "${expected_log}" txt_lines ENCODING UTF-8)
set(checked_headers 0)
foreach(txt_line IN LISTS txt_lines)
    string(FIND "${txt_line}" "[payloadType=CHILDSTDOUT]" payload_pos)
    if(payload_pos EQUAL -1)
        continue()
    endif()
    string(FIND "${txt_line}" "[executionId=${execution_id}]" id_pos)
    string(FIND "${txt_line}" "[phase=RUNTIME]" phase_pos)
    if(id_pos EQUAL -1 OR phase_pos EQUAL -1 OR NOT id_pos LESS phase_pos)
        message(FATAL_ERROR "Invalid TXT execution identity header: ${txt_line}")
    endif()
    math(EXPR checked_headers "${checked_headers} + 1")
endforeach()
if(NOT checked_headers EQUAL 2)
    message(FATAL_ERROR "Expected two TXT execution identity headers, got ${checked_headers}.")
endif()
sr_assert_file_occurrence_count(
    "${expected_log}"
    "N4_LOG_ONE"
    1
)
sr_assert_file_occurrence_count(
    "${expected_log}"
    "N4_LOG_TWO"
    1
)

sr_assert_directory_file_count("${log_dir}" 1)
