include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Replays dual text+base64 JSONL through both the child-byte and SilentRunner-diagnostic decoder branches.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-replay-jsonl-dual-end")

set(expected_stdout_log
    "${log_dir}/${execution_id}_stdout_success.jsonl"
)
set(expected_stdout_running_log
    "${log_dir}/${execution_id}_stdout_running.jsonl"
)

set(expected_sr_log
    "${log_dir}/${execution_id}_stderr_sr_success.jsonl"
)
set(expected_sr_running_log
    "${log_dir}/${execution_id}_stderr_sr_running.jsonl"
)

cmake_path(
    NATIVE_PATH expected_stdout_running_log
    NORMALIZE expected_stdout_running_log_native
)
cmake_path(
    NATIVE_PATH expected_sr_running_log
    NORMALIZE expected_sr_running_log_native
)

set(expected_child_payload "N2_DUAL_CHILD")
set(payload_file "${SR_TEST_ROOT}/dual-replay.bin")
set(child_cmd "${SR_TEST_ROOT}/dual-replay.cmd")

file(WRITE "${payload_file}" "${expected_child_payload}")
file(WRITE
    "${child_cmd}"
    "@echo off\r\ntype \"%~dp0dual-replay.bin\"\r\nexit /b 0\r\n"
)

sr_run(r ARGS
    --debug
    --id-base "${execution_id}"
    --stdout-dir-jsonl "${log_dir}"
    --stderr-dir-sr-jsonl "${log_dir}"
    --jsonl-payload-presentation text+base64
    --stdout-event-framing lf
    --stdout-emit end
    --stderr-emit-sr end
    "${child_cmd}"
)

sr_assert_exit(r 0)

sr_assert_stderr_contains(
    r
    "[PARENT-REPLAY] Replay completed with result ok using plan: "
)
sr_assert_stderr_contains(
    r
    "stdout={target=StdoutParent source=Jsonl path=${expected_stdout_running_log_native}}"
)
sr_assert_stderr_contains(
    r
    "stderr={target=StderrSrParent source=Jsonl path=${expected_sr_running_log_native}}"
)

# Child-byte dual decoder branch.
string(FIND "${r_STDOUT}" "\n" header_end)

if(header_end LESS 0)
    message(FATAL_ERROR
        "Missing parent stdout header:\n${r_STDOUT}"
    )
endif()

math(EXPR payload_start "${header_end} + 1")
string(
    SUBSTRING
    "${r_STDOUT}"
    ${payload_start}
    -1
    parent_child_payload
)

if(NOT parent_child_payload STREQUAL "${expected_child_payload}")
    message(FATAL_ERROR
        "Dual child replay mismatch. Expected [${expected_child_payload}], "
        "got [${parent_child_payload}]."
    )
endif()

# SrDiag dual decoder is a separate parser path. Successful stderr replay and
# recovery of a deterministic diagnostic prove that branch consumed the dual
# JSONL representation.
sr_assert_stderr_txt_header(r "SRDIAGEVENT")
sr_assert_stderr_contains(r "fullCmdLine=")

sr_assert_file_not_empty("${expected_stdout_log}")
sr_assert_file_not_empty("${expected_sr_log}")
sr_assert_directory_file_count("${log_dir}" 2)

file(
    STRINGS
    "${expected_stdout_log}"
    stdout_records
    ENCODING UTF-8
)
list(LENGTH stdout_records stdout_record_count)

if(NOT stdout_record_count EQUAL 1)
    message(FATAL_ERROR
        "Expected exactly one child stdout JSONL record, got ${stdout_record_count}."
    )
endif()

list(GET stdout_records 0 stdout_record)

foreach(field IN ITEMS
    payloadType
    payloadRepresentation
    payloadText
    payloadBase64
    payloadByteCount
    payloadDropped
)
    string(JSON stdout_${field} GET "${stdout_record}" "${field}")
endforeach()

if(NOT stdout_payloadType STREQUAL "ChildStdout"
    OR NOT stdout_payloadRepresentation STREQUAL "text+base64"
    OR NOT stdout_payloadText STREQUAL "${expected_child_payload}"
    OR NOT stdout_payloadBase64 STREQUAL
        "TjJfRFVBTF9DSElMRA=="
    OR NOT stdout_payloadByteCount STREQUAL "13"
    OR stdout_payloadDropped)
    message(FATAL_ERROR
        "Unexpected dual child JSONL record:\n${stdout_record}"
    )
endif()

file(
    STRINGS
    "${expected_sr_log}"
    sr_records
    ENCODING UTF-8
)

set(sr_record_count 0)

foreach(record IN LISTS sr_records)
    foreach(field IN ITEMS
        payloadType
        payloadRepresentation
        payloadText
        payloadBase64
        payloadByteCount
        payloadDropped
    )
        string(JSON ${field} GET "${record}" "${field}")
    endforeach()

    if(NOT payloadType STREQUAL "SrDiagEvent"
        OR payloadDropped
        OR NOT payloadRepresentation STREQUAL "text+base64"
        OR payloadText STREQUAL ""
        OR payloadBase64 STREQUAL ""
        OR payloadByteCount LESS_EQUAL 0)
        message(FATAL_ERROR
            "Unexpected dual SrDiagEvent JSONL record:\n${record}"
        )
    endif()

    math(EXPR sr_record_count "${sr_record_count} + 1")
endforeach()

if(sr_record_count LESS 1)
    message(FATAL_ERROR
        "Expected at least one dual SrDiagEvent JSONL record."
    )
endif()
