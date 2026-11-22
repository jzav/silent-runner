include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Replays an exact unterminated Base64 JSONL child payload at End from the persistent Jsonl source without duplication.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-replay-jsonl-base64-end")
set(expected_log
    "${log_dir}/${execution_id}_stdout_success.jsonl"
)
set(expected_running_log
    "${log_dir}/${execution_id}_stdout_running.jsonl"
)
set(expected_payload "N2_BASE64_REPLAY")

cmake_path(
    NATIVE_PATH expected_running_log
    NORMALIZE expected_running_log_native
)

set(payload_file "${SR_TEST_ROOT}/base64-replay.bin")
set(child_cmd "${SR_TEST_ROOT}/base64-replay.cmd")

file(WRITE "${payload_file}" "${expected_payload}")
file(WRITE
    "${child_cmd}"
    "@echo off\r\ntype \"%~dp0base64-replay.bin\"\r\nexit /b 0\r\n"
)

sr_run(r ARGS
    --debug
    --id-base "${execution_id}"
    --stdout-dir-jsonl "${log_dir}"
    --stdout-event-framing lf
    --jsonl-payload-representation base64
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
    "stdout={target=StdoutParent source=Jsonl path=${expected_running_log_native}}"
)

string(FIND "${r_STDOUT}" "\n" header_end)

if(header_end LESS 0)
    message(FATAL_ERROR
        "Missing parent stdout header:\n${r_STDOUT}"
    )
endif()

string(SUBSTRING "${r_STDOUT}" 0 ${header_end} parent_header)

string(FIND
    "${parent_header}"
    "[payloadType=CHILDSTDOUT]"
    header_type
)
string(FIND
    "${parent_header}"
    "[payloadByteCount=16]"
    header_size
)

if(NOT header_type EQUAL 0 OR header_size LESS 0)
    message(FATAL_ERROR
        "Unexpected parent stdout header:\n${parent_header}"
    )
endif()

math(EXPR payload_start "${header_end} + 1")
string(
    SUBSTRING
    "${r_STDOUT}"
    ${payload_start}
    -1
    parent_payload
)

# Comparing the complete remainder also detects duplicate replay.
if(NOT parent_payload STREQUAL "${expected_payload}")
    message(FATAL_ERROR
        "Expected exact Base64-decoded parent payload "
        "[${expected_payload}], got [${parent_payload}]."
    )
endif()

sr_assert_file_not_empty("${expected_log}")
sr_assert_directory_file_count("${log_dir}" 1)

file(STRINGS "${expected_log}" records ENCODING UTF-8)
list(LENGTH records record_count)

if(NOT record_count EQUAL 1)
    message(FATAL_ERROR
        "Expected exactly one Base64 JSONL event, got ${record_count}."
    )
endif()

list(GET records 0 record)

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

if(NOT payloadType STREQUAL "ChildStdout"
    OR NOT payloadRepresentation STREQUAL "base64"
    OR NOT payloadText STREQUAL ""
    OR NOT payloadBase64 STREQUAL
        "TjJfQkFTRTY0X1JFUExBWQ=="
    OR NOT payloadByteCount STREQUAL "16"
    OR payloadDropped)
    message(FATAL_ERROR
        "Unexpected Base64 JSONL replay source record:\n${record}"
    )
endif()
