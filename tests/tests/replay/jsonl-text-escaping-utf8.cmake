include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Preserves JSON escaping, CR/LF, tab, backslash, quote, and multibyte UTF-8 through JSONL serialization, parsing, replay, and parent emission.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-jsonl-text-escaping-utf8")
set(expected_log
    "${log_dir}/${execution_id}_stdout_success.jsonl"
)
set(expected_running_log
    "${log_dir}/${execution_id}_stdout_running.jsonl"
)

cmake_path(
    NATIVE_PATH expected_running_log
    NORMALIZE expected_running_log_native
)

# Construct U+00E9 as its exact UTF-8 byte sequence C3 A9 rather than relying
# on the source file's encoding.
string(ASCII 195 169 utf8_e_acute)

set(expected_payload
    "quote:\" backslash:\\ tab:\t utf8:${utf8_e_acute}\r\n"
)
set(fixture_payload
    "quote:\" backslash:\\ tab:\t utf8:${utf8_e_acute}\n"
)

set(payload_file "${SR_TEST_ROOT}/escaping-utf8.bin")
set(child_cmd "${SR_TEST_ROOT}/escaping-utf8.cmd")
set(parent_stdout_file "${SR_TEST_ROOT}/parent-stdout.bin")

file(WRITE "${payload_file}" "${fixture_payload}")
file(WRITE
    "${child_cmd}"
    "@echo off\r\ntype \"%~dp0escaping-utf8.bin\"\r\nexit /b 0\r\n"
)

file(SIZE "${payload_file}" payload_file_size)
if(NOT payload_file_size EQUAL 35)
    message(FATAL_ERROR
        "Test fixture construction failed: expected 35 bytes, got ${payload_file_size}."
    )
endif()

sr_run(
    r
    OUTPUT_FILE "${parent_stdout_file}"
    ARGS
        --debug
        --id-base "${execution_id}"
        --stdout-dir-jsonl "${log_dir}"
        --stdout-event-framing crlf
        --jsonl-payload-presentation text
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

# Parent replay emits one ASCII TXT framing header followed by the reconstructed
# child bytes. Capture stdout to a file so CRLF is not normalized by
# execute_process(OUTPUT_VARIABLE).
sr_assert_file_not_empty("${parent_stdout_file}")

file(READ "${parent_stdout_file}" parent_stdout_text)

string(FIND "${parent_stdout_text}" "\n" header_end)

if(header_end LESS 0)
    message(FATAL_ERROR
        "Missing parent stdout header."
    )
endif()

string(
    SUBSTRING
    "${parent_stdout_text}"
    0
    ${header_end}
    parent_header
)

string(FIND
    "${parent_header}"
    "[payloadType=CHILDSTDOUT]"
    header_type
)
string(FIND
    "${parent_header}"
    "[payloadByteCount=35]"
    header_size
)

if(NOT header_type EQUAL 0 OR header_size LESS 0)
    message(FATAL_ERROR
        "Unexpected parent stdout header:\n${parent_header}"
    )
endif()

# Compare the replayed payload as raw hexadecimal bytes. The header is ASCII,
# so its CMake string length is also its byte length. Skip that header plus its
# terminating LF and compare the complete remainder with the original fixture.
file(READ "${parent_stdout_file}" parent_stdout_hex HEX)
file(READ "${payload_file}" expected_payload_hex HEX)

string(LENGTH "${parent_header}" parent_header_byte_count)
math(
    EXPR
    payload_hex_start
    "(${parent_header_byte_count} + 1) * 2"
)

string(
    SUBSTRING
    "${parent_stdout_hex}"
    ${payload_hex_start}
    -1
    parent_payload_hex
)

if(NOT parent_payload_hex STREQUAL expected_payload_hex)
    message(FATAL_ERROR
        "JSONL text replay did not preserve the exact escaped/UTF-8 payload bytes.\n"
        "Expected hex: ${expected_payload_hex}\n"
        "Actual hex:   ${parent_payload_hex}"
    )
endif()

sr_assert_file_not_empty("${expected_log}")
sr_assert_directory_file_count("${log_dir}" 1)

file(STRINGS "${expected_log}" records ENCODING UTF-8)
list(LENGTH records record_count)

if(NOT record_count EQUAL 1)
    message(FATAL_ERROR
        "Expected exactly one JSONL event, got ${record_count}."
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
    OR NOT payloadRepresentation STREQUAL "text"
    OR NOT payloadText STREQUAL "${expected_payload}"
    OR NOT payloadBase64 STREQUAL ""
    OR NOT payloadByteCount STREQUAL "35"
    OR payloadDropped)
    message(FATAL_ERROR
        "Unexpected serialized escaped/UTF-8 JSONL payload:\n${record}"
    )
endif()
