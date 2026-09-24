include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Falls back losslessly to Base64 when a child payload is invalid UTF-8 under text or dual JSONL presentation.")

# Exact invalid UTF-8 bytes:
#   66 6f 80 ff 6f
# Their Base64 representation is Zm+A/28=.
string(ASCII 102 111 128 255 111 invalid_payload)

set(payload_file "${SR_TEST_ROOT}/invalid-utf8.bin")
set(child_cmd "${SR_TEST_ROOT}/invalid-utf8.cmd")

file(WRITE "${payload_file}" "${invalid_payload}")
file(WRITE
    "${child_cmd}"
    "@echo off\r\ntype \"%~dp0invalid-utf8.bin\"\r\nexit /b 0\r\n"
)

file(SIZE "${payload_file}" payload_file_size)
if(NOT payload_file_size EQUAL 5)
    message(FATAL_ERROR
        "Test fixture construction failed: expected 5 bytes, got ${payload_file_size}."
    )
endif()

foreach(presentation IN ITEMS
    text
    text+base64
)
    string(REPLACE "+" "-" case_name "${presentation}")

    set(log_dir "${SR_TEST_ROOT}/logs-${case_name}")
    set(execution_id "ctest-invalid-utf8-${case_name}")
    set(expected_log
        "${log_dir}/${execution_id}_stdout_success.jsonl"
    )

    sr_run(r ARGS
        --id-base "${execution_id}"
        --stdout-dir-jsonl "${log_dir}"
        --stdout-event-framing lf
        --jsonl-payload-presentation "${presentation}"
        --stdout-emit never
        "${child_cmd}"
    )

    sr_assert_exit(r 0)
    sr_assert_stdout_empty(r)
    sr_assert_file_not_empty("${expected_log}")
    sr_assert_directory_file_count("${log_dir}" 1)

    file(STRINGS "${expected_log}" records ENCODING UTF-8)
    list(LENGTH records record_count)

    if(NOT record_count EQUAL 1)
        message(FATAL_ERROR
            "Expected exactly one invalid-UTF-8 JSONL event for ${presentation}, got ${record_count}."
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

    string(JSON dropped_type TYPE "${record}" payloadDropped)
    string(JSON byte_count_type TYPE "${record}" payloadByteCount)

    if(NOT payloadType STREQUAL "ChildStdout"
        OR NOT payloadRepresentation STREQUAL "base64"
        OR NOT payloadText STREQUAL ""
        OR NOT payloadBase64 STREQUAL "Zm+A/28="
        OR NOT payloadByteCount STREQUAL "5"
        OR payloadDropped
        OR NOT dropped_type STREQUAL "BOOLEAN"
        OR NOT byte_count_type STREQUAL "NUMBER")
        message(FATAL_ERROR
            "Invalid UTF-8 was not preserved as exact Base64 under ${presentation}:\n${record}"
        )
    endif()
endforeach()
