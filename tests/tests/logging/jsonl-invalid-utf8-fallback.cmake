include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Falls back losslessly to Base64 when a child payload is invalid UTF-8 under text or dual JSONL representation.")

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

foreach(representation IN ITEMS
    text
    text+base64
)
    string(REPLACE "+" "-" case_name "${representation}")

    set(log_dir "${SR_TEST_ROOT}/logs-${case_name}")
    set(execution_id "ctest-invalid-utf8-${case_name}")
    set(expected_log
        "${log_dir}/${execution_id}_stdout_success.jsonl"
    )

    sr_run(r ARGS
        --id-base "${execution_id}"
        --stdout-dir-jsonl "${log_dir}"
        --stdout-event-framing lf
        --jsonl-payload-representation "${representation}"
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
            "Expected exactly one invalid-UTF-8 JSONL event for ${representation}, got ${record_count}."
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
            "Invalid UTF-8 was not preserved as exact Base64 under ${representation}:\n${record}"
        )
    endif()
endforeach()

# Raw presentation must not decode or replace invalid UTF-8 bytes, in either
# parent channel or either child-only Raw TXT log target.
sr_assert_file_hex("${payload_file}" "666f80ff6f")
foreach(raw_stream IN ITEMS stdout stderr)
    set(raw_log_dir "${SR_TEST_ROOT}/raw-${raw_stream}")
    set(raw_diag_dir "${SR_TEST_ROOT}/raw-diag-${raw_stream}")
    set(raw_execution_id "ctest-raw-invalid-utf8-${raw_stream}")
    set(raw_child_cmd "${SR_TEST_ROOT}/raw-invalid-utf8-${raw_stream}.cmd")
    set(raw_parent_file "${SR_TEST_ROOT}/raw-parent-${raw_stream}.bin")
    sr_write_type_emitter_cmd("${raw_child_cmd}" "${payload_file}" "${raw_stream}")

    if(raw_stream STREQUAL "stdout")
        set(raw_parent_file_option OUTPUT_FILE)
        set(raw_log
            "${raw_log_dir}/${raw_execution_id}_stdout_raw_success.log"
        )
        set(raw_options
            --stdout-emit-raw stream
            --stdout-dir-raw "${raw_log_dir}"
            --stderr-emit-sr stream
        )
    else()
        set(raw_parent_file_option ERROR_FILE)
        set(raw_log
            "${raw_log_dir}/${raw_execution_id}_stderr_child_raw_success.log"
        )
        set(raw_options
            --stdout-emit never
            --stderr-emit-child-raw stream
            --stderr-dir-child-raw "${raw_log_dir}"
            --stderr-dir-sr "${raw_diag_dir}"
        )
    endif()

    sr_run(raw ${raw_parent_file_option} "${raw_parent_file}" ARGS
        --id-base "${raw_execution_id}"
        ${raw_options}
        "${raw_child_cmd}"
    )
    sr_assert_exit(raw 0)
    sr_assert_files_equal_bytes("${raw_parent_file}" "${payload_file}")
    sr_assert_files_equal_bytes("${raw_log}" "${payload_file}")
    sr_assert_directory_file_count("${raw_log_dir}" 1)
    if(raw_stream STREQUAL "stderr")
        sr_assert_stdout_empty(raw)
        sr_assert_directory_file_count("${raw_diag_dir}" 1)
    endif()
endforeach()
