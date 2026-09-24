include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Splits child events at byte thresholds even inside a UTF-8 code point and preserves both resulting invalid-UTF-8 events losslessly as Base64.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-framing-utf8-byte-threshold")
set(expected_log
    "${log_dir}/${execution_id}_stdout_success.jsonl"
)

set(payload_file "${SR_TEST_ROOT}/utf8-threshold.bin")
set(child_cmd "${SR_TEST_ROOT}/utf8-threshold.cmd")

# Exact valid UTF-8 input:
#   41 C3 A9 42   ("A", U+00E9, "B")
#
# Threshold 2 deliberately creates:
#   event 1: 41 C3 -> QcM=
#   event 2: A9 42 -> qUI=
#
# Both individual events are invalid UTF-8 even though their concatenation is
# valid UTF-8, so default text presentation must fall back to Base64 per event.
string(ASCII 195 169 utf8_e_acute)
set(payload "A${utf8_e_acute}B")

file(WRITE "${payload_file}" "${payload}")
sr_write_type_emitter_cmd("${child_cmd}" "${payload_file}" stdout)

sr_run(r ARGS
    --id-base "${execution_id}"
    --stdout-dir-jsonl "${log_dir}"
    --stdout-event-framing lf
    --stdout-event-newline-max-bytes 2
    --stdout-emit never
    --stderr-emit-sr stream
    "${child_cmd}"
)

sr_assert_exit(r 0)
sr_assert_stdout_empty(r)
sr_assert_directory_file_count("${log_dir}" 1)
sr_assert_file_not_empty("${expected_log}")

file(STRINGS "${expected_log}" records ENCODING UTF-8)
list(LENGTH records record_count)

if(NOT record_count EQUAL 2)
    message(FATAL_ERROR
        "Expected exactly two threshold-split JSONL events, got ${record_count}."
    )
endif()

set(expected_base64_0 "QcM=")
set(expected_base64_1 "qUI=")

foreach(index RANGE 0 1)
    list(GET records ${index} record)

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

    set(expected_base64 "${expected_base64_${index}}")

    if(NOT payloadType STREQUAL "ChildStdout"
        OR NOT payloadRepresentation STREQUAL "base64"
        OR NOT "${payloadText}" STREQUAL ""
        OR NOT "${payloadBase64}" STREQUAL "${expected_base64}"
        OR NOT payloadByteCount EQUAL 2
        OR payloadDropped
        OR NOT dropped_type STREQUAL "BOOLEAN"
        OR NOT byte_count_type STREQUAL "NUMBER")
        message(FATAL_ERROR
            "Unexpected UTF-8 threshold event ${index}.\n"
            "Expected Base64: ${expected_base64}\n"
            "Record: ${record}"
        )
    endif()
endforeach()
