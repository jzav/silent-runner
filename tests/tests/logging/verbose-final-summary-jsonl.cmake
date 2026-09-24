include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Writes exactly one final verbose JSONL summary with a non-dropped payload and its correct UTF-8 byte count.")

# Regression A2, anchored snapshot 2026-09-21_15-02-25.
set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-verbose-final-summary")
set(expected_log "${log_dir}/${execution_id}_stderr_sr_success.jsonl")

sr_run(r ARGS
    --verbose
    --id-base "${execution_id}"
    --stderr-dir-sr-jsonl "${log_dir}"
    --jsonl-payload-presentation text
    --stdout-emit never
    "${SR_OK}"
)
sr_assert_exit(r 0)
sr_assert_stdout_empty(r)
sr_assert_file_not_empty("${expected_log}")
sr_assert_directory_file_count("${log_dir}" 1)

# JSON decoding reconstructs the actual payload, including escaped newlines.
# Counting serialized JSON characters would give the wrong byte count.
file(STRINGS "${expected_log}" records ENCODING UTF-8)
set(final_summary_count 0)
foreach(record IN LISTS records)
    string(JSON payload_type GET "${record}" payloadType)
    if(NOT payload_type STREQUAL "SrDiagEvent")
        message(FATAL_ERROR "Unexpected payload type in SR-only JSONL log: ${record}")
    endif()
    string(JSON payload_text GET "${record}" payloadText)
    string(FIND "${payload_text}" "EventSummary=[Final]" final_prefix)
    if(NOT final_prefix EQUAL 0)
        continue()
    endif()

    math(EXPR final_summary_count "${final_summary_count} + 1")
    foreach(field IN ITEMS severity payloadRepresentation payloadBase64 payloadByteCount payloadDropped)
        string(JSON ${field} GET "${record}" "${field}")
    endforeach()
    string(JSON dropped_type TYPE "${record}" payloadDropped)
    string(JSON byte_count_type TYPE "${record}" payloadByteCount)
    if(NOT severity STREQUAL "verbose"
        OR NOT payloadRepresentation STREQUAL "text"
        OR NOT payloadBase64 STREQUAL ""
        OR payloadDropped
        OR NOT dropped_type STREQUAL "BOOLEAN"
        OR NOT byte_count_type STREQUAL "NUMBER")
        message(FATAL_ERROR "Unexpected final summary metadata: ${record}")
    endif()

    # CMake strings contain UTF-8 bytes; string(LENGTH) measures bytes rather
    # than Unicode characters. No trimming or newline normalization here.
    string(LENGTH "${payload_text}" actual_byte_count)
    if(actual_byte_count EQUAL 0 OR NOT payloadByteCount STREQUAL "${actual_byte_count}")
        message(FATAL_ERROR
            "Final verbose summary payloadByteCount mismatch: declared=${payloadByteCount}, actual UTF-8 bytes=${actual_byte_count}\n${record}")
    endif()
endforeach()

if(NOT final_summary_count EQUAL 1)
    message(FATAL_ERROR "Expected exactly one EventSummary=[Final] record, got ${final_summary_count}")
endif()
