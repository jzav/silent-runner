include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Replays a JSONL child payload ending in a comma without a newline in text, dual, and base64 representations.")

# Regression A1, anchored snapshot 2026-09-21_15-02-25.
# Generate the exact bytes locally; echo would append CRLF and hide the bug.
file(WRITE "${SR_TEST_ROOT}/trailing-comma.bin" "tail,")
set(child_cmd "${SR_TEST_ROOT}/trailing-comma.cmd")
file(WRITE "${child_cmd}" "@echo off\r\ntype \"%~dp0trailing-comma.bin\"\r\nexit /b 0\r\n")

foreach(representation IN ITEMS default text text+base64 base64+text base64)
    message(STATUS "JSONL trailing-comma representation: ${representation}")
    string(REPLACE "+" "-" case_name "${representation}")
    set(execution_id "ctest-trailing-comma-${case_name}")
    set(log_dir "${SR_TEST_ROOT}/logs-${case_name}")
    set(expected_log "${log_dir}/${execution_id}_stdout_success.jsonl")
    set(running_log "${log_dir}/${execution_id}_stdout_running.jsonl")
    cmake_path(NATIVE_PATH running_log NORMALIZE running_log_native)

    set(representation_args)
    set(expected_representation "${representation}")
    if(representation STREQUAL "default")
        set(expected_representation "text")
    else()
        list(APPEND representation_args --jsonl-payload-representation "${representation}")
    endif()
    if(representation STREQUAL "base64+text")
        set(expected_representation "text+base64")
    endif()

    # LF framing flushes the unterminated tail as one event at EOF, independent
    # of how the pipe reader splits reads. Its payload must still have no LF.
    sr_run(r ARGS
        --debug
        --id-base "${execution_id}"
        --stdout-dir-jsonl "${log_dir}"
        --stdout-event-framing lf
        --stdout-emit end
        --stderr-emit-sr stream
        ${representation_args}
        "${child_cmd}"
    )
    sr_assert_exit(r 0)
    sr_assert_stderr_contains(r
        "[PARENT-REPLAY] Replay completed with result ok using plan: stdout={target=StdoutParent source=Jsonl path=${running_log_native}}")

    # Parent stdout is headered in this snapshot. Validate its header and then
    # compare the entire remaining payload, catching newline/duplication bugs.
    string(FIND "${r_STDOUT}" "\n" header_end)
    if(header_end LESS 0)
        message(FATAL_ERROR "Missing parent stdout header for ${representation}: [${r_STDOUT}]")
    endif()
    string(SUBSTRING "${r_STDOUT}" 0 ${header_end} parent_header)
    string(FIND "${parent_header}" "[payloadType=CHILDSTDOUT]" header_type)
    string(FIND "${parent_header}" "[payloadByteCount=5]" header_size)
    if(NOT header_type EQUAL 0 OR header_size LESS 0)
        message(FATAL_ERROR "Unexpected parent header for ${representation}: [${parent_header}]")
    endif()
    math(EXPR payload_start "${header_end} + 1")
    string(SUBSTRING "${r_STDOUT}" ${payload_start} -1 parent_payload)
    if(NOT parent_payload STREQUAL "tail,")
        message(FATAL_ERROR "Expected exact parent payload [tail,] for ${representation}, got [${parent_payload}]")
    endif()

    sr_assert_file_not_empty("${expected_log}")
    sr_assert_directory_file_count("${log_dir}" 1)
    file(STRINGS "${expected_log}" records ENCODING UTF-8)
    list(LENGTH records record_count)
    if(NOT record_count EQUAL 1)
        message(FATAL_ERROR "Expected one EOF-flushed JSONL event for ${representation}, got ${record_count}")
    endif()
    list(GET records 0 record)
    foreach(field IN ITEMS payloadType payloadRepresentation payloadText payloadBase64 payloadByteCount payloadDropped)
        string(JSON ${field} GET "${record}" "${field}")
    endforeach()
    string(JSON dropped_type TYPE "${record}" payloadDropped)
    string(JSON byte_count_type TYPE "${record}" payloadByteCount)
    if(NOT payloadType STREQUAL "ChildStdout"
        OR NOT payloadRepresentation STREQUAL expected_representation
        OR NOT payloadByteCount STREQUAL "5"
        OR payloadDropped
        OR NOT dropped_type STREQUAL "BOOLEAN"
        OR NOT byte_count_type STREQUAL "NUMBER")
        message(FATAL_ERROR "Unexpected JSONL metadata for ${representation}: ${record}")
    endif()

    set(expected_text "tail,")
    set(expected_base64 "dGFpbCw=")
    if(expected_representation STREQUAL "text")
        set(expected_base64 "")
    elseif(expected_representation STREQUAL "base64")
        set(expected_text "")
    endif()
    if(NOT payloadText STREQUAL expected_text OR NOT payloadBase64 STREQUAL expected_base64)
        message(FATAL_ERROR "Unexpected JSONL payload fields for ${representation}: ${record}")
    endif()
endforeach()
