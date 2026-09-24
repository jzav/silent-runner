include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Accepts every JSONL payload representation spelling and proves its canonical representation in generated JSONL.")

function(assert_jsonl_representation case_name expected_representation)
    set(log_dir "${SR_TEST_ROOT}/logs-${case_name}")
    set(execution_id "ctest-jsonl-representation-${case_name}")
    set(expected_log
        "${log_dir}/${execution_id}_stdout_success.jsonl"
    )

    sr_run(r ARGS
        --id-base "${execution_id}"
        --stdout-dir-jsonl "${log_dir}"
        --stdout-event-framing lf
        --stdout-emit never
        ${ARGN}
        "${SR_STDOUT_CMD}"
    )

    sr_assert_exit(r 0)
    sr_assert_file_not_empty("${expected_log}")
    sr_assert_directory_file_count("${log_dir}" 1)

    file(STRINGS "${expected_log}" records ENCODING UTF-8)
    list(LENGTH records record_count)

    if(NOT record_count EQUAL 1)
        message(FATAL_ERROR
            "Expected exactly one stdout JSONL event for ${case_name}, got ${record_count}."
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

    if(NOT payloadType STREQUAL "ChildStdout")
        message(FATAL_ERROR
            "Unexpected payload type for ${case_name}: ${record}"
        )
    endif()

    if(NOT payloadRepresentation STREQUAL "${expected_representation}")
        message(FATAL_ERROR
            "Unexpected canonical payload representation for ${case_name}.\n"
            "Expected: ${expected_representation}\n"
            "Actual:   ${payloadRepresentation}\n"
            "Record:   ${record}"
        )
    endif()

    if(NOT payloadByteCount STREQUAL "15"
        OR payloadDropped
        OR NOT dropped_type STREQUAL "BOOLEAN"
        OR NOT byte_count_type STREQUAL "NUMBER")
        message(FATAL_ERROR
            "Unexpected payload metadata for ${case_name}: ${record}"
        )
    endif()

    set(expected_text "SRTEST_STDOUT\r\n")
    set(expected_base64 "U1JURVNUX1NURE9VVA0K")

    if(expected_representation STREQUAL "text")
        if(NOT payloadText STREQUAL "${expected_text}"
            OR NOT payloadBase64 STREQUAL "")
            message(FATAL_ERROR
                "Unexpected text-only payload for ${case_name}: ${record}"
            )
        endif()
    elseif(expected_representation STREQUAL "base64")
        if(NOT payloadText STREQUAL ""
            OR NOT payloadBase64 STREQUAL "${expected_base64}")
            message(FATAL_ERROR
                "Unexpected base64-only payload for ${case_name}: ${record}"
            )
        endif()
    elseif(expected_representation STREQUAL "text+base64")
        if(NOT payloadText STREQUAL "${expected_text}"
            OR NOT payloadBase64 STREQUAL "${expected_base64}")
            message(FATAL_ERROR
                "Unexpected dual payload for ${case_name}: ${record}"
            )
        endif()
    else()
        message(FATAL_ERROR
            "Test bug: unsupported expected representation ${expected_representation}."
        )
    endif()
endfunction()

assert_jsonl_representation(
    "text"
    "text"
    --jsonl-payload-representation text
)

assert_jsonl_representation(
    "base64"
    "base64"
    --jsonl-payload-representation base64
)

assert_jsonl_representation(
    "text-base64"
    "text+base64"
    --jsonl-payload-representation text+base64
)

assert_jsonl_representation(
    "base64-text"
    "text+base64"
    --jsonl-payload-representation base64+text
)

assert_jsonl_representation(
    "mixed-case"
    "text+base64"
    --JSONL-PAYLOAD-REPRESENTATION TeXt+BaSe64
)

assert_jsonl_representation(
    "equals-form"
    "text+base64"
    "--jsonl-payload-representation=BaSe64+TeXt"
)
