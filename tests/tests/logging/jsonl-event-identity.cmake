include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Validates JSONL child-event identity metadata structurally without assuming globally contiguous eventOrderNo values.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-jsonl-event-identity")
set(expected_log
    "${log_dir}/${execution_id}_stdout_success.jsonl"
)

set(payload_file "${SR_TEST_ROOT}/jsonl-identity-events.bin")
set(first_part "${SR_TEST_ROOT}/jsonl-identity-first.bin")
set(second_part "${SR_TEST_ROOT}/jsonl-identity-second.bin")
set(third_part "${SR_TEST_ROOT}/jsonl-identity-third.bin")
set(child_cmd "${SR_TEST_ROOT}/jsonl-identity-events.cmd")

sr_write_lf_terminated_fixture(
    "${first_part}"
    "N6_JSONL_ONE"
)
sr_write_lf_terminated_fixture(
    "${second_part}"
    "N6_JSONL_TWO"
)
sr_write_lf_terminated_fixture(
    "${third_part}"
    "N6_JSONL_THREE"
)

sr_concat_files(
    "${payload_file}"
    "${first_part}"
    "${second_part}"
    "${third_part}"
)

sr_write_type_emitter_cmd(
    "${child_cmd}"
    "${payload_file}"
    stdout
)

sr_run(r ARGS
    --id-base "${execution_id}"
    --stdout-dir-jsonl "${log_dir}"
    --stdout-event-framing lf
    --stdout-event-newline-max-bytes 64
    --stdout-emit never
    --stderr-emit-sr stream
    "${child_cmd}"
)

sr_assert_exit(r 0)

sr_assert_file_not_empty("${expected_log}")

sr_assert_jsonl_text_event_sequence(
    "${expected_log}"
    "ChildStdout"
    "N6_JSONL_ONE\n"
    "N6_JSONL_TWO\n"
    "N6_JSONL_THREE\n"
)

file(STRINGS
    "${expected_log}"
    records
    ENCODING UTF-8
)

set(matched_count 0)
set(previous_event_order "")

foreach(record IN LISTS records)
    if("${record}" STREQUAL "")
        continue()
    endif()

    string(JSON payload_type GET "${record}" payloadType)

    if(NOT payload_type STREQUAL "ChildStdout")
        continue()
    endif()

    string(JSON timestamp_utc GET "${record}" tsUtc)
    string(JSON phase GET "${record}" phase)
    string(JSON phase_order_no GET "${record}" phaseOrderNo)
    string(JSON event_order_no GET "${record}" eventOrderNo)

    string(JSON timestamp_type TYPE "${record}" tsUtc)
    string(JSON phase_type TYPE "${record}" phase)
    string(JSON phase_order_type TYPE "${record}" phaseOrderNo)
    string(JSON event_order_type TYPE "${record}" eventOrderNo)

    if(NOT timestamp_type STREQUAL "STRING"
        OR NOT phase_type STREQUAL "STRING"
        OR NOT phase_order_type STREQUAL "NUMBER"
        OR NOT event_order_type STREQUAL "NUMBER")
        message(FATAL_ERROR
            "Unexpected JSONL event identity field types.\n"
            "Record: ${record}"
        )
    endif()

    if("${timestamp_utc}" STREQUAL "")
        message(FATAL_ERROR
            "Expected non-empty tsUtc in JSONL child event.\n"
            "Record: ${record}"
        )
    endif()

    if(NOT "${phase}" STREQUAL "runtime")
        message(FATAL_ERROR
            "Expected runtime JSONL child event phase, got: ${phase}\n"
            "Record: ${record}"
        )
    endif()

    if(NOT "${phase_order_no}" EQUAL 2)
        message(FATAL_ERROR
            "Expected runtime phaseOrderNo=2, got: ${phase_order_no}\n"
            "Record: ${record}"
        )
    endif()

    if(NOT "${previous_event_order}" STREQUAL ""
        AND "${previous_event_order}" GREATER_EQUAL "${event_order_no}")
        message(FATAL_ERROR
            "ChildStdout eventOrderNo values are not strictly increasing.\n"
            "Previous: ${previous_event_order}\n"
            "Current:  ${event_order_no}\n"
            "Record: ${record}"
        )
    endif()

    set(previous_event_order "${event_order_no}")
    math(EXPR matched_count "${matched_count} + 1")
endforeach()

if(NOT matched_count EQUAL 3)
    message(FATAL_ERROR
        "Expected exactly three ChildStdout JSONL identity records, got ${matched_count}."
    )
endif()

sr_assert_directory_file_count("${log_dir}" 1)
