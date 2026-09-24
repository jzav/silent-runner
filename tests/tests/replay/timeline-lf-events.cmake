include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Preserves distinct increasing child eventOrderNo identities from LF-framed TXT logging through TXT parent replay.")

function(extract_stdout_event_orders text expected_count context out_var)
    string(REPLACE "\n" ";" lines "${text}")

    set(headers)

    foreach(line IN LISTS lines)
        string(FIND
            "${line}"
            "[payloadType=CHILDSTDOUT]"
            payload_type_position
        )

        if(payload_type_position EQUAL 0)
            list(APPEND headers "${line}")
        endif()
    endforeach()

    list(LENGTH headers header_count)
    if(NOT header_count EQUAL expected_count)
        message(FATAL_ERROR
            "Unexpected CHILDSTDOUT header count in ${context}.\n"
            "Expected: ${expected_count}\n"
            "Actual:   ${header_count}"
        )
    endif()

    set(orders)
    set(previous_order "")

    foreach(header IN LISTS headers)
        string(FIND
            "${header}"
            "[payloadByteCount=10]"
            byte_count_position
        )

        if(byte_count_position LESS 0)
            message(FATAL_ERROR
                "Unexpected LF event byte count in ${context}.\n"
                "Header: ${header}"
            )
        endif()

        string(
            REGEX MATCH
            "\\[eventOrderNo=([0-9]+)\\]"
            order_field
            "${header}"
        )

        if(order_field STREQUAL "")
            message(FATAL_ERROR
                "Missing eventOrderNo in ${context}.\n"
                "Header: ${header}"
            )
        endif()

        set(event_order "${CMAKE_MATCH_1}")

        if(NOT previous_order STREQUAL ""
            AND previous_order GREATER_EQUAL event_order)
            message(FATAL_ERROR
                "CHILDSTDOUT eventOrderNo values are not strictly increasing in ${context}.\n"
                "Previous: ${previous_order}\n"
                "Current:  ${event_order}"
            )
        endif()

        list(APPEND orders "${event_order}")
        set(previous_order "${event_order}")
    endforeach()

    set(${out_var} "${orders}" PARENT_SCOPE)
endfunction()

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-replay-timeline-lf-events")
set(expected_log
    "${log_dir}/${execution_id}_stdout_success.log"
)
set(expected_running_log
    "${log_dir}/${execution_id}_stdout_running.log"
)

cmake_path(
    NATIVE_PATH expected_running_log
    NORMALIZE expected_running_log_native
)

set(payload_file "${SR_TEST_ROOT}/timeline-events.bin")
set(first_part "${SR_TEST_ROOT}/timeline-first.bin")
set(second_part "${SR_TEST_ROOT}/timeline-second.bin")
set(third_part "${SR_TEST_ROOT}/timeline-third.bin")
set(child_cmd "${SR_TEST_ROOT}/timeline-events.cmd")

sr_write_lf_terminated_fixture("${first_part}" "N4_TL_ONE")
sr_write_lf_terminated_fixture("${second_part}" "N4_TL_TWO")
sr_write_lf_terminated_fixture("${third_part}" "N4_TL_TRI")

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
    --debug
    --id-base "${execution_id}"
    --stdout-dir "${log_dir}"
    --stdout-event-framing lf
    --stdout-event-newline-max-bytes 64
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
    "stdout={target=StdoutParent source=Txt path=${expected_running_log_native}}"
)

sr_assert_file_not_empty("${expected_log}")

file(READ "${expected_log}" log_text)

extract_stdout_event_orders(
    "${log_text}"
    3
    "persistent TXT log"
    log_event_orders
)
extract_stdout_event_orders(
    "${r_STDOUT}"
    3
    "parent TXT replay"
    replay_event_orders
)

if(NOT "${log_event_orders}" STREQUAL "${replay_event_orders}")
    message(FATAL_ERROR
        "TXT replay did not preserve CHILDSTDOUT event identities.\n"
        "Persistent log eventOrderNo values: ${log_event_orders}\n"
        "Parent replay eventOrderNo values: ${replay_event_orders}"
    )
endif()

foreach(marker IN ITEMS
    N4_TL_ONE
    N4_TL_TWO
    N4_TL_TRI
)
    sr_assert_file_occurrence_count(
        "${expected_log}"
        "${marker}"
        1
    )
    sr_assert_stdout_occurrence_count(
        r
        "${marker}"
        1
    )
endforeach()

sr_assert_directory_file_count("${log_dir}" 1)
