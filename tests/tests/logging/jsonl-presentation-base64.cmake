include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Writes explicit Base64 JSONL payloads for child stdout, child stderr, and SilentRunner diagnostics and replays them successfully.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-jsonl-presentation-base64")
set(expected_log
    "${log_dir}/${execution_id}_stderr_incl_stdout_success.jsonl"
)
set(expected_running_log
    "${log_dir}/${execution_id}_stderr_incl_stdout_running.jsonl"
)
cmake_path(
    NATIVE_PATH expected_running_log
    NORMALIZE expected_running_log_native
)

sr_run(r ARGS
    --debug
    --id-base "${execution_id}"
    --stderr-dir-incl-stdout-jsonl "${log_dir}"
    --jsonl-payload-presentation base64
    --stdout-event-framing lf
    --stderr-child-event-framing lf
    --stdout-emit never
    --stderr-emit-incl-stdout end
    "${SR_BOTH_CMD}"
)

sr_assert_exit(r 0)
sr_assert_stdout_empty(r)

sr_assert_stderr_contains(
    r
    "[PARENT-REPLAY] Replay completed with result ok using plan: "
)
sr_assert_stderr_contains(
    r
    "stderr={target=StderrSrAndChildInclStdoutParent source=Jsonl path=${expected_running_log_native}}"
)

# Successful replay proves that the Base64 representation is consumable by
# the JSONL replay parser. The child markers additionally prove that decoded
# bytes reach the parent emitter.
sr_assert_stderr_contains(r "fullCmdLine=")
sr_assert_stderr_occurrence_count(
    r
    "${SR_TEST_CHILD_STDOUT_MARKER}"
    1
)
sr_assert_stderr_occurrence_count(
    r
    "${SR_TEST_CHILD_STDERR_MARKER}"
    1
)

sr_assert_file_not_empty("${expected_log}")
sr_assert_directory_file_count("${log_dir}" 1)

file(STRINGS "${expected_log}" records ENCODING UTF-8)

set(seen_stdout 0)
set(seen_stderr 0)
set(seen_sr 0)

foreach(record IN LISTS records)
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

    if(payloadDropped
        OR NOT dropped_type STREQUAL "BOOLEAN"
        OR NOT byte_count_type STREQUAL "NUMBER"
        OR NOT payloadRepresentation STREQUAL "base64"
        OR NOT payloadText STREQUAL ""
        OR payloadBase64 STREQUAL "")
        message(FATAL_ERROR
            "Unexpected explicit Base64 JSONL record:\n${record}"
        )
    endif()

    if(payloadType STREQUAL "ChildStdout")
        math(EXPR seen_stdout "${seen_stdout} + 1")

        if(NOT payloadByteCount STREQUAL "15"
            OR NOT payloadBase64 STREQUAL
                "U1JURVNUX1NURE9VVA0K")
            message(FATAL_ERROR
                "Unexpected ChildStdout Base64 payload:\n${record}"
            )
        endif()

    elseif(payloadType STREQUAL "ChildStderr")
        math(EXPR seen_stderr "${seen_stderr} + 1")

        if(NOT payloadByteCount STREQUAL "15"
            OR NOT payloadBase64 STREQUAL
                "U1JURVNUX1NUREVSUg0K")
            message(FATAL_ERROR
                "Unexpected ChildStderr Base64 payload:\n${record}"
            )
        endif()

    elseif(payloadType STREQUAL "SrDiagEvent")
        math(EXPR seen_sr "${seen_sr} + 1")

        if(payloadByteCount LESS_EQUAL 0)
            message(FATAL_ERROR
                "Unexpected empty SrDiagEvent Base64 payload:\n${record}"
            )
        endif()

    else()
        message(FATAL_ERROR
            "Unexpected payload type in combined JSONL log: ${payloadType}"
        )
    endif()
endforeach()

if(NOT seen_stdout EQUAL 1)
    message(FATAL_ERROR
        "Expected exactly one ChildStdout record, got ${seen_stdout}."
    )
endif()

if(NOT seen_stderr EQUAL 1)
    message(FATAL_ERROR
        "Expected exactly one ChildStderr record, got ${seen_stderr}."
    )
endif()

if(seen_sr LESS 1)
    message(FATAL_ERROR
        "Expected at least one SrDiagEvent record."
    )
endif()
