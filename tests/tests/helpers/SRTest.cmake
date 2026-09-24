include(CMakeParseArguments)

if(NOT DEFINED SILENTRUNNER_EXE)
    message(FATAL_ERROR "SILENTRUNNER_EXE is not defined.")
endif()

if(NOT DEFINED SR_TESTS_SOURCE_DIR)
    message(FATAL_ERROR "SR_TESTS_SOURCE_DIR is not defined.")
endif()

if(NOT DEFINED SR_TESTS_BINARY_DIR)
    message(FATAL_ERROR "SR_TESTS_BINARY_DIR is not defined.")
endif()

if(NOT DEFINED SR_TEST_NAME)
    message(FATAL_ERROR "SR_TEST_NAME is not defined.")
endif()

set(SR_TEST_CHILD_STDOUT_MARKER "SRTEST_STDOUT")
set(SR_TEST_CHILD_STDERR_MARKER "SRTEST_STDERR")
set(SR_TEST_CHILD_STDOUT_TXT_PREFIX "[payloadType=CHILDSTDOUT]")
set(SR_TEST_CHILD_STDERR_TXT_PREFIX "[payloadType=CHILDSTDERR]")
set(SR_TEST_SRDIAG_TXT_PREFIX "[payloadType=SRDIAGEVENT]")
set(SR_TEST_SRDIAG_JSONL_PREFIX "{\"payloadType\":\"SrDiagEvent\"")
set(SR_TEST_CHILD_STDOUT_JSONL_PREFIX "{\"payloadType\":\"ChildStdout\"")
set(SR_TEST_CHILD_STDERR_JSONL_PREFIX "{\"payloadType\":\"ChildStderr\"")
set(SR_TEST_JSONL_PAYLOAD_BASE64_FIELD "\"payloadBase64\":")
set(SR_TEST_EXIT_CLI_ERROR 2)
set(SR_TEST_FAIL_CMD_EXIT_CODE 7)
set(SR_TEST_EXIT_TIMEOUT 124)
set(SR_TEST_EXIT_BUFFER_LIMIT 125)


set(SR_TEST_EXIT_NO_DIAGNOSTIC_CHANNEL 254)
set(SR_TEST_EXIT_INTERNAL 255)
set(SR_TEST_PUBLIC_CLI_HELP_ENTRIES
    "--help"
    "--debug"
    "--verbose"
    "--probe-dir <dir>"
    "--inherit-stdin"
    "--utf8 or --utf-8"
    "--timeout-ms <ms>"
    "--cwd <dir>"
    "--run-on-success <path>"
    "--run-on-failure <path>"
    "--id-prefix <value>"
    "--id-base <value>"
    "--id-suffix <timestamp|pid|timestamp+pid|pid+timestamp>"
    "--stdout-emit <mode>"
    "--stderr-emit <mode>"
    "--stderr-emit-child <mode>"
    "--stderr-emit-sr <mode>"
    "--stderr-emit-incl-stdout <mode>"
    "--stdout-event-framing <chunk|lf|newline|crlf>"
    "--stderr-child-event-framing <chunk|lf|newline|crlf>"
    "--stdout-event-newline-max-bytes <bytes>"
    "--stderr-child-event-newline-max-bytes <bytes>"
    "--stdout-max-buffer-bytes <bytes>"
    "--stderr-max-buffer-bytes <bytes>"
    "--std-total-max-buffer-bytes <bytes>"
    "--stdout-dir <dir>"
    "--stderr-dir <dir>"
    "--stderr-dir-child <dir>"
    "--stderr-dir-sr <dir>"
    "--stderr-dir-incl-stdout <dir>"
    "--stdout-dir-jsonl <dir>"
    "--stderr-dir-jsonl <dir>"
    "--stderr-dir-child-jsonl <dir>"
    "--stderr-dir-sr-jsonl <dir>"
    "--stderr-dir-incl-stdout-jsonl <dir>"
    "--jsonl-payload-presentation <text|base64|(text+base64|base64+text)>"
    "--stdout-dir-keep-log <mode>"
    "--stderr-dir-keep-log <mode>"
    "--stderr-dir-child-keep-log <mode>"
    "--stderr-dir-sr-keep-log <mode>"
    "--stderr-dir-incl-stdout-keep-log <mode>"
    "SilentRunner.exe [options] -c \"<command>\""
)

function(sr_test_init)
    set(options)
    set(one_value_args DESCRIPTION)
    cmake_parse_arguments(SR_TEST_INIT "${options}" "${one_value_args}" "" ${ARGN})

    if(SR_TEST_INIT_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR
            "sr_test_init received unparsed arguments: ${SR_TEST_INIT_UNPARSED_ARGUMENTS}"
        )
    endif()

    if(SR_TEST_INIT_KEYWORDS_MISSING_VALUES)
        message(FATAL_ERROR
            "sr_test_init is missing values for: ${SR_TEST_INIT_KEYWORDS_MISSING_VALUES}"
        )
    endif()

    if(NOT DEFINED SR_TEST_INIT_DESCRIPTION OR SR_TEST_INIT_DESCRIPTION STREQUAL "")
        message(FATAL_ERROR "sr_test_init requires DESCRIPTION.")
    endif()

    message(STATUS "[TEST] ${SR_TEST_INIT_DESCRIPTION}")

    string(REGEX REPLACE "[^A-Za-z0-9._-]" "_" safe_test_name "${SR_TEST_NAME}")

    set(test_root "${SR_TESTS_BINARY_DIR}/work/${safe_test_name}")
    file(REMOVE_RECURSE "${test_root}")
    file(MAKE_DIRECTORY "${test_root}")
    file(COPY "${SR_TESTS_SOURCE_DIR}/fixtures/" DESTINATION "${test_root}")

    set(SR_TEST_ROOT "${test_root}" PARENT_SCOPE)
    set(SR_OK "${test_root}/ok.cmd" PARENT_SCOPE)
    set(SR_FAIL "${test_root}/fail.cmd" PARENT_SCOPE)
    set(SR_STDOUT_CMD "${test_root}/stdout.cmd" PARENT_SCOPE)
    set(SR_STDERR_CMD "${test_root}/stderr.cmd" PARENT_SCOPE)
    set(SR_BOTH_CMD "${test_root}/both.cmd" PARENT_SCOPE)
    set(SR_ECHO_ARGS "${test_root}/echo-args.cmd" PARENT_SCOPE)
    set(SR_PRINT_CWD "${test_root}/print-cwd.cmd" PARENT_SCOPE)
    set(SR_SLEEP "${test_root}/sleep.cmd" PARENT_SCOPE)
    set(SR_SLEEP_OUTPUT "${test_root}/sleep-output.cmd" PARENT_SCOPE)
    set(SR_PRINT_CODEPAGE "${test_root}/print-codepage.cmd" PARENT_SCOPE)
    set(SR_SUCCESS_HOOK "${test_root}/success-hook.cmd" PARENT_SCOPE)
    set(SR_FAILURE_HOOK "${test_root}/failure-hook.cmd" PARENT_SCOPE)
    set(SR_HOOK_CWD "${test_root}/hook-cwd.cmd" PARENT_SCOPE)
    set(SR_HOOK_ENV "${test_root}/hook-env.cmd" PARENT_SCOPE)
endfunction()

# Create one controlled test line terminated with an exact requested newline
# sequence. configure_file performs the final newline normalization after the
# staging file has been created using the host's text conventions.
function(_sr_write_terminated_fixture path content newline_style)
    set(staging_path "${path}.sr-stage")

    file(WRITE "${staging_path}" "${content}\n")
    configure_file(
        "${staging_path}"
        "${path}"
        @ONLY
        NEWLINE_STYLE "${newline_style}"
    )
    file(REMOVE "${staging_path}")
endfunction()

function(sr_write_lf_terminated_fixture path content)
    _sr_write_terminated_fixture(
        "${path}"
        "${content}"
        LF
    )
endfunction()

function(sr_write_crlf_terminated_fixture path content)
    _sr_write_terminated_fixture(
        "${path}"
        "${content}"
        CRLF
    )
endfunction()

# Concatenate fixture components byte-for-byte. Using cmake -E cat with
# OUTPUT_FILE avoids routing the bytes through a CMake text variable.
function(sr_concat_files path)
    if(NOT ARGN)
        message(FATAL_ERROR "sr_concat_files requires at least one input file.")
    endif()

    execute_process(
        COMMAND "${CMAKE_COMMAND}" -E cat ${ARGN}
        OUTPUT_FILE "${path}"
        ERROR_VARIABLE error_text
        RESULT_VARIABLE result
    )

    if(NOT "${result}" STREQUAL "0")
        message(FATAL_ERROR
            "Failed to concatenate byte-exact fixture files.\n"
            "Output: ${path}\n"
            "Result: ${result}\n"
            "Error: ${error_text}"
        )
    endif()
endfunction()

# Verify the fixture itself before SilentRunner consumes it. This prevents a
# newline-normalization error in the test harness from being mistaken for a
# framing error in SilentRunner.
function(sr_assert_file_hex path expected_hex)
    if(NOT EXISTS "${path}")
        message(FATAL_ERROR "Expected fixture file does not exist: ${path}")
    endif()

    file(READ "${path}" actual_hex HEX)
    string(TOLOWER "${actual_hex}" actual_hex)
    string(TOLOWER "${expected_hex}" expected_hex_normalized)

    if(NOT actual_hex STREQUAL expected_hex_normalized)
        message(FATAL_ERROR
            "Unexpected fixture bytes.\n"
            "File:     ${path}\n"
            "Expected: ${expected_hex_normalized}\n"
            "Actual:   ${actual_hex}"
        )
    endif()
endfunction()

# Assert a single headered TXT parent-output event against an exact payload
# fixture. The parseable header is inspected as text while the complete payload
# tail is compared as hexadecimal bytes, so the payload comparison does not
# depend on execute_process text capture or line-ending handling.
function(sr_assert_single_txt_output_payload_equals_file output_path payload_path payload_type)
    if(NOT EXISTS "${output_path}")
        message(FATAL_ERROR
            "Expected TXT output file does not exist: ${output_path}"
        )
    endif()

    if(NOT EXISTS "${payload_path}")
        message(FATAL_ERROR
            "Expected payload fixture does not exist: ${payload_path}"
        )
    endif()

    file(SIZE "${payload_path}" payload_byte_count)
    file(READ "${output_path}" output_prefix LIMIT 4096)

    string(FIND "${output_prefix}" "\n" header_end)
    if(header_end LESS 0)
        message(FATAL_ERROR
            "Missing terminating LF after TXT output header: ${output_path}"
        )
    endif()

    string(
        SUBSTRING
        "${output_prefix}"
        0
        ${header_end}
        header
    )

    string(FIND
        "${header}"
        "[payloadType=${payload_type}]"
        payload_type_position
    )
    string(FIND
        "${header}"
        "[payloadDropped=FALSE]"
        dropped_position
    )
    string(FIND
        "${header}"
        "[payloadByteCount=${payload_byte_count}]"
        byte_count_position
    )
    string(
        REGEX MATCH
        "\\[parsingToken=[0-9a-f]+\\]"
        parsing_token_field
        "${header}"
    )

    if(NOT payload_type_position EQUAL 0
        OR dropped_position LESS 0
        OR byte_count_position LESS 0
        OR parsing_token_field STREQUAL "")
        message(FATAL_ERROR
            "Unexpected TXT output header.\n"
            "Header: ${header}"
        )
    endif()

    # The parseable TXT header is ASCII, so its CMake string length is also its
    # byte length. Skip the header and its terminating LF in the hex stream.
    string(LENGTH "${header}" header_byte_count)

    file(READ "${output_path}" output_hex HEX)
    file(READ "${payload_path}" expected_payload_hex HEX)

    math(
        EXPR
        payload_hex_start
        "(${header_byte_count} + 1) * 2"
    )

    string(LENGTH "${output_hex}" output_hex_length)
    if(payload_hex_start GREATER output_hex_length)
        message(FATAL_ERROR
            "TXT output ends before its declared payload begins.\n"
            "File: ${output_path}"
        )
    endif()

    string(
        SUBSTRING
        "${output_hex}"
        ${payload_hex_start}
        -1
        actual_payload_hex
    )

    string(TOLOWER "${actual_payload_hex}" actual_payload_hex)
    string(TOLOWER "${expected_payload_hex}" expected_payload_hex)

    if(NOT actual_payload_hex STREQUAL expected_payload_hex)
        string(LENGTH "${actual_payload_hex}" actual_hex_length)
        string(LENGTH "${expected_payload_hex}" expected_hex_length)

        message(FATAL_ERROR
            "Headered TXT output did not preserve the exact payload bytes.\n"
            "Output: ${output_path}\n"
            "Payload: ${payload_path}\n"
            "Expected hex length: ${expected_hex_length}\n"
            "Actual hex length:   ${actual_hex_length}"
        )
    endif()
endfunction()




# Create a child .cmd that forwards the payload file byte-for-byte to one child
# standard stream. The payload file and command file must share a directory.
function(sr_write_type_emitter_cmd path payload_path stream)
    get_filename_component(payload_name "${payload_path}" NAME)

    if(stream STREQUAL "stdout")
        set(redirect "")
    elseif(stream STREQUAL "stderr")
        set(redirect " 1>&2")
    else()
        message(FATAL_ERROR
            "sr_write_type_emitter_cmd stream must be stdout or stderr, got: ${stream}"
        )
    endif()

    file(WRITE
        "${path}"
        "@echo off\r\ntype \"%~dp0${payload_name}\"${redirect}\r\nexit /b 0\r\n"
    )
endfunction()


function(sr_run prefix)
    set(options)
    set(one_value_args WORKING_DIRECTORY INPUT_FILE OUTPUT_FILE ERROR_FILE)
    set(multi_value_args ARGS ENV UNSET_ENV)
    cmake_parse_arguments(SR_RUN "${options}" "${one_value_args}" "${multi_value_args}" ${ARGN})

    if(SR_RUN_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR
            "sr_run(${prefix}) received unparsed arguments: ${SR_RUN_UNPARSED_ARGUMENTS}"
        )
    endif()

    if(SR_RUN_WORKING_DIRECTORY)
        set(working_directory "${SR_RUN_WORKING_DIRECTORY}")
    else()
        set(working_directory "${SR_TEST_ROOT}")
    endif()

    set(command)

    if(SR_RUN_ENV OR SR_RUN_UNSET_ENV)
        list(APPEND command "${CMAKE_COMMAND}" -E env)

        foreach(env_entry IN LISTS SR_RUN_ENV)
            list(APPEND command "${env_entry}")
        endforeach()

        foreach(env_name IN LISTS SR_RUN_UNSET_ENV)
            list(APPEND command "--unset=${env_name}")
        endforeach()
    endif()

    list(APPEND command "${SILENTRUNNER_EXE}")
    list(APPEND command ${SR_RUN_ARGS})

    set(stdout_text "")
    set(stderr_text "")

    set(execute_process_args
        COMMAND ${command}
        WORKING_DIRECTORY "${working_directory}"
        RESULT_VARIABLE result
    )

    if(SR_RUN_OUTPUT_FILE)
        list(APPEND execute_process_args OUTPUT_FILE "${SR_RUN_OUTPUT_FILE}")
    else()
        list(APPEND execute_process_args OUTPUT_VARIABLE stdout_text)
    endif()

    if(SR_RUN_ERROR_FILE)
        list(APPEND execute_process_args ERROR_FILE "${SR_RUN_ERROR_FILE}")
    else()
        list(APPEND execute_process_args ERROR_VARIABLE stderr_text)
    endif()

    if(SR_RUN_INPUT_FILE)
        list(APPEND execute_process_args INPUT_FILE "${SR_RUN_INPUT_FILE}")
    endif()

    execute_process(${execute_process_args})

    set(${prefix}_EXIT_CODE "${result}" PARENT_SCOPE)
    set(${prefix}_STDOUT "${stdout_text}" PARENT_SCOPE)
    set(${prefix}_STDERR "${stderr_text}" PARENT_SCOPE)
endfunction()

function(sr_failure_context prefix out_var)
    set(context
        "exit code: ${${prefix}_EXIT_CODE}\n"
        "stdout:\n${${prefix}_STDOUT}\n"
        "stderr:\n${${prefix}_STDERR}"
    )
    set(${out_var} "${context}" PARENT_SCOPE)
endfunction()

function(sr_assert_exit prefix expected)
    if(NOT "${${prefix}_EXIT_CODE}" STREQUAL "${expected}")
        sr_failure_context(${prefix} context)
        message(FATAL_ERROR
            "Expected exit code: ${expected}\n"
            "Actual exit code:   ${${prefix}_EXIT_CODE}\n\n"
            "${context}"
        )
    endif()
endfunction()

function(sr_assert_exit_one_of prefix)
    set(allowed_values ${ARGN})
    list(FIND allowed_values "${${prefix}_EXIT_CODE}" match_index)

    if(match_index EQUAL -1)
        sr_failure_context(${prefix} context)
        message(FATAL_ERROR
            "Expected exit code to be one of: ${allowed_values}\n"
            "Actual exit code: ${${prefix}_EXIT_CODE}\n\n"
            "${context}"
        )
    endif()
endfunction()

function(sr_assert_stdout_empty prefix)
    if(NOT "${${prefix}_STDOUT}" STREQUAL "")
        sr_failure_context(${prefix} context)
        message(FATAL_ERROR "Expected empty stdout.\n\n${context}")
    endif()
endfunction()

function(sr_assert_stderr_empty prefix)
    if(NOT "${${prefix}_STDERR}" STREQUAL "")
        sr_failure_context(${prefix} context)
        message(FATAL_ERROR "Expected empty stderr.\n\n${context}")
    endif()
endfunction()

function(sr_assert_stdout_contains prefix expected)
    string(FIND "${${prefix}_STDOUT}" "${expected}" position)
    if(position EQUAL -1)
        sr_failure_context(${prefix} context)
        message(FATAL_ERROR
            "Expected stdout to contain: [${expected}]\n\n${context}"
        )
    endif()
endfunction()

function(sr_assert_stdout_not_contains prefix unexpected)
    string(FIND "${${prefix}_STDOUT}" "${unexpected}" position)
    if(NOT position EQUAL -1)
        sr_failure_context(${prefix} context)
        message(FATAL_ERROR
            "Expected stdout not to contain: [${unexpected}]\n\n${context}"
        )
    endif()
endfunction()

function(sr_assert_stderr_contains prefix expected)
    string(FIND "${${prefix}_STDERR}" "${expected}" position)
    if(position EQUAL -1)
        sr_failure_context(${prefix} context)
        message(FATAL_ERROR
            "Expected stderr to contain: [${expected}]\n\n${context}"
        )
    endif()
endfunction()

function(sr_assert_stderr_not_contains prefix unexpected)
    string(FIND "${${prefix}_STDERR}" "${unexpected}" position)
    if(NOT position EQUAL -1)
        sr_failure_context(${prefix} context)
        message(FATAL_ERROR
            "Expected stderr not to contain: [${unexpected}]\n\n${context}"
        )
    endif()
endfunction()
function(_sr_assert_occurrence_count text needle expected_count context)
    if("${needle}" STREQUAL "")
        message(FATAL_ERROR "Cannot count occurrences of an empty string.")
    endif()

    set(remaining "${text}")
    set(actual_count 0)
    string(LENGTH "${needle}" needle_length)

    while(1)
        string(FIND "${remaining}" "${needle}" position)
        if(position EQUAL -1)
            break()
        endif()

        math(EXPR actual_count "${actual_count} + 1")
        math(EXPR consumed "${position} + ${needle_length}")
        string(LENGTH "${remaining}" remaining_length)

        if(consumed GREATER_EQUAL remaining_length)
            set(remaining "")
        else()
            string(SUBSTRING "${remaining}" ${consumed} -1 remaining)
        endif()
    endwhile()

    if(NOT actual_count EQUAL expected_count)
        message(FATAL_ERROR
            "Unexpected occurrence count in ${context}.\n"
            "Needle:   [${needle}]\n"
            "Expected: ${expected_count}\n"
            "Actual:   ${actual_count}\n"
            "Content:\n${text}"
        )
    endif()
endfunction()

function(sr_assert_stdout_occurrence_count prefix expected expected_count)
    _sr_assert_occurrence_count(
        "${${prefix}_STDOUT}"
        "${expected}"
        "${expected_count}"
        "stdout"
    )
endfunction()

function(sr_assert_stderr_occurrence_count prefix expected expected_count)
    _sr_assert_occurrence_count(
        "${${prefix}_STDERR}"
        "${expected}"
        "${expected_count}"
        "stderr"
    )
endfunction()

function(sr_assert_file_occurrence_count path expected expected_count)
    if(NOT EXISTS "${path}")
        message(FATAL_ERROR "Expected file does not exist: ${path}")
    endif()

    file(READ "${path}" file_text)
    _sr_assert_occurrence_count(
        "${file_text}"
        "${expected}"
        "${expected_count}"
        "file ${path}"
    )
endfunction()

function(_sr_assert_txt_header_fields text payload_type context)
    set(payload_type_field "[payloadType=${payload_type}]")
    string(FIND "${text}" "${payload_type_field}" payload_type_position)
    if(payload_type_position EQUAL -1)
        message(FATAL_ERROR
            "Expected TXT header payload type in ${context}: ${payload_type_field}\n"
            "Content:\n${text}"
        )
    endif()

    string(SUBSTRING "${text}" ${payload_type_position} -1 from_header)
    string(FIND "${from_header}" "\n" header_end)
    if(header_end EQUAL -1)
        set(header "${from_header}")
    else()
        string(SUBSTRING "${from_header}" 0 ${header_end} header)
    endif()

    string(FIND "${header}" "[payloadDropped=FALSE]" dropped_position)
    if(dropped_position EQUAL -1)
        message(FATAL_ERROR
            "Expected non-dropped TXT header in ${context}.\n"
            "Header: ${header}"
        )
    endif()

    string(REGEX MATCH "\\[payloadByteCount=[1-9][0-9]*\\]" byte_count_field "${header}")
    if(byte_count_field STREQUAL "")
        message(FATAL_ERROR
            "Expected positive payloadByteCount in TXT header in ${context}.\n"
            "Header: ${header}"
        )
    endif()

    string(REGEX MATCH "\\[parsingToken=[0-9a-f]+\\]" parsing_token_field "${header}")
    if(parsing_token_field STREQUAL "")
        message(FATAL_ERROR
            "Expected non-empty parsingToken in TXT header in ${context}.\n"
            "Header: ${header}"
        )
    endif()
endfunction()

function(sr_assert_stdout_txt_header prefix payload_type)
    _sr_assert_txt_header_fields(
        "${${prefix}_STDOUT}"
        "${payload_type}"
        "stdout"
    )
endfunction()

function(sr_assert_stderr_txt_header prefix payload_type)
    _sr_assert_txt_header_fields(
        "${${prefix}_STDERR}"
        "${payload_type}"
        "stderr"
    )
endfunction()

function(sr_assert_file_txt_header path payload_type)
    if(NOT EXISTS "${path}")
        message(FATAL_ERROR "Expected file does not exist: ${path}")
    endif()

    file(READ "${path}" file_text)
    _sr_assert_txt_header_fields(
        "${file_text}"
        "${payload_type}"
        "file ${path}"
    )
endfunction()

function(_sr_assert_jsonl_default_text path payload_type check_expected expected_payload)
    if(NOT EXISTS "${path}")
        message(FATAL_ERROR "Expected JSONL file does not exist: ${path}")
    endif()

    file(READ "${path}" remaining)
    set(reconstructed "")
    set(match_count 0)
    set(line_no 0)

    while(NOT "${remaining}" STREQUAL "")
        math(EXPR line_no "${line_no} + 1")
        string(FIND "${remaining}" "\n" newline_position)

        if(newline_position EQUAL -1)
            set(line "${remaining}")
            set(remaining "")
        else()
            string(SUBSTRING "${remaining}" 0 ${newline_position} line)
            math(EXPR next_position "${newline_position} + 1")
            string(SUBSTRING "${remaining}" ${next_position} -1 remaining)
        endif()

        string(LENGTH "${line}" line_length)
        if(line_length GREATER 0)
            math(EXPR last_position "${line_length} - 1")
            string(SUBSTRING "${line}" ${last_position} 1 last_character)
            if(last_character STREQUAL "\r")
                string(SUBSTRING "${line}" 0 ${last_position} line)
            endif()
        endif()

        if("${line}" STREQUAL "")
            continue()
        endif()

        string(JSON object_type TYPE "${line}")
        if(NOT object_type STREQUAL "OBJECT")
            message(FATAL_ERROR
                "Expected a JSON object at ${path}:${line_no}.\n"
                "Line: ${line}"
            )
        endif()

        string(JSON current_payload_type GET "${line}" payloadType)
        if(NOT current_payload_type STREQUAL payload_type)
            continue()
        endif()

        math(EXPR match_count "${match_count} + 1")

        string(JSON payload_representation GET "${line}" payloadRepresentation)
        string(JSON payload_text GET "${line}" payloadText)
        string(JSON payload_base64 GET "${line}" payloadBase64)
        string(JSON payload_byte_count GET "${line}" payloadByteCount)
        string(JSON payload_dropped GET "${line}" payloadDropped)
        string(JSON byte_count_type TYPE "${line}" payloadByteCount)
        string(JSON dropped_type TYPE "${line}" payloadDropped)

        if(NOT payload_representation STREQUAL "text")
            message(FATAL_ERROR
                "Expected default text representation for ${payload_type} at ${path}:${line_no}.\n"
                "Line: ${line}"
            )
        endif()

        if(NOT payload_base64 STREQUAL "")
            message(FATAL_ERROR
                "Expected empty payloadBase64 for text representation at ${path}:${line_no}.\n"
                "Line: ${line}"
            )
        endif()

        if(payload_dropped OR NOT dropped_type STREQUAL "BOOLEAN")
            message(FATAL_ERROR
                "Expected payloadDropped=false BOOLEAN at ${path}:${line_no}.\n"
                "Line: ${line}"
            )
        endif()

        if(NOT byte_count_type STREQUAL "NUMBER")
            message(FATAL_ERROR
                "Expected numeric payloadByteCount at ${path}:${line_no}.\n"
                "Line: ${line}"
            )
        endif()

        string(LENGTH "${payload_text}" actual_byte_count)
        if(NOT actual_byte_count EQUAL payload_byte_count)
            message(FATAL_ERROR
                "payloadByteCount mismatch at ${path}:${line_no}.\n"
                "Expected from payloadText: ${actual_byte_count}\n"
                "Recorded: ${payload_byte_count}\n"
                "Line: ${line}"
            )
        endif()

        string(APPEND reconstructed "${payload_text}")
    endwhile()

    if(match_count EQUAL 0)
        message(FATAL_ERROR
            "No JSONL records with payloadType=${payload_type} in ${path}."
        )
    endif()

    if(check_expected AND NOT "${reconstructed}" STREQUAL "${expected_payload}")
        message(FATAL_ERROR
            "Unexpected reconstructed ${payload_type} payload.\n"
            "File: ${path}\n"
            "Expected: [${expected_payload}]\n"
            "Actual:   [${reconstructed}]"
        )
    endif()
endfunction()

function(sr_assert_jsonl_default_text_records path payload_type)
    _sr_assert_jsonl_default_text(
        "${path}"
        "${payload_type}"
        FALSE
        ""
    )
endfunction()

function(sr_assert_jsonl_default_text_payload path payload_type expected_payload)
    _sr_assert_jsonl_default_text(
        "${path}"
        "${payload_type}"
        TRUE
        "${expected_payload}"
    )
endfunction()

# Assert the exact ordered sequence of text-representable JSONL events for one
# payload type. This validates event count, boundaries, bytes, representation,
# byte count, and dropped state without relying on parent-output text capture.
function(sr_assert_jsonl_text_event_sequence path payload_type)
    if(NOT EXISTS "${path}")
        message(FATAL_ERROR "Expected JSONL file does not exist: ${path}")
    endif()

    set(expected_payloads ${ARGN})
    list(LENGTH expected_payloads expected_count)

    file(STRINGS "${path}" records ENCODING UTF-8)

    set(actual_count 0)

    foreach(record IN LISTS records)
        if("${record}" STREQUAL "")
            continue()
        endif()

        string(JSON object_type TYPE "${record}")
        if(NOT object_type STREQUAL "OBJECT")
            message(FATAL_ERROR
                "Expected JSON object in ${path}.\n"
                "Record: ${record}"
            )
        endif()

        string(JSON current_payload_type GET "${record}" payloadType)
        if(NOT current_payload_type STREQUAL "${payload_type}")
            continue()
        endif()

        if(actual_count GREATER_EQUAL expected_count)
            message(FATAL_ERROR
                "Unexpected extra ${payload_type} event in ${path}.\n"
                "Record: ${record}"
            )
        endif()

        list(GET expected_payloads ${actual_count} expected_payload)

        foreach(field IN ITEMS
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
        string(LENGTH "${expected_payload}" expected_byte_count)

        if(NOT payloadRepresentation STREQUAL "text"
            OR NOT "${payloadText}" STREQUAL "${expected_payload}"
            OR NOT "${payloadBase64}" STREQUAL ""
            OR NOT payloadByteCount EQUAL expected_byte_count
            OR payloadDropped
            OR NOT dropped_type STREQUAL "BOOLEAN"
            OR NOT byte_count_type STREQUAL "NUMBER")
            message(FATAL_ERROR
                "Unexpected ${payload_type} event ${actual_count} in ${path}.\n"
                "Expected payload byte count: ${expected_byte_count}\n"
                "Expected payload: [${expected_payload}]\n"
                "Record: ${record}"
            )
        endif()

        math(EXPR actual_count "${actual_count} + 1")
    endforeach()

    if(NOT actual_count EQUAL expected_count)
        message(FATAL_ERROR
            "Unexpected ${payload_type} event count in ${path}.\n"
            "Expected: ${expected_count}\n"
            "Actual:   ${actual_count}"
        )
    endif()
endfunction()



function(sr_assert_path_exists path)
    if(NOT EXISTS "${path}")
        message(FATAL_ERROR "Expected path does not exist: ${path}")
    endif()
endfunction()

function(sr_assert_path_not_exists path)
    if(EXISTS "${path}")
        message(FATAL_ERROR "Path was expected not to exist: ${path}")
    endif()
endfunction()

function(sr_wait_for_path path)
    foreach(attempt RANGE 1 50)
        if(EXISTS "${path}")
            return()
        endif()
        execute_process(COMMAND "${CMAKE_COMMAND}" -E sleep 0.1)
    endforeach()

    message(FATAL_ERROR "Timed out waiting for path: ${path}")
endfunction()

function(sr_assert_file_contains path expected)
    if(NOT EXISTS "${path}")
        message(FATAL_ERROR "Expected file does not exist: ${path}")
    endif()

    file(READ "${path}" file_text)
    string(FIND "${file_text}" "${expected}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR
            "Expected file to contain: [${expected}]\n"
            "File: ${path}\n"
            "Actual content:\n${file_text}"
        )
    endif()
endfunction()

function(sr_assert_file_equals path expected)
    if(NOT EXISTS "${path}")
        message(FATAL_ERROR "Expected file does not exist: ${path}")
    endif()

    file(READ "${path}" file_text)
    if(NOT "${file_text}" STREQUAL "${expected}")
        message(FATAL_ERROR
            "Unexpected file content.\n"
            "File: ${path}\n"
            "Expected: [${expected}]\n"
            "Actual:   [${file_text}]"
        )
    endif()
endfunction()

function(sr_assert_file_not_contains path unexpected)
    if(NOT EXISTS "${path}")
        message(FATAL_ERROR "Expected file does not exist: ${path}")
    endif()

    file(READ "${path}" file_text)
    string(FIND "${file_text}" "${unexpected}" position)
    if(NOT position EQUAL -1)
        message(FATAL_ERROR
            "Expected file not to contain: [${unexpected}]\n"
            "File: ${path}\n"
            "Actual content:\n${file_text}"
        )
    endif()
endfunction()

function(sr_assert_file_not_empty path)
    if(NOT EXISTS "${path}")
        message(FATAL_ERROR "Expected file does not exist: ${path}")
    endif()

    file(SIZE "${path}" file_size)
    if(file_size EQUAL 0)
        message(FATAL_ERROR "Expected non-empty file: ${path}")
    endif()
endfunction()

function(sr_assert_directory_file_count directory expected)
    if(EXISTS "${directory}")
        file(GLOB entries LIST_DIRECTORIES false "${directory}/*")
    else()
        set(entries)
    endif()

    list(LENGTH entries actual)
    if(NOT actual EQUAL expected)
        message(FATAL_ERROR
            "Unexpected file count in directory.\n"
            "Directory: ${directory}\n"
            "Expected:  ${expected}\n"
            "Actual:    ${actual}\n"
            "Files:     ${entries}"
        )
    endif()
endfunction()
function(sr_assert_single_file_name_matches directory pattern)
    sr_assert_directory_file_count("${directory}" 1)
    file(GLOB entries LIST_DIRECTORIES false "${directory}/*")
    list(GET entries 0 entry)
    get_filename_component(file_name "${entry}" NAME)
    if(NOT file_name MATCHES "${pattern}")
        message(FATAL_ERROR
            "Unexpected file name: ${file_name}\n"
            "Expected pattern: ${pattern}"
        )
    endif()
endfunction()
