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
set(SR_TEST_SRDIAG_TXT_PREFIX "[payloadType=SRDIAG]")
set(SR_TEST_SRDIAG_JSONL_PREFIX "{\"payloadType\":\"SrDiag\"")
set(SR_TEST_CHILD_STDOUT_JSONL_PREFIX "{\"payloadType\":\"ChildStdout\"")
set(SR_TEST_CHILD_STDERR_JSONL_PREFIX "{\"payloadType\":\"ChildStderr\"")
set(SR_TEST_JSONL_PAYLOAD_BASE64_FIELD "\"payloadBase64\":")
set(SR_TEST_EXIT_CLI_ERROR 2)
set(SR_TEST_FAIL_CMD_EXIT_CODE 7)
set(SR_TEST_EXIT_TIMEOUT 124)

function(sr_test_init)
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

function(sr_run prefix)
    set(options)
    set(one_value_args WORKING_DIRECTORY INPUT_FILE)
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

    set(execute_process_args
        COMMAND ${command}
        WORKING_DIRECTORY "${working_directory}"
        RESULT_VARIABLE result
        OUTPUT_VARIABLE stdout_text
        ERROR_VARIABLE stderr_text
    )

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
