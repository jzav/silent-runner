include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Treats only an exact CRLF pair as a delimiter under CRLF framing while lone LF and lone CR remain payload bytes.")


set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-framing-crlf-exact")
set(expected_log
    "${log_dir}/${execution_id}_stdout_success.jsonl"
)

set(payload_file "${SR_TEST_ROOT}/crlf-exact.bin")
set(lf_part "${SR_TEST_ROOT}/crlf-exact-lf.bin")
set(lone_cr_part "${SR_TEST_ROOT}/crlf-exact-lone-cr.bin")
set(crlf_part "${SR_TEST_ROOT}/crlf-exact-crlf.bin")
set(tail_part "${SR_TEST_ROOT}/crlf-exact-tail.bin")
set(child_cmd "${SR_TEST_ROOT}/crlf-exact.cmd")

string(ASCII 10 lf)
string(ASCII 13 cr)

# Exact bytes:
#   41 0a 42 0d 43 0d 0a 44
#   A  LF B  CR C  CR LF D
#
# Only CR LF is a delimiter. The earlier LF and CR must stay in the event.
sr_write_lf_terminated_fixture("${lf_part}" "A")
file(WRITE "${lone_cr_part}" "B${cr}")
sr_write_crlf_terminated_fixture("${crlf_part}" "C")
file(WRITE "${tail_part}" "D")

sr_concat_files(
    "${payload_file}"
    "${lf_part}"
    "${lone_cr_part}"
    "${crlf_part}"
    "${tail_part}"
)

sr_assert_file_hex(
    "${payload_file}"
    "410a420d430d0a44"
)

sr_write_type_emitter_cmd("${child_cmd}" "${payload_file}" stdout)


sr_run(r ARGS
    --id-base "${execution_id}"
    --stdout-dir-jsonl "${log_dir}"
    --stdout-event-framing crlf
    --stdout-event-newline-max-bytes 64
    --stdout-emit never
    --stderr-emit-sr stream
    "${child_cmd}"
)

sr_assert_exit(r 0)
sr_assert_stdout_empty(r)
sr_assert_directory_file_count("${log_dir}" 1)

sr_assert_jsonl_text_event_sequence(
    "${expected_log}"
    "ChildStdout"
    "A${lf}B${cr}C${cr}${lf}"
    "D"
)

# Raw parent and Raw TXT output must remain byte-exact under each framing
# mode, including a lone LF, a lone CR, CRLF, and the unterminated EOF tail.
foreach(raw_framing IN ITEMS chunk lf newline crlf)
    set(raw_log_dir "${SR_TEST_ROOT}/raw-${raw_framing}")
    set(raw_execution_id "ctest-raw-crlf-exact-${raw_framing}")
    set(raw_parent_stdout "${SR_TEST_ROOT}/raw-parent-${raw_framing}.bin")
    set(raw_log
        "${raw_log_dir}/${raw_execution_id}_stdout_raw_success.log"
    )

    set(raw_newline_options)
    if(NOT raw_framing STREQUAL "chunk")
        list(APPEND raw_newline_options
            --stdout-event-newline-max-bytes 2
        )
    endif()

    sr_run(raw OUTPUT_FILE "${raw_parent_stdout}" ARGS
        --id-base "${raw_execution_id}"
        --stdout-emit-raw stream
        --stdout-dir-raw "${raw_log_dir}"
        --stdout-event-framing "${raw_framing}"
        ${raw_newline_options}
        --stderr-emit-sr stream
        "${child_cmd}"
    )
    sr_assert_exit(raw 0)
    sr_assert_files_equal_bytes("${raw_parent_stdout}" "${payload_file}")
    sr_assert_files_equal_bytes("${raw_log}" "${payload_file}")
    sr_assert_directory_file_count("${raw_log_dir}" 1)
endforeach()

# A small CMake-generated TAR archive supplies embedded NUL bytes without
# introducing PowerShell, Python, or another binary-fixture generator dependency.
# The original archive file is the independent byte-exact reference.
set(binary_source "${SR_TEST_ROOT}/raw-nul-source.txt")
set(binary_payload "${SR_TEST_ROOT}/raw-nul-fixture.tar")
set(binary_cmd "${SR_TEST_ROOT}/raw-nul.cmd")
file(WRITE "${binary_source}" "RAW_NUL_FIXTURE")
execute_process(
    COMMAND "${CMAKE_COMMAND}" -E tar cf "${binary_payload}" --format=gnutar raw-nul-source.txt
    WORKING_DIRECTORY "${SR_TEST_ROOT}"
    RESULT_VARIABLE binary_tar_result
    ERROR_VARIABLE binary_tar_error
)
if(NOT "${binary_tar_result}" STREQUAL "0")
    message(FATAL_ERROR "Failed to generate NUL-byte fixture: ${binary_tar_error}")
endif()
file(READ "${binary_payload}" binary_hex HEX)
string(FIND "${binary_hex}" "00" binary_nul_position)
if(binary_nul_position LESS 0)
    message(FATAL_ERROR "Binary TAR fixture unexpectedly contains no NUL byte.")
endif()

file(WRITE "${binary_cmd}"
    "@echo off\r\n"
    "type \"%~dp0raw-nul-fixture.tar\"\r\n"
    "type \"%~dp0raw-nul-fixture.tar\" 1>&2\r\n"
    "exit /b 0\r\n"
)

foreach(binary_framing IN ITEMS chunk crlf)
    set(binary_log_dir "${SR_TEST_ROOT}/nul-${binary_framing}")
    set(binary_diag_dir "${SR_TEST_ROOT}/nul-diag-${binary_framing}")
    set(binary_execution_id "ctest-raw-nul-${binary_framing}")
    set(binary_parent_stdout "${SR_TEST_ROOT}/nul-stdout-${binary_framing}.bin")
    set(binary_parent_stderr "${SR_TEST_ROOT}/nul-stderr-${binary_framing}.bin")
    set(binary_stdout_log
        "${binary_log_dir}/${binary_execution_id}_stdout_raw_success.log"
    )
    set(binary_stderr_log
        "${binary_log_dir}/${binary_execution_id}_stderr_child_raw_success.log"
    )
    set(binary_newline_options)
    if(binary_framing STREQUAL "crlf")
        list(APPEND binary_newline_options
            --stdout-event-newline-max-bytes 32
            --stderr-child-event-newline-max-bytes 32
        )
    endif()

    sr_run(binary
        OUTPUT_FILE "${binary_parent_stdout}"
        ERROR_FILE "${binary_parent_stderr}"
        ARGS
            --id-base "${binary_execution_id}"
            --stdout-emit-raw stream
            --stderr-emit-child-raw stream
            --stdout-dir-raw "${binary_log_dir}"
            --stderr-dir-child-raw "${binary_log_dir}"
            --stderr-dir-sr "${binary_diag_dir}"
            --stdout-event-framing "${binary_framing}"
            --stderr-child-event-framing "${binary_framing}"
            ${binary_newline_options}
            "${binary_cmd}"
    )
    sr_assert_exit(binary 0)
    sr_assert_files_equal_bytes("${binary_parent_stdout}" "${binary_payload}")
    sr_assert_files_equal_bytes("${binary_parent_stderr}" "${binary_payload}")
    sr_assert_files_equal_bytes("${binary_stdout_log}" "${binary_payload}")
    sr_assert_files_equal_bytes("${binary_stderr_log}" "${binary_payload}")
    sr_assert_directory_file_count("${binary_log_dir}" 2)
    sr_assert_directory_file_count("${binary_diag_dir}" 1)
endforeach()
