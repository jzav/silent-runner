include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Replays one LF-framed TXT child event larger than the 64 KiB TXT replay read buffer without loss or duplication.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-replay-txt-large-event")
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

set(payload_file "${SR_TEST_ROOT}/large-event.bin")
set(child_cmd "${SR_TEST_ROOT}/large-event.cmd")
set(parent_stdout_file "${SR_TEST_ROOT}/parent-stdout.bin")

string(REPEAT "A" 65520 large_prefix)
string(REPEAT "B" 10000 large_suffix)

set(
    large_payload
    "${large_prefix}N4_LARGE_BOUNDARY${large_suffix}"
)

sr_write_lf_terminated_fixture(
    "${payload_file}"
    "${large_payload}"
)

file(SIZE "${payload_file}" payload_size)
if(NOT payload_size EQUAL 75538)
    message(FATAL_ERROR
        "Large TXT event fixture construction failed: expected 75538 bytes, got ${payload_size}."
    )
endif()

sr_write_type_emitter_cmd(
    "${child_cmd}"
    "${payload_file}"
    stdout
)

sr_run(
    r
    OUTPUT_FILE "${parent_stdout_file}"
    ARGS
        --debug
        --id-base "${execution_id}"
        --stdout-dir "${log_dir}"
        --stdout-event-framing lf
        --stdout-event-newline-max-bytes 131072
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

sr_assert_single_txt_output_payload_equals_file(
    "${expected_log}"
    "${payload_file}"
    "CHILDSTDOUT"
)

sr_assert_single_txt_output_payload_equals_file(
    "${parent_stdout_file}"
    "${payload_file}"
    "CHILDSTDOUT"
)

sr_assert_file_occurrence_count(
    "${expected_log}"
    "N4_LARGE_BOUNDARY"
    1
)
sr_assert_file_occurrence_count(
    "${parent_stdout_file}"
    "N4_LARGE_BOUNDARY"
    1
)

sr_assert_directory_file_count("${log_dir}" 1)

# Raw persistent replay must copy an event spanning the 64 KiB file-read
# boundary without adding headers, dropping bytes, or duplicating the tail.
set(raw_log_dir "${SR_TEST_ROOT}/raw-logs")
set(raw_execution_id "ctest-raw-large-event")
set(raw_running_log
    "${raw_log_dir}/${raw_execution_id}_stdout_raw_running.log"
)
set(raw_final_log
    "${raw_log_dir}/${raw_execution_id}_stdout_raw_success.log"
)
set(raw_parent_file "${SR_TEST_ROOT}/raw-large-parent.bin")
cmake_path(NATIVE_PATH raw_running_log NORMALIZE raw_running_log_native)

sr_run(raw OUTPUT_FILE "${raw_parent_file}" ARGS
    --debug
    --id-base "${raw_execution_id}"
    --stdout-emit-raw end
    --stdout-dir-raw "${raw_log_dir}"
    --stdout-event-framing lf
    --stdout-event-newline-max-bytes 131072
    --stderr-emit-sr stream
    "${child_cmd}"
)
sr_assert_exit(raw 0)
sr_assert_stderr_contains(raw
    "stdout={target=StdoutParentRaw source=Txt path=${raw_running_log_native}}"
)
sr_assert_files_equal_bytes("${raw_parent_file}" "${payload_file}")
sr_assert_files_equal_bytes("${raw_final_log}" "${payload_file}")
sr_assert_directory_file_count("${raw_log_dir}" 1)
