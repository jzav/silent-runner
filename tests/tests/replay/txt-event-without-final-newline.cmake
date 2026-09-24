include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Replays an LF-framed final TXT event without a terminating newline byte-exactly and does not synthesize one.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-replay-txt-event-without-final-newline")
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

set(payload_file "${SR_TEST_ROOT}/without-final-newline.bin")
set(child_cmd "${SR_TEST_ROOT}/without-final-newline.cmd")
set(parent_stdout_file "${SR_TEST_ROOT}/parent-stdout.bin")

file(WRITE "${payload_file}" "N4_NO_FINAL_LF")

sr_assert_file_hex(
    "${payload_file}"
    "4e345f4e4f5f46494e414c5f4c46"
)

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

sr_assert_directory_file_count("${log_dir}" 1)
