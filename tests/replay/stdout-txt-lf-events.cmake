include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Replays LF-framed stdout TXT events with one preserved parent header and payload per child event.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-replay-stdout-txt-lf-events")
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

set(payload_file "${SR_TEST_ROOT}/replay-lf-events.bin")
set(first_part "${SR_TEST_ROOT}/replay-lf-first.bin")
set(second_part "${SR_TEST_ROOT}/replay-lf-second.bin")
set(child_cmd "${SR_TEST_ROOT}/replay-lf-events.cmd")

string(ASCII 10 lf)

sr_write_lf_terminated_fixture(
    "${first_part}"
    "N4_REPLAY_ONE"
)
sr_write_lf_terminated_fixture(
    "${second_part}"
    "N4_REPLAY_TWO"
)

sr_concat_files(
    "${payload_file}"
    "${first_part}"
    "${second_part}"
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

sr_assert_stdout_txt_header(r "CHILDSTDOUT")
sr_assert_stdout_occurrence_count(
    r
    "[payloadType=CHILDSTDOUT]"
    2
)
sr_assert_stdout_occurrence_count(
    r
    "[payloadByteCount=14]"
    2
)
sr_assert_stdout_occurrence_count(r "N4_REPLAY_ONE" 1)
sr_assert_stdout_occurrence_count(r "N4_REPLAY_TWO" 1)

sr_assert_file_not_empty("${expected_log}")
sr_assert_file_occurrence_count(
    "${expected_log}"
    "[payloadType=CHILDSTDOUT]"
    2
)
sr_assert_file_occurrence_count(
    "${expected_log}"
    "[payloadByteCount=14]"
    2
)
sr_assert_file_occurrence_count(
    "${expected_log}"
    "N4_REPLAY_ONE"
    1
)
sr_assert_file_occurrence_count(
    "${expected_log}"
    "N4_REPLAY_TWO"
    1
)

sr_assert_directory_file_count("${log_dir}" 1)
