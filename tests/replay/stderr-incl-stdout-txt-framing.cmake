include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Replays LF-framed child stdout and stderr events independently from the combined stderr-including-stdout TXT source.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-replay-stderr-incl-stdout-txt-framing")
set(expected_log
    "${log_dir}/${execution_id}_stderr_incl_stdout_success.log"
)
set(expected_running_log
    "${log_dir}/${execution_id}_stderr_incl_stdout_running.log"
)

cmake_path(
    NATIVE_PATH expected_running_log
    NORMALIZE expected_running_log_native
)

set(stdout_payload "${SR_TEST_ROOT}/mixed-stdout.bin")
set(stdout_first "${SR_TEST_ROOT}/mixed-stdout-first.bin")
set(stdout_second "${SR_TEST_ROOT}/mixed-stdout-second.bin")

set(stderr_payload "${SR_TEST_ROOT}/mixed-stderr.bin")
set(stderr_first "${SR_TEST_ROOT}/mixed-stderr-first.bin")
set(stderr_second "${SR_TEST_ROOT}/mixed-stderr-second.bin")

set(child_cmd "${SR_TEST_ROOT}/mixed-streams.cmd")

sr_write_lf_terminated_fixture(
    "${stdout_first}"
    "N4_MIX_OUT1"
)
sr_write_lf_terminated_fixture(
    "${stdout_second}"
    "N4_MIX_OUT2"
)
sr_concat_files(
    "${stdout_payload}"
    "${stdout_first}"
    "${stdout_second}"
)

sr_write_lf_terminated_fixture(
    "${stderr_first}"
    "N4_MIX_ERR1"
)
sr_write_lf_terminated_fixture(
    "${stderr_second}"
    "N4_MIX_ERR2"
)
sr_concat_files(
    "${stderr_payload}"
    "${stderr_first}"
    "${stderr_second}"
)

file(WRITE
    "${child_cmd}"
    "@echo off\r\n"
    "type \"%~dp0mixed-stdout.bin\"\r\n"
    "type \"%~dp0mixed-stderr.bin\" 1>&2\r\n"
    "exit /b 0\r\n"
)

sr_run(r ARGS
    --debug
    --id-base "${execution_id}"
    --stderr-dir-incl-stdout "${log_dir}"
    --stdout-event-framing lf
    --stdout-event-newline-max-bytes 64
    --stderr-child-event-framing lf
    --stderr-child-event-newline-max-bytes 64
    --stdout-emit never
    --stderr-emit-incl-stdout end
    "${child_cmd}"
)

sr_assert_exit(r 0)
sr_assert_stdout_empty(r)

sr_assert_stderr_contains(
    r
    "[PARENT-REPLAY] Replay completed with result ok using plan: "
)
sr_assert_stderr_contains(
    r
    "stderr={target=StderrSrAndChildInclStdoutParent source=Txt path=${expected_running_log_native}}"
)

# stdout and stderr pipes are drained independently, so this test deliberately
# checks per-stream event framing without assuming cross-pipe chronology.
sr_assert_stderr_occurrence_count(
    r
    "[payloadType=CHILDSTDOUT]"
    2
)
sr_assert_stderr_occurrence_count(
    r
    "[payloadType=CHILDSTDERR]"
    2
)

foreach(marker IN ITEMS
    N4_MIX_OUT1
    N4_MIX_OUT2
    N4_MIX_ERR1
    N4_MIX_ERR2
)
    sr_assert_stderr_occurrence_count(r "${marker}" 1)
endforeach()

sr_assert_file_not_empty("${expected_log}")
sr_assert_file_occurrence_count(
    "${expected_log}"
    "[payloadType=CHILDSTDOUT]"
    2
)
sr_assert_file_occurrence_count(
    "${expected_log}"
    "[payloadType=CHILDSTDERR]"
    2
)

foreach(marker IN ITEMS
    N4_MIX_OUT1
    N4_MIX_OUT2
    N4_MIX_ERR1
    N4_MIX_ERR2
)
    sr_assert_file_occurrence_count(
        "${expected_log}"
        "${marker}"
        1
    )
endforeach()

sr_assert_directory_file_count("${log_dir}" 1)
