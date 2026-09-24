include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Applies stdout and stderr-child framing modes and thresholds independently during the same execution.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-framing-independent-streams")

set(stdout_log
    "${log_dir}/${execution_id}_stdout_success.jsonl"
)
set(stderr_log
    "${log_dir}/${execution_id}_stderr_child_success.jsonl"
)

set(stdout_payload_file "${SR_TEST_ROOT}/independent-stdout.bin")
set(stdout_lf_part "${SR_TEST_ROOT}/independent-stdout-lf.bin")
set(stdout_tail_part "${SR_TEST_ROOT}/independent-stdout-tail.bin")

set(stderr_payload_file "${SR_TEST_ROOT}/independent-stderr.bin")
set(stderr_lf_part "${SR_TEST_ROOT}/independent-stderr-lf.bin")
set(stderr_crlf_part "${SR_TEST_ROOT}/independent-stderr-crlf.bin")
set(stderr_tail_part "${SR_TEST_ROOT}/independent-stderr-tail.bin")

set(child_cmd "${SR_TEST_ROOT}/independent-streams.cmd")

string(ASCII 10 lf)
string(ASCII 13 cr)

# stdout exact bytes:
#   41 0a 42 43
#   A  LF B  C
#
# LF framing with threshold 2 must produce:
#   A LF | BC
sr_write_lf_terminated_fixture("${stdout_lf_part}" "A")
file(WRITE "${stdout_tail_part}" "BC")

sr_concat_files(
    "${stdout_payload_file}"
    "${stdout_lf_part}"
    "${stdout_tail_part}"
)

sr_assert_file_hex(
    "${stdout_payload_file}"
    "410a4243"
)

# stderr exact bytes:
#   58 0a 59 0d 0a 5a
#   X  LF Y  CR LF Z
#
# CRLF framing with threshold 64 must produce:
#   X LF Y CR LF | Z
#
# The lone LF must remain inside the first stderr event.
sr_write_lf_terminated_fixture("${stderr_lf_part}" "X")
sr_write_crlf_terminated_fixture("${stderr_crlf_part}" "Y")
file(WRITE "${stderr_tail_part}" "Z")

sr_concat_files(
    "${stderr_payload_file}"
    "${stderr_lf_part}"
    "${stderr_crlf_part}"
    "${stderr_tail_part}"
)

sr_assert_file_hex(
    "${stderr_payload_file}"
    "580a590d0a5a"
)

file(WRITE
    "${child_cmd}"
    "@echo off\r\n"
    "type \"%~dp0independent-stdout.bin\"\r\n"
    "type \"%~dp0independent-stderr.bin\" 1>&2\r\n"
    "exit /b 0\r\n"
)

sr_run(r ARGS
    --id-base "${execution_id}"
    --stdout-dir-jsonl "${log_dir}"
    --stderr-dir-child-jsonl "${log_dir}"
    --stdout-event-framing lf
    --stdout-event-newline-max-bytes 2
    --stderr-child-event-framing crlf
    --stderr-child-event-newline-max-bytes 64
    --stdout-emit never
    --stderr-emit-sr stream
    "${child_cmd}"
)

sr_assert_exit(r 0)
sr_assert_stdout_empty(r)
sr_assert_directory_file_count("${log_dir}" 2)

sr_assert_jsonl_text_event_sequence(
    "${stdout_log}"
    "ChildStdout"
    "A${lf}"
    "BC"
)

sr_assert_jsonl_text_event_sequence(
    "${stderr_log}"
    "ChildStderr"
    "X${lf}Y${cr}${lf}"
    "Z"
)
