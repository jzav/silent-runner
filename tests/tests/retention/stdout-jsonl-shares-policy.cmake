include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Applies the stdout keep-log policy to TXT and JSONL logs together.")
set(log_dir "${SR_TEST_ROOT}/logs")
sr_run(r ARGS
    --id-base ctest-jsonl-policy
    --stdout-dir "${log_dir}"
    --stdout-dir-jsonl "${log_dir}"
    --stdout-dir-keep-log success
    --stdout-emit never
    "${SR_FAIL}"
)
sr_assert_exit(r "${SR_TEST_FAIL_CMD_EXIT_CODE}")
sr_assert_directory_file_count("${log_dir}" 0)
