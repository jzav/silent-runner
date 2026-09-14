include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Creates all ten persistent log destinations in parallel for one failed execution.")
set(log_dir "${SR_TEST_ROOT}/logs")
sr_run(r ARGS
    --id-base ctest-all-logs
    --stdout-dir "${log_dir}"
    --stdout-dir-jsonl "${log_dir}"
    --stderr-dir "${log_dir}"
    --stderr-dir-jsonl "${log_dir}"
    --stderr-dir-child "${log_dir}"
    --stderr-dir-child-jsonl "${log_dir}"
    --stderr-dir-sr "${log_dir}"
    --stderr-dir-sr-jsonl "${log_dir}"
    --stderr-dir-incl-stdout "${log_dir}"
    --stderr-dir-incl-stdout-jsonl "${log_dir}"
    "${SR_FAIL}"
)
sr_assert_exit(r "${SR_TEST_FAIL_CMD_EXIT_CODE}")
sr_assert_directory_file_count("${log_dir}" 10)
