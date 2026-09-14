include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Exposes empty hook environment variables for logs removed by retention policy.")
set(log_dir "${SR_TEST_ROOT}/logs")
sr_run(r ARGS
    --id-base ctest-hook-no-log
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
    --stdout-dir-keep-log failure
    --stderr-dir-keep-log failure
    --stderr-dir-child-keep-log failure
    --stderr-dir-sr-keep-log failure
    --stderr-dir-incl-stdout-keep-log failure
    --stdout-emit never
    --run-on-success hook-env.cmd
    "${SR_BOTH_CMD}"
)
sr_assert_exit(r 0)
set(env_file "${SR_TEST_ROOT}/hook-env.txt")
sr_wait_for_path("${env_file}")
sr_assert_file_contains("${env_file}" "STDOUT_LOG=[]")
sr_assert_file_contains("${env_file}" "STDOUT_JSONL_LOG=[]")
sr_assert_file_contains("${env_file}" "STDERR_LOG=[]")
sr_assert_file_contains("${env_file}" "STDERR_JSONL_LOG=[]")
sr_assert_file_contains("${env_file}" "STDERR_CHILD_LOG=[]")
sr_assert_file_contains("${env_file}" "STDERR_CHILD_JSONL_LOG=[]")
sr_assert_file_contains("${env_file}" "STDERR_SR_LOG=[]")
sr_assert_file_contains("${env_file}" "STDERR_SR_JSONL_LOG=[]")
sr_assert_file_contains("${env_file}" "STDERR_INCL_STDOUT_LOG=[]")
sr_assert_file_contains("${env_file}" "STDERR_INCL_STDOUT_JSONL_LOG=[]")
