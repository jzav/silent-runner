include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Ensures SilentRunner-generated hook environment values override same-named inherited environment variables.")

sr_run(r
    ENV
        "SILENTRUNNER_EXIT_CODE=N6_INHERITED"
        "SILENTRUNNER_EXECUTION_ID=N6_INHERITED"
        "SILENTRUNNER_STDOUT_LOG=N6_INHERITED"
        "SILENTRUNNER_STDOUT_JSONL_LOG=N6_INHERITED"
        "SILENTRUNNER_STDERR_LOG=N6_INHERITED"
        "SILENTRUNNER_STDERR_JSONL_LOG=N6_INHERITED"
        "SILENTRUNNER_STDERR_CHILD_LOG=N6_INHERITED"
        "SILENTRUNNER_STDERR_CHILD_JSONL_LOG=N6_INHERITED"
        "SILENTRUNNER_STDERR_SR_LOG=N6_INHERITED"
        "SILENTRUNNER_STDERR_SR_JSONL_LOG=N6_INHERITED"
        "SILENTRUNNER_STDERR_INCL_STDOUT_LOG=N6_INHERITED"
        "SILENTRUNNER_STDERR_INCL_STDOUT_JSONL_LOG=N6_INHERITED"
    ARGS
        --id-base ctest-hook-env-override
        --run-on-success hook-env.cmd
        "${SR_OK}"
)

sr_assert_exit(r 0)

set(env_file "${SR_TEST_ROOT}/hook-env.txt")
sr_wait_for_path("${env_file}")

sr_assert_file_contains(
    "${env_file}"
    "EXIT_CODE=[0]"
)
sr_assert_file_contains(
    "${env_file}"
    "EXECUTION_ID=[ctest-hook-env-override]"
)

foreach(variable_name IN ITEMS
    STDOUT_LOG
    STDOUT_JSONL_LOG
    STDERR_LOG
    STDERR_JSONL_LOG
    STDERR_CHILD_LOG
    STDERR_CHILD_JSONL_LOG
    STDERR_SR_LOG
    STDERR_SR_JSONL_LOG
    STDERR_INCL_STDOUT_LOG
    STDERR_INCL_STDOUT_JSONL_LOG
)
    sr_assert_file_contains(
        "${env_file}"
        "${variable_name}=[]"
    )
endforeach()

sr_assert_file_not_contains(
    "${env_file}"
    "N6_INHERITED"
)
