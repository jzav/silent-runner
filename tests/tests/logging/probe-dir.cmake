include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Creates probe logs in literal and environment-expanded directories, rejecting undefined variables.")
set(log_dir "${SR_TEST_ROOT}/probe")
set(expected_log "${log_dir}/ctest-probe_probe.log")
sr_run(r ARGS --id-base ctest-probe --probe-dir "${log_dir}" "${SR_OK}")
sr_assert_exit(r 0)
sr_assert_file_not_empty("${expected_log}")
sr_assert_directory_file_count("${log_dir}" 1)
sr_run(expanded_probe
    ENV "SR_D4_PROBE_DIR=expanded-probe"
    ARGS --id-base d4-expanded-probe --probe-dir "%SR_D4_PROBE_DIR%" "${SR_OK}"
)
sr_assert_exit(expanded_probe 0)
sr_assert_file_not_empty("${SR_TEST_ROOT}/expanded-probe/d4-expanded-probe_probe.log")
sr_run(undefined_probe
    UNSET_ENV SR_D4_MISSING_PROBE_DIR
    ARGS --probe-dir "%SR_D4_MISSING_PROBE_DIR%" "${SR_OK}"
)
sr_assert_exit(undefined_probe "${SR_TEST_EXIT_CLI_ERROR}")
sr_assert_stdout_not_contains(undefined_probe "${SR_TEST_CHILD_STDOUT_MARKER}")
sr_run(empty_probe ENV "SR_D4_EMPTY_PROBE_DIR="
    ARGS --probe-dir "%SR_D4_EMPTY_PROBE_DIR%" "${SR_OK}")
sr_assert_exit(empty_probe "${SR_TEST_EXIT_CLI_ERROR}")
