include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Keeps the successful child result when a detached success hook starts and later exits non-zero.")

sr_run(r ARGS --run-on-success hook-nonzero.cmd "${SR_OK}")

sr_assert_exit(r 0)
set(marker_file "${SR_TEST_ROOT}/hook-nonzero.txt")
sr_wait_for_path("${marker_file}")
sr_assert_file_contains("${marker_file}" "HOOK_RAN")
