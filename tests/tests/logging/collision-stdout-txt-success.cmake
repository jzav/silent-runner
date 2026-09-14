include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Refuses stdout TXT logging with exit code 255 when the success candidate already exists, without overwriting it or starting the child.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-collision-stdout-txt-success")
set(collision_log "${log_dir}/${execution_id}_stdout_success.log")
set(sentinel "SRTEST_COLLISION_SENTINEL")

file(MAKE_DIRECTORY "${log_dir}")
file(WRITE "${collision_log}" "${sentinel}")

sr_run(r ARGS --id-base "${execution_id}" --stdout-dir "${log_dir}" "${SR_OK}")

sr_assert_exit(r "${SR_TEST_EXIT_INTERNAL}")
sr_assert_stdout_not_contains(r "${SR_TEST_CHILD_STDOUT_MARKER}")
sr_assert_file_equals("${collision_log}" "${sentinel}")
sr_assert_directory_file_count("${log_dir}" 1)
