include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Timeout returns 124 and terminates descendants that outlive the main child.")
sr_run(r ARGS --timeout-ms 100 "${SR_SLEEP}")
sr_assert_exit(r "${SR_TEST_EXIT_TIMEOUT}")

# The launcher exits successfully, but its descendant remains active.
# The timeout must still terminate the entire Job Object process tree.
sr_make_process_tree_fixture(tree_timeout 5)

sr_run(tree ARGS
    --timeout-ms 2000
    --stderr-emit-sr stream
    "${tree_timeout_LAUNCHER}"
)

sr_assert_exit(tree "${SR_TEST_EXIT_TIMEOUT}")
sr_assert_path_exists("${tree_timeout_STARTED}")
sr_assert_stderr_contains(
    tree
    "Runtime stop: Timeout exceeded; timeout_ms=2000 exit_code=124"
)

# Wait beyond the descendant's expected completion time.
# If it survived the timeout, it would create the finished marker.
execute_process(COMMAND "${CMAKE_COMMAND}" -E sleep 5)
sr_assert_path_not_exists("${tree_timeout_FINISHED}")
