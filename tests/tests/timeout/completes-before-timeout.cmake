include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Normal completion waits for descendants and accepts runtime-failure abort configuration.")
sr_run(r ARGS --timeout-ms 5000 "${SR_OK}")
sr_assert_exit(r 0)

# Enabling the optional runtime-failure abort policy must not affect
# a successful execution.
sr_run(guarded ARGS
    --abort-on-runtime-failure
    --timeout-ms 5000
    "${SR_OK}"
)
sr_assert_exit(guarded 0)
sr_assert_stdout_contains(guarded "${SR_TEST_CHILD_STDOUT_MARKER}")

# The main child exits successfully while its descendant is still running.
# SilentRunner must wait for process-tree completion, not just the main child.
sr_make_process_tree_fixture(tree 4)

# Make the descendant exit with code 7 while the launcher still exits with 0.
set(descendant_path "${SR_TEST_ROOT}/tree-descendant.cmd")
file(READ "${descendant_path}" descendant_script)
string(REPLACE "exit /b 0" "exit 7" descendant_script "${descendant_script}")
file(WRITE "${descendant_path}" "${descendant_script}")

sr_run(tree ARGS
    --debug
    --timeout-ms 10000
    "${tree_LAUNCHER}"
)

sr_assert_exit(tree 0)
sr_assert_path_exists("${tree_STARTED}")
sr_assert_path_exists("${tree_FINISHED}")

# IOCP diagnostics must expose the descendant's individual exit code.
# Either exit notification is acceptable; notification ordering is not fixed.
string(REGEX MATCH
    " (EXIT_PROCESS|ABNORMAL_EXIT) [^\r\n]*EXIT_CODE=7"
    descendant_exit_event
    "${tree_STDERR}"
)
if(descendant_exit_event STREQUAL "")
    sr_failure_context(tree context)
    message(FATAL_ERROR
        "Missing IOCP exit event with descendant EXIT_CODE=7.\n${context}"
    )
endif()
