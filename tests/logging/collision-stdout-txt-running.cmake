include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Refuses pre-existing Headered and Raw log candidates in running, success, or failure state without overwriting them.")

set(log_dir "${SR_TEST_ROOT}/logs")
set(execution_id "ctest-collision-stdout-txt-running")
set(collision_log "${log_dir}/${execution_id}_stdout_running.log")
set(sentinel "SRTEST_COLLISION_SENTINEL")

file(MAKE_DIRECTORY "${log_dir}")
file(WRITE "${collision_log}" "${sentinel}")

sr_run(r ARGS --id-base "${execution_id}" --stdout-dir "${log_dir}" "${SR_OK}")

sr_assert_exit(r "${SR_TEST_EXIT_INTERNAL}")
sr_assert_stdout_not_contains(r "${SR_TEST_CHILD_STDOUT_MARKER}")
sr_assert_file_equals("${collision_log}" "${sentinel}")
sr_assert_directory_file_count("${log_dir}" 1)
# Check both Raw log target types and all three candidate result suffixes.
# Every case has its own directory so that earlier assertions cannot mask
# unexpected log creation or cleanup by the current case.
foreach(raw_target IN ITEMS stdout stderr-child)
    if(raw_target STREQUAL "stdout")
        set(raw_dir_option --stdout-dir-raw)
        set(raw_filename_component stdout_raw)
    else()
        set(raw_dir_option --stderr-dir-child-raw)
        set(raw_filename_component stderr_child_raw)
    endif()
    foreach(raw_state IN ITEMS running success failure)
        set(raw_case_dir "${SR_TEST_ROOT}/raw/${raw_target}/${raw_state}")
        set(raw_execution_id "ctest-collision-${raw_target}-raw-${raw_state}")
        set(raw_collision_log
            "${raw_case_dir}/${raw_execution_id}_${raw_filename_component}_${raw_state}.log"
        )
        file(MAKE_DIRECTORY "${raw_case_dir}")
        file(WRITE "${raw_collision_log}" "${sentinel}")
        sr_run(raw ARGS
            --id-base "${raw_execution_id}"
            "${raw_dir_option}" "${raw_case_dir}"
            "${SR_OK}"
        )
        sr_assert_exit(raw "${SR_TEST_EXIT_INTERNAL}")
        sr_assert_stdout_not_contains(raw "${SR_TEST_CHILD_STDOUT_MARKER}")
        sr_assert_file_equals("${raw_collision_log}" "${sentinel}")
        sr_assert_directory_file_count("${raw_case_dir}" 1)
    endforeach()
endforeach()
