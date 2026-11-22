include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Rejects all conflicting stderr emitters involving Raw child stderr, in either argument order.")
sr_run(r ARGS --stderr-emit stream --stderr-emit-child stream "${SR_OK}")
sr_assert_exit(r "${SR_TEST_EXIT_CLI_ERROR}")
# Raw child-stderr emission is mutually exclusive with every other stderr
# parent emitter, including when its selected mode is never.
foreach(peer_option IN ITEMS
    --stderr-emit
    --stderr-emit-child
    --stderr-emit-sr
    --stderr-emit-incl-stdout
)
    if(peer_option STREQUAL "--stderr-emit" OR
       peer_option STREQUAL "--stderr-emit-child")
        set(expected_conflict
            "Mutually exclusive options: ${peer_option} and --stderr-emit-child-raw"
        )
    else()
        set(expected_conflict
            "Mutually exclusive options: --stderr-emit-child-raw and ${peer_option}"
        )
    endif()
    sr_run(raw_last ARGS
        "${peer_option}" stream
        --stderr-emit-child-raw never
        "${SR_OK}"
    )
    sr_assert_exit(raw_last "${SR_TEST_EXIT_CLI_ERROR}")
    sr_assert_stdout_empty(raw_last)
    sr_assert_stderr_contains(raw_last "${expected_conflict}")
    sr_run(raw_first ARGS
        --stderr-emit-child-raw never
        "${peer_option}" stream
        "${SR_OK}"
    )
    sr_assert_exit(raw_first "${SR_TEST_EXIT_CLI_ERROR}")
    sr_assert_stdout_empty(raw_first)
    sr_assert_stderr_contains(raw_first "${expected_conflict}")
endforeach()
