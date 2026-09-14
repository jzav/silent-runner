include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Accepts one millisecond as the lower nonzero --timeout-ms boundary.")
sr_run(r ARGS --timeout-ms 1 "${SR_OK}")
# 1 ms is intentionally a parser boundary test. Depending on scheduling, the
# trivial child may either finish first (0) or legitimately time out (124).
sr_assert_exit_one_of(r 0 "${SR_TEST_EXIT_TIMEOUT}")
