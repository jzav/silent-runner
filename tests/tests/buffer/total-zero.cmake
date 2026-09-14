include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Accepts zero for --std-total-max-buffer-bytes.")
sr_run(r ARGS --std-total-max-buffer-bytes 0 "${SR_OK}")
sr_assert_exit(r 0)
