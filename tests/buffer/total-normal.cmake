include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Accepts a normal numeric --std-total-max-buffer-bytes value.")
sr_run(r ARGS --std-total-max-buffer-bytes 1024 "${SR_OK}")
sr_assert_exit(r 0)
