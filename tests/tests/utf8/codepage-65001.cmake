include("${SR_TESTS_SOURCE_DIR}/helpers/SRTest.cmake")
sr_test_init(DESCRIPTION "Verifies default and UTF-8 child execution, including cmd.exe-expanded script paths.")
sr_run(default_cp ARGS --debug "${SR_PRINT_CODEPAGE}")
sr_assert_exit(default_cp 0)
sr_assert_stderr_contains(default_cp "fullCmdLine=")
sr_assert_stderr_not_contains(default_cp "chcp 65001")
sr_run(utf8_cp ARGS --debug --utf8 "${SR_PRINT_CODEPAGE}")
sr_assert_exit(utf8_cp 0)
sr_assert_stdout_contains(utf8_cp "65001")
sr_assert_stderr_contains(utf8_cp "chcp 65001")
sr_run(expanded_utf8
    ENV "SR_D4_CODEPAGE_SCRIPT=${SR_PRINT_CODEPAGE}"
    ARGS --utf8 "%SR_D4_CODEPAGE_SCRIPT%"
)
sr_assert_exit(expanded_utf8 0)
sr_assert_stdout_contains(expanded_utf8 "65001")
