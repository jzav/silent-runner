SilentRunner CMake/CTest regression suite
=============================================

This project is a black-box regression suite for SilentRunner.exe.
It uses standard CMake/CTest orchestration and CMake script-mode tests.
There is one CMakeLists.txt only: the one in the project root.

Current registered test count: 239

Directory layout
----------------

    CMakeLists.txt
    README.txt
    TEST-PLAN.txt
    tests/
        helpers/
            SRTest.cmake
        fixtures/
            *.cmd
        parser/
        id/
        path/
        cwd/
        hooks/
        command/
        utf8/
        timeout/
        emit/
        replay/
        logging/
        retention/
        buffer/
        comspec/
        help/
        defaults/
        cross/

How it works
------------

The root CMakeLists.txt registers every test with add_test().
Each CTest case starts CMake in script mode (-P) for one .cmake test file.
The test script creates an isolated sandbox, copies simple .cmd fixtures,
runs SilentRunner.exe with execute_process(), and asserts exit code/output/files.

Configure and run
-----------------

1. Configure the test project (in the test project root):

    cmake -S . -B build -DSILENTRUNNER_EXE=%SR_EXE%

   If SR_EXE is not an environment variable, provide the executable path directly.

2. Run all tests:

    ctest --test-dir build --output-on-failure

Useful CTest commands
---------------------

List all registered tests without running them:
	ctest --test-dir build -N

Run tests in verbose mode. Displays each test's behavioral description
and full test output:
	ctest --test-dir build -V

Run tests whose names match a regular expression:
	ctest --test-dir build -R "hooks\."

Run all tests with a given label and show output for failed tests:
	ctest --test-dir build -L logging --output-on-failure

Run tests in parallel using up to 8 jobs and show output for failed tests:
	ctest --test-dir build -j 8 --output-on-failure

Rerun only tests that failed in the previous CTest run and show their
output if they fail again:
	ctest --test-dir build --rerun-failed --output-on-failure

Notes
-----

- Every test gets a clean work directory under build/tests/work/.
- Run hooks are detached, so hook tests poll for their marker/output file.
- TXT log files use the current SilentRunner .log naming convention.
- JSONL tests inspect structural markers rather than duplicating the full parser.
- The suite intentionally does not require PowerShell or a custom test-runner EXE.
- The advanced scenarios like the ones listed as DEFERRED in TEST-PLAN.txt are intentionally
  excluded for now
