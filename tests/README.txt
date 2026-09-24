SilentRunner CMake/CTest regression suite
=============================================

This repository contains the SilentRunner build and its black-box regression suite.
It uses standard CMake/CTest orchestration and CMake script-mode tests.

The repository-root CMakeLists.txt builds SilentRunner and includes tests/ when
BUILD_TESTING is enabled. tests/CMakeLists.txt can also be configured standalone
against an existing SilentRunner.exe.

Current registered test count: 288












Directory layout
----------------

    CMakeLists.txt
    README.txt
    TEST-PLAN.txt
    src/
    tests/
        CMakeLists.txt
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
        framing/
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

The repository-root CMakeLists.txt builds SilentRunner and includes the tests/
subdirectory in integrated mode. tests/CMakeLists.txt registers every CTest case
with add_test(). Each CTest case starts CMake in script mode (-P) for one .cmake
test file. The test script creates an isolated sandbox, uses or creates its
fixtures, runs SilentRunner.exe with execute_process(), and asserts
exit code/output/files.


Configure and run
-----------------

Integrated mode - build SilentRunner and run its tests:

1. Configure from the repository root:

    cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_CXX_COMPILER=g++ -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON

2. Build SilentRunner:

    cmake --build build

3. Run all tests:

    ctest --test-dir build --output-on-failure

For a multi-config generator, use the same configuration for both build and
CTest, for example:

    cmake --build build --config Release
    ctest --test-dir build -C Release --output-on-failure

Standalone mode - test an already existing SilentRunner.exe without building it:

1. From the tests/ directory, configure the test suite:

    cmake -S . -B build-tests -DSILENTRUNNER_EXE=%SR_EXE%

   If SR_EXE is not an environment variable, provide the executable path directly.

2. Run all tests:

    ctest --test-dir build-tests --output-on-failure


Useful CTest commands (standalone mode)

---------------------

List all registered tests without running them:
	ctest --test-dir build-tests -N


Run tests in verbose mode. Displays each test's behavioral description
and full test output:
	ctest --test-dir build-tests -V


Run tests whose names match a regular expression:
	ctest --test-dir build-tests -R "hooks\."


Run all tests with a given label and show output for failed tests:
	ctest --test-dir build-tests -L logging --output-on-failure


Run tests in parallel using up to 8 jobs and show output for failed tests:
	ctest --test-dir build-tests -j 8 --output-on-failure


Rerun only tests that failed in the previous CTest run and show their
output if they fail again:
	ctest --test-dir build-tests --rerun-failed --output-on-failure


Notes
-----

- Every test gets a clean work directory under build/tests/work/.
- Run hooks are detached, so hook tests poll for their marker/output file.
- TXT log files use the current SilentRunner .log naming convention.
- JSONL tests use CMake's string(JSON) support when exact schema fields, metadata, or decoded payload values need validation.
- The suite intentionally does not require PowerShell or a custom test-runner EXE.
- The advanced scenarios like the ones listed as DEFERRED in TEST-PLAN.txt are intentionally
  excluded for now
