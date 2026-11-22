@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "ERRORLEVEL="

rem Do not redirect this invocation or disable diagnostics explicitly.
rem Verify that the nested SilentRunner succeeds despite the missing diagnostic channel.
"%SR_TEST_NESTED_EXE%" "%~dp0ok.cmd"
set "nested_exit_code=%ERRORLEVEL%"

rem Publish the completed result atomically for the waiting CMake test.
> "%~dp0hook-nested-no-diagnostic-channel.tmp" echo %nested_exit_code%
move /y "%~dp0hook-nested-no-diagnostic-channel.tmp" "%~dp0hook-nested-no-diagnostic-channel.txt" >nul
exit /b 0
