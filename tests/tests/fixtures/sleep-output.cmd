@echo off
echo BEFORE_TIMEOUT
>&2 echo STDERR_BEFORE_TIMEOUT
ping 127.0.0.1 -n 6 >nul
exit /b 0
