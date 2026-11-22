@echo off
> "%~dp0hook-cwd.tmp" echo CWD=[%CD%]
move /y "%~dp0hook-cwd.tmp" "%~dp0hook-cwd.txt" >nul
exit /b 0
