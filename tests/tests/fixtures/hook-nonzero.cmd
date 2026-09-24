@echo off
> "%~dp0hook-nonzero.tmp" echo HOOK_RAN
move /y "%~dp0hook-nonzero.tmp" "%~dp0hook-nonzero.txt" >nul
exit /b 23
