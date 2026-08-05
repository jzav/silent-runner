@echo off
setlocal

rem ============================================================================
rem SilentRunner release build
rem Target toolchain: MinGW g++
rem Output: SilentRunner.exe
rem ============================================================================

set "SCRIPT_DIR=%~dp0"
pushd "%SCRIPT_DIR%" || exit /b 1

set "OUTPUT=SilentRunner.exe"
set "CXX=g++"
set "CXXFLAGS=-std=c++17 -O2 -static-libgcc -static-libstdc++ -s -mwindows -municode"
set "SOURCES=*.cpp"
set "LDLIBS=-lbcrypt"

echo [INFO] Building %OUTPUT%...
%CXX% %CXXFLAGS% -o "%OUTPUT%" %SOURCES% %LDLIBS%
if errorlevel 1 (
    echo [ERROR] Build failed.
    popd
    exit /b 1
)

echo [OK] Build succeeded: %SCRIPT_DIR%%OUTPUT%
popd
exit /b 0