// SilentRunner.cpp - run hidden and capture stdout+stderr (Windows)
// -----------------------------------------------------------
//
//
// What it does
//   - Runs a command via cmd.exe so that pipes (|), conditionals (&&), and builtins (echo, chcp, etc.) work.
//   - Hides any console window (CREATE_NO_WINDOW + Windows subsystem).
//   - Captures BOTH stdout and stderr without deadlocks by draining both pipes concurrently.
//   - Writes captured bytes back to THIS process stdout/stderr, so a caller can capture them from there.
//   - Returns the child exit code.
//   - Optional timeout that kills the process tree best-effort.
//
// Important behavior and design notes
//   - Built as a Windows GUI subsystem (/SUBSYSTEM:WINDOWS) → no console window flashes.
//     Works with stdout/stderr when launched by a parent that supplies handles
//     (redirected console, automation runners, etc.).
//
//   - Child process is executed via `cmd.exe /d /s /c "<inner>"`.
//     /d → disables AutoRun commands from registry (prevents unwanted autorun injections)
//     /s → preserves quoted strings when passing the inner command
//     /c → executes the command and terminates cmd.exe afterwards
//
//   - stdout and stderr are captured through two separate pipes and drained
//     concurrently in two threads to avoid deadlocks if one stream fills up.
//     Output is fully buffered in memory and written to this process' stdout
//     and stderr only after the child exits.
//
//   - This means:
//       * Execution is synchronous — output is buffered in memory and delivered only after the child exits.
//       * High-volume output increases RAM usage (not suitable for GB-scale logs).
//       * stdout and stderr ordering is NOT preserved — they are replayed sequentially
//         (stdout first, then stderr).
//       * Streams are captured as raw bytes without CRLF/encoding conversion.
//       * The child inherits the parent's current working directory.
//         If your script relies on relative paths, either:
//            - use absolute paths, or
//            - switch to its own directory inside .cmd via `pushd "%~dp0"` and `popd`.
//       * Stdin is bound to NUL — child processes requiring interactive input
//         will see EOF (no input from parent). However, .cmd scripts may still
//         provide input internally using redirection (e.g. `echo text | command`).
//       * Best suited for short/medium tasks where you need hidden execution + captured output.
//       * Not recommended for infinite or long-running processes.
//       * For fire-and-forget long-running tasks where you simply need to hide
//         the window (without capturing output), consider using:
//         nircmd exec hide <command> (https://nircmd.nirsoft.net/exec.html)
//
//   - Quoting notes:
//       * `cmd.exe /s` has non-trivial quoting rules.
//       * For complex one-liners with quotes, pipes or variables,
//         prefer a `.cmd` file (script path mode) over a single `-c` string.
//       * .cmd scripts can receive arguments via %1 %2 ...,
//         so script mode remains flexible even for parametrized tasks.
//       * NOTE: SilentRunner does not escape or sanitize commands. Treat input exactly
//         as you would when writing .cmd/.bat — especially if arguments originate
//         from user input.
//
//   - Exit codes:
//       * 0–254 (except 124): exit code of the child process.
//       * 124: timeout — best-effort termination via `taskkill /T /F`.
//       * 255: internal launcher failure (CreatePipe/CreateProcess, etc.).
//
//
// ---------------------------------------------------------------------------
// Usage examples
// ---------------------------------------------------------------------------
//
// Run simple inline command (no file needed):
// SilentRunner.exe -c "echo Hello & ver"
//
// Run executable with arguments:
// SilentRunner.exe "C:\Tools\app.exe" --mode fast --silent
//
// Run .cmd script with parameters:
// SilentRunner.exe backup.cmd D:\ 30
//
// Inside backup.cmd:
//   @echo off
//   REM `echo off` is recommended to suppress command echo (otherwise each command is echoed before execution)
//   REM you can temporarily remove this for debugging by switching to `echo on`
//   set "DRIVE=%~1"
//   set "DAYS=%~2"
//   echo Backing up %DRIVE% (keeping %DAYS% days)
//
// With UTF-8 enabled:
// SilentRunner.exe --utf8 -c "echo こんにちは"
//   --utf8 prepends `chcp 65001>nul & ...` but does NOT transcode output;
//   it only affects how the child generates text.
//
// With timeout:
// SilentRunner.exe --timeout-ms 5000 -c "long_running_task.cmd"
//
// Providing input inside script using redirection (stdin is NUL externally!):
// ✗ echo yes | SilentRunner.exe -c "somecommand"  ← won't work (stdin=NUL)
// ✓ echo yes | somecommand                        ← OK inside .cmd script
//
//
// ---------------------------------------------------------------------------
// CLI / Switches
// ---------------------------------------------------------------------------
//
//   SilentRunner.exe [options] <script-or-exe> [args...]
//   SilentRunner.exe [options] -c "<raw-cmd>"
//
// Options:
//   --timeout-ms <N>
//       If N > 0, waits at most N milliseconds for the child to exit.
//       On timeout:
//         - attempts to kill the entire process tree (taskkill /T /F),
//         - returns exit code 124,
//         - writes "[SilentRunner] TIMEOUT" to stderr.
//
//   --print-cmdline
//       Writes debug info to stderr (UTF-8):
//         - PID of the spawned cmd.exe process
//         - Full cmdline passed to CreateProcessW (including cmd.exe /d /s /c "...").
//       This is intended for diagnosing quoting/parsing issues.
//
//   --utf8
//       Prefixes the inner command with:
//         chcp 65001>nul & ...
//       This makes cmd.exe and many console programs emit UTF-8 (if they respect console code pages).
//       NOTE: This does not magically force every program to output UTF-8.
//       The captured bytes are still passed through raw.
//
//   -c "<raw-cmd>"
//       Raw command string mode. The text after -c is used as the inner command directly.
//       Example:
//         SilentRunner.exe -c "ver & echo hello"
//       Useful when you want to pass one-liners without creating a .cmd file.
//       If your raw command contains quotes and pipes, cmd.exe quoting can get tricky;
//       in that case "script path mode" is usually easier.
//
// Script/Exe path mode:
//   SilentRunner.exe "C:\path\tool.exe" arg1 arg2
//
//   SilentRunner.exe script.cmd arg1 arg2
//       Inside script.cmd, for example:
//         @echo off
//         set "DRIVE=%~1"
//         echo DRIVE=%DRIVE%
//
// In this mode, SilentRunner constructs the inner command as:
//   "<path>" arg1 arg2 ...
// and runs it via:
//   cmd.exe /d /s /c "<inner>"
//
//
// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------
//
// Tested toolchain (MinGW-w64 via winlibs):
//   - 64-bit Windows
//   - winlibs x86_64-posix-seh-gcc-15.2.0-mingw-w64ucrt-13.0.0-r4
//     https://github.com/brechtsanders/winlibs_mingw/releases
//
// Example build command (MinGW-w64 g++):
//   g++ -O2 -static -std=gnu++17 -municode -Wl,-subsystem,windows SilentRunner.cpp -o SilentRunner.exe
//
// Notes:
//   - -std=gnu++17      → enables modern C++17 features used by this file.
//   - -O2               → reasonable optimization level for a small CLI helper.
//   - -static           → links libstdc++/libgcc statically so SilentRunner.exe
//                         is self-contained (no extra DLLs needed). You can drop
//                         this if you prefer smaller binaries and are ok with
//                         shipping the runtime DLLs.
//   - -municode         → uses wide-character wWinMain as the entrypoint, which
//                         matches the Windows subsystem entry defined in the code.
//   - -Wl,-subsystem,windows
//                       → tells the linker to build a GUI subsystem binary
//                         (no console window). For MSVC builds the equivalent
//                         is configured via the #pragma comment(linker, ...) in
//                         the source.
//
// Prebuilt binaries:
//   - The repository also provides a prebuilt SilentRunner.exe for convenience.
//     If you rebuild from source, use a recent, trusted Windows toolchain such
//     as the winlibs MinGW-w64 distribution above.
//
//
// ---------------------------------------------------------------------------

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>

#include <string>
#include <vector>
#include <thread>
#include <cstdint>

// Windows subsystem (no console window), with wide entrypoint.
#pragma comment(linker, "/SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup")

// -------------------------- small helpers --------------------------

static std::wstring GetComSpec() {
    wchar_t buf[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"ComSpec", buf, MAX_PATH);
    if (n > 0 && n < MAX_PATH) return std::wstring(buf, n);
    return L"C:\\Windows\\System32\\cmd.exe";
}

static std::wstring QuoteIfNeeded(const std::wstring& s) {
    if (s.empty()) return L"\"\"";
    bool need = false;
    for (wchar_t c : s) {
        if (c == L' ' || c == L'\t') { need = true; break; }
    }
    if (!need) return s;
    std::wstring out;
    out.push_back(L'"');
    for (wchar_t c : s) {
        // This is a "good enough" quoting for typical file paths/args.
        // cmd.exe quoting is complex; for hardest cases prefer .cmd file mode.
        if (c == L'"') out.append(L"\\\"");
        else out.push_back(c);
    }
    out.push_back(L'"');
    return out;
}

static void AppendLiteral(std::vector<char>& v, const char* s) {
    if (!s) return;
    size_t n = 0;
    while (s[n] != '\0') n++;
    v.insert(v.end(), s, s + n);
}

static void ReadAllFromPipe(HANDLE hRead, std::vector<char>& out) {
    const DWORD BUFSZ = 1u << 15; // 32768
    char buf[BUFSZ];
    DWORD got = 0;
    for (;;) {
        BOOL ok = ReadFile(hRead, buf, BUFSZ, &got, nullptr);
        if (!ok || got == 0) break;
        out.insert(out.end(), buf, buf + got);
    }
}

static void WriteAll(HANDLE h, const std::vector<char>& data) {
    if (!h || h == INVALID_HANDLE_VALUE || data.empty()) return;
    const char* p = data.data();
    size_t left = data.size();
    while (left > 0) {
        DWORD chunk = (left > 0x7fffffffULL) ? 0x7fffffffUL : (DWORD)left;
        DWORD written = 0;
        if (!WriteFile(h, p, chunk, &written, nullptr)) break;
        if (written == 0) break;
        p += written;
        left -= written;
    }
}

static void WriteTextStderrUtf8(const std::wstring& s) {
    HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
    if (!h || h == INVALID_HANDLE_VALUE) return;

    int need = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(),
                                   nullptr, 0, nullptr, nullptr);
    if (need <= 0) return;

    std::vector<char> buf((size_t)need);
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(),
                        buf.data(), need, nullptr, nullptr);
    WriteAll(h, buf);
}

static void KillProcessTreeBestEffort(DWORD pid) {
    // Best-effort using taskkill (present on modern Windows).
    // Because we are /SUBSYSTEM:WINDOWS and pass CREATE_NO_WINDOW, this won't flash.
    std::wstring cmd = L"taskkill /PID " + std::to_wstring(pid) + L" /T /F >nul 2>nul";
    std::wstring comspec = GetComSpec();
    std::wstring full = comspec + L" /d /s /c \"" + cmd + L"\"";

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> buf(full.begin(), full.end());
    buf.push_back(L'\0');

    CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                   nullptr, nullptr, &si, &pi);

    if (pi.hThread) CloseHandle(pi.hThread);
    if (pi.hProcess) CloseHandle(pi.hProcess);
}

// -------------------------- options parsing --------------------------

struct Options {
    bool printCmdline = false;
    bool utf8 = false;        // prefixes inner with: chcp 65001>nul &
    uint32_t timeoutMs = 0;   // 0 = infinite
    std::wstring inner;       // inner command passed to cmd.exe /c "...".
};

static bool ParseArgs(int argc, wchar_t** argv, Options& opt, std::wstring& err) {
    // Minimal parser:
    //   --timeout-ms N
    //   --print-cmdline
    //   --utf8
    //   -c "<raw>"
    // else: first non-flag is script/exe path; rest are args to it.

    int i = 1;

    for (; i < argc; i++) {
        std::wstring a = argv[i];

        if (a == L"--print-cmdline") {
            opt.printCmdline = true;
            continue;
        }
        if (a == L"--utf8") {
            opt.utf8 = true;
            continue;
        }
        if (a == L"--timeout-ms") {
            if (i + 1 >= argc) { err = L"Missing value for --timeout-ms\n"; return false; }
            opt.timeoutMs = (uint32_t)_wtoi(argv[++i]);
            continue;
        }
        if (a == L"-c" || a == L"/c") {
            if (i + 1 >= argc) { err = L"Missing command after -c\n"; return false; }
            opt.inner = argv[++i]; // raw inner
            return true;
        }

        // first non-flag -> path mode
        break;
    }

    if (i >= argc) {
        err =
            L"Usage:\n"
            L"  SilentRunner.exe [--timeout-ms N] [--print-cmdline] [--utf8] <script-or-exe> [args...]\n"
            L"  SilentRunner.exe [--timeout-ms N] [--print-cmdline] [--utf8] -c \"ver & echo hello\"\n";
        return false;
    }

    std::wstring path = argv[i];

    // Build inner: "<path>" arg1 arg2 ...
    std::wstring inner = L"\"" + path + L"\"";
    for (int k = i + 1; k < argc; k++) {
        inner.push_back(L' ');
        inner.append(QuoteIfNeeded(argv[k]));
    }

    opt.inner = inner;
    return true;
}

static std::wstring BuildCmdExeCommandLine(const Options& opt) {
    // Build:
    //   cmd.exe /d /s /c "<inner>"
    // Optionally:
    //   cmd.exe /d /s /c "chcp 65001>nul & <inner>"
    std::wstring comspec = GetComSpec();
    std::wstring inner = opt.inner;

    if (opt.utf8) {
        inner = L"chcp 65001>nul & " + inner;
    }

    return comspec + L" /d /s /c \"" + inner + L"\"";
}

// -------------------------- core runner --------------------------

static int RunHiddenCaptureBytes(const std::wstring& fullCmdLineForCreateProcess,
                                 uint32_t timeoutMs,
                                 std::vector<char>& outBytes,
                                 std::vector<char>& errBytes,
                                 bool printCmdline) {
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE outR = nullptr, outW = nullptr;
    HANDLE errR = nullptr, errW = nullptr;

    if (!CreatePipe(&outR, &outW, &sa, 0)) {
        DWORD gle = GetLastError();
        AppendLiteral(errBytes, "CreatePipe(stdout) failed\n");
        return -(int)gle;
    }
    if (!CreatePipe(&errR, &errW, &sa, 0)) {
        DWORD gle = GetLastError();
        CloseHandle(outR); CloseHandle(outW);
        AppendLiteral(errBytes, "CreatePipe(stderr) failed\n");
        return -(int)gle;
    }

    // Ensure READ ends are not inheritable
    SetHandleInformation(outR, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(errR, HANDLE_FLAG_INHERIT, 0);

    // Provide stdin = NUL (safe even if we are GUI subsystem)
    HANDLE hNul = CreateFileW(L"NUL", GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput  = (hNul && hNul != INVALID_HANDLE_VALUE) ? hNul : GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = outW;
    si.hStdError  = errW;

    PROCESS_INFORMATION pi{};

    std::wstring cmdline = fullCmdLineForCreateProcess;
    std::vector<wchar_t> mutableCmd(cmdline.begin(), cmdline.end());
    mutableCmd.push_back(L'\0');

    DWORD flags = CREATE_NO_WINDOW;

    BOOL ok = CreateProcessW(
        nullptr,
        mutableCmd.data(),
        nullptr,
        nullptr,
        TRUE,   // inherit handles (pipes)
        flags,
        nullptr,
        nullptr,
        &si,
        &pi
    );

    // Parent: close write ends so reader threads can see EOF
    CloseHandle(outW);
    CloseHandle(errW);
    if (hNul && hNul != INVALID_HANDLE_VALUE) CloseHandle(hNul);

    if (!ok) {
        DWORD gle = GetLastError();
        CloseHandle(outR);
        CloseHandle(errR);
        return -(int)gle;
    }

    CloseHandle(pi.hThread);

    if (printCmdline) {
        std::wstring msg = L"[SilentRunner] PID=" + std::to_wstring(pi.dwProcessId)
                         + L"\n[SilentRunner] CMD=" + cmdline + L"\n";
        WriteTextStderrUtf8(msg);
    }

    // Drain both streams concurrently (avoids deadlock)
    std::thread tOut([&]{ ReadAllFromPipe(outR, outBytes); });
    std::thread tErr([&]{ ReadAllFromPipe(errR, errBytes); });

    DWORD wait = WAIT_OBJECT_0;
    if (timeoutMs == 0) {
        wait = WaitForSingleObject(pi.hProcess, INFINITE);
    } else {
        wait = WaitForSingleObject(pi.hProcess, timeoutMs);
    }

    if (wait == WAIT_TIMEOUT) {
        DWORD pid = pi.dwProcessId;
        WriteTextStderrUtf8(L"[SilentRunner] TIMEOUT\n");
        KillProcessTreeBestEffort(pid);
        // give it a moment to die
        WaitForSingleObject(pi.hProcess, 2000);
    }

    // Close read ends to unblock threads if needed
    CloseHandle(outR);
    CloseHandle(errR);

    tOut.join();
    tErr.join();

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);

    if (wait == WAIT_TIMEOUT) {
        return 124; // conventional timeout code
    }
    return (int)exitCode;
}

// -------------------------- entrypoint --------------------------

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return 2;

    Options opt;
    std::wstring parseErr;
    if (!ParseArgs(argc, argv, opt, parseErr)) {
        if (!parseErr.empty()) WriteTextStderrUtf8(parseErr);
        LocalFree(argv);
        return 2;
    }

    std::wstring full = BuildCmdExeCommandLine(opt);

    std::vector<char> outBytes, errBytes;
    int code = RunHiddenCaptureBytes(full, opt.timeoutMs, outBytes, errBytes, opt.printCmdline);

    WriteAll(GetStdHandle(STD_OUTPUT_HANDLE), outBytes);
    WriteAll(GetStdHandle(STD_ERROR_HANDLE),  errBytes);

    LocalFree(argv);

    // Negative => -GLE used internally for CreatePipe/CreateProcess failures.
    // Expose a conventional non-negative code to callers.
    if (code < 0) return 255;
    return code;
}
