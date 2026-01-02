# SilentRunner.exe  
_Run Windows CLI commands silently and capture exit code, stdout and stderr._

SilentRunner is a lightweight Windows tool that runs commands silently (no console window) via `cmd.exe` and captures **exit code, stdout and stderr**.  
Useful for automation, Task Scheduler jobs, scripting, and tools that require silent execution with output retrieval.
AI-assisted project — see Acknowledgements for more info.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightblue)
![Build](https://img.shields.io/badge/build-gcc-9cf)

---

## Features

✔ Runs commands via `cmd.exe` — supports pipes, `&&`, `|`, builtins (`echo`, `chcp`, ...)  
✔ Silent execution (no flashing console window)  
✔ Captures **exit code, stdout and stderr without deadlocks**  
✔ Optional timeout with best-effort process tree kill  
✔ Streams are passed as **raw bytes** (no CRLF/encoding conversion)  
✔ Single .exe — no dependencies

> **More detailed internal behavior, CMD execution model, quoting rules, and limitations are extensively documented  
> inside `src/SilentRunner.cpp` in the header section.**

---

## Usage

```
SilentRunner.exe [options] <script-or-exe> [args...]
SilentRunner.exe [options] -c "<raw-cmd>"
```

## CLI Options

| Option               | Description                                  |
|----------------------|----------------------------------------------|
| `--timeout-ms <N>`   | Kill process tree after N ms → exit code 124 |
| `--print-cmdline`    | Print PID + CMD line to stderr (debug)       |
| `--utf8`             | Prepends `chcp 65001>nul & ...` inside child |
| `-c "<cmd>"`         | Raw inline command instead of script mode    |

---

### Examples

Run inline command:
```
SilentRunner.exe -c "echo Hello & ver"
```

Run program with arguments:
```
SilentRunner.exe "C:\Tools\app.exe" --mode fast --silent
```

Run `.cmd` script with parameters:
```
SilentRunner.exe backup.cmd D:\ 30
```

`backup.cmd` example:
```
@echo off
REM disable command echo for cleaner output
set "DRIVE=%~1"
set "DAYS=%~2"
echo Backing up %DRIVE% (keeping %DAYS% days)
```

UTF-8 mode:
```
SilentRunner.exe --utf8 -c "echo こんにちは"
```

Timeout example:
```
SilentRunner.exe --timeout-ms 5000 "long_running_task.cmd"
```

### About stdin
SilentRunner binds stdin to **NUL**, so external input pipes do not work:

```
✗ echo yes | SilentRunner.exe -c "somecommand"    # won't work
✓ echo yes | somecommand                          # works only inside .cmd script
```

## Behavior Notes

- Execution is **synchronous** — output appears only after child exits  
- Output is fully buffered in RAM → **not ideal for GB-scale logs**  
- stdout/stderr order is not preserved — both streams are drained concurrently and replayed sequentially after the process exits
- Working directory inherits the parent’s — use absolute paths, or `pushd`/`popd` inside `.cmd` if needed
- `-c` is convenient for short one-liners, but CMD quoting rules can get tricky
- For complex commands involving quotes, pipes or variables, using a `.cmd` script is usually safer
- For long-running or fire-and-forget tasks, use `nircmd exec hide` instead — https://nircmd.nirsoft.net/exec.html

> Full technical notes including implementation details, quoting behavior, caveats and design reasoning  
> are documented at the top of `src/SilentRunner.cpp`.

---

## Build

Prebuilt binary is included in `bin/`.

Manual compilation is optional — full build steps (toolchain, flags, notes)
are documented inside the header of `src/SilentRunner.cpp` under **Build** section.

---

# Acknowledgements

Developed in C++ with a focus on a minimal, self-contained Windows binary without external dependencies, using direct WinAPI process handling — ideal for this type of tool.
The code and documentation were created with assistance from ChatGPT (v5.2) and iteratively reviewed, refined, and extensively tested during development to validate reliability and performance.
Contributions, bug reports, and security notes are welcome.


---

## License

Released under the MIT License — see `LICENSE` for details.

---
