# SilentRunner.exe  
_Run Windows CLI commands silently and capture exit code, stdout and stderr._

SilentRunner is a lightweight Windows tool that runs commands silently (no console window) via `cmd.exe` and captures **exit code, stdout and stderr**.  
Useful for automation, Task Scheduler jobs, scripting, and tools that require silent execution with output retrieval.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightblue)
![Build](https://img.shields.io/badge/build-gcc-9cf)

---

## Usage

SilentRunner supports two execution modes:
- Script/Executable path mode: `<script-or-exe> [args...]`
- Raw command mode: `-c "<raw-cmd>"`

```
SilentRunner.exe [options] <script-or-exe> [args...]
SilentRunner.exe [options] -c "<raw-cmd>"
```

---

## Parameter Categories

SilentRunner options are organized into logical groups. Most execution scenarios require configuring only a small subset of these categories.

### Execution

Controls how the child command is started and managed.

Options:

- `-c "<command>"` or `/c "<command>"`
- `--timeout-ms <ms>`

---

### Process Environment

Controls the environment in which the child process and run hooks are started.

Options:

- `--cwd <dir>`
- `--inherit-stdin`
- `--utf8` or `--utf-8`

---

### Execution ID

Controls the identifier assigned to an execution and its log files.

Options:

- `--id-prefix <value>`
- `--id-base <value>`
- `--id-suffix <timestamp|pid|timestamp+pid|pid+timestamp>`

---

### Output Routing

Controls which output is emitted to the parent process and when it is emitted.

Options:

- `--stdout-emit <mode>`
- `--stderr-emit <mode>`
- `--stderr-emit-child <mode>`
- `--stderr-emit-sr <mode>`

---

### Persistent Logging

Controls which stdout, stderr, and SilentRunner diagnostic streams are written to TXT or JSONL log files.

Options:

- `--stdout-dir <dir>`
- `--stdout-dir-jsonl <dir>`
- `--stderr-dir <dir>`
- `--stderr-dir-jsonl <dir>`
- `--stderr-dir-child <dir>`
- `--stderr-dir-child-jsonl <dir>`
- `--stderr-dir-sr <dir>`
- `--stderr-dir-sr-jsonl <dir>`

---

### Log Retention

Controls whether persistent logs are kept after successful or failed executions.

Options:

- `--stdout-dir-keep-log <mode>`
- `--stderr-dir-keep-log <mode>`
- `--stderr-dir-child-keep-log <mode>`
- `--stderr-dir-sr-keep-log <mode>`

---

### Buffering

Limits memory used when output must be retained for delayed parent replay.

Options:

- `--stdout-max-buffer-bytes <bytes>`
- `--stderr-max-buffer-bytes <bytes>`
- `--std-total-max-buffer-bytes <bytes>`

---

### Post-Execution Hooks

Runs an external hook after a successful or failed child execution.

Options:

- `--run-on-success <path>`
- `--run-on-failure <path>`

---

### Diagnostics

Controls SilentRunner diagnostic detail and internal probe logging.

Options:

- `--debug`
- `--verbose`
- `--probe-dir <dir>`

---

### Help

Displays the built-in CLI reference.

Options:

- `--help`
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
SilentRunner.exe cleanup.cmd C:\Temp
```

`cleanup.cmd` example:
```
@echo off
set "TARGET=%~1"
echo Cleaning %TARGET%...
if exist "%TARGET%\*.tmp" del /q "%TARGET%\*.tmp"
echo Done.
```

UTF-8 mode:
```
SilentRunner.exe --utf8 -c "echo こんにちは"
```

Timeout example:
```
SilentRunner.exe --timeout-ms 5000 "medium_running_task.cmd"
```













---

## Build
Prebuilt binary is included in `bin/`.


---

# Acknowledgements

Developed in C++ with a focus on a minimal, self-contained Windows binary without external dependencies, using direct WinAPI process handling.
The code and documentation were created with assistance from ChatGPT.
Contributions, bug reports, and security notes are welcome.


---

## License

Released under the MIT License — see `LICENSE` for details.

---
