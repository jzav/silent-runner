# SilentRunner.exe  

SilentRunner is a lightweight Windows command runner that executes console applications without creating a console window while capturing **exit code, stdout, stderr, and execution diagnostics**.

Beyond silent execution, SilentRunner provides flexible output routing, persistent TXT/JSONL logging, delayed output replay, execution hooks, configurable process environment, and structured diagnostics for automation, scripting, CI/CD pipelines, and scheduled tasks.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightblue)
![Build](https://img.shields.io/badge/build-gcc-9cf)

Key capabilities include:

- Silent execution via `cmd.exe` without creating a console window.
- Independent routing of stdout, child stderr, and SilentRunner diagnostics.
- Streaming or delayed parent output emission.
- Persistent TXT and JSONL logging with configurable retention policies.
- Replay of buffered or persisted output after execution completes.
- Configurable execution IDs for log naming and automation workflows.
- Post-execution hooks with execution metadata exposed through environment variables.
- Configurable working directory, standard input, UTF-8 mode, and execution timeout.
- Multiple diagnostic levels ranging from normal execution messages to detailed debugging and verbose execution summaries.

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

### Process Environment

Controls the execution environment and runtime behavior of the child process and run hooks.

By default, the child process inherits SilentRunner's current working directory, receives `NUL` as its standard input, uses the system's default console code page, and runs without a time limit.

These options allow the working directory, standard input handling, console code page, and execution timeout to be customized.

Options:

- `--cwd <dir>`
- `--inherit-stdin`
- `--utf8` or `--utf-8`
- `--timeout-ms <ms>`

---

### Execution ID

Controls the identifier assigned to each execution.

The execution ID is used to uniquely identify an execution and forms the base name of all log files created during that run.

The execution ID is composed as:

`id-prefix + id-base + id-suffix`

By default, SilentRunner uses `timestamp+pid` (UTC) as the suffix, providing a unique identifier for each execution.

Options:

- `--id-prefix <value>`
- `--id-base <value>`
- `--id-suffix <timestamp|pid|timestamp+pid|pid+timestamp>`

---

### Output Routing

Controls which output is emitted to the parent process and when it is emitted.

Emission modes:

- `never` – Never emit the selected stream to the parent.
- `stream` – Emit output to the parent as it is produced.
- `end` – Emit the buffered output after the child process terminates.
- `success` – Emit the buffered output only if the child process exits successfully.
- `failure` – Emit the buffered output only if the child process fails.

Options:

- `--stdout-emit <mode>` – Controls emission of the child process stdout.
- `--stderr-emit <mode>` – Controls emission of the combined stderr view: child stderr and SilentRunner diagnostics.
- `--stderr-emit-child <mode>` – Controls emission of child stderr only.
- `--stderr-emit-sr <mode>` – Controls emission of SilentRunner diagnostics only.

The three stderr emit options are mutually exclusive.

---

### Persistent Logging

In addition to Output Routing, SilentRunner can write execution output to persistent log files.

Persistent logging is independent of parent output emission. Any combination of parent emission and log files can be used simultaneously. For example, output may be streamed to the parent process while also being recorded as TXT and/or JSONL logs.

Unlike the parent stderr routing options, all stderr log destinations may be enabled at the same time. This allows combined stderr, child stderr, and SilentRunner diagnostics (described below) to be captured independently in parallel.

Each execution creates a new set of log files. SilentRunner never appends output to an existing log file. Log file names are derived from the execution ID, which is described above.

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

Controls whether persistent log files are retained after execution completes.

Each stdout and stderr log target has its own retention policy. JSONL log files use the same retention policy as the corresponding TXT log stream.

Supported modes:

- `always` – Always keep the log file.
- `success` – Keep the log file only if the child process exits successfully.
- `failure` – Keep the log file only if the child process fails.

Options:

- `--stdout-dir-keep-log <mode>`
- `--stderr-dir-keep-log <mode>`
- `--stderr-dir-child-keep-log <mode>`
- `--stderr-dir-sr-keep-log <mode>`

---

### Buffering

Controls how much output may be buffered in memory for delayed parent replay (`end`, `success`, or `failure` emission modes).

Buffering is only used when parent output emission is delayed. When output is streamed to the parent process, these limits are not used.

If persistent logging is enabled for the corresponding stream, SilentRunner can replay the output from the persistent log file instead of the in-memory buffer. For example, `--stderr-emit-sr end` can replay from logs written by `--stderr-dir-sr` or `--stderr-dir-sr-jsonl`. This allows delayed replay of arbitrarily large outputs while keeping memory usage bounded.

Options:

- `--stdout-max-buffer-bytes <bytes>`
- `--stderr-max-buffer-bytes <bytes>`
- `--std-total-max-buffer-bytes <bytes>`

---

### Post-Execution Hooks

Runs an external program after execution without arguments.

Hooks execute in the same process environment as the child process, including the configured working directory and environment variables. SilentRunner also provides additional execution-specific environment variables, allowing hooks to access execution metadata such as the execution ID, execution result, and log file locations.

The complete list of available environment variables can be displayed using `SilentRunner --help`.

Options:

- `--run-on-success <path>`
- `--run-on-failure <path>`

---

### Diagnostics

Controls the level of SilentRunner diagnostics.

Informational, error, and fatal diagnostics are enabled by default. Their parent emission and persistent logging follow the SilentRunner diagnostic routing configured through the stderr Output Routing and Persistent Logging options.

If no SilentRunner diagnostic channel is available (neither parent emission nor persistent logging), SilentRunner terminates immediately with exit code `254`, because diagnostic messages could not be reported.

The `--debug` option enables additional diagnostic messages describing internal decisions and execution behavior.

The `--verbose` option implies `--debug` and adds detailed execution summaries, including event processing, output routing, worker activity, and final processing results.

Options:

- `--debug`
- `--verbose`

---

### Help

Displays the built-in CLI reference.

Options:

- `--help`

---

### Examples (TO BE UPDATED)

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

## Architecture Overview

SilentRunner is organized as a small processing pipeline rather than a monolithic command wrapper.

Output from the child process and SilentRunner diagnostics is collected into a common execution timeline. This unified event stream is then consumed by independent worker components responsible for parent output emission and persistent logging.

This architecture allows parent output routing, persistent logging, buffering, replay, diagnostics, and post-execution hooks to operate independently while sharing the same execution timeline.

Most features described below are implemented as independent processing components built on top of this common execution timeline.

---

# Acknowledgements

Developed in C++ with a focus on a minimal, self-contained Windows binary without external dependencies, using direct WinAPI process handling.
The code and documentation were created with assistance from ChatGPT.
Contributions, bug reports, and security notes are welcome.

---

## License

Released under the MIT License — see `LICENSE` for details.

---
