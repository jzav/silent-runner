# SilentRunner.exe

SilentRunner is a lightweight Windows command runner that executes
console applications without creating a console window **(no flashing)**
while capturing **exit code, stdout, stderr, and execution
diagnostics**.

SilentRunner is designed for unattended and automated execution
scenarios such as scripting, CI/CD pipelines, and scheduled tasks, while
retaining detailed control over process execution, output, and
diagnostics.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightblue)
![Build](https://img.shields.io/badge/build-gcc-9cf)

Key capabilities include:

-   Silent windowless execution via `cmd.exe /d /s /c`.
-   Child process tree management, tracking, and controlled
    termination.
-   Independent routing of child stdout, child stderr, and SilentRunner diagnostics
    to parent stdout/stderr and persistent logs.
-   Immediate or delayed emission to parent stdout/stderr,
    with delayed output optionally replayed from buffer or persistent logs at the
    end of execution, on child success, or on child failure.
-   Persistent TXT and JSONL logging with configurable retention
    policies.
-   Configurable execution IDs for log naming and workflow integration.
-   Post-execution hooks with execution metadata exposed through
    environment variables.
-   Configurable working directory, standard input, UTF-8 mode, and
    execution timeout.
-   Multiple diagnostic levels ranging from normal execution messages to
    detailed debugging and verbose execution summaries.

------------------------------------------------------------------------

## Architecture Overview

SilentRunner is organized as an event-driven processing pipeline rather
than a monolithic command wrapper.

SilentRunner separates child process execution management from child stdout/stderr
capture and routing to parent stdout/stderr and persistent logs. The child process tree
is tracked and controlled through Windows Job Object integration, including process-tree
termination and debug monitoring.

Child process stdout/stderr and SilentRunner diagnostics are collected into a
common execution timeline. The timeline maintains job state and queue semantics, while
independent worker components handle parent stdout/stderr emission and persistent logging.

------------------------------------------------------------------------

## Execution Modes

SilentRunner supports two execution modes:

### Script/Executable mode

``` text
SilentRunner.exe [SilentRunner options...] <script-or-exe> [child args...]
```

In Script/Executable mode, SilentRunner parses its own options first.
The first non-option argument marks the beginning of the child command.
That argument is treated as the script or executable path, and all
remaining arguments are treated as child arguments.

Paths and arguments containing spaces should be enclosed in quotes.

### Raw mode

``` text
SilentRunner.exe [SilentRunner options...] -c "<raw-cmd>"
```

In Raw mode, `-c` consumes the following argument as the complete raw
command string. Enclose the command in quotes when needed to keep it as
a single argument.

------------------------------------------------------------------------

## Parameter Categories

SilentRunner options are organized into logical groups. Most execution
scenarios require configuring only a small subset of these categories.

### Process Environment

Controls the execution environment and runtime behavior of the child
process and run hooks.

By default, the child process inherits SilentRunner's current working
directory, receives `NUL` as its standard input, uses the system's
default console code page, and runs without a time limit.

These options allow the working directory, standard input handling,
console code page, and execution timeout to be customized.

Options:

-   `--cwd <dir>`
-   `--inherit-stdin`
-   `--utf8` or `--utf-8`
-   `--timeout-ms <ms>`

------------------------------------------------------------------------

### Execution ID

Controls the identifier assigned to each execution.

The execution ID is used to uniquely identify an execution and forms the
base name of all log files created during that run.

The execution ID is composed as:

`id-prefix + id-base + id-suffix`

By default, SilentRunner uses `timestamp+pid` (UTC) as the suffix,
providing a unique identifier for each execution.

Options:

-   `--id-prefix <value>`
-   `--id-base <value>`
-   `--id-suffix <timestamp|pid|timestamp+pid|pid+timestamp>`

------------------------------------------------------------------------

### Output Routing

Controls which output is emitted to the parent process and when it is
emitted.

Emission modes:

-   `never` -- Never emit the selected stream to the parent. When used
    with `--stderr-emit`, this disables the default parent diagnostic
    channel. Unless another SilentRunner diagnostic channel, such as
    `--stderr-dir`, is available, SilentRunner terminates before
    starting the child process with exit code 254.
-   `stream` -- Emit child stdout/stderr to the parent as it is produced (default).
-   `end` -- Emit the buffered output after the child process
    finishes.
-   `success` -- Emit the buffered output only if execution succeeds.
-   `failure` -- Emit the buffered output only if execution fails.

Options:

-   `--stdout-emit <mode>` -- Controls emission of the child process
    stdout.
-   `--stderr-emit <mode>` -- Controls emission of the combined stderr
    view: child stderr and SilentRunner diagnostics.
-   `--stderr-emit-child <mode>` -- Controls emission of child stderr
    only.
-   `--stderr-emit-sr <mode>` -- Controls emission of SilentRunner
    diagnostics only.

The three stderr emit options are mutually exclusive.

------------------------------------------------------------------------

### Persistent Logging

In addition to Output Routing, SilentRunner can write execution output
to persistent log files.

Persistent logging is independent of parent stdout/stderr emission. Any
combination of parent emission and log files can be used simultaneously.
For example, output may be streamed to the parent process while also
being recorded as TXT and/or JSONL logs.

Unlike the parent stderr routing options, all stderr log destinations
may be enabled at the same time. This allows combined stderr, child
stderr, and SilentRunner diagnostics (described below) to be captured
independently in parallel.

Each execution creates a new set of log files. SilentRunner never
appends output to an existing log file. Log file names are derived from
the execution ID, which is described above.

While execution is in progress, log file names include the running state.
After execution completes, they are renamed to reflect the final execution
result: `success` or `failure`.
For example: `my-execution_stdout_running.log` →
`my-execution_stdout_success.log` or `my-execution_stdout_failure.log`.

Options:

-   `--stdout-dir <dir>`
-   `--stdout-dir-jsonl <dir>`
-   `--stderr-dir <dir>`
-   `--stderr-dir-jsonl <dir>`
-   `--stderr-dir-child <dir>`
-   `--stderr-dir-child-jsonl <dir>`
-   `--stderr-dir-sr <dir>`
-   `--stderr-dir-sr-jsonl <dir>`

------------------------------------------------------------------------

### Log Retention

Controls whether persistent log files are retained after execution
completes.

Each stdout and stderr log target has its own retention policy. JSONL
log files use the same retention policy as the corresponding TXT log
stream.

Logs removed by a retention policy are deleted permanently and are not
moved to the Windows Recycle Bin.

Supported modes:

-   `always` -- Always keep the log file (default).
-   `success` -- Keep the log file only if execution succeeds.
-   `failure` -- Keep the log file only if execution fails.

Options:

-   `--stdout-dir-keep-log <mode>`
-   `--stderr-dir-keep-log <mode>`
-   `--stderr-dir-child-keep-log <mode>`
-   `--stderr-dir-sr-keep-log <mode>`

------------------------------------------------------------------------

### Buffering

Controls how much output may be buffered in memory for delayed parent
replay (`end`, `success`, or `failure` emission modes). By default,
buffer limits are 0 (unlimited).

Buffering is only used when parent stdout/stderr emission is delayed. When
output is streamed to the parent process, these limits are not used.

If persistent logging is enabled for the corresponding stream,
SilentRunner can replay the output from the persistent log file instead
of the in-memory buffer. For example, `--stderr-emit-sr end` can replay
from logs written by `--stderr-dir-sr` or `--stderr-dir-sr-jsonl`. This
allows delayed replay of arbitrarily large outputs while keeping memory
usage bounded.

Options:

-   `--stdout-max-buffer-bytes <bytes>`
-   `--stderr-max-buffer-bytes <bytes>`
-   `--std-total-max-buffer-bytes <bytes>`

------------------------------------------------------------------------

### Post-Execution Hooks

Runs an external program after execution without arguments.

Hooks execute in the same process environment as the child process,
including the configured working directory and environment variables.
SilentRunner also provides additional execution-specific environment
variables, allowing hooks to access execution metadata such as the
execution ID, execution result, and log file locations.

The complete list of currently available environment variables can be displayed
using `SilentRunner --help`. Requests for additional environment variables are
welcome.

Post-execution hooks are started as detached processes without inherited
standard handles. The hook and programs started by it therefore cannot
rely on the original SilentRunner parent stdout or stderr handles.

If a hook starts another SilentRunner instance, that instance must have an
available diagnostic channel. For example, persistent stderr logging can be
enabled with `--stderr-dir`; otherwise, if no diagnostic channel is available,
the nested SilentRunner terminates with exit code 254.

Options:

-   `--run-on-success <path>`
-   `--run-on-failure <path>`

------------------------------------------------------------------------

### Diagnostics

Controls the level of SilentRunner diagnostics.

Informational, error, and fatal diagnostics are enabled by default.
Their parent emission and persistent logging follow the SilentRunner
diagnostic routing configured through the stderr Output Routing and
Persistent Logging options.

If no SilentRunner diagnostic channel is available (neither parent
emission nor persistent logging) before the child process starts,
SilentRunner terminates immediately with exit code 254, because
diagnostic messages could not be reported.

Exit code 255 indicates an internal SilentRunner failure.

The `--debug` option enables additional diagnostic messages describing
internal execution flow, child (sub)process lifecycle, and output
routing decisions.

The `--verbose` option implies `--debug` and adds detailed execution
summaries, including event processing, worker activity, and final
processing results.

Options:

-   `--debug`
-   `--verbose`

------------------------------------------------------------------------

### Help

Displays the built-in CLI reference.

Options:

-   `--help`

------------------------------------------------------------------------

## Usage

### 1. Basic execution

Run a command using the default SilentRunner configuration:

```text
SilentRunner.exe task.cmd
```

- `task.cmd` runs without creating a console window.
- The child process inherits SilentRunner's current working directory.
- Standard input is connected to `NUL`.
- UTF-8 mode is not enabled.
- No execution timeout is applied.
- Child stdout is streamed to parent stdout.
- Child stderr and SilentRunner diagnostics are both streamed to parent stderr.
- No persistent log files are created.
- Debug and verbose diagnostics are disabled.
- No post-execution hooks are executed.

------------------------------------------------------------------------

### 2. Controlling the process environment

Run the child process in a specific working directory with a five-second
execution timeout:

```text
SilentRunner.exe --cwd "D:\Work" --utf8 --timeout-ms 5000 task.cmd
```

`task.cmd`:

```text
@echo off
echo Příliš žluťoučký kůň úpěl ďábelské ódy
echo こんにちは
```

- `task.cmd` runs with `D:\Work` as its working directory.
- UTF-8 code page (`65001`) is enabled for the child process.
- If execution exceeds five seconds, SilentRunner terminates the child process tree with exit code 124.
- All other settings retain their default behavior described in the previous example.

------------------------------------------------------------------------

### 3. Controlling parent output

Keep child stdout/stderr out of parent output during execution and emit it
only if the child process fails:

```text
SilentRunner.exe --stdout-emit failure --stderr-emit failure task.cmd
```

- Child stdout and stderr are not streamed to parent stdout/stderr while
  `task.cmd` is running.
- Output is buffered in memory in the execution timeline during execution.
- If the child process fails, the buffered stdout/stderr is replayed to
  parent stdout/stderr after execution completes.
- If the child process succeeds, no child stdout/stderr is emitted to the
  parent.
- SilentRunner diagnostics remain part of the combined stderr stream.
- All other settings retain their default behavior described in the first
  example.

------------------------------------------------------------------------

### 4. Adding persistent logging

Stream child output to the parent while also recording it in persistent
log files:

```text
SilentRunner.exe --stdout-dir "D:\Logs" --stderr-dir "D:\Logs" task.cmd
```

- Child stdout is streamed to parent stdout.
- Child stderr and SilentRunner diagnostics are streamed to parent stderr.
- Child stdout is also written to a persistent TXT stdout log.
- Child stderr and SilentRunner diagnostics are also written to a persistent
  combined stderr TXT log.
- While execution is running, the log file names contain the `running` state.
  After execution completes, they are renamed to contain `success` or `failure`
  according to the final execution result.
- The log files are retained after execution using the default `always`
  retention policy.
- All other settings retain their default behavior described in the first
  example.

------------------------------------------------------------------------

### 5. Advanced persistent logging

Record child stdout, combined stderr, child stderr, and SilentRunner diagnostics
to persistent TXT and JSONL log files:

```text
SilentRunner.exe ^
  --stdout-dir "D:\Logs" ^
  --stdout-dir-jsonl "D:\Logs" ^
  --stderr-dir "D:\Logs" ^
  --stderr-dir-jsonl "D:\Logs" ^
  --stderr-dir-child "D:\Logs" ^
  --stderr-dir-child-jsonl "D:\Logs" ^
  --stderr-dir-sr "D:\Logs" ^
  --stderr-dir-sr-jsonl "D:\Logs" ^
  task.cmd
```

- Child stdout is recorded independently in TXT and JSONL formats.
- The combined stderr stream is recorded independently in TXT and JSONL formats.
- Child stderr is also recorded separately in TXT and JSONL formats.
- SilentRunner diagnostics are also recorded separately in TXT and JSONL formats.
- All persistent log destinations may be enabled at the same time.
- Parent stdout/stderr emission keeps its default streaming behavior.
- Log retention keeps its default `always` policy.

------------------------------------------------------------------------

### 6. Failure-only diagnostic replay from persistent logs

Keep SilentRunner diagnostics out of parent stderr during execution, persist
them as JSONL, and replay them to the parent only if execution fails:

```text
SilentRunner.exe ^
  --stderr-emit-sr failure ^
  --stderr-dir-sr-jsonl "D:\Logs" ^
  --stderr-dir-sr-keep-log failure ^
  task.cmd
```

- SilentRunner diagnostics are not streamed to parent stderr while `task.cmd`
  is running.
- SilentRunner diagnostics are written to a persistent JSONL log.
- The persistent log is used as the replay source instead of the in-memory
  execution timeline buffer.
- If execution fails, the diagnostics are replayed from the JSONL log to
  parent stderr after execution completes.
- If execution succeeds, no SilentRunner diagnostics are emitted to parent
  stderr.
- The JSONL diagnostic log is retained only on failure. The
  `--stderr-dir-sr-keep-log` policy applies to both TXT and JSONL logs for
  the SilentRunner diagnostic stream.
- Child stdout keeps its default streaming behavior to parent stdout.

------------------------------------------------------------------------

### 7. Execution ID, structured diagnostics, and post-execution hooks

Run a data-processing task with a custom execution ID, persist structured
SilentRunner diagnostics, and process them through chained post-execution
hooks:

```text
SilentRunner.exe ^
  --id-prefix processing ^
  --id-base data ^
  --id-suffix timestamp+pid ^
  --stderr-dir-sr-jsonl "D:\Logs" ^
  --debug ^
  --run-on-success "D:\Hooks\filter-execution-data.cmd" ^
  process-data.cmd "D:\Input" --mode fast
```

`process-data.cmd`:

```text
@echo off
set "SOURCE=%~1"
set "MODE=%~3"

echo Processing %SOURCE%...
echo Mode: %MODE%
```

`filter-execution-data.cmd`:

```text
@echo off

pathTo\SilentRunner.exe ^
  --stdout-dir "%TEMP%" ^
  --stderr-dir "%TEMP%" ^
  --run-on-success "%~dp0store-execution-data.cmd" ^
  "%~dp0jq.exe" -c "select(.message | startswith(\"[JOB]\"))" ^
  "%SILENTRUNNER_STDERR_SR_JSONL_LOG%"
```

`store-execution-data.cmd`:

```text
@echo off

set "FILTERED_DATA=%SILENTRUNNER_STDOUT_LOG%"

rem Store the filtered data in SQLite or elsewhere.
...
```

- The execution ID is built from the configured prefix, base, and
  `timestamp+pid` suffix and identifies the original execution and its log files.
- `process-data.cmd` is the child script; `"D:\Input"` and `--mode fast` are
  passed to it as child arguments.
- SilentRunner diagnostics are recorded in a persistent JSONL log.
- Debug diagnostics are enabled, including child process lifecycle information.
- `filter-execution-data.cmd` runs after a successful execution.
- Hooks receive execution metadata through SilentRunner environment variables,
  including the execution ID, execution result, and retained log file locations.
- Use `--help` for the complete list of available environment variables.
- `filter-execution-data.cmd` uses `SILENTRUNNER_STDERR_SR_JSONL_LOG` to access
  the retained SilentRunner diagnostic JSONL log.
- [`jq`](https://jqlang.org/) is an external command-line tool for processing
  JSON data. Here it filters the structured diagnostic log to retain only
  records whose `message` starts with `[JOB]`. `[JOB]` identifies process
  lifecycle diagnostics generated from Windows Job Object events.
- `--stderr-dir "%TEMP%"` provides a persistent diagnostic channel for the
  nested SilentRunner. Since post-execution hooks do not inherit standard
  handles, without an available diagnostic channel the nested SilentRunner
  would terminate before starting `jq` with exit code 254.
- The nested SilentRunner starts a separate execution with its own execution ID
  and captures the filtered `jq` output using its TXT stdout log. Since `jq -c`
  already produces one JSON object per line, this preserves the filtered JSONL
  data directly.
- After `jq` completes successfully, the nested SilentRunner runs
  `store-execution-data.cmd`. Its `SILENTRUNNER_STDOUT_LOG` environment variable
  provides the path to the filtered data produced by `jq`.
- `store-execution-data.cmd` can then store the filtered data in SQLite or another destination.

------------------------------------------------------------------------

### 8. Raw command execution

Execute a complete command using raw `cmd.exe` shell syntax:

```text
SilentRunner.exe -c "echo Starting... & task1.exe | task2.exe"
```

- The entire quoted string after `-c` is treated as a single raw command.
- Shell operators such as `&` and `|` are interpreted by `cmd.exe`.
- Unlike Script/Executable mode, the command is not separated into a script or
  executable path and individual child arguments.
- All other settings retain their default behavior described in the first
  example.

------------------------------------------------------------------------

## Build

Prebuilt binary is included in `bin/`. Release builder is included in
`scripts/`.

------------------------------------------------------------------------

## Acknowledgements

Developed in C++ with a focus on a minimal, self-contained Windows
binary without external dependencies, using the Windows API directly.
The project uses
[Snapshot Toolset](https://github.com/jzav/snapshot-toolset) to provide
anchored project snapshots for ChatGPT-assisted patch generation and application.
ChatGPT also assists with design and documentation. Contributions, bug reports, and
security notes are welcome.

------------------------------------------------------------------------

## License

Released under the MIT License --- see `LICENSE` for details.

------------------------------------------------------------------------
