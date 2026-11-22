# Tutorial

Examples use Windows Command Prompt syntax and assume SilentRunner.exe is
available on PATH. Each example script is introduced once and reused
unchanged in subsequent examples. The shared scripts are stored in
D:\Scripts unless another directory is specified.

## 1. Basic execution

Create `D:\Scripts\task.cmd`:

~~~cmd
@echo off
echo Task output: %CD%
echo Task diagnostic 1>&2
exit /b 0
~~~

Run the script with the default SilentRunner configuration:

```text
SilentRunner.exe "D:\Scripts\task.cmd"
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

The default parent output uses Headered presentation, so child output and
SilentRunner diagnostics include event metadata such as timestamps and event
ordering. For an explanation of these fields, see
[Event Metadata](architecture.md#event-metadata).

------------------------------------------------------------------------

## 2. Command-string execution

Use `-c` to pass a complete command string to `cmd.exe`:

~~~cmd
SilentRunner.exe -c "echo Starting... & call D:\Scripts\task.cmd"
~~~

- The entire string after `-c` is passed as one command argument.
- `cmd.exe` interprets `&` and executes the two commands in sequence.

------------------------------------------------------------------------

## 3. Execution with parameters

In Script/Executable mode, SilentRunner passes arguments following the
script or executable path to the child command.

This example revisits the device-volume script from
[README — Programmatic Integration](../README.md#example-1-programmatic-integration),
but passes the device ID as a command-line argument instead of hardcoding it.

The example uses NirSoft's
[SoundVolumeCommandLine](https://www.nirsoft.net/utils/sound_volume_command_line.html)
(`svcl.exe`) and
[GetNir](https://www.nirsoft.net/utils/get_nir_command_line_tool.html)
(`GetNir.exe`).

Create `D:\Scripts\getdevicevolume.cmd`:

~~~cmd
@echo off
setlocal

set "deviceId=%~1"

if not defined deviceId (
    echo Missing device ID.>&2
    exit /b 2
)

"D:\Tools\svcl.exe" /scomma "" | "D:\Tools\GetNir.exe" "Volume Percent" "'Command-Line Friendly ID'='%deviceId%' && 'Device State'=Active"
~~~

Pass the device's Command-Line Friendly ID as an argument:

~~~cmd
SilentRunner.exe "D:\Scripts\getdevicevolume.cmd" "YOUR_DEVICE_ID"
~~~

Replace `YOUR_DEVICE_ID` with the actual device ID and adjust the executable
paths.

- SilentRunner options must precede the script or executable path (`D:\Scripts\getdevicevolume.cmd`).
  Arguments following that path belong to the child command.
- `"YOUR_DEVICE_ID"` is passed to the script as its first argument.
- Inside the script, `%~1` retrieves that argument without surrounding
  quotation marks and assigns it to the `deviceId` variable.
- The script checks whether the argument is missing before using it.

For the complete syntax, see
[Script/Executable Mode](execution.md#scriptexecutable-mode).

------------------------------------------------------------------------

## 4. Controlling the process environment


Run the child process in a specific working directory with a five-second
execution timeout and automatic termination on runtime supervision failure:

```text
SilentRunner.exe --cwd "D:\Work" --utf8 --timeout-ms 5000 --abort-on-runtime-failure "D:\Scripts\task.cmd"
```

- `task.cmd` runs with `D:\Work` as its working directory (which must exist).
- UTF-8 code page (`65001`) is enabled for the child process.
- If execution exceeds five seconds, SilentRunner terminates the child process tree with exit code 124.
- `--abort-on-runtime-failure` requests termination of the child process tree
  if SilentRunner's own runtime supervision fails. Without this option,
  SilentRunner does not terminate the child process tree solely because of
  a runtime supervision failure.
  This is distinct from an unsuccessful child execution or a timeout.

For details, see
[Termination on Runtime Supervision Failure](parameters.md#termination-on-runtime-supervision-failure).

------------------------------------------------------------------------

## 5. Controlling parent output


Create `D:\Scripts\fail.cmd` to demonstrate unsuccessful execution:

~~~cmd
@echo off
echo Failed task output
echo Failed task diagnostic 1>&2
exit /b 1
~~~

Unlike `task.cmd`, this script exits with code `1`. Keep child output
out of parent stdout/stderr during execution and emit it only on failure:

```text
SilentRunner.exe --stdout-emit failure --stderr-emit failure "D:\Scripts\fail.cmd"
```

- Child stdout and stderr and SilentRunner diagnostics are not streamed to parent
  stdout/stderr while `fail.cmd` is running.
- The execution timeline retains the necessary event payloads in
  memory for delayed parent emission.
- If the execution fails, the buffered stdout/stderr is replayed to
  parent stdout/stderr during finalization.
- With `task.cmd` (exit code `0`) and the same options, no child output
  or SilentRunner diagnostics are emitted to the parent.

------------------------------------------------------------------------

## 6. Adding persistent logging


Stream child stdout/stderr to the parent while also recording it in persistent
log files:

```text
SilentRunner.exe --stdout-dir "D:\Logs" --stderr-dir "D:\Logs" "D:\Scripts\task.cmd"
```

- Child stdout is streamed to parent stdout.
- Child stderr and SilentRunner diagnostics are streamed to parent stderr.
- Child stdout is also written to a persistent TXT stdout log.
- Child stderr and SilentRunner diagnostics are also written to a persistent
  mixed stderr TXT log.
- While the child process is running, the log filenames contain the `running`
  suffix. During finalization, they are renamed to reflect the `success` or
  `failure` result.
- The default `always` retention policy keeps the log files.

Each execution also receives an Execution ID. By default, it consists of a UTC
timestamp and the SilentRunner process ID. The ID identifies the execution
across its log files, allowing files from the same run to be associated even
when several SilentRunner instances execute concurrently.

The optional `--id-prefix`, `--id-base`, and `--id-suffix` parameters customize
this identifier. Example 9b demonstrates their use in a pipeline.

------------------------------------------------------------------------

## 7. Advanced persistent logging


Enable all supported persistent logging destinations simultaneously to
demonstrate independent Raw TXT, Headered TXT, and JSONL recording:

```text
SilentRunner.exe ^
  --stdout-dir "D:\Logs" ^
  --stdout-dir-jsonl "D:\Logs" ^
  --stdout-dir-raw "D:\Logs" ^
  --stderr-dir "D:\Logs" ^
  --stderr-dir-jsonl "D:\Logs" ^
  --stderr-dir-child "D:\Logs" ^
  --stderr-dir-child-jsonl "D:\Logs" ^
  --stderr-dir-child-raw "D:\Logs" ^
  --stderr-dir-sr "D:\Logs" ^
  --stderr-dir-sr-jsonl "D:\Logs" ^
  --stderr-dir-incl-stdout "D:\Logs" ^
  --stderr-dir-incl-stdout-jsonl "D:\Logs" ^
  "D:\Scripts\task.cmd"
```

- Child stdout is recorded independently in Raw TXT, Headered TXT, and JSONL.
- Child stderr and SilentRunner diagnostics are recorded together in
  Headered TXT and JSONL.
- Child stderr is also recorded separately in Raw TXT, Headered TXT, and JSONL.
- SilentRunner diagnostics are also recorded separately in Headered TXT and JSONL.
- The combined chronological output including child stdout, child
  stderr, and SilentRunner diagnostics is recorded in Headered TXT and JSONL.
- Headered TXT applies headers according to child event framing;
  Raw TXT preserves the original child bytes without headers.
- All persistent log destinations may be enabled at the same time.
- Parent stdout/stderr emission keeps its default streaming behavior.
- Log retention keeps its default `always` policy.

## 8. Controlling child event framing


Child event framing determines how captured stdout and stderr are divided into
events. This affects event boundaries and timestamps in Headered TXT and JSONL
output.

With the default `chunk` framing:

~~~cmd
SilentRunner.exe --stdout-dir "D:\Logs" -c "echo First line & echo Second line"
~~~

Both lines may share a single Headered TXT header because read chunks do not
necessarily correspond to individual lines.

To give each line its own event and timestamp, enable LF framing:

~~~cmd
SilentRunner.exe --stdout-event-framing lf --stdout-dir "D:\Logs" -c "echo First line & echo Second line"
~~~

Stdout and stderr framing can be configured independently. For framing modes
and event size limits, see [Child Event Framing](parameters.md#child-event-framing).
For details on event boundaries and output presentation, see
[Child Event Model](architecture.md#child-event-model).

The VLC example in [README.md](../README.md#example-2-vlc---long-running-diagnostics)
demonstrates LF framing in a real-world logging scenario.

------------------------------------------------------------------------

## 9. Delayed output replay


SilentRunner supports delayed output replay from either the in-memory
execution timeline or compatible persistent log files. The following
examples demonstrate both approaches.

### 9a. Failure-only replay from the execution timeline


Build tools can produce substantial output even when compilation
succeeds. In unattended workflows, this output is usually unnecessary,
but it becomes valuable when a build fails.

SilentRunner can keep successful builds silent while preserving the
complete output for failed builds.

Run a build with four parallel jobs:

~~~cmd
SilentRunner.exe --stdout-emit failure --stderr-emit failure --std-total-max-buffer-bytes 33554432 mingw32-make.exe -j4
~~~

- `mingw32-make.exe -j4` runs up to four build jobs in parallel.
- `--stdout-emit failure` withholds child stdout until the execution
  result is known.
- `--stderr-emit failure` similarly withholds child stderr and
  SilentRunner diagnostics.
- No persistent log files are configured. The necessary events and
  payloads are retained in the in-memory execution timeline.
- To limit memory usage, `--std-total-max-buffer-bytes 33554432` sets a
  32 MiB combined replay buffer limit for stdout and stderr. Exceeding
  this limit aborts execution with exit code `125`. It does not limit
  total process memory usage.
- If the build succeeds, nothing is emitted to parent stdout or
  stderr.
- If the build fails, the captured output is replayed during
  finalization, allowing the build failure to be investigated.
- SilentRunner returns the build's exit code on normal completion.

Both stdout and stderr are included because build tools may write
important diagnostic information to either stream.

For large outputs, a compatible persistent log is recommended as the replay
source to avoid excessive memory usage. Example 9b demonstrates this approach.

Separate per-stream limits are also available. See
[Buffering](parameters.md#buffering) for details.

### 9b. Success-only Raw replay from persistent logs


This example demonstrates a creative use of SilentRunner: acting as a
conditional intermediary in a binary-data pipeline. Instead of forwarding
data immediately, SilentRunner stores it temporarily and releases it only
after the downloading process completes successfully.
Downloading an archive directly into an extraction pipeline allows the
extractor to start processing files before the download has finished.
If the download fails, some files may already have been extracted.

SilentRunner can delay the transfer of the downloaded data until `curl.exe`
completes successfully. This example uses the real GNU Hello source
archive from the [official GNU server](https://ftp.gnu.org/gnu/hello/hello-2.12.3.tar.gz).

Create `D:\Extracted` before running the example. SilentRunner creates
the log directory `D:\DownloadSpool` if necessary.

~~~cmd
SilentRunner.exe ^
  --id-prefix download --id-suffix timestamp+pid ^
  --stdout-emit-raw success ^
  --stdout-dir-raw "D:\DownloadSpool" ^
  --stdout-dir-keep-log failure ^
  curl.exe -fsSL "https://ftp.gnu.org/gnu/hello/hello-2.12.3.tar.gz" ^
| SilentRunner.exe ^
  --id-prefix extract --id-suffix timestamp+pid ^
  --inherit-stdin ^
  tar.exe -xzf - -C "D:\Extracted"
~~~

- `curl.exe` downloads the compressed TAR archive and writes its binary
  contents to stdout. It does not save a separate `.tar.gz` file.
- `--stdout-dir-raw` stores the original stdout bytes in a Raw TXT log.
  Despite the log extension, this file contains binary archive data,
  not a textual representation of the archive.
- The Raw log also serves as the persistent file replay source.
  SilentRunner writes the download to disk instead of retaining the
  entire archive in memory. This approach is recommended for larger
  data volumes to avoid excessive memory usage.
- `--stdout-emit-raw success` withholds the downloaded bytes from the
  pipeline until `curl.exe` completes successfully. If the download
  fails, no archive data is forwarded to `tar.exe`.
- The right-hand SilentRunner uses `--inherit-stdin` to pass the
  pipeline input to `tar.exe`.
- `tar.exe` starts when the pipeline is created but waits for input.
  After a successful download, the left-hand SilentRunner replays
  the Raw log, which `tar.exe` decompresses and extracts.
- `--stdout-dir-keep-log failure` removes the Raw log after successful
  execution but preserves it if the download fails.
- `--id-prefix` distinguishes the download and extraction executions.
  `--id-suffix timestamp+pid` adds a unique timestamp and process ID
  to each execution ID, avoiding log filename collisions.

**Pipeline exit codes:** Windows `cmd.exe` does not provide Bash-style
`pipefail` behavior. The exit code reported for a pipeline does not
automatically combine the results of both sides. In this example, the
success-only replay condition applies to the left-hand download execution,
not to the extraction performed by the right-hand SilentRunner.

For workflows that must evaluate every process independently, collect and
check the relevant execution results separately.

After a successful run, the extracted files are available in
`D:\Extracted\hello-2.12.3`. The temporary Raw log is removed,
so no downloaded archive file remains in `D:\DownloadSpool`.

------------------------------------------------------------------------

## 10. Post-execution hooks

Post-execution hooks allow SilentRunner to trigger an action after an
execution succeeds or fails. This example creates a PostgreSQL database
backup and sends an `ntfy` notification if the backup fails.

Create `D:\Backups` and `D:\Hooks` before running the example.

### Database backup

Run `pg_dump.exe` through SilentRunner:

~~~cmd
SilentRunner.exe ^
  --stderr-dir "D:\BackupLogs" ^
  --stderr-dir-keep-log failure ^
  --run-on-failure "D:\Hooks\backup-failure.cmd" ^
  pg_dump.exe -Fc -v -d mydb -f "D:\Backups\mydb.dump"
~~~

- `pg_dump.exe -Fc` creates a PostgreSQL custom-format backup directly
  in the specified file, rather than writing the dump to stdout.
- `-v` enables verbose progress messages, which `pg_dump.exe` writes
  to stderr along with warnings and errors.
- `--stderr-dir` records child stderr and SilentRunner diagnostics in
  a persistent Headered TXT log.
- `--stderr-dir-keep-log failure` retains the diagnostic log only when
  execution fails.
- `--run-on-failure` launches the failure hook after unsuccessful
  execution.

### Failure hook

Create `D:\Hooks\backup-failure.cmd`:

~~~cmd
@echo off
curl.exe -fsS -d "PostgreSQL backup failed (exit code %SILENTRUNNER_EXIT_CODE%). Log: %SILENTRUNNER_STDERR_LOG%" "https://ntfy.sh/YOUR_PRIVATE_TOPIC"
~~~

Replace `YOUR_PRIVATE_TOPIC` with a suitably secured `ntfy` topic,
or configure authentication on a private notification server.

SilentRunner provides execution metadata to the hook through environment
variables. `SILENTRUNNER_EXIT_CODE` contains the execution result, while
`SILENTRUNNER_STDERR_LOG` provides the final diagnostic log path.

The hook is launched as a detached process. SilentRunner does not wait
for its completion or monitor its exit code. Only a failure to launch
the hook itself can change SilentRunner's exit code.
