# SilentRunner.exe

SilentRunner is a lightweight Windows command runner that executes
console applications without creating a console window **(no flashing)**
while capturing **exit code, stdout, stderr, and execution
diagnostics**.

SilentRunner is designed for unattended and automated execution
scenarios such as scripting, CI/CD pipelines, and scheduled tasks.
Its unified chronological timeline can combine captured child output,
process lifecycle events, and execution diagnostics, making it easier
to reconstruct execution flow and investigate failures in both simple
and complex multi-process workflows.

[![CI](https://github.com/jzav/silent-runner/actions/workflows/ci.yml/badge.svg)](https://github.com/jzav/silent-runner/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightblue)
![C++17](https://img.shields.io/badge/C%2B%2B-17-blue)

Key capabilities include:

-   Silent windowless execution via `cmd.exe /d /s /c`.
-   Child process tree management, tracking, and controlled
    termination.
-   Independent routing of child stdout, child stderr, and SilentRunner diagnostics
    to parent stdout/stderr and persistent logs.
-   Immediate or delayed emission to parent stdout/stderr,
    with delayed output optionally replayed from buffer or persistent logs
    `at the end of execution`, `on execution success`, or `on execution failure`.
-   Persistent TXT and JSONL logging with configurable retention policies
    (`always` | `success` | `failure`) and the execution result recorded
    in log filenames.
-   Configurable execution IDs for log naming and workflow integration.
-   Post-execution hooks (`on success` | `on failure`) with execution metadata exposed through
    environment variables.
-   Configurable environment: working directory, standard input, UTF-8 mode, and
    execution timeout.
-   Multiple diagnostic levels, from basic execution messages to detailed debugging with
    process lifecycle tracking and verbose execution summaries.

------------------------------------------------------------------------

## Quick Start

Download `SilentRunner.exe` from the [latest release](https://github.com/jzav/silent-runner/releases/latest).

### Example 1: Programmatic Integration

This example reads the volume of a Windows audio output device without
flashing a console window. The same command is called from Python, Node.js,
and AutoHotkey. SilentRunner streams raw stdout to the calling application,
which uses the exit code to decide whether to use the result. Diagnostic
logs are retained only on failure.

**Shared script (`getdevicevolume.cmd`):**

The script uses NirSoft's
[SoundVolumeCommandLine](https://www.nirsoft.net/utils/sound_volume_command_line.html)
(`svcl.exe`) and
[GetNir](https://www.nirsoft.net/utils/get_nir_command_line_tool.html)
to extract the volume percentage of an active audio device:

~~~cmd
@echo off
"D:\Tools\svcl.exe" /scomma "" | "D:\Tools\GetNir.exe" "Volume Percent" "'Command-Line Friendly ID'='YOUR_DEVICE_ID' && 'Device State'=Active"
~~~

Replace `YOUR_DEVICE_ID` with the device's Command-Line Friendly ID and
adjust the executable paths.

To pass the device ID as a command-line argument instead of hardcoding it
in the script, see
[Tutorial — Execution with parameters](docs/tutorial.md#3-execution-with-parameters).

#### Python

~~~python
import subprocess
import sys

sr_exe = r"D:\Tools\SilentRunner.exe"
cmd_file = r"D:\Scripts\getdevicevolume.cmd"
log_dir = r"D:\Logs\SilentRunner"

cmd = [
    sr_exe,
    "--stdout-emit-raw", "stream",
    "--stderr-emit", "never",
    "--debug",
    "--stderr-dir-incl-stdout", log_dir,
    "--stderr-dir-incl-stdout-keep-log", "failure",
    "--timeout-ms", "3000",
    cmd_file,
]

try:
    completed = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
except OSError as err:
    print(f"Failed to start SilentRunner: {err}", file=sys.stderr)
else:
    volume = completed.stdout

    if completed.returncode == 0 and volume:
        print(f"Device volume: {volume}%")
    else:
        print(f"Volume not available (exit code {completed.returncode}).", file=sys.stderr)
~~~

#### Node.js

~~~javascript
import { spawn } from "node:child_process";

const srExe = "D:\\Tools\\SilentRunner.exe";
const cmdFile = "D:\\Scripts\\getdevicevolume.cmd";
const logDir = "D:\\Logs\\SilentRunner";

const args = [
    "--stdout-emit-raw", "stream",
    "--stderr-emit", "never",
    "--debug",
    "--stderr-dir-incl-stdout", logDir,
    "--stderr-dir-incl-stdout-keep-log", "failure",
    "--timeout-ms", "3000",
    cmdFile
];

const p = spawn(srExe, args);
let volume = "";
let spawnFailed = false;

p.stdout.setEncoding("utf8");
p.stdout.on("data", data => { volume += data; });

p.on("error", err => {
    spawnFailed = true;
    console.error(`Failed to start SilentRunner: ${err.message}`);
});

p.on("close", code => {
    if (spawnFailed) return;

    if (code === 0 && volume !== "")
        console.log(`Device volume: ${volume}%`);
    else
        console.error(`Volume not available (exit code ${code}).`);
});
~~~

#### AutoHotkey_L (v1.1)

~~~autohotkey
srExe := "D:\Tools\SilentRunner.exe"
cmdFile := "D:\Scripts\getdevicevolume.cmd"
logDir := "D:\Logs\SilentRunner"
q := Chr(34)

cmd := q . srExe . q
    . " --stdout-emit-raw stream"
    . " --stderr-emit never"
    . " --debug"
    . " --stderr-dir-incl-stdout " . q . logDir . q
    . " --stderr-dir-incl-stdout-keep-log failure"
    . " --timeout-ms 3000 " . q . cmdFile . q

try
    exec := ComObjCreate("WScript.Shell").Exec(cmd)
catch e
{
    MsgBox, % "Failed to start SilentRunner: " . e.Message
    return
}

volume := exec.StdOut.ReadAll()
code := exec.ExitCode

if (code = 0 && volume != "")
    MsgBox, % "Device volume: " . volume . "%"
else
    MsgBox, % "Volume not available (exit code " . code . ")."
~~~

#### SilentRunner Configuration

All three implementations use the same SilentRunner options:

- `--stdout-emit-raw stream` forwards the original child stdout to the
  calling application without headers or diagnostic messages.
- `--stderr-emit never` suppresses parent stderr output.
- `--stderr-dir-incl-stdout` records child stdout, child stderr, and
  SilentRunner diagnostics in a single Headered TXT log.
- `--debug` adds detailed execution and process lifecycle diagnostics.
- `--stderr-dir-incl-stdout-keep-log failure` retains the log only when
  execution fails.
- `--timeout-ms 3000` limits execution to three seconds.

Each execution has its own log file, identified by an execution ID
(`timestamp+pid` by default). Files are written with a `running` suffix
during execution and renamed with a `success` or `failure` suffix during
finalization. Successful runs leave no log files; failed runs retain the
combined diagnostic log, making it easier to identify the cause of a problem.

### Example 2: VLC - Long-Running Diagnostics

VLC, like many other applications, can run continuously for a long time,
producing diagnostic messages without individual timestamps.
SilentRunner captures these messages, adds UTC timestamps, and writes
them to a continuously updated log without modifying VLC itself. 

#### Prepare VLC

In VLC, open **Tools > Preferences > Interface > Playlist and Instances** and
enable **Allow only one instance** and **Use only one instance when started
from file manager**. This allows media opened later from File Explorer to be
handled by the already running VLC instance.

Also disable VLC's built-in file logging so that SilentRunner can capture its
diagnostic output.

#### Launch VLC using a Windows shortcut (.lnk)

For manual launching, create a Windows shortcut (`.lnk`) with the following
properties:

**Target:**

```text
"D:\Tools\SilentRunner.exe" --debug --stderr-child-event-framing lf --stderr-dir-incl-stdout "D:\Logs" "C:\Program Files\VideoLAN\VLC\vlc.exe" --verbose=2
```

**Start in:**

```text
"C:\Program Files\VideoLAN\VLC"
```

#### Start VLC at logon with Task Scheduler

As an alternative to launching VLC manually through the shortcut, Windows Task
Scheduler can start VLC through SilentRunner automatically when the user logs on.
This keeps VLC ready for opening media files while capturing its diagnostics
from the beginning of the session.

Create a new task in Task Scheduler (`taskschd.msc`) with these settings:

| Tab | Setting | Value |
| --- | --- | --- |
| General | Name | `VLC with SilentRunner logging` |
| General | Security options | `Run only when user is logged on` |
| Triggers | Begin the task | `At log on` (specific user) |
| Actions | Action | `Start a program` |
| Actions | Program/script | `D:\Tools\SilentRunner.exe` |
| Actions | Add arguments | See below |
| Actions | Start in | `C:\Program Files\VideoLAN\VLC` |
| Settings | If the task is already running | `Do not start a new instance` |
| Settings | Stop the task if it runs longer than | Disabled |

**Add arguments:**

~~~text
--debug --stderr-child-event-framing lf --stderr-dir-incl-stdout "D:\Logs" "C:\Program Files\VideoLAN\VLC\vlc.exe" --verbose=2
~~~

Use `Run only when user is logged on` because VLC is a graphical application
that needs access to the interactive desktop. 

#### Understanding the VLC diagnostic log

The `--verbose=2` argument belongs to VLC and enables detailed VLC
diagnostics. SilentRunner's `--stderr-child-event-framing lf` divides
VLC's stderr into individual line-based events, each receiving its
own timestamped header.

For a step-by-step comparison of `chunk` and `lf` framing, see
[Tutorial — Controlling child event framing](docs/tutorial.md#8-controlling-child-event-framing).

An illustrative excerpt from the Headered TXT log (some header fields
and message details omitted):

~~~text
[payloadType=CHILDSTDERR] [tsUtc=2026-11-17T12:31:12.550Z] [executionId=2026-11-17_12-31-12Z_pid14636][phase=RUNTIME][phaseOrderNo=2][eventOrderNo=35] ...
[0000020767ec38f0] main libvlc debug: VLC media player - 3.0.24 Vetinari
[payloadType=CHILDSTDERR] [tsUtc=2026-11-17T12:31:12.550Z] [executionId=2026-11-17_12-31-12Z_pid14636][phase=RUNTIME][phaseOrderNo=2][eventOrderNo=36] ...
[0000020767ec38f0] main libvlc debug: Copyright © 1996-2026 the VideoLAN team
[payloadType=CHILDSTDERR] [tsUtc=2026-11-17T12:31:12.550Z] [executionId=2026-11-17_12-31-12Z_pid14636][phase=RUNTIME][phaseOrderNo=2][eventOrderNo=37] ...
[0000020767ec38f0] main libvlc debug: revision 3.0.24-rc1-0-g6de05adcba
~~~

The `--stderr-dir-incl-stdout` target records VLC stderr and stdout
alongside SilentRunner diagnostics in a single chronological log.
With `--debug`, the log also includes process lifecycle information.

For a general step-by-step introduction, see [Tutorial](docs/tutorial.md).
For detailed configuration options, see
[Parameter Categories](docs/parameters.md).

------------------------------------------------------------------------

## Documentation

- [Architecture Overview](docs/architecture.md)
- [Execution](docs/execution.md)
- [Parameter Categories](docs/parameters.md)
- [Tutorial](docs/tutorial.md)

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
