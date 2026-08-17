#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SilentRunner GUI Tester

Target:
- Python 3.10+
- Windows-friendly Tkinter GUI

Purpose:
- Run SilentRunner with arbitrary arguments.
- Capture stdout and stderr concurrently to avoid pipe deadlocks.
- Show exit code, stdout, and stderr in copy-friendly text areas.
- Keep working even when one stream is effectively silent because SilentRunner
  is configured with modes like stdout=never and stderr=stream.

Notes:
- The tester captures whatever SilentRunner emits to its own parent stdout/stderr.
- If SilentRunner is configured to log to files only and not emit to parent,
  the corresponding text area will stay empty by design.
"""

from __future__ import annotations

import ctypes
import locale
import os
import queue
from ctypes import wintypes
import shutil
import subprocess
import sys
import threading
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from typing import Callable


def split_windows_command_line(command_line: str) -> list[str]:
    if not command_line.strip():
        return []

    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    command_line_to_argv_w = shell32.CommandLineToArgvW
    command_line_to_argv_w.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(ctypes.c_int),
    ]
    command_line_to_argv_w.restype = ctypes.POINTER(wintypes.LPWSTR)

    local_free = kernel32.LocalFree
    local_free.argtypes = [wintypes.HLOCAL]
    local_free.restype = wintypes.HLOCAL

    argc = ctypes.c_int()
    argv = command_line_to_argv_w(
        "SilentRunnerTester.exe " + command_line,
        ctypes.byref(argc),
    )
    if not argv:
        raise OSError(
            ctypes.get_last_error(),
            "CommandLineToArgvW failed.",
        )

    try:
        return [argv[index] for index in range(1, argc.value)]
    finally:
        local_free(argv)


@dataclass(frozen=True)
class StreamChunk:
    stream_name: str
    data: bytes


@dataclass(frozen=True)
class ProcessFinished:
    exit_code: int


class SilentRunnerTesterApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("SilentRunner Tester")
        self.root.geometry("1200x820")
        self.root.minsize(980, 680)

        self.process: subprocess.Popen[bytes] | None = None
        self.reader_threads: list[threading.Thread] = []
        self.event_queue: queue.Queue[StreamChunk | ProcessFinished | tuple[str, str]] = queue.Queue()
        self.stdout_buffer = bytearray()
        self.stderr_buffer = bytearray()
        self.running = False
        self.stop_requested = False

        self._build_variables()
        self._build_ui()
        self._schedule_queue_pump()

    def _build_variables(self) -> None:
        self.sr_path_var = tk.StringVar(value="SilentRunner.exe")
        self.args_var = tk.StringVar()
        self.parsed_args_var = tk.StringVar()
        self.arguments_expanded = False
        self.parsed_arguments_expanded = False
        self.exit_code_var = tk.StringVar(value="-")
        self.status_var = tk.StringVar(value="Ready")
        self.decode_var = tk.StringVar(value="auto")
        self.wrap_var = tk.BooleanVar(value=False)
        self.autoscroll_var = tk.BooleanVar(value=True)
        self.merge_stderr_to_stdout_var = tk.BooleanVar(value=False)

    def _build_ui(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(3, weight=1)

        top = ttk.Frame(self.root, padding=10)
        top.grid(row=0, column=0, sticky="nsew")
        top.columnconfigure(1, weight=1)

        ttk.Label(top, text="SilentRunner path:").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=(0, 6))
        ttk.Entry(top, textvariable=self.sr_path_var).grid(row=0, column=1, sticky="ew", pady=(0, 6))
        ttk.Button(top, text="Browse...", command=self._browse_sr_path).grid(row=0, column=2, sticky="ew", padx=(8, 0), pady=(0, 6))
        ttk.Button(top, text="?", width=3, command=self._show_sr_path_help).grid(row=0, column=3, sticky="ew", padx=(4, 0), pady=(0, 6))

        ttk.Label(top, text="Arguments:").grid(
            row=1,
            column=0,
            sticky="nw",
            padx=(0, 8),
            pady=(0, 6),
        )

        self.arguments_container = ttk.Frame(top)
        self.arguments_container.grid(
            row=1,
            column=1,
            sticky="ew",
            pady=(0, 6),
        )
        self.arguments_container.columnconfigure(0, weight=1)

        self.arguments_entry = ttk.Entry(
            self.arguments_container,
            textvariable=self.args_var,
        )
        self.arguments_entry.grid(row=0, column=0, sticky="ew")

        self.arguments_text = tk.Text(
            self.arguments_container,
            height=1,
            wrap="word",
            font=("Consolas", 10),
        )
        self.arguments_text.bind(
            "<<Modified>>",
            lambda _event: self._on_expandable_text_modified(self.arguments_text),
        )

        self.arguments_toggle_button = ttk.Button(
            top,
            text="Expand",

            command=self._toggle_arguments_expanded,
        )
        self.arguments_toggle_button.grid(
            row=1,
            column=2,
            sticky="ne",
            padx=(8, 0),
            pady=(0, 6),
        )


        options = ttk.Frame(self.root, padding=(10, 0, 10, 8))
        options.grid(row=1, column=0, sticky="ew")
        for i in range(10):
            options.columnconfigure(i, weight=0)
        options.columnconfigure(10, weight=1)

        ttk.Button(options, text="Run", command=self._run_process).grid(row=0, column=0, padx=(0, 8))
        ttk.Button(options, text="Parse args", command=self._parse_args_only).grid(row=0, column=1, padx=(0, 8))
        ttk.Button(options, text="Stop", command=self._stop_process).grid(row=0, column=2, padx=(0, 12))
        ttk.Button(options, text="Clear", command=self._clear_outputs).grid(row=0, column=3, padx=(0, 12))

        ttk.Label(options, text="Decode:").grid(row=0, column=4, sticky="w", padx=(0, 4))
        decode_combo = ttk.Combobox(
            options,
            textvariable=self.decode_var,
            width=16,
            state="readonly",
            values=["auto", "utf-8", "cp1250", "cp850", "cp852", "latin-1"],
        )
        decode_combo.grid(row=0, column=5, padx=(0, 12))

        ttk.Checkbutton(options, text="Word wrap", variable=self.wrap_var, command=self._apply_wrap_mode).grid(row=0, column=6, padx=(0, 12))
        ttk.Checkbutton(options, text="Autoscroll", variable=self.autoscroll_var).grid(row=0, column=7, padx=(0, 12))
        ttk.Checkbutton(options, text="Merge stderr -> stdout", variable=self.merge_stderr_to_stdout_var).grid(row=0, column=8, padx=(0, 12))

        ttk.Label(options, text="Exit code:").grid(row=0, column=9, sticky="e", padx=(0, 4))
        ttk.Label(options, textvariable=self.exit_code_var, width=8).grid(row=0, column=10, sticky="w")

        parsed = ttk.Frame(self.root, padding=(10, 0, 10, 8))
        parsed.grid(row=2, column=0, sticky="ew")
        parsed.columnconfigure(1, weight=1)

        ttk.Label(parsed, text="Parsed arguments:").grid(
            row=0,
            column=0,
            sticky="nw",
            padx=(0, 8),
        )

        self.parsed_arguments_container = ttk.Frame(parsed)
        self.parsed_arguments_container.grid(
            row=0,
            column=1,
            sticky="ew",
        )
        self.parsed_arguments_container.columnconfigure(0, weight=1)

        self.parsed_arguments_entry = ttk.Entry(
            self.parsed_arguments_container,
            textvariable=self.parsed_args_var,
        )
        self.parsed_arguments_entry.grid(row=0, column=0, sticky="ew")

        self.parsed_arguments_text = tk.Text(
            self.parsed_arguments_container,
            height=1,
            wrap="word",
            font=("Consolas", 10),
        )
        self.parsed_arguments_text.bind(
            "<<Modified>>",
            lambda _event: self._on_expandable_text_modified(self.parsed_arguments_text),
        )

        self.parsed_arguments_toggle_button = ttk.Button(
            parsed,
            text="Expand",

            command=self._toggle_parsed_arguments_expanded,
        )
        self.parsed_arguments_toggle_button.grid(
            row=0,
            column=2,
            sticky="ne",
            padx=(8, 0),
        )

        panes = ttk.Panedwindow(self.root, orient=tk.VERTICAL)
        panes.grid(row=3, column=0, sticky="nsew", padx=10, pady=(0, 10))

        stdout_frame = self._build_stream_panel(panes, "STDOUT", self._copy_stdout)
        stderr_frame = self._build_stream_panel(panes, "STDERR", self._copy_stderr)
        panes.add(stdout_frame, weight=1)
        panes.add(stderr_frame, weight=1)

        bottom = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        bottom.grid(row=4, column=0, sticky="ew")
        bottom.columnconfigure(0, weight=1)
        ttk.Label(bottom, textvariable=self.status_var, anchor="w").grid(row=0, column=0, sticky="ew")
        ttk.Button(bottom, text="Copy both", command=self._copy_both).grid(row=0, column=1, padx=(8, 0))

        self._apply_wrap_mode()

    def _build_stream_panel(self, parent: ttk.Panedwindow, title: str, copy_callback: Callable[[], None]) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=4)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)

        header = ttk.Frame(frame)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 4))
        header.columnconfigure(0, weight=1)

        ttk.Label(header, text=title).grid(row=0, column=0, sticky="w")
        ttk.Button(header, text=f"Copy {title.lower()}", command=copy_callback).grid(row=0, column=1, sticky="e")

        text = ScrolledText(frame, undo=False, maxundo=0, font=("Consolas", 10))
        text.grid(row=1, column=0, sticky="nsew")
        text.configure(state="normal")

        if title == "STDOUT":
            self.stdout_text = text
        else:
            self.stderr_text = text

        return frame

    def _get_arguments_text(self) -> str:
        if self.arguments_expanded:
            return self.arguments_text.get("1.0", "end-1c")
        return self.args_var.get()

    def _set_parsed_arguments(self, tokens: list[str]) -> None:
        parsed = " ".join(
            f"[{index}] {token}"
            for index, token in enumerate(tokens)
        )
        self.parsed_args_var.set(parsed)

        if self.parsed_arguments_expanded:
            self.parsed_arguments_text.delete("1.0", "end")
            self.parsed_arguments_text.insert("1.0", parsed)
            self.parsed_arguments_text.edit_modified(False)
            self._fit_expanded_text(self.parsed_arguments_text)

    def _parse_arguments(self) -> list[str]:
        try:
            tokens = split_windows_command_line(self._get_arguments_text())
        except OSError as exc:
            raise ValueError(f"Arguments could not be parsed: {exc}") from exc

        self._set_parsed_arguments(tokens)
        return tokens

    def _parse_args_only(self) -> None:
        try:
            tokens = self._parse_arguments()
        except ValueError as exc:
            messagebox.showerror("SilentRunner Tester", str(exc))
            return

        self.status_var.set(f"Parsed {len(tokens)} argument(s)")

    def _fit_expanded_text(self, text_widget: tk.Text) -> None:
        self.root.update_idletasks()

        count = text_widget.count(
            "1.0",
            "end-1c",
            "displaylines",
        )
        required_lines = max(1, count[0] if count else 1)

        current_lines = max(1, int(text_widget.cget("height")))
        if required_lines <= current_lines:
            text_widget.configure(height=required_lines)
            return

        line_height = text_widget.dlineinfo("1.0")
        if not line_height:
            return
        line_height_px = line_height[3]

        stdout_line_height = self.stdout_text.dlineinfo("1.0")
        stderr_line_height = self.stderr_text.dlineinfo("1.0")
        if not stdout_line_height or not stderr_line_height:
            return

        self.root.update_idletasks()

        available_output_px = (
            self.stdout_text.winfo_height()
            + self.stderr_text.winfo_height()
            - stdout_line_height[3]
            - stderr_line_height[3]
        )
        additional_lines = max(0, available_output_px // line_height_px)

        text_widget.configure(
            height=min(required_lines, current_lines + additional_lines)
        )


    def _on_expandable_text_modified(self, text_widget: tk.Text) -> None:
        if not text_widget.edit_modified():
            return

        text_widget.edit_modified(False)
        self._fit_expanded_text(text_widget)

    def _toggle_arguments_expanded(self) -> None:
        if self.arguments_expanded:
            self.args_var.set(self.arguments_text.get("1.0", "end-1c"))
            self.arguments_text.grid_remove()
            self.arguments_entry.grid(row=0, column=0, sticky="ew")
            self.arguments_toggle_button.configure(text="Expand")

            self.arguments_expanded = False
            return

        self.arguments_text.delete("1.0", "end")
        self.arguments_text.insert("1.0", self.args_var.get())
        self.arguments_text.edit_modified(False)
        self.arguments_entry.grid_remove()
        self.arguments_text.grid(row=0, column=0, sticky="ew")
        self.arguments_toggle_button.configure(text="Collapse")
        self.arguments_expanded = True
        self._fit_expanded_text(self.arguments_text)

    def _toggle_parsed_arguments_expanded(self) -> None:
        if self.parsed_arguments_expanded:
            self.parsed_args_var.set(
                self.parsed_arguments_text.get("1.0", "end-1c")
            )
            self.parsed_arguments_text.grid_remove()
            self.parsed_arguments_entry.grid(row=0, column=0, sticky="ew")
            self.parsed_arguments_toggle_button.configure(text="Expand")
            self.parsed_arguments_expanded = False
            return

        self.parsed_arguments_text.delete("1.0", "end")
        self.parsed_arguments_text.insert("1.0", self.parsed_args_var.get())
        self.parsed_arguments_text.edit_modified(False)
        self.parsed_arguments_entry.grid_remove()
        self.parsed_arguments_text.grid(row=0, column=0, sticky="ew")
        self.parsed_arguments_toggle_button.configure(text="Collapse")
        self.parsed_arguments_expanded = True
        self._fit_expanded_text(self.parsed_arguments_text)

    def _schedule_queue_pump(self) -> None:
        self.root.after(50, self._process_event_queue)

    def _process_event_queue(self) -> None:
        try:
            while True:
                item = self.event_queue.get_nowait()
                if isinstance(item, StreamChunk):
                    self._append_stream_chunk(item.stream_name, item.data)
                elif isinstance(item, ProcessFinished):
                    self.exit_code_var.set(str(item.exit_code))
                    self.running = False
                    self.process = None
                    self.reader_threads.clear()
                    status = "Stopped by user" if self.stop_requested else f"Finished with exit code {item.exit_code}"
                    self.status_var.set(status)
                    self.stop_requested = False
                else:
                    kind, message = item
                    if kind == "error":
                        self.running = False
                        self.process = None
                        self.reader_threads.clear()
                        self.status_var.set(message)
                        messagebox.showerror("SilentRunner Tester", message)
        except queue.Empty:
            pass
        finally:
            self._schedule_queue_pump()

    def _append_stream_chunk(self, stream_name: str, data: bytes) -> None:
        if stream_name == "stdout":
            self.stdout_buffer.extend(data)
            target = self.stdout_text
        else:
            self.stderr_buffer.extend(data)
            target = self.stderr_text

        decoded = self._decode_bytes(data)
        target.insert("end", decoded)
        if self.autoscroll_var.get():
            target.see("end")

    def _decode_bytes(self, data: bytes) -> str:
        mode = self.decode_var.get().strip().lower()
        if mode and mode != "auto":
            return data.decode(mode, errors="replace")

        for encoding in ("utf-8", locale.getpreferredencoding(False), "cp1250", "cp850", "cp852", "latin-1"):
            try:
                return data.decode(encoding)
            except UnicodeDecodeError:
                continue

        return data.decode("utf-8", errors="replace")

    def _build_command(self) -> tuple[list[str], str]:
        sr_path_raw = self.sr_path_var.get().strip()
        if not sr_path_raw:
            raise ValueError("SilentRunner path is empty.")

        resolved_executable = shutil.which(sr_path_raw)
        if not resolved_executable:
            raise ValueError(
                f"SilentRunner executable was not found:\n{sr_path_raw}"
            )

        extra_args = self._parse_arguments()

        executable = Path(resolved_executable).resolve()
        command = [str(executable), *extra_args]
        working_dir = str(executable.parent)

        return command, working_dir

    def _run_process(self) -> None:
        if self.running:
            messagebox.showwarning("SilentRunner Tester", "A process is already running.")
            return

        try:
            command, working_dir = self._build_command()
        except ValueError as exc:
            messagebox.showerror("SilentRunner Tester", str(exc))
            return


        self._clear_outputs()
        self.exit_code_var.set("running")
        self.status_var.set("Running...")
        self.stop_requested = False

        stderr_target: int | None
        if self.merge_stderr_to_stdout_var.get():
            stderr_target = subprocess.STDOUT
        else:
            stderr_target = subprocess.PIPE

        try:
            self.process = subprocess.Popen(
                command,
                cwd=working_dir,
                stdout=subprocess.PIPE,
                stderr=stderr_target,
                stdin=subprocess.DEVNULL,
                bufsize=0,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except OSError as exc:
            self.process = None
            self.exit_code_var.set("-")
            self.status_var.set("Launch failed")
            messagebox.showerror("SilentRunner Tester", f"Failed to start process:\n{exc}")
            return

        self.running = True
        self.reader_threads = []

        if self.process.stdout is not None:
            self.reader_threads.append(
                threading.Thread(target=self._reader_loop, args=("stdout", self.process.stdout), daemon=True)
            )

        if self.process.stderr is not None:
            self.reader_threads.append(
                threading.Thread(target=self._reader_loop, args=("stderr", self.process.stderr), daemon=True)
            )

        for thread in self.reader_threads:
            thread.start()

        threading.Thread(target=self._waiter_loop, daemon=True).start()

    def _reader_loop(self, stream_name: str, stream) -> None:
        try:
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    break
                self.event_queue.put(StreamChunk(stream_name=stream_name, data=chunk))
        except Exception as exc:
            self.event_queue.put(("error", f"Reader thread for {stream_name} failed: {exc}"))
        finally:
            try:
                stream.close()
            except Exception:
                pass

    def _waiter_loop(self) -> None:
        if self.process is None:
            return

        try:
            exit_code = self.process.wait()
        except Exception as exc:
            self.event_queue.put(("error", f"Waiting for process failed: {exc}"))
            return

        for thread in self.reader_threads:
            thread.join(timeout=1.0)

        self.event_queue.put(ProcessFinished(exit_code=exit_code))

    def _stop_process(self) -> None:
        if not self.running or self.process is None:
            return

        self.stop_requested = True

        try:
            self.process.terminate()
            self.status_var.set("Stop requested...")
        except OSError as exc:
            messagebox.showerror("SilentRunner Tester", f"Failed to stop process:\n{exc}")

    def _clear_outputs(self) -> None:
        self.stdout_buffer.clear()
        self.stderr_buffer.clear()
        self.stdout_text.delete("1.0", "end")
        self.stderr_text.delete("1.0", "end")
        self.exit_code_var.set("-")
        if not self.running:
            self.status_var.set("Ready")

    def _copy_stdout(self) -> None:
        self._copy_to_clipboard(self.stdout_text.get("1.0", "end-1c"), "STDOUT copied to clipboard")

    def _copy_stderr(self) -> None:
        self._copy_to_clipboard(self.stderr_text.get("1.0", "end-1c"), "STDERR copied to clipboard")

    def _copy_both(self) -> None:
        payload = (
            f"ExitCode: {self.exit_code_var.get()}\n"
            f"\n===== STDOUT =====\n"
            f"{self.stdout_text.get('1.0', 'end-1c')}\n"
            f"\n===== STDERR =====\n"
            f"{self.stderr_text.get('1.0', 'end-1c')}"
        )
        self._copy_to_clipboard(payload, "Exit code, stdout, and stderr copied to clipboard")

    def _copy_to_clipboard(self, text: str, status_message: str) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update_idletasks()
        self.status_var.set(status_message)

    def _apply_wrap_mode(self) -> None:
        wrap_mode = "word" if self.wrap_var.get() else "none"
        self.stdout_text.configure(wrap=wrap_mode)
        self.stderr_text.configure(wrap=wrap_mode)

    def _show_sr_path_help(self) -> None:
        messagebox.showinfo(
            "SilentRunner path",
            "Specifies the SilentRunner executable to run.\n\n"
            "If only an executable name is specified, the tester attempts to "
            "locate it using the Windows PATH environment variable.\n\n"
            "The tester starts the resolved SilentRunner executable with the "
            "executable's directory as its working directory.\n\n"
            "This is different from SilentRunner's --cwd option, which sets "
            "the working directory for the child process and post-execution "
            "hooks.\n\n"
            "To test SilentRunner with a different inherited working "
            "directory, place or copy the executable to that directory and "
            "select it here.",
        )

    def _browse_sr_path(self) -> None:
        filename = filedialog.askopenfilename(
            title="Select SilentRunner executable",
            filetypes=[("Executable files", "*.exe"), ("All files", "*.*")],
        )
        if filename:
            self.sr_path_var.set(filename)



def main() -> int:
    root = tk.Tk()
    style = ttk.Style(root)
    try:
        style.theme_use("vista")
    except tk.TclError:
        pass

    SilentRunnerTesterApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
