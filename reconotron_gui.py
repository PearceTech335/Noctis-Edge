#!/usr/bin/env python3
"""
ReconoTron GUI — Tkinter front-end for reconotron.py

Run with:  python3 reconotron_gui.py
"""

import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import messagebox, filedialog

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
RECONOTRON  = os.path.join(BASE_DIR, "reconotron.py")
PYTHON      = sys.executable

# ── Colour palette (VS Code Dark+ inspired) ────────────────────────────────
BG          = "#1e1e1e"
BG_PANEL    = "#252526"
BG_INPUT    = "#3c3c3c"
BG_TERMINAL = "#0d0d0d"
FG          = "#d4d4d4"
FG_DIM      = "#858585"
ACCENT      = "#007acc"
BTN_RUN     = "#28a745"
BTN_STOP    = "#c0392b"
BTN_SEND    = "#007acc"
BTN_FG      = "#ffffff"
BTN_Y       = "#27ae60"
BTN_N       = "#c0392b"

# Terminal output colour tags
TAG_GOOD    = "#4ec9b0"   # [+]  green-teal
TAG_WARN    = "#ce9178"   # [!]  amber
TAG_BAD     = "#f44747"   # [-]  red
TAG_INFO    = "#569cd6"   # [*]  blue
TAG_HEAD    = "#dcdcaa"   # ===/ --- headers  yellow
TAG_INPUT   = "#c586c0"   # > user input  purple
TAG_DIM     = "#6a6a6a"   # comments / dim
TAG_NORMAL  = "#d4d4d4"

PROFILES    = ["web", "external", "internal_ad", "api", "cloud"]

PROFILE_DESCRIPTIONS = {
    "web":         "Web Application Assessment — curl, nikto, nuclei, gobuster, ffuf",
    "external":    "External Perimeter Review — nmap, curl, nuclei, gobuster, dns_enum",
    "internal_ad": "Internal AD Assessment — nmap, nxc (SMB/LDAP)",
    "api":         "API Assessment — curl, nuclei, ffuf",
    "cloud":       "Cloud Exposure Review — curl, nuclei, dns_enum",
}

FLAGS = [
    ("--aggressive",   "Disable safe-mode: run gobuster / ffuf / hydra without approval"),
    ("--airgap",       "Disable internet-dependent tools (amass, dnsenum, dnsrecon)"),
    ("--msf-validate", "Run safe Metasploit 'check' probes for each matched CVE"),
    ("--cve-test",     "Ask the LLM to generate & execute probe scripts per CVE"),
    ("--resume",       "Resume the most recent interrupted scan for this target"),
]


# ── Small helpers ───────────────────────────────────────────────────────────

def _flat_btn(parent, text, command, bg, fg=BTN_FG, **kw):
    kw.setdefault("padx", 14)
    kw.setdefault("pady", 5)
    return tk.Button(
        parent, text=text, command=command,
        bg=bg, fg=fg, activebackground=bg, activeforeground=fg,
        relief=tk.FLAT, bd=0, cursor="hand2",
        font=("Consolas", 10, "bold"),
        **kw,
    )


class _Tooltip:
    """Minimal hover tooltip."""
    def __init__(self, widget, text):
        self._tip = None
        widget.bind("<Enter>", lambda _: self._show(widget, text))
        widget.bind("<Leave>", lambda _: self._hide())

    def _show(self, widget, text):
        x = widget.winfo_rootx() + 10
        y = widget.winfo_rooty() + widget.winfo_height() + 4
        self._tip = tk.Toplevel(widget)
        self._tip.wm_overrideredirect(True)
        self._tip.wm_geometry(f"+{x}+{y}")
        tk.Label(
            self._tip, text=text, bg="#3c3c3c", fg=FG,
            font=("Consolas", 9), relief=tk.FLAT, padx=8, pady=4,
        ).pack()

    def _hide(self):
        if self._tip:
            self._tip.destroy()
            self._tip = None


# ── Main application ────────────────────────────────────────────────────────

class ReconoTronGUI:
    def __init__(self, root: tk.Tk):
        self.root    = root
        self.process: subprocess.Popen | None = None
        self.q:       queue.Queue = queue.Queue()
        self.running  = False

        root.title("ReconoTron — AI-Assisted Penetration Testing")
        root.configure(bg=BG)
        root.minsize(820, 580)
        root.geometry("1000x740")

        self._build_ui()
        self._poll_queue()

    # ── UI construction ─────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Header bar ──────────────────────────────────────────────────────
        hdr = tk.Frame(self.root, bg=BG_PANEL, pady=10, padx=14)
        hdr.pack(fill=tk.X)

        tk.Label(
            hdr, text="ReconoTron",
            font=("Consolas", 18, "bold"), bg=BG_PANEL, fg=ACCENT,
        ).pack(side=tk.LEFT)

        tk.Label(
            hdr, text="  AI-Assisted Penetration Testing Platform",
            font=("Consolas", 10), bg=BG_PANEL, fg=FG_DIM,
        ).pack(side=tk.LEFT, pady=4)

        # ── Target row ───────────────────────────────────────────────────────
        row1 = tk.Frame(self.root, bg=BG, padx=12, pady=6)
        row1.pack(fill=tk.X)

        tk.Label(row1, text="Target:", bg=BG, fg=FG,
                 font=("Consolas", 11)).pack(side=tk.LEFT)

        self.target_var = tk.StringVar()
        target_entry = tk.Entry(
            row1, textvariable=self.target_var, width=30,
            bg=BG_INPUT, fg=FG, insertbackground=FG,
            relief=tk.FLAT, font=("Consolas", 11),
            highlightthickness=1, highlightcolor=ACCENT,
            highlightbackground=FG_DIM,
        )
        target_entry.pack(side=tk.LEFT, padx=(5, 0), ipady=3)
        target_entry.bind("<Return>", lambda _: self._start_scan())
        _Tooltip(target_entry, "Hostname or IP address to scan (e.g. 192.168.0.1)")

        # ── Profiles (multi-select checkboxes) ───────────────────────────────
        profiles_outer = tk.Frame(self.root, bg=BG, padx=12)
        profiles_outer.pack(fill=tk.X)

        profiles_frame = tk.LabelFrame(
            profiles_outer, text="  Profiles (select one or more)  ",
            bg=BG_PANEL, fg=FG_DIM,
            font=("Consolas", 9), bd=1, relief=tk.GROOVE,
            padx=10, pady=8,
        )
        profiles_frame.pack(fill=tk.X)

        self.profile_vars: dict[str, tk.BooleanVar] = {}
        for col, name in enumerate(PROFILES):
            var = tk.BooleanVar(value=(name == "web"))  # web checked by default
            self.profile_vars[name] = var
            cb = tk.Checkbutton(
                profiles_frame, text=name, variable=var,
                bg=BG_PANEL, fg=FG, selectcolor=BG_INPUT,
                activebackground=BG_PANEL, activeforeground=FG,
                font=("Consolas", 10),
            )
            cb.grid(row=0, column=col, padx=14, sticky=tk.W)
            _Tooltip(cb, PROFILE_DESCRIPTIONS[name])

        # ── Flags ────────────────────────────────────────────────────────────
        flags_outer = tk.Frame(self.root, bg=BG, padx=12)
        flags_outer.pack(fill=tk.X)

        flags_frame = tk.LabelFrame(
            flags_outer, text="  Scan Flags  ",
            bg=BG_PANEL, fg=FG_DIM,
            font=("Consolas", 9), bd=1, relief=tk.GROOVE,
            padx=10, pady=8,
        )
        flags_frame.pack(fill=tk.X)

        self.flag_vars: dict[str, tk.BooleanVar] = {}
        for col, (flag, tip) in enumerate(FLAGS):
            var = tk.BooleanVar()
            self.flag_vars[flag] = var
            cb = tk.Checkbutton(
                flags_frame, text=flag, variable=var,
                bg=BG_PANEL, fg=FG, selectcolor=BG_INPUT,
                activebackground=BG_PANEL, activeforeground=FG,
                font=("Consolas", 10),
            )
            cb.grid(row=0, column=col, padx=14, sticky=tk.W)
            _Tooltip(cb, tip)

        # ── Toolbar ──────────────────────────────────────────────────────────
        toolbar = tk.Frame(self.root, bg=BG, padx=12, pady=6)
        toolbar.pack(fill=tk.X)

        self.run_btn = _flat_btn(toolbar, "▶  Start Scan", self._start_scan, BTN_RUN)
        self.run_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.stop_btn = _flat_btn(toolbar, "■  Stop", self._stop_scan, BTN_STOP,
                                  state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 6))

        _flat_btn(toolbar, "Clear", self._clear_output,
                  BG_PANEL, fg=FG_DIM).pack(side=tk.LEFT, padx=(0, 6))

        _flat_btn(toolbar, "Report", self._generate_report,
                  "#7d3c98").pack(side=tk.LEFT, padx=(0, 16))

        self.cmd_label = tk.Label(
            toolbar, text="", bg=BG, fg=FG_DIM,
            font=("Consolas", 9), anchor=tk.W,
        )
        self.cmd_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # ── Terminal output ──────────────────────────────────────────────────
        out_frame = tk.Frame(self.root, bg=BG, padx=12)
        out_frame.pack(fill=tk.BOTH, expand=True)

        self.output = tk.Text(
            out_frame,
            bg=BG_TERMINAL, fg=TAG_NORMAL,
            font=("Consolas", 10), wrap=tk.WORD,
            state=tk.DISABLED, relief=tk.FLAT,
            insertbackground=FG, selectbackground=ACCENT,
            padx=10, pady=8,
        )
        vsb = tk.Scrollbar(out_frame, command=self.output.yview,
                           bg=BG_PANEL, troughcolor=BG, activebackground=ACCENT)
        self.output.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # colour tags
        self.output.tag_config("good",   foreground=TAG_GOOD)
        self.output.tag_config("warn",   foreground=TAG_WARN)
        self.output.tag_config("bad",    foreground=TAG_BAD)
        self.output.tag_config("info",   foreground=TAG_INFO)
        self.output.tag_config("head",   foreground=TAG_HEAD)
        self.output.tag_config("userinp",foreground=TAG_INPUT)
        self.output.tag_config("dim",    foreground=TAG_DIM)
        self.output.tag_config("normal", foreground=TAG_NORMAL)

        # ── Input row ────────────────────────────────────────────────────────
        inp_row = tk.Frame(self.root, bg=BG_PANEL, padx=12, pady=6)
        inp_row.pack(fill=tk.X)

        tk.Label(inp_row, text="Prompt reply:", bg=BG_PANEL, fg=FG_DIM,
                 font=("Consolas", 9)).pack(side=tk.LEFT)

        self.input_var = tk.StringVar()
        self.input_entry = tk.Entry(
            inp_row, textvariable=self.input_var,
            bg=BG_INPUT, fg=FG, insertbackground=FG,
            relief=tk.FLAT, font=("Consolas", 10),
            highlightthickness=1, highlightcolor=ACCENT,
            highlightbackground=FG_DIM,
        )
        self.input_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 6), ipady=3)
        self.input_entry.bind("<Return>", lambda _: self._send_input())
        _Tooltip(self.input_entry,
                 "Type a reply to any y/n prompt and press Enter (or use the quick buttons)")

        _flat_btn(inp_row, "Send", self._send_input,
                  BTN_SEND, padx=10).pack(side=tk.LEFT, padx=(0, 8))
        _flat_btn(inp_row, "Y", lambda: self._quick_reply("y"),
                  BTN_Y, padx=14).pack(side=tk.LEFT, padx=(0, 4))
        _flat_btn(inp_row, "N", lambda: self._quick_reply("n"),
                  BTN_N, padx=14).pack(side=tk.LEFT)

        # ── Status bar ───────────────────────────────────────────────────────
        status_bar = tk.Frame(self.root, bg="#007acc", pady=2, padx=10)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

        self.status_var = tk.StringVar(value="Ready")
        tk.Label(
            status_bar, textvariable=self.status_var,
            bg="#007acc", fg=BTN_FG,
            font=("Consolas", 9), anchor=tk.W,
        ).pack(side=tk.LEFT)

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _append(self, text: str):
        """Append coloured text to the output widget."""
        self.output.configure(state=tk.NORMAL)
        tag = self._classify(text)
        self.output.insert(tk.END, text, tag)
        self.output.see(tk.END)
        self.output.configure(state=tk.DISABLED)

    def _classify(self, line: str) -> str:
        s = line.lstrip()
        if s.startswith("[+]"):            return "good"
        if s.startswith("[!]"):            return "warn"
        if s.startswith("[-]"):            return "bad"
        if s.startswith("[*]"):            return "info"
        if s.startswith("> "):             return "userinp"
        if s.startswith("===") or s.startswith("---") or s.startswith("===="):
            return "head"
        if s.startswith("#"):              return "dim"
        return "normal"

    def _clear_output(self):
        self.output.configure(state=tk.NORMAL)
        self.output.delete("1.0", tk.END)
        self.output.configure(state=tk.DISABLED)

    def _set_status(self, msg: str):
        self.status_var.set(msg)

    # ── Scan lifecycle ───────────────────────────────────────────────────────

    def _build_command(self) -> list[str] | None:
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning(
                "Missing Target",
                "Please enter a target hostname or IP address.",
            )
            return None
        selected_profiles = [p for p, var in self.profile_vars.items() if var.get()]
        if not selected_profiles:
            selected_profiles = ["web"]
        cmd = [PYTHON, "-u", RECONOTRON, target] + selected_profiles
        for flag, var in self.flag_vars.items():
            if var.get():
                cmd.append(flag)
        return cmd

    def _start_scan(self):
        if self.running:
            return
        cmd = self._build_command()
        if cmd is None:
            return

        display = " ".join(cmd[3:])   # strip python + -u + script path
        self._launch_process(cmd, display)

    def _launch_process(self, cmd: list[str], display: str):
        """Start a reconotron.py subprocess and stream its output."""
        self._clear_output()
        self.cmd_label.configure(text=f"$ python3 reconotron.py {display}")
        self._append(f"[*] Launching: python3 reconotron.py {display}\n\n")
        self._set_status("Running …")
        self.run_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self.running = True

        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"

        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE,
            bufsize=0,          # unbuffered — essential for live output
            cwd=BASE_DIR,
            env=env,
        )
        threading.Thread(target=self._reader_thread, daemon=True).start()

    def _generate_report(self):
        """Open a JSON report file and regenerate HTML/PDF via reconotron.py --report."""
        if self.running:
            messagebox.showwarning(
                "Busy",
                "A process is already running. Please wait for it to finish.",
            )
            return
        json_file = filedialog.askopenfilename(
            title="Select JSON Report File",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not json_file:
            return
        cmd = [PYTHON, "-u", RECONOTRON, "--report", json_file]
        self._launch_process(cmd, f"--report \"{json_file}\"")

    def _stop_scan(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self._append("\n[!] Scan terminated by user.\n")
        self._finish(forced=True)

    def _reader_thread(self):
        """Read raw bytes from the subprocess, handle \\r overwriting."""
        buf = b""
        try:
            while True:
                chunk = self.process.stdout.read(256)
                if not chunk:
                    break
                buf += chunk
                # Process complete lines (terminated by \n)
                while b"\n" in buf:
                    line_bytes, buf = buf.split(b"\n", 1)
                    # Spinner lines use \r to overwrite — keep only the last segment
                    if b"\r" in line_bytes:
                        line_bytes = line_bytes.split(b"\r")[-1]
                    line = line_bytes.decode("utf-8", errors="replace").rstrip()
                    if line:
                        self.q.put(line + "\n")
        except Exception:
            pass
        # Flush anything left (line without trailing newline)
        if buf.strip(b"\r\n"):
            self.q.put(buf.replace(b"\r", b"").decode("utf-8", errors="replace").rstrip() + "\n")
        self.process.wait()
        self.q.put(None)    # sentinel

    def _poll_queue(self):
        """Called every 50 ms on the main thread to drain the output queue."""
        try:
            while True:
                item = self.q.get_nowait()
                if item is None:
                    self._finish()
                    break
                self._append(item)
        except queue.Empty:
            pass
        self.root.after(50, self._poll_queue)

    def _finish(self, forced: bool = False):
        if not self.running:
            return
        self.running = False
        rc = self.process.returncode if self.process else "?"
        if not forced:
            self._append(f"\n[*] Process exited — exit code {rc}\n")
        self._set_status(
            f"Finished (exit {rc})" if rc == 0 else f"Finished with errors (exit {rc})"
        )
        self.run_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)

    # ── Input ────────────────────────────────────────────────────────────────

    def _send_input(self):
        text = self.input_var.get().strip()
        if not text:
            return
        self._write_stdin(text)
        self.input_var.set("")

    def _quick_reply(self, text: str):
        self._write_stdin(text)
        self.input_var.set("")

    def _write_stdin(self, text: str):
        if self.process and self.process.poll() is None:
            try:
                self.process.stdin.write((text + "\n").encode())
                self.process.stdin.flush()
                self._append(f"> {text}\n")
            except (BrokenPipeError, OSError):
                self._append("[!] Could not send input — process has already exited.\n")
        else:
            self._append("[!] No running scan to send input to.\n")


# ── Entry point ──────────────────────────────────────────────────────────────

def main():
    root = tk.Tk()
    ReconoTronGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
