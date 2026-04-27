#!/usr/bin/env python3
"""
Noctis Edge GUI — Tkinter front-end for noctis.py

Run with:  python3 noctis_gui.py
"""

import os
import sys

if __name__ == "__main__":
    _BASE = os.path.dirname(os.path.abspath(__file__))
    _VENV_PY = os.path.join(_BASE, ".venv", "bin", "python3")
    _VENV_PREFIX = os.path.realpath(os.path.join(_BASE, ".venv"))
    if os.path.exists(_VENV_PY) and os.path.realpath(sys.prefix) != _VENV_PREFIX:
        _env = os.environ.copy()
        _env["PATH"] = os.path.dirname(_VENV_PY) + os.pathsep + _env.get("PATH", "")
        _env["VIRTUAL_ENV"] = _VENV_PREFIX
        os.execve(_VENV_PY, [_VENV_PY, __file__, *sys.argv[1:]], _env)

import queue
import subprocess
import threading
import tkinter as tk
from tkinter import messagebox, filedialog

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
NOCTIS      = os.path.join(BASE_DIR, "noctis.py")
PYTHON      = sys.executable

LOGO_PATH   = os.path.join(BASE_DIR, "noctis_logo.png")


def _ensure_logo() -> str | None:
    """Return path to logo PNG if it exists alongside this script."""
    return LOGO_PATH if os.path.isfile(LOGO_PATH) else None

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

class NoctisEdgeGUI:
    def __init__(self, root: tk.Tk):
        self.root    = root
        self.process: subprocess.Popen | None = None
        self.q:       queue.Queue = queue.Queue()
        self.running  = False
        self._logo_wm_img = None   # PIL watermark PhotoImage for canvas background
        self._wm_img_id:  int | None = None  # canvas item id of the watermark
        self._y_cursor:   int = 10           # current y insertion point on canvas
        self._term_w:     int = 940          # canvas text wrap width (updated on resize)

        root.title("Noctis Edge — Security Through Exposure")
        root.configure(bg=BG)
        root.minsize(820, 580)
        root.geometry("1000x740")

        self._load_logo()
        self._build_ui()
        self._poll_queue()

    def _load_logo(self):
        """Load the logo as a faded watermark image using PIL (12 % opacity)."""
        logo_path = _ensure_logo()
        if not logo_path:
            return
        try:
            from PIL import Image, ImageTk
            img = Image.open(logo_path).convert("RGBA")
            # Resize to a comfortable watermark size
            wm_size = 340
            img = img.resize((wm_size, wm_size), Image.LANCZOS)
            # Fade alpha channel to 12 % opacity
            r, g, b, a = img.split()
            a = a.point(lambda v: int(v * 0.65))
            img = Image.merge("RGBA", (r, g, b, a))
            # Composite onto terminal background colour so it is safe for canvas
            bg_r = int(BG_TERMINAL[1:3], 16)
            bg_g = int(BG_TERMINAL[3:5], 16)
            bg_b = int(BG_TERMINAL[5:7], 16)
            bg = Image.new("RGBA", (wm_size, wm_size), (bg_r, bg_g, bg_b, 255))
            bg.alpha_composite(img)
            self._logo_wm_img = ImageTk.PhotoImage(bg.convert("RGB"))
        except Exception as e:
            print(f"[noctis_gui] Logo load failed: {e}")
            self._logo_wm_img = None

    # ── UI construction ─────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Header bar ──────────────────────────────────────────────────────
        hdr = tk.Frame(self.root, bg=BG_PANEL, pady=10, padx=14)
        hdr.pack(fill=tk.X)

        tk.Label(
            hdr, text="Noctis Edge",
            font=("Consolas", 18, "bold"), bg=BG_PANEL, fg=ACCENT,
        ).pack(side=tk.LEFT)

        tk.Label(
            hdr, text="  Security Through Exposure",
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

        # ── Terminal output (Canvas-based so the watermark shows through text) ─
        out_frame = tk.Frame(self.root, bg=BG_TERMINAL)
        out_frame.pack(fill=tk.BOTH, expand=True, padx=12)

        vsb = tk.Scrollbar(out_frame, bg=BG_PANEL, troughcolor=BG, activebackground=ACCENT)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self._term_canvas = tk.Canvas(
            out_frame,
            bg=BG_TERMINAL, bd=0, highlightthickness=0,
            yscrollcommand=vsb.set,
        )
        vsb.configure(command=self._term_canvas.yview)
        self._term_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._term_canvas.bind("<Configure>", self._on_terminal_configure)
        self._term_canvas.bind("<MouseWheel>",
            lambda e: self._term_canvas.yview_scroll(-1 * (e.delta // 120), "units"))
        self._term_canvas.bind("<Button-4>",
            lambda _: self._term_canvas.yview_scroll(-3, "units"))
        self._term_canvas.bind("<Button-5>",
            lambda _: self._term_canvas.yview_scroll(3, "units"))

        # Draw watermark once the canvas is first mapped
        self.root.after(100, self._draw_watermark)

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

    # ── Terminal canvas helpers ──────────────────────────────────────────────

    def _draw_watermark(self, cy: int | None = None):
        """Draw (or reposition) the faded logo centred in the current viewport."""
        if self._logo_wm_img is None:
            return
        tc = self._term_canvas
        cw = tc.winfo_width()  or 500
        ch = tc.winfo_height() or 400
        cx = cw // 2
        if cy is None:
            # Centre within the visible viewport using the current scroll position
            top, bot = tc.yview()
            sr = tc.cget("scrollregion")
            try:
                total_h = int(str(sr).split()[3])
            except Exception:
                total_h = ch
            cy = int((top + bot) / 2 * total_h)
        if self._wm_img_id is not None:
            tc.coords(self._wm_img_id, cx, cy)
        else:
            self._wm_img_id = tc.create_image(
                cx, cy, image=self._logo_wm_img, anchor=tk.CENTER, tags="watermark"
            )
        tc.tag_lower("watermark")

    def _on_terminal_configure(self, event):
        """Reposition watermark and update text wrap width when canvas is resized."""
        self._term_w = max(100, event.width - 24)
        self._draw_watermark()  # recalculate viewport centre on resize
        sr = self._term_canvas.bbox("output_text")
        if sr:
            self._term_canvas.configure(
                scrollregion=(0, 0, event.width, sr[3] + 10)
            )

    def _line_color(self, line: str) -> str:
        """Return a hex colour for a terminal output line."""
        s = line.lstrip()
        if s.startswith("[+]"): return TAG_GOOD
        if s.startswith("[!]"): return TAG_WARN
        if s.startswith("[-]"): return TAG_BAD
        if s.startswith("[*]"): return TAG_INFO
        if s.startswith("> "):  return TAG_INPUT
        if s.startswith("===") or s.startswith("---"): return TAG_HEAD
        if s.startswith("#"):   return TAG_DIM
        return TAG_NORMAL

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _append(self, text: str):
        """Append coloured text to the canvas terminal."""
        tc = self._term_canvas
        w  = self._term_w
        for raw_line in text.split("\n"):
            if not raw_line:
                self._y_cursor += 5
                continue
            color = self._line_color(raw_line)
            item = tc.create_text(
                12, self._y_cursor,
                text=raw_line, fill=color,
                anchor=tk.NW, font=("Consolas", 10),
                width=w, tags="output_text",
            )
            bbox = tc.bbox(item)
            self._y_cursor = (bbox[3] if bbox else self._y_cursor + 16) + 3
        tc.configure(scrollregion=(0, 0, max(tc.winfo_width(), w + 24), self._y_cursor + 10))
        tc.yview_moveto(1.0)
        self._draw_watermark()  # keep watermark centred in the now-scrolled viewport

    def _clear_output(self):
        self._term_canvas.delete("output_text")
        self._y_cursor = 10
        self._draw_watermark()
        self._term_canvas.configure(
            scrollregion=(0, 0,
                          self._term_canvas.winfo_width() or 960,
                          self._term_canvas.winfo_height() or 600)
        )

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
        cmd = [PYTHON, "-u", NOCTIS, target] + selected_profiles
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
        """Start a noctis.py subprocess and stream its output."""
        self._clear_output()
        self.cmd_label.configure(text=f"$ python3 noctis.py {display}")
        self._append(f"[*] Launching: python3 noctis.py {display}\n\n")
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
        """Open a JSON report file and regenerate HTML/PDF via noctis.py --report."""
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
        cmd = [PYTHON, "-u", NOCTIS, "--report", json_file]
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
    NoctisEdgeGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
