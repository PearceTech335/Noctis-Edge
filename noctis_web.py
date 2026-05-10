#!/usr/bin/env python3
# Copyright (C) 2026 Pearce Technologies Pty Ltd
# SPDX-License-Identifier: AGPL-3.0-or-later
# <https://www.gnu.org/licenses/agpl-3.0.html>
"""
Noctis Edge Web UI — Flask + WebSocket front-end for noctis.py

Run with:  python3 noctis_web.py
           python3 noctis_web.py --port 8080

The UI mirrors the Tkinter GUI: same dark VS Code palette, same controls,
live streaming terminal output via WebSocket.
"""

import os
import sys

# ── venv bootstrap (mirrors noctis.py / noctis_gui.py) ─────────────────────
if __name__ == "__main__":
    _BASE = os.path.dirname(os.path.abspath(__file__))
    _VENV_PY = os.path.join(_BASE, ".venv", "bin", "python3")
    _VENV_PREFIX = os.path.realpath(os.path.join(_BASE, ".venv"))
    if os.path.exists(_VENV_PY) and os.path.realpath(sys.prefix) != _VENV_PREFIX:
        _env = os.environ.copy()
        _env["PATH"] = os.path.dirname(_VENV_PY) + os.pathsep + _env.get("PATH", "")
        _env["VIRTUAL_ENV"] = _VENV_PREFIX
        os.execve(_VENV_PY, [_VENV_PY, __file__, *sys.argv[1:]], _env)

import json
import os
import pty
import queue
import re
import select
import subprocess
import threading
from pathlib import Path

from flask import Flask, render_template_string, request, jsonify
from flask_sock import Sock

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
NOCTIS   = os.path.join(BASE_DIR, "noctis.py")
PYTHON   = sys.executable


def _read_noctis_version() -> str:
    """Read VERSION from noctis.py without importing it."""
    import re as _re
    try:
        with open(NOCTIS, "r", encoding="utf-8") as _f:
            for _line in _f:
                _m = _re.match(r'^VERSION\s*=\s*["\']([^"\']+)["\']', _line)
                if _m:
                    return _m.group(1)
    except Exception:
        pass
    return "unknown"


VERSION  = _read_noctis_version()

PROFILES = ["standard", "full", "ot"]

PROFILE_DESCRIPTIONS = {
    "standard": (
        "Standard Assessment — Use for most engagements: web apps, APIs, external perimeters, "
        "cloud-exposed services. Runs curl, nikto, nuclei, ffuf, dns_enum and service-specific "
        "enumerators (SSH, RDP, MySQL, MSSQL). The LLM selects tools per service automatically."
    ),
    "full": (
        "Full Authorised Assessment — Use when you have explicit written authorisation for "
        "credential testing and Active Directory enumeration. Adds nxc (SMB/LDAP), Impacket "
        "and Hydra on top of the Standard toolset. Do not run without a signed scope document."
    ),
    "ot": (
        "Industrial / OT Assessment — Use only on OT/ICS/SCADA networks. Runs passive "
        "Nmap NSE probes only — no active scanners that could crash PLCs or disrupt "
        "safety systems. Requires dedicated OT authorisation."
    ),
}

# Regex to strip ANSI/VT100 escape sequences from PTY output before sending to browser
_ANSI_RE = re.compile(r'\x1b(?:\[[0-9;]*[mGKHFABCDJr]|\([AB]|[^[\(])')

FLAGS = [
    ("--aggressive",   "Disable safe-mode: run gobuster / ffuf / hydra without approval"),
    ("--dns-enum",     "Enable DNS enumeration tools — requires internet"),
    ("--msf-validate", "Run safe Metasploit 'check' probes for each matched CVE"),
    ("--cve-test",     "Ask the LLM to generate & execute probe scripts per CVE"),
    ("--unattended",   "Auto-approve all prompts — run to completion without user input"),
]

app  = Flask(__name__)
sock = Sock(app)

# ── Global scan state ────────────────────────────────────────────────────────
_lock    = threading.Lock()
_process: subprocess.Popen | None = None
_pty_master_fd: int | None = None   # PTY master fd when running update.sh
_running = False
_ws_clients: set = set()   # active WebSocket connections


def _broadcast(msg: dict):
    """Send a JSON message to all connected WebSocket clients."""
    dead = set()
    payload = json.dumps(msg)
    with _lock:
        clients = set(_ws_clients)
    for ws in clients:
        try:
            ws.send(payload)
        except Exception:
            dead.add(ws)
    if dead:
        with _lock:
            _ws_clients.difference_update(dead)


def _pty_reader_thread(proc: subprocess.Popen, master_fd: int):
    """Read from a PTY master fd and broadcast lines to WebSocket clients.
    Used for update.sh so that sudo password prompts (written to /dev/tty)
    are captured and forwarded to the browser."""
    global _running, _pty_master_fd
    buf = b""
    try:
        while True:
            try:
                rlist, _, _ = select.select([master_fd], [], [], 0.1)
            except (ValueError, OSError):
                break
            if rlist:
                try:
                    data = os.read(master_fd, 4096)
                except OSError:
                    break
                if not data:
                    break
                buf += data
                while b"\n" in buf:
                    line_bytes, buf = buf.split(b"\n", 1)
                    line = line_bytes.decode("utf-8", errors="replace").rstrip("\r")
                    line = _ANSI_RE.sub("", line)
                    if line:
                        _broadcast({"type": "line", "text": line})
                # Flush partial line as spinner (sudo prompt has no newline)
                if buf:
                    partial = buf.decode("utf-8", errors="replace").rstrip("\r")
                    partial = _ANSI_RE.sub("", partial)
                    if partial:
                        _broadcast({"type": "spinner", "text": partial})
                    buf = b""  # clear so next chunk starts fresh, not prepended with spinner text
            else:
                if proc.poll() is not None:
                    break
    except Exception:
        pass
    if buf.strip(b"\r\n"):
        line = buf.decode("utf-8", errors="replace").rstrip()
        line = _ANSI_RE.sub("", line)
        if line:
            _broadcast({"type": "line", "text": line})
    proc.wait()
    exit_code = proc.returncode
    _broadcast({"type": "exit", "code": exit_code})
    try:
        os.close(master_fd)
    except OSError:
        pass
    with _lock:
        _running = False
        _pty_master_fd = None
    # Schedule a self-restart so the freshly pulled noctis_web.py is loaded
    if exit_code == 0:
        _broadcast({"type": "restart_pending", "delay": 4})
        threading.Timer(4.0, _self_restart).start()


def _reader_thread(proc: subprocess.Popen):
    """Read raw bytes from subprocess stdout, broadcast to WebSocket clients."""
    global _running
    buf = b""
    try:
        while True:
            chunk = proc.stdout.read(256)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line_bytes, buf = buf.split(b"\n", 1)
                if b"\r" in line_bytes:
                    line_bytes = line_bytes.split(b"\r")[-1]
                line = line_bytes.decode("utf-8", errors="replace").rstrip()
                if line:
                    _broadcast({"type": "line", "text": line})
            # Flush partial spinner frames (\r without \n)
            if b"\r" in buf:
                spinner = buf.split(b"\r")[-1].decode("utf-8", errors="replace").rstrip()
                if spinner:
                    _broadcast({"type": "spinner", "text": spinner})
                buf = b""
    except Exception:
        pass
    if buf.strip(b"\r\n"):
        line = buf.replace(b"\r", b"").decode("utf-8", errors="replace").rstrip()
        if line:
            _broadcast({"type": "line", "text": line})
    proc.wait()
    _broadcast({"type": "exit", "code": proc.returncode})
    with _lock:
        _running = False


def _self_restart():
    """Replace the current process with a fresh instance after an update."""
    os.execv(sys.executable, [sys.executable, __file__] + sys.argv[1:])


# ── Routes ───────────────────────────────────────────────────────────────────

_PROFILE_DISPLAY = {
    "standard": "Standard",
    "full":     "Full Authorised",
    "ot":       "Industrial / OT",
}

@app.route("/")
def index():
    return render_template_string(
        _HTML_TEMPLATE,
        profiles=PROFILES,
        profiles_display=_PROFILE_DISPLAY,
        profile_descriptions=PROFILE_DESCRIPTIONS,
        flags=FLAGS,
        version=VERSION,
    )


@app.route("/api/start", methods=["POST"])
def api_start():
    global _process, _running
    data   = request.get_json(force=True)
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"ok": False, "error": "Target is required"}), 400

    with _lock:
        if _running:
            return jsonify({"ok": False, "error": "A scan is already running"}), 409

    profiles   = [p for p in data.get("profiles", []) if p in PROFILES] or ["standard"]
    flags      = [f for f, _ in FLAGS if f in data.get("flags", [])]
    session_dir = (data.get("session_dir") or "").strip()

    cmd = [PYTHON, "-u", NOCTIS, target] + profiles + flags
    if session_dir:
        # Restrict to paths inside BASE_DIR to prevent path traversal
        resolved_sd = os.path.realpath(session_dir)
        if not resolved_sd.startswith(os.path.realpath(BASE_DIR) + os.sep):
            return jsonify({"ok": False, "error": "session_dir outside project directory"}), 403
        cmd += ["--session-dir", resolved_sd]
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE,
        bufsize=0,
        cwd=BASE_DIR,
        env=env,
    )
    with _lock:
        _process = proc
        _running = True

    threading.Thread(target=_reader_thread, args=(proc,), daemon=True).start()
    display = " ".join([target] + profiles + flags)
    _broadcast({"type": "started", "cmd": display})
    return jsonify({"ok": True})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    global _process, _running
    with _lock:
        proc = _process
    if proc and proc.poll() is None:
        proc.terminate()
        _broadcast({"type": "line", "text": "[!] Scan terminated by user."})
        _broadcast({"type": "exit", "code": -1})
    with _lock:
        _running = False
    return jsonify({"ok": True})


@app.route("/api/input", methods=["POST"])
def api_input():
    data = request.get_json(force=True)
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"ok": False, "error": "Empty input"}), 400
    with _lock:
        proc = _process
        mfd  = _pty_master_fd
    # PTY-based process (update.sh): write to the PTY master fd
    if mfd is not None:
        try:
            os.write(mfd, (text + "\n").encode())
            # Don't echo raw text — it may be a sudo password; show a redacted marker
            _broadcast({"type": "line", "text": "> [input sent]"})
            return jsonify({"ok": True})
        except OSError:
            return jsonify({"ok": False, "error": "Process has exited"}), 409
    # Regular pipe-based process (noctis.py scans)
    if proc and proc.poll() is None:
        try:
            proc.stdin.write((text + "\n").encode())
            proc.stdin.flush()
            _broadcast({"type": "line", "text": f"> {text}"})
            return jsonify({"ok": True})
        except (BrokenPipeError, OSError):
            return jsonify({"ok": False, "error": "Process has exited"}), 409
    return jsonify({"ok": False, "error": "No running scan"}), 409


@app.route("/api/status")
def api_status():
    with _lock:
        return jsonify({"running": _running})


@app.route("/api/report", methods=["POST"])
def api_report():
    global _process, _running
    data      = request.get_json(force=True)
    json_path = (data.get("json_path") or "").strip()
    if not json_path:
        return jsonify({"ok": False, "error": "json_path required"}), 400

    # Restrict to files inside BASE_DIR to prevent path traversal
    resolved = os.path.realpath(json_path)
    if not resolved.startswith(os.path.realpath(BASE_DIR) + os.sep):
        return jsonify({"ok": False, "error": "Path outside project directory"}), 403

    if not os.path.isfile(resolved):
        return jsonify({"ok": False, "error": "File not found"}), 404

    with _lock:
        if _running:
            return jsonify({"ok": False, "error": "A scan is already running"}), 409

    cmd = [PYTHON, "-u", NOCTIS, "--report", resolved]
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE,
        bufsize=0,
        cwd=BASE_DIR,
        env=env,
    )
    with _lock:
        _process = proc
        _running = True

    threading.Thread(target=_reader_thread, args=(proc,), daemon=True).start()
    _broadcast({"type": "started", "cmd": f"--report {resolved}"})
    return jsonify({"ok": True})


@app.route("/api/update", methods=["POST"])
def api_update():
    global _process, _running
    with _lock:
        if _running:
            return jsonify({"ok": False, "error": "A process is already running"}), 409

    update_script = os.path.join(BASE_DIR, "update.sh")
    if not os.path.isfile(update_script):
        return jsonify({"ok": False, "error": "update.sh not found"}), 404

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    # Run update.sh inside a PTY so sudo can write its password prompt
    # to /dev/tty (the PTY slave) and we can read it from the master fd.
    master_fd, slave_fd = pty.openpty()
    proc = subprocess.Popen(
        ["bash", update_script],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        close_fds=True,
        cwd=BASE_DIR,
        env=env,
        preexec_fn=os.setsid,
    )
    os.close(slave_fd)   # parent doesn't need the slave end
    with _lock:
        global _pty_master_fd
        _process = proc
        _pty_master_fd = master_fd
        _running = True

    threading.Thread(target=_pty_reader_thread, args=(proc, master_fd), daemon=True).start()
    _broadcast({"type": "started", "cmd": "update.sh"})
    return jsonify({"ok": True})


@app.route("/api/sessions")
def api_sessions():
    """List available JSON reports from the sessions directory."""
    sessions_dir = os.path.join(BASE_DIR, "sessions")
    reports = []
    if os.path.isdir(sessions_dir):
        for root, _dirs, files in os.walk(sessions_dir):
            for fname in files:
                if fname.endswith(".json") and "session" not in fname:
                    full = os.path.join(root, fname)
                    rel  = os.path.relpath(full, BASE_DIR)
                    reports.append({"path": full, "label": rel})
    reports.sort(key=lambda r: r["label"])
    return jsonify(reports)


@app.route("/api/resume-sessions")
def api_resume_sessions():
    """List session directories that have a session.json (resumable scans)."""
    sessions_dir = os.path.join(BASE_DIR, "sessions")
    sessions = []
    if os.path.isdir(sessions_dir):
        for entry in os.scandir(sessions_dir):
            if not entry.is_dir():
                continue
            sf = os.path.join(entry.path, "session.json")
            if not os.path.isfile(sf):
                continue
            try:
                with open(sf) as fh:
                    import json as _json
                    state = _json.load(fh)
            except Exception:
                state = {}
            label = os.path.relpath(entry.path, BASE_DIR)
            sessions.append({
                "path":      entry.path,
                "label":     label,
                "target":    state.get("target", "unknown"),
                "phase":     state.get("phase", ""),
                "timestamp": label.split("_", 1)[-1] if "_" in label else "",
            })
    sessions.sort(key=lambda s: s["label"], reverse=True)
    return jsonify(sessions)


@sock.route("/ws")
def ws_endpoint(ws):
    """WebSocket endpoint — client connects here to receive live output."""
    with _lock:
        _ws_clients.add(ws)
    try:
        # Keep the connection alive; handle incoming pings silently
        while True:
            msg = ws.receive(timeout=30)
            if msg is None:
                break
    except Exception:
        pass
    finally:
        with _lock:
            _ws_clients.discard(ws)


# ── HTML / CSS / JS template ─────────────────────────────────────────────────

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Noctis Edge — Security Through Exposure</title>
<style>
/* ── Reset & base ─────────────────────────────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  --bg:          #1e1e1e;
  --bg-panel:    #252526;
  --bg-input:    #3c3c3c;
  --bg-term:     #0d0d0d;
  --fg:          #d4d4d4;
  --fg-dim:      #858585;
  --accent:      #007acc;
  --btn-run:     #28a745;
  --btn-stop:    #c0392b;
  --btn-send:    #007acc;
  --btn-fg:      #ffffff;
  --btn-y:       #27ae60;
  --btn-n:       #c0392b;
  /* terminal line colours */
  --c-good:   #4ec9b0;
  --c-warn:   #ce9178;
  --c-bad:    #f44747;
  --c-info:   #569cd6;
  --c-head:   #dcdcaa;
  --c-input:  #c586c0;
  --c-dim:    #6a6a6a;
  --c-normal: #d4d4d4;
  --c-promo:  #29d7f5;
  --radius: 3px;
}
html, body { height: 100%; }
body {
  font-family: 'Consolas', 'Courier New', monospace;
  background: var(--bg);
  color: var(--fg);
  display: flex;
  flex-direction: column;
  height: 100vh;
  overflow: hidden;
}

/* ── Header ──────────────────────────────────────────────────────────── */
#header {
  background: var(--bg-panel);
  padding: 10px 14px;
  flex-shrink: 0;
  display: flex;
  align-items: baseline;
  gap: 10px;
  border-bottom: 1px solid #333;
}
#header h1 { font-size: 18px; color: var(--accent); font-weight: bold; }
#header .sub { font-size: 10px; color: var(--fg-dim); }

/* ── Controls section ────────────────────────────────────────────────── */
#controls {
  flex-shrink: 0;
  padding: 8px 12px 0;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

/* Target row */
#target-row {
  display: flex;
  align-items: center;
  gap: 8px;
}
#target-row label { font-size: 11px; white-space: nowrap; }
#target-input {
  flex: 0 0 280px;
  background: var(--bg-input);
  color: var(--fg);
  border: 1px solid var(--fg-dim);
  border-radius: var(--radius);
  padding: 4px 8px;
  font-family: inherit;
  font-size: 11px;
  outline: none;
  transition: border-color .15s;
}
#target-input:focus { border-color: var(--accent); }

/* Fieldset groups */
.group {
  border: 1px solid #3a3a3a;
  border-radius: var(--radius);
  padding: 6px 10px;
  background: var(--bg-panel);
}
.group legend {
  font-size: 9px;
  color: var(--fg-dim);
  padding: 0 4px;
}
.cb-row {
  display: flex;
  flex-wrap: wrap;
  gap: 2px 20px;
}
.cb-row label {
  display: flex;
  align-items: center;
  gap: 5px;
  font-size: 10px;
  cursor: pointer;
  white-space: nowrap;
  position: relative;
}
.cb-row label:hover .tip { display: block; }
input[type=checkbox], input[type=radio] {
  accent-color: var(--accent);
  width: 13px;
  height: 13px;
  cursor: pointer;
}

/* Tooltip */
.tip {
  display: none;
  position: absolute;
  bottom: calc(100% + 4px);
  left: 0;
  background: #3c3c3c;
  color: var(--fg);
  font-size: 9px;
  padding: 4px 8px;
  border-radius: var(--radius);
  white-space: nowrap;
  z-index: 99;
  pointer-events: none;
}

/* Toolbar */
#toolbar {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}
button {
  font-family: inherit;
  font-size: 10px;
  font-weight: bold;
  border: none;
  border-radius: var(--radius);
  padding: 5px 14px;
  cursor: pointer;
  transition: filter .12s;
}
button:hover:not(:disabled) { filter: brightness(1.15); }
button:disabled { opacity: .45; cursor: not-allowed; }
#btn-run  { background: var(--btn-run);  color: var(--btn-fg); }
#btn-stop { background: var(--btn-stop); color: var(--btn-fg); }
#btn-clear   { background: var(--bg-panel); color: var(--fg-dim); border: 1px solid #444; }
#btn-report  { background: #7d3c98; color: var(--btn-fg); }
#btn-resume  { background: #e65100; color: var(--btn-fg); }
#cmd-label   { font-size: 9px; color: var(--fg-dim); flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
#btn-update  { background: #1a6b8a; color: var(--btn-fg); margin-left: auto; }

/* ── Terminal ─────────────────────────────────────────────────────────── */
#term-wrap {
  flex: 1;
  margin: 6px 12px;
  background: var(--bg-term);
  border-radius: var(--radius);
  overflow: hidden;
  position: relative;
  min-height: 0;
}
#terminal {
  height: 100%;
  overflow-y: auto;
  padding: 10px 12px;
  font-size: 10px;
  line-height: 1.55;
  scroll-behavior: smooth;
}
#terminal::-webkit-scrollbar { width: 8px; }
#terminal::-webkit-scrollbar-track { background: var(--bg); }
#terminal::-webkit-scrollbar-thumb { background: #444; border-radius: 4px; }
.t-line { white-space: pre-wrap; word-break: break-all; }
.t-good   { color: var(--c-good); }
.t-warn   { color: var(--c-warn); }
.t-bad    { color: var(--c-bad); }
.t-info   { color: var(--c-info); }
.t-head   { color: var(--c-head); }
.t-input  { color: var(--c-input); }
.t-dim    { color: var(--c-dim); }
.t-normal { color: var(--c-normal); }
.t-promo  { color: var(--c-promo); font-weight: bold; }
.t-promo a { color: var(--c-promo); text-decoration: underline; }
.t-line a  { color: inherit; text-decoration: underline; cursor: pointer; }
#spinner-line { color: var(--c-info); }

/* Watermark logo */
#wm-logo {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  opacity: .45;
  pointer-events: none;
  max-width: 340px;
  max-height: 340px;
  user-select: none;
}

/* ── Input row ────────────────────────────────────────────────────────── */
#inp-row {
  flex-shrink: 0;
  background: var(--bg-panel);
  padding: 6px 12px;
  display: flex;
  align-items: center;
  gap: 6px;
  border-top: 1px solid #333;
}
#inp-row label { font-size: 9px; color: var(--fg-dim); white-space: nowrap; }
#reply-input {
  flex: 1;
  background: var(--bg-input);
  color: var(--fg);
  border: 1px solid var(--fg-dim);
  border-radius: var(--radius);
  padding: 3px 8px;
  font-family: inherit;
  font-size: 10px;
  outline: none;
  transition: border-color .15s;
}
#reply-input:focus { border-color: var(--accent); }
#btn-send { background: var(--btn-send); color: var(--btn-fg); padding: 4px 10px; }
#btn-y    { background: var(--btn-y);    color: var(--btn-fg); padding: 4px 14px; }
#btn-n    { background: var(--btn-n);    color: var(--btn-fg); padding: 4px 14px; }

/* ── Status bar ────────────────────────────────────────────────────────── */
#status-bar {
  flex-shrink: 0;
  background: var(--accent);
  padding: 2px 10px;
  font-size: 9px;
  color: var(--btn-fg);
  display: flex;
  justify-content: space-between;
  align-items: center;
}
#version-badge {
  font-size: 9px;
  opacity: 0.75;
  letter-spacing: 0.04em;
}

/* ── Report / Resume modals ──────────────────────────────────────────── */
#resume-modal-overlay {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,.65);
  z-index: 200;
  align-items: center;
  justify-content: center;
}
#resume-modal-overlay.open { display: flex; }
#resume-modal {
  background: var(--bg-panel);
  border: 1px solid #555;
  border-radius: 5px;
  padding: 20px 24px;
  min-width: 420px;
  max-width: 90vw;
  display: flex;
  flex-direction: column;
  gap: 12px;
}
#resume-modal h2 { font-size: 13px; color: #ff9800; }
#resume-modal label { font-size: 10px; color: var(--fg-dim); display: block; margin-bottom: 4px; }
#resume-modal select {
  width: 100%;
  background: var(--bg-input);
  color: var(--fg);
  border: 1px solid #555;
  border-radius: var(--radius);
  padding: 4px 8px;
  font-family: inherit;
  font-size: 10px;
}
#resume-modal-footer { display: flex; gap: 8px; justify-content: flex-end; }
#resume-modal-ok     { background: #e65100; color: var(--btn-fg); }
#resume-modal-cancel { background: var(--bg-input); color: var(--fg); }

#modal-overlay {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,.65);
  z-index: 200;
  align-items: center;
  justify-content: center;
}
#modal-overlay.open { display: flex; }
#modal {
  background: var(--bg-panel);
  border: 1px solid #555;
  border-radius: 5px;
  padding: 20px 24px;
  min-width: 420px;
  max-width: 90vw;
  display: flex;
  flex-direction: column;
  gap: 12px;
}
#modal h2 { font-size: 13px; color: var(--accent); }
#modal label { font-size: 10px; color: var(--fg-dim); display: block; margin-bottom: 4px; }
#modal select, #modal input[type=text] {
  width: 100%;
  background: var(--bg-input);
  color: var(--fg);
  border: 1px solid #555;
  border-radius: var(--radius);
  padding: 4px 8px;
  font-family: inherit;
  font-size: 10px;
}
#modal-footer { display: flex; gap: 8px; justify-content: flex-end; }
#modal-ok     { background: var(--btn-run); color: var(--btn-fg); }
#modal-cancel { background: var(--bg-input); color: var(--fg); }
</style>
</head>
<body>

<!-- Header -->
<div id="header">
  <h1>Noctis Edge</h1>
  <span class="sub">Security Through Exposure</span>
</div>

<!-- Controls -->
<div id="controls">

  <!-- Target -->
  <div id="target-row">
    <label for="target-input">Target:</label>
    <input id="target-input" type="text" placeholder="192.168.0.1 or hostname" autocomplete="off" spellcheck="false">
  </div>

  <!-- Profiles -->
  <fieldset class="group">
    <legend>Assessment Profile</legend>
    <div class="cb-row" id="profiles-row">
      {% for p in profiles %}
      <label title="{{ profile_descriptions[p] }}">
        <input type="radio" class="profile-rb" name="profile" value="{{ p }}"{% if p == 'standard' %} checked{% endif %}>
        {{ profiles_display[p] }}
        <span class="tip">{{ profile_descriptions[p] }}</span>
      </label>
      {% endfor %}
    </div>
  </fieldset>

  <!-- Flags -->
  <fieldset class="group">
    <legend>Scan Flags</legend>
    <div class="cb-row" id="flags-row">
      {% for flag, tip in flags %}
      <label>
        <input type="checkbox" class="flag-cb" value="{{ flag }}">
        {{ flag }}
        <span class="tip">{{ tip }}</span>
      </label>
      {% endfor %}
    </div>
  </fieldset>

  <!-- Toolbar -->
  <div id="toolbar">
    <button id="btn-run"  onclick="startScan()">&#9654;  Start Scan</button>
    <button id="btn-stop" onclick="stopScan()" disabled>&#9632;  Stop</button>
    <button id="btn-resume" onclick="openResumeModal()">&#9166; Resume</button>
    <button id="btn-clear" onclick="clearTerm()">Clear</button>
    <button id="btn-report" onclick="openReportModal()">Report</button>
    <span id="cmd-label"></span>
    <button id="btn-update" onclick="runUpdate()">&#8635;  Update</button>
  </div>

</div>

<!-- Terminal -->
<div id="term-wrap">
  <img id="wm-logo" src="/logo" alt="" onerror="this.style.display='none'">
  <div id="terminal"></div>
</div>

<!-- Input row -->
<div id="inp-row">
  <label for="reply-input">Prompt reply:</label>
  <input id="reply-input" type="text" placeholder="Type y/n or free-text reply and press Enter…" autocomplete="off">
  <button id="btn-send" onclick="sendInput()">Send</button>
  <button id="btn-y" onclick="quickReply('y')">Y</button>
  <button id="btn-n" onclick="quickReply('n')">N</button>
</div>

<!-- Status bar -->
<div id="status-bar"><span id="status-text">Ready</span><span id="version-badge">{{ version }}</span></div>

<!-- Resume modal -->
<div id="resume-modal-overlay">
  <div id="resume-modal">
    <h2>&#9654; Resume Scan — Select Session</h2>
    <div>
      <label for="resume-select">Select an interrupted session to resume:</label>
      <select id="resume-select"><option value="">— loading… —</option></select>
    </div>
    <div id="resume-modal-footer">
      <button id="resume-modal-cancel" onclick="closeResumeModal()">Cancel</button>
      <button id="resume-modal-ok" onclick="submitResume()">Resume Scan</button>
    </div>
  </div>
</div>

<!-- Report modal -->
<div id="modal-overlay">
  <div id="modal">
    <h2>Regenerate Report</h2>
    <div>
      <label for="report-select">Select a session JSON report:</label>
      <select id="report-select"><option value="">— loading… —</option></select>
    </div>
    <div>
      <label for="report-path">Or enter path manually:</label>
      <input id="report-path" type="text" placeholder="/absolute/path/to/report.json" spellcheck="false">
    </div>
    <div id="modal-footer">
      <button id="modal-cancel" onclick="closeReportModal()">Cancel</button>
      <button id="modal-ok" onclick="submitReport()">Generate</button>
    </div>
  </div>
</div>

<script>
/* ── WebSocket connection ─────────────────────────────────────────────── */
const term    = document.getElementById('terminal');
const status  = document.getElementById('status-text');
const cmdLbl  = document.getElementById('cmd-label');
const btnRun  = document.getElementById('btn-run');
const btnStop = document.getElementById('btn-stop');
const btnUpdate = document.getElementById('btn-update');
const btnResume = document.getElementById('btn-resume');
let   running = false;
let   spinnerEl = null;   // current spinner <div> element

const WS_URL = (location.protocol === 'https:' ? 'wss' : 'ws') + '://' + location.host + '/ws';
let ws = null;

function connectWS() {
  ws = new WebSocket(WS_URL);

  ws.onopen = () => {
    console.log('[noctis-web] WebSocket connected');
  };

  ws.onmessage = (ev) => {
    try {
      const msg = JSON.parse(ev.data);
      handleMsg(msg);
    } catch (_) {}
  };

  ws.onclose = () => {
    console.log('[noctis-web] WebSocket closed — reconnecting in 2s');
    setTimeout(connectWS, 2000);
  };

  ws.onerror = () => ws.close();
}

connectWS();

// Keep-alive ping every 20 s (server has 30 s timeout)
setInterval(() => { if (ws && ws.readyState === WebSocket.OPEN) ws.send('ping'); }, 20000);

/* ── Message handler ─────────────────────────────────────────────────── */
function handleMsg(msg) {
  if (msg.type === 'line') {
    flushSpinner();
    appendLine(msg.text);
  } else if (msg.type === 'spinner') {
    setSpinner(msg.text);
  } else if (msg.type === 'started') {
    clearTerm();
    running = true;
    setRunning(true);
    const isUpdate = msg.cmd === 'update.sh';
    const label = isUpdate ? '$ bash update.sh' : '$ python3 noctis.py ' + msg.cmd;
    cmdLbl.textContent = label;
    appendLine('[*] Launching: ' + label + '\n');
    status.textContent = isUpdate ? 'Updating…' : 'Running…';
  } else if (msg.type === 'exit') {
    flushSpinner();
    running = false;
    setRunning(false);
    const code = msg.code;
    appendLine('\n[*] Process exited — exit code ' + code);
    status.textContent = code === 0 ? 'Finished (exit 0)' : 'Finished with errors (exit ' + code + ')';
  } else if (msg.type === 'restart_pending') {
    const delay = msg.delay || 4;
    appendLine('\n[*] Update complete — restarting server in ' + delay + 's…');
    status.textContent = 'Restarting in ' + delay + 's…';
    let countdown = delay;
    const iv = setInterval(() => {
      countdown--;
      if (countdown <= 0) {
        clearInterval(iv);
        status.textContent = 'Reconnecting…';
        appendLine('[*] Reconnecting to new server…');
        _pollForRestart();
      } else {
        status.textContent = 'Restarting in ' + countdown + 's…';
      }
    }, 1000);
  }
}

/* ── Terminal helpers ────────────────────────────────────────────────── */
function lineClass(text) {
  const s = text.trimStart();
  if (s.startsWith('[+]'))  return 't-good';
  if (s.startsWith('[!]'))  return 't-warn';
  if (s.startsWith('[-]'))  return 't-bad';
  if (s.startsWith('[**]')) return 't-promo';
  if (s.startsWith('[*]'))  return 't-info';
  if (s.startsWith('> '))   return 't-input';
  if (s.startsWith('===') || s.startsWith('---')) return 't-head';
  if (s.startsWith('#'))    return 't-dim';
  return 't-normal';
}

function appendLine(text) {
  const div = document.createElement('div');
  div.className = 't-line ' + lineClass(text);
  // Linkify URLs safely using DOM nodes (no innerHTML)
  const urlRe = /(https?:\/\/[^\s]+)/g;
  let last = 0, m;
  while ((m = urlRe.exec(text)) !== null) {
    if (m.index > last) div.appendChild(document.createTextNode(text.slice(last, m.index)));
    const a = document.createElement('a');
    a.href = m[1];
    a.textContent = m[1];
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    div.appendChild(a);
    last = m.index + m[1].length;
  }
  if (last < text.length) div.appendChild(document.createTextNode(text.slice(last)));
  term.appendChild(div);
  term.scrollTop = term.scrollHeight;
}

function setSpinner(text) {
  if (!spinnerEl) {
    spinnerEl = document.createElement('div');
    spinnerEl.id = 'spinner-line';
    spinnerEl.className = 't-line t-info';
    term.appendChild(spinnerEl);
  }
  spinnerEl.textContent = text;
  term.scrollTop = term.scrollHeight;
}

function flushSpinner() {
  if (spinnerEl) {
    // Convert spinner into a permanent line with proper colour
    spinnerEl.className = 't-line ' + lineClass(spinnerEl.textContent);
    spinnerEl.id = '';
    spinnerEl = null;
  }
}

function clearTerm() {
  term.innerHTML = '';
  spinnerEl = null;
  cmdLbl.textContent = '';
}

/* ── Button state ────────────────────────────────────────────────────── */
function setRunning(on) {
  btnRun.disabled    = on;
  btnStop.disabled   = !on;
  btnUpdate.disabled = on;
  btnResume.disabled = on;
}

/* ── Scan control ────────────────────────────────────────────────────── */
function startScan() {
  const target = document.getElementById('target-input').value.trim();
  if (!target) { alert('Please enter a target hostname or IP address.'); return; }

  const profileEl = document.querySelector('.profile-rb:checked');
  const profiles  = profileEl ? [profileEl.value] : ['standard'];
  const flags      = [...document.querySelectorAll('.flag-cb:checked')].map(cb => cb.value);

  fetch('/api/start', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ target, profiles, flags }),
  }).then(r => r.json()).then(d => {
    if (!d.ok) { status.textContent = 'Error: ' + d.error; alert(d.error); }
  });
}

function stopScan() {
  fetch('/api/stop', { method: 'POST' });
}

function runUpdate() {
  if (running) { alert('A process is already running. Stop it first.'); return; }
  fetch('/api/update', { method: 'POST' })
    .then(r => r.json()).then(d => {
      if (!d.ok) { status.textContent = 'Error: ' + d.error; alert(d.error); }
    });
}

function _pollForRestart() {
  fetch('/', { method: 'GET', cache: 'no-store' })
    .then(r => {
      if (r.ok) {
        appendLine('[+] Server restarted — reloading page…');
        status.textContent = 'Reloading…';
        setTimeout(() => location.reload(), 500);
      } else {
        setTimeout(_pollForRestart, 1000);
      }
    })
    .catch(() => setTimeout(_pollForRestart, 1000));
}

/* ── Input ───────────────────────────────────────────────────────────── */
document.getElementById('reply-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') sendInput();
});
document.getElementById('target-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') startScan();
});

function sendInput() {
  const el   = document.getElementById('reply-input');
  const text = el.value.trim();
  if (!text) return;
  el.value = '';
  fetch('/api/input', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ text }),
  }).then(r => r.json()).then(d => {
    if (!d.ok) alert('Could not send: ' + d.error);
  });
}

function quickReply(v) {
  fetch('/api/input', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ text: v }),
  }).then(r => r.json()).then(d => {
    if (!d.ok) alert('Could not send: ' + d.error);
  });
}

/* ── Resume modal ───────────────────────────────────────────────────── */
function openResumeModal() {
  document.getElementById('resume-modal-overlay').classList.add('open');
  fetch('/api/resume-sessions').then(r => r.json()).then(list => {
    const sel = document.getElementById('resume-select');
    sel.innerHTML = '<option value="">— select a session —</option>';
    list.forEach(item => {
      const opt = document.createElement('option');
      opt.value = item.path;
      opt.textContent = item.label + '  [' + item.target + (item.phase ? ' · ' + item.phase : '') + ']';
      sel.appendChild(opt);
    });
  });
}

function closeResumeModal() {
  document.getElementById('resume-modal-overlay').classList.remove('open');
}

function submitResume() {
  const path = document.getElementById('resume-select').value;
  if (!path) { alert('Please select a session to resume.'); return; }
  closeResumeModal();
  const target   = document.getElementById('target-input').value.trim();
  const profileEl = document.querySelector('.profile-rb:checked');
  const profiles   = profileEl ? [profileEl.value] : ['standard'];
  const flags      = [...document.querySelectorAll('.flag-cb:checked')].map(cb => cb.value);
  // Always inject --resume since the checkbox no longer exists
  const allFlags = flags.includes('--resume') ? flags : ['--resume', ...flags];
  fetch('/api/start', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ target, profiles, flags: allFlags, session_dir: path }),
  }).then(r => r.json()).then(d => {
    if (!d.ok) { status.textContent = 'Error: ' + d.error; alert(d.error); }
  });
}

document.getElementById('resume-modal-overlay').addEventListener('click', e => {
  if (e.target === document.getElementById('resume-modal-overlay')) closeResumeModal();
});

/* ── Report modal ────────────────────────────────────────────────────── */
function openReportModal() {
  if (running) { alert('A scan is already running. Please wait.'); return; }
  document.getElementById('modal-overlay').classList.add('open');
  // Load sessions
  fetch('/api/sessions').then(r => r.json()).then(list => {
    const sel = document.getElementById('report-select');
    sel.innerHTML = '<option value="">— select a report —</option>';
    list.forEach(item => {
      const opt = document.createElement('option');
      opt.value = item.path;
      opt.textContent = item.label;
      sel.appendChild(opt);
    });
  });
}

function closeReportModal() {
  document.getElementById('modal-overlay').classList.remove('open');
}

function submitReport() {
  const sel  = document.getElementById('report-select').value;
  const man  = document.getElementById('report-path').value.trim();
  const path = man || sel;
  if (!path) { alert('Please select or enter a JSON report path.'); return; }
  closeReportModal();
  fetch('/api/report', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ json_path: path }),
  }).then(r => r.json()).then(d => {
    if (!d.ok) alert('Error: ' + d.error);
  });
}

// Close modal on overlay click
document.getElementById('modal-overlay').addEventListener('click', e => {
  if (e.target === document.getElementById('modal-overlay')) closeReportModal();
});

/* ── Sync run state on page load ─────────────────────────────────────── */
fetch('/api/status').then(r => r.json()).then(d => {
  running = d.running;
  setRunning(d.running);
  if (d.running) status.textContent = 'Running…';
});
</script>
</body>
</html>
"""


# ── Serve logo if it exists ──────────────────────────────────────────────────
@app.route("/logo")
def serve_logo():
    logo = os.path.join(BASE_DIR, "noctis_logo.png")
    if os.path.isfile(logo):
        from flask import send_file
        return send_file(logo, mimetype="image/png")
    return "", 404


# ── Entry point ──────────────────────────────────────────────────────────────
def main():
    port = 5000
    args = sys.argv[1:]
    if "--port" in args:
        idx = args.index("--port")
        if idx + 1 < len(args):
            try:
                port = int(args[idx + 1])
            except ValueError:
                pass

    # NOCTIS_BIND_HOST=0.0.0.0 is set automatically by docker-compose so the
    # container port is reachable from the host.  Locally it stays 127.0.0.1.
    bind_host = os.environ.get("NOCTIS_BIND_HOST", "127.0.0.1")

    print(f"[*] Noctis Edge Web UI starting on http://{bind_host}:{port}")
    if bind_host == "0.0.0.0":
        print(f"[*] Open your browser at: http://localhost:{port}")
    else:
        print(f"[*] Open your browser at: http://127.0.0.1:{port}")
    print(f"[*] Press Ctrl+C to stop the server\n")

    # use_reloader=False is important — the scanner subprocess must not be forked
    app.run(host=bind_host, port=port, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()
