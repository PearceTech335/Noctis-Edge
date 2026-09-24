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
import pty
import re
import select
import subprocess
import threading
from datetime import datetime

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
  ("--nse-aggressive",   "Disable safe-mode: enables aggressive NSE script tier (ffuf / hydra run without approval)"),
  ("--dns-enum",     "Enable DNS enumeration tools — requires internet"),
  ("--msf-validate", "Run safe Metasploit 'check' probes for each matched CVE"),
  ("--cve-test",     "Ask the LLM to generate & execute probe scripts per CVE"),
  ("--cve-nse",      "\u26a0\ufe0f  Enables CVE-targeted NSE escalation. Requires --cve-test plus explicit operator confirmation. Runs active NSE checks tied to matched CVEs."),
  ("--unsafe",       "\u26a0\ufe0f  Enables intrusive/unsafe verifier and exploit checks. You must have explicit authorisation. Operator confirmation required. Results are flagged as unsafe in reports."),
  ("--device",       "Single-host embedded/IoT assessment (IP, DHCP hostname, or FQDN — no subnets). Implies aggressive-but-safe NSE; combine with --unsafe for the full tier."),
  ("--recon",        "Discovery-only subnet sweep (CIDR/range) producing recon.json triage. Refuses --unsafe/--cve-test. Second-sweep hosts via --input."),
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


_batch_stop = False  # set by /api/stop to abort a running follow-up batch


def _followup_batch_thread(batch_dir: str, specs: list):
    """Run batch hosts sequentially, one session subfolder + report per host."""
    global _process, _running, _batch_stop
    manifest = os.path.join(batch_dir, "batch.json")
    results = []
    for n, spec in enumerate(specs, 1):
        with _lock:
            if _batch_stop:
                break
        ip = spec["ip"]
        _broadcast({"type": "line",
                    "text": f"[*] Follow-up batch [{n}/{len(specs)}]: {ip} "
                            f"({' '.join(spec['profiles'])} {' '.join(spec['flags'])})".strip()})
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        cmd = [PYTHON, "-u", NOCTIS, ip] + spec["profiles"] + spec["flags"] + \
              ["--session-dir", spec["session_dir"]]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                stdin=subprocess.PIPE, bufsize=0, cwd=BASE_DIR, env=env)
        with _lock:
            _process = proc
            _running = True
        reader = threading.Thread(target=_reader_thread, args=(proc,), daemon=True)
        reader.start()
        reader.join()
        results.append({"ip": ip, "session_dir": os.path.relpath(spec["session_dir"], BASE_DIR),
                        "returncode": proc.returncode,
                        "status": "done" if proc.returncode == 0 else "error"})
        try:
            with open(manifest, "w", encoding="utf-8") as fh:
                json.dump({"batch_dir": os.path.relpath(batch_dir, BASE_DIR),
                           "hosts": results}, fh, indent=2)
        except Exception:
            pass
    with _lock:
        _batch_stop = False
        _running = False
    _broadcast({"type": "line",
                "text": f"[+] Follow-up batch complete: {len(results)}/{len(specs)} hosts "
                        f"(manifest: {os.path.relpath(manifest, BASE_DIR)})"})


@app.route("/api/followup-batch", methods=["POST"])
def api_followup_batch():
    """Queue ticked recon hosts as sequential unattended scans.

    Each host gets sessions/followup_<ts>/<ip>_<ts>/ with its own full
    report. --unsafe/--cve-nse are refused in batch (automation + intrusive
    tiers don't mix); --unattended is forced on.
    """
    global _process, _running, _batch_stop
    data = request.get_json(force=True)
    raw_hosts = data.get("hosts", [])
    if not isinstance(raw_hosts, list) or not raw_hosts:
        return jsonify({"ok": False, "error": "hosts[] required"}), 400
    if len(raw_hosts) > 64:
        return jsonify({"ok": False, "error": "batch capped at 64 hosts"}), 400
    with _lock:
        if _running:
            return jsonify({"ok": False, "error": "A scan is already running"}), 409
    _phase_flags = ("--device-phase-1", "--device-phase-2", "--device-phase-3")
    _allowed_flags = {f for f, _ in FLAGS} | set(_phase_flags)
    specs = []
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    batch_dir = os.path.join(BASE_DIR, "sessions", f"followup_{ts}")
    for h in raw_hosts:
        if not isinstance(h, dict):
            return jsonify({"ok": False, "error": "bad host entry"}), 400
        ip = str(h.get("ip", "")).strip()
        if not re.fullmatch(r"[A-Za-z0-9_.:\-]{1,80}", ip):
            return jsonify({"ok": False, "error": f"bad host: {ip[:40]}"}), 400
        profiles = [p for p in (h.get("profiles") or []) if p in PROFILES] or ["standard"]
        flags = [f for f in (h.get("flags") or []) if f in _allowed_flags]
        if any(f in flags for f in ("--unsafe", "--cve-nse", "--recon")):
            return jsonify({"ok": False, "error": f"refused intrusive/recon flag for {ip}"}), 400
        if "--unattended" not in flags:
            flags.append("--unattended")
        safe_ip = re.sub(r"[^a-zA-Z0-9_-]", "_", ip)
        sdir = os.path.join(batch_dir, f"{safe_ip}_{ts}")
        os.makedirs(sdir, exist_ok=True)
        specs.append({"ip": ip, "profiles": profiles, "flags": flags, "session_dir": sdir})
    os.makedirs(batch_dir, exist_ok=True)
    with _lock:
        _batch_stop = False
        _running = True
    threading.Thread(target=_followup_batch_thread, args=(batch_dir, specs), daemon=True).start()
    _broadcast({"type": "started",
                "cmd": f"followup-batch {len(specs)} hosts -> {os.path.relpath(batch_dir, BASE_DIR)}"})
    return jsonify({"ok": True, "batch_dir": os.path.relpath(batch_dir, BASE_DIR),
                    "count": len(specs)})


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
    for _pf in ("--device-phase-1", "--device-phase-2", "--device-phase-3"):
      if _pf in data.get("flags", []) and _pf not in flags:
        flags.append(_pf)
    if "--resume" in data.get("flags", []) and "--resume" not in flags:
      flags.append("--resume")
    # Orphan phase flags imply device mode (CLI coerces the same way).
    if any(f.startswith("--device-phase-") for f in flags) and "--device" not in flags:
      flags.append("--device")
    session_dir = (data.get("session_dir") or "").strip()

    # --device / --recon mutual exclusion + scope guards (mirror CLI).
    # Prerequisite mirrors (CLI exits 2 on each): cve-nse/unsafe needs.
    if "--cve-nse" in flags and "--cve-test" not in flags:
      return jsonify({"ok": False, "error": "--cve-nse requires --cve-test"}), 400
    # CLI checks SAFE_MODE state (which --device clears in code), not the flag.
    _unsafe_aggr = "--nse-aggressive" in flags or "--device" in flags
    if "--unsafe" in flags and ("--cve-test" not in flags or not _unsafe_aggr):
      return jsonify({"ok": False, "error": "--unsafe requires --cve-test plus --nse-aggressive (or Device mode, which implies it)"}), 400
    if "--device" in flags and "--recon" in flags:
      return jsonify({"ok": False, "error": "--device and --recon are mutually exclusive"}), 400
    if "ot" in profiles and any(f in flags for f in ("--unsafe", "--cve-test", "--cve-nse", "--msf-validate", "--nse-aggressive")):
      return jsonify({"ok": False, "error": "OT profile refuses active flags (--unsafe/--cve-test/--cve-nse/--msf-validate/--nse-aggressive)"}), 400
    if "--device" in flags:
      _host = target.split(":")[0] if not target.startswith("[") else target
      if any(t in _host for t in ("/", ",", "*", " ")) or ("-" in _host and any(c.isdigit() for c in _host)):
        return jsonify({"ok": False, "error": "--device accepts exactly one host (IP, DHCP hostname, or FQDN); use --recon for subnets"}), 400
    if "--recon" in flags and ("--unsafe" in flags or "--cve-test" in flags):
      return jsonify({"ok": False, "error": "--recon is discovery-only; --unsafe/--cve-test are refused in recon mode"}), 400

    cmd = [PYTHON, "-u", NOCTIS, target] + profiles + flags
    if session_dir:
      # Restrict to paths inside BASE_DIR to prevent path traversal
      resolved_sd = os.path.realpath(session_dir)
      if not resolved_sd.startswith(os.path.realpath(BASE_DIR) + os.sep):
        return jsonify({"ok": False, "error": "session_dir outside project directory"}), 403
      cmd += ["--session-dir", resolved_sd]
    # Optional file-backed modes: paths must exist; recon input must also
    # live inside BASE_DIR (it is read as structured triage data).
    for _key, _flag, _inside in (("recon_input", "--input", True),
                                 ("firmware", "--firmware", False),
                                 ("creds_file", "--creds-file", False)):
      _val = (data.get(_key) or "").strip()
      if not _val:
        continue
      _resolved = os.path.realpath(_val if os.path.isabs(_val) else os.path.join(BASE_DIR, _val))
      if _inside and not _resolved.startswith(os.path.realpath(BASE_DIR) + os.sep):
        return jsonify({"ok": False, "error": f"{_key} outside project directory"}), 403
      if not os.path.isfile(_resolved):
        return jsonify({"ok": False, "error": f"{_key} file not found: {_val}"}), 400
      cmd += [_flag, _resolved]
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    # If --unsafe is present, set NOCTIS_WEBUI_UNSAFE_ACK=1 and create webui_unsafe_ack file in session_dir
    if "--unsafe" in flags:
      env["NOCTIS_WEBUI_UNSAFE_ACK"] = "1"
      if session_dir:
        try:
          ack_path = os.path.join(resolved_sd, "webui_unsafe_ack")
          with open(ack_path, "w") as f:
            f.write("acknowledged by web UI on scan start\n")
        except Exception as e:
          print(f"[!] Failed to create webui_unsafe_ack file: {e}")

    # If --cve-nse is present, set NOCTIS_WEBUI_CVE_NSE_ACK=1 and create
    # webui_cve_nse_ack file in session_dir.
    if "--cve-nse" in flags:
      env["NOCTIS_WEBUI_CVE_NSE_ACK"] = "1"
      if session_dir:
        try:
          ack_path = os.path.join(resolved_sd, "webui_cve_nse_ack")
          with open(ack_path, "w") as f:
            f.write("acknowledged by web UI on scan start\n")
        except Exception as e:
          print(f"[!] Failed to create webui_cve_nse_ack file: {e}")

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
    global _running, _batch_stop
    with _lock:
        proc = _process
        _batch_stop = True
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


# ── License key helpers (legacy — community KB is open access) ───────────────
# Kept so old noctis.conf files still parse and a paid tier can be
# re-introduced later without a migration.  The key is stored but ignored.
_CONF_FILE = os.path.join(BASE_DIR, "noctis.conf")


def _read_license_key() -> str:
    """Return the raw KB_LICENSE_KEY value from noctis.conf, or ''."""
    try:
        with open(_CONF_FILE, "r", encoding="utf-8") as f:
            for line in f:
                m = re.match(r'^KB_LICENSE_KEY=["\']?([^"\']*)["\']?', line.strip())
                if m:
                    return m.group(1).strip()
    except Exception:
        pass
    return ""


def _write_license_key(key: str) -> None:
    """Replace KB_LICENSE_KEY line in noctis.conf."""
    try:
        with open(_CONF_FILE, "r", encoding="utf-8") as f:
            content = f.read()
        new_line = f'KB_LICENSE_KEY="{key}"'
        new_content = re.sub(r'^KB_LICENSE_KEY=.*$', new_line, content, flags=re.MULTILINE)
        if 'KB_LICENSE_KEY=' not in new_content:
            new_content += f'\n{new_line}\n'
        with open(_CONF_FILE, "w", encoding="utf-8") as f:
            f.write(new_content)
    except Exception as exc:
        raise RuntimeError(f"Could not write noctis.conf: {exc}")


@app.route("/api/license-key", methods=["GET"])
def api_get_license_key():
    key = _read_license_key()
    if key:
        masked = "****-****-****-" + key[-4:] if len(key) >= 4 else "****"
        return jsonify({"set": True, "masked": masked})
    return jsonify({"set": False, "masked": ""})


@app.route("/api/license-key", methods=["POST"])
def api_set_license_key():
    data = request.get_json(force=True) or {}
    key = (data.get("key") or "").strip()
    try:
        _write_license_key(key)
        return jsonify({"ok": True})
    except RuntimeError as e:
        return jsonify({"ok": False, "error": str(e)}), 500


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


@app.route("/api/recon-files")
def api_recon_files():
    """List recon.json triage files under sessions/ for the Recon dropdown."""
    out = []
    sessions_dir = os.path.join(BASE_DIR, "sessions")
    if os.path.isdir(sessions_dir):
        for entry in os.scandir(sessions_dir):
            if not entry.is_dir():
                continue
            rp = os.path.join(entry.path, "recon.json")
            if not os.path.isfile(rp):
                continue
            try:
                with open(rp, encoding="utf-8") as fh:
                    import json as _json
                    recon = _json.load(fh)
                summary = recon.get("summary", {}) if isinstance(recon, dict) else {}
                fams = summary.get("families", {}) if isinstance(summary, dict) else {}
                out.append({
                    "path":  os.path.relpath(rp, BASE_DIR),
                    "label": os.path.relpath(entry.path, BASE_DIR),
                    "scope": recon.get("scope", "?") if isinstance(recon, dict) else "?",
                    "alive": summary.get("alive", "?") if isinstance(summary, dict) else "?",
                    "families": fams,
                })
            except Exception:
                out.append({"path": os.path.relpath(rp, BASE_DIR),
                            "label": os.path.relpath(entry.path, BASE_DIR),
                            "scope": "?", "alive": "?", "families": {}})
    out.sort(key=lambda r: r["label"], reverse=True)
    return jsonify(out)


@app.route("/api/recon-hosts")
def api_recon_hosts():
    """Return ranked host entries from a recon.json file for checkbox display."""
    rel = (request.args.get("path") or "").strip()
    if not rel:
        return jsonify({"ok": False, "error": "path is required"}), 400
    resolved = os.path.realpath(os.path.join(BASE_DIR, rel))
    if not resolved.startswith(os.path.realpath(BASE_DIR) + os.sep):
        return jsonify({"ok": False, "error": "path outside project directory"}), 403
    if os.path.basename(resolved) != "recon.json" or not os.path.isfile(resolved):
        return jsonify({"ok": False, "error": "not a recon.json file"}), 400
    try:
        with open(resolved, encoding="utf-8") as fh:
            import json as _json
            recon = _json.load(fh)
        hosts = recon.get("hosts", []) if isinstance(recon, dict) else []
        rows = []
        for h in hosts:
            if not isinstance(h, dict):
                continue
            rows.append({
                "ip": h.get("ip", "?"),
                "family": h.get("family", "unknown"),
                "device_likelihood": h.get("device_likelihood", 0),
                "recommended_profile": h.get("recommended_profile", "standard"),
                "reason": h.get("reason", ""),
                "second_sweep_cmd": h.get("second_sweep_cmd", ""),
            })
        rows.sort(key=lambda r: (-float(r["device_likelihood"] or 0), r["ip"]))
        return jsonify({"ok": True, "hosts": rows})
    except Exception as e:
        return jsonify({"ok": False, "error": f"could not read recon file: {e}"}), 400


@app.route("/api/firmware-files")
def api_firmware_files():
    """List operator-supplied firmware images in firmware/ for the Device dropdown."""
    fw_dir = os.path.join(BASE_DIR, "firmware")
    out = []
    if os.path.isdir(fw_dir):
        for entry in os.scandir(fw_dir):
            if entry.is_file() and not entry.name.startswith("."):
                out.append({"path": os.path.relpath(entry.path, BASE_DIR),
                            "label": f"{entry.name} ({entry.stat().st_size // 1024} KB)"})
    out.sort(key=lambda r: r["label"])
    return jsonify(out)


@app.route("/api/creds-files")
def api_creds_files():
    """List likely creds JSON files (names containing 'cred') under sessions/."""
    out = []
    sessions_dir = os.path.join(BASE_DIR, "sessions")
    if os.path.isdir(sessions_dir):
        for root, _dirs, files in os.walk(sessions_dir):
            for fn in files:
                if "cred" in fn.lower() and fn.endswith(".json"):
                    full = os.path.join(root, fn)
                    out.append({"path": os.path.relpath(full, BASE_DIR),
                                "label": os.path.relpath(full, sessions_dir)})
                    if len(out) >= 100:
                        break
            if len(out) >= 100:
                break
    out.sort(key=lambda r: r["label"], reverse=True)
    return jsonify(out)


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
#resume-modal-overlay, #filepicker-modal-overlay {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,.65);
  z-index: 200;
  align-items: center;
  justify-content: center;
}
#resume-modal-overlay.open, #filepicker-modal-overlay.open { display: flex; }
#resume-modal, #filepicker-modal {
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
#resume-modal h2, #filepicker-modal h2 { font-size: 13px; color: #ff9800; }
#resume-modal label, #filepicker-modal label { font-size: 10px; color: var(--fg-dim); display: block; margin-bottom: 4px; }
#resume-modal select, #filepicker-modal select {
  width: 100%;
  background: var(--bg-input);
  color: var(--fg);
  border: 1px solid #555;
  border-radius: var(--radius);
  padding: 4px 8px;
  font-family: inherit;
  font-size: 10px;
}
#resume-modal-footer, #filepicker-modal-footer { display: flex; gap: 8px; justify-content: flex-end; }
#resume-modal-ok, #filepicker-modal-ok     { background: #e65100; color: var(--btn-fg); }
#resume-modal-cancel, #filepicker-modal-cancel { background: var(--bg-input); color: var(--fg); }

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

/* ── Settings modal ──────────────────────────────────────────────────── */
#settings-modal-overlay {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,.65);
  z-index: 200;
  align-items: center;
  justify-content: center;
}
#settings-modal-overlay.open { display: flex; }
#settings-modal {
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
#settings-modal h2 { font-size: 13px; color: #ff9800; }
#settings-modal label { font-size: 10px; color: var(--fg-dim); display: block; margin-bottom: 4px; }
#settings-modal input[type="password"], #settings-modal input[type="text"] {
  width: 100%;
  background: var(--bg-input);
  color: var(--fg);
  border: 1px solid #555;
  border-radius: var(--radius);
  padding: 4px 8px;
  font-family: inherit;
  font-size: 10px;
  box-sizing: border-box;
}
#settings-modal .lic-status { font-size: 10px; color: var(--fg-dim); }
#settings-modal .lic-status.active { color: #66bb6a; }
#settings-modal-footer { display: flex; gap: 8px; justify-content: flex-end; }
#settings-modal-ok     { background: #1a6b8a; color: var(--btn-fg); }
#settings-modal-cancel { background: var(--bg-input); color: var(--fg); }
#btn-settings { background: var(--bg-input); color: var(--fg); font-size: 14px; padding: 4px 8px; }
#lic-badge { font-size: 9px; color: var(--fg-dim); margin-right: 4px; white-space: nowrap; }
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
    <input id="target-input" type="text" placeholder="192.168.0.1, hostname, host:port, CIDR for --recon, or single host for --device" autocomplete="off" spellcheck="false">
  </div>

  <!-- Profiles -->
  <fieldset class="group">
    <legend>Assessment Profile</legend>
    <div class="cb-row" id="profiles-row">
      <label title="Soft initial sweep first: discovery-only subnet triage into recon.json, then Follow-Up Scan the interesting hosts. The default kickoff point." style="font-weight:bold; color:#7fd67f;">
        <input type="radio" class="profile-rb" id="profile-recon-rb" name="profile" value="__recon" checked>
        Recon
        <span class="tip">Default kickoff: discovery-only sweep (no intrusive flags), triage hosts, then second-sweep from the recon file.</span>
      </label>
      {% for p in profiles %}
      <label title="{{ profile_descriptions[p] }}">
        <input type="radio" class="profile-rb" name="profile" value="{{ p }}">
        {{ profiles_display[p] }}
        <span class="tip">{{ profile_descriptions[p] }}</span>
      </label>
      {% endfor %}
      <label title="Single-host embedded/IoT assessment. Only one IP, DHCP hostname, or FQDN — no CIDR. Alters the kickoff: aggressive-but-safe NSE, device sweep phases, firmware intake." style="font-weight:bold; color:#29b6f6;">
        <input type="radio" class="profile-rb" id="profile-device-rb" name="profile" value="__device">
        Device
        <span class="tip">Embedded / IoT / camera assessment. Single host only; unlocks sweep phases and firmware intake below, greys out inapplicable flags.</span>
      </label>
    </div>
    <div class="cb-row" id="dphase-row" style="display:none; margin-top:6px;">
      <span style="font-size:11px; color:#888;">Device sweep phase:</span>
      <label><input type="radio" class="dphase-rb" name="dphase" value="0"> All</label>
      <label title="Surface + client harvest only (discovery, forms, scripts, cookies). CVE probing disabled."><input type="radio" class="dphase-rb" name="dphase" value="1" checked> 1 · Surface</label>
      <label title="Auth-flow assistant: HAR/JS ingest, state machine, one targeted probe."><input type="radio" class="dphase-rb" name="dphase" value="2"> 2 · Auth flow</label>
      <label title="Authenticated mapping — requires creds file or session cookie."><input type="radio" class="dphase-rb" name="dphase" value="3"> 3 · Authenticated</label>
    </div>
  </fieldset>

  <!-- Flags -->
  <fieldset class="group">
    <legend>Scan Flags</legend>
    <div class="cb-row" id="flags-row">
      {% for flag, tip in flags %}
        {% if flag not in ('--unsafe', '--cve-nse', '--device', '--recon') %}
        <label>
          <input type="checkbox" class="flag-cb" value="{{ flag }}">
          {{ flag }}
          <span class="tip">{{ tip }}</span>
        </label>
        {% endif %}
      {% endfor %}
      <div style="margin-left:auto;">
        <label style="font-weight:bold; color:#d68910; margin-right:14px;">
          <input type="checkbox" class="flag-cb" id="cve-nse-flag-cb" value="--cve-nse">
          --cve-nse
          <span class="tip" style="color:#d68910;">Enables CVE-targeted NSE escalation. Explicit operator confirmation required.</span>
        </label>
        <label style="font-weight:bold; color:#c0392b;">
          <input type="checkbox" class="flag-cb" id="unsafe-flag-cb" value="--unsafe">
          --unsafe
          <span class="tip" style="color:#c0392b;">Enables intrusive/unsafe verifier and exploit checks. You must have explicit authorisation. Operator confirmation required. Results are flagged as unsafe in reports.</span>
        </label>
      </div>
    </div>
  </fieldset>

  <!-- Second-sweep inputs: one row per file kind; rows grey out unless
       relevant to the selected assessment profile (see updateModeUI) -->
  <fieldset class="group">
    <legend>Second-Sweep Inputs</legend>
    <div id="row-recon" style="display:flex; gap:10px; flex-wrap:wrap; align-items:center; font-size:11px; padding:4px 0; border-bottom:1px solid #333;">
      <b style="min-width:86px;">Recon file</b>
      <label>File:
        <select id="recon-select"><option value="">— none —</option></select>
      </label>
      <button type="button" onclick="openFilePicker('recon')" title="Browse recon.json from any previous session">&#128193;</button>
      <button type="button" onclick="loadReconHosts()">Load hosts</button>
      <label title="Use the selected recon file as second-sweep input (--input)">
        <input type="checkbox" id="recon-input-cb"> --input
      </label>
    </div>
    <div id="recon-hosts" style="margin:4px 0 4px 0; max-height:180px; overflow-y:auto; font-size:11px;"></div>
    <div style="margin:0 0 6px 0; display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
      <button type="button" onclick="followUpScan()" title="Print second-sweep commands for ticked hosts and launch the first one">&#9889; Follow-Up Scan</button>
      <label title="Scan every ticked host as sequential unattended scans (sessions/followup_<ts>/, one report per host). Intrusive tiers refused in batch.">
        <input type="checkbox" id="followup-batch-cb"> batch all ticked (--unattended)
      </label>
      <span style="color:#888; font-size:10px;">tick hosts above, then scan — commands print to the terminal and the top pick launches</span>
    </div>
    <div id="row-firmware" style="display:flex; gap:10px; flex-wrap:wrap; align-items:center; font-size:11px; padding:4px 0; border-bottom:1px solid #333;">
      <b style="min-width:86px;">Firmware</b>
      <label title="Offline firmware string scan (stdlib only, --unsafe only). Drop images into firmware/ on the server.">
        <input type="checkbox" id="firmware-flag-cb"> --firmware
      </label>
      <label>File:
        <select id="firmware-select" disabled><option value="">— none —</option></select>
      </label>
      <button type="button" onclick="openFilePicker('firmware')" title="Browse firmware images">&#128193;</button>
      <button type="button" onclick="loadFirmwareFiles()" title="Refresh firmware/ listing">&#8635;</button>
    </div>
    <div id="row-creds" style="display:flex; gap:10px; flex-wrap:wrap; align-items:center; font-size:11px; padding:4px 0;">
      <b style="min-width:86px;">Creds file</b>
      <label title="Cookies-only JSON for device Phase-3 (0600 recommended)">File:
        <input id="creds-input" type="text" placeholder="path/to/creds.json" size="22" autocomplete="off" spellcheck="false">
      </label>
      <button type="button" onclick="openFilePicker('creds')" title="Browse saved creds files">&#128193;</button>
    </div>
  </fieldset>

  <!-- Toolbar -->
  <div id="toolbar">
    <button id="btn-run"  onclick="startScan()">&#9654;  Start Scan</button>
    <button id="btn-stop" onclick="stopScan()" disabled>&#9632;  Stop</button>
    <button id="btn-resume" onclick="openResumeModal()">&#9166; Resume</button>
    <button id="btn-clear" onclick="clearTerm()">Clear</button>
    <button id="btn-report" onclick="openReportModal()">Report</button>
    <button id="btn-man" onclick="printFlagsMan()" title="Print flag manual to terminal (same as noctis.py --man)">Manual</button>
    <span id="cmd-label"></span>
    <button id="btn-update" onclick="runUpdate()">&#8635;  Update</button>
    <button id="btn-settings" onclick="openSettingsModal()" title="Community KB &amp; Settings">&#9881;</button>
    <span id="lic-badge"></span>
  </div>

</div>

<!-- Terminal -->
<div id="term-wrap">
  <img id="wm-logo" src="/logo" alt="" onerror="this.style.display='none'">
  <div id="terminal"></div>
</div>

<!-- Input row -->
<div id="inp-row">
  <!-- CVE-NSE CONFIRMATION MODAL -->
  <div id="cve-nse-confirm-modal-overlay" style="display:none; position:fixed; left:0; top:0; right:0; bottom:0; background:rgba(10,10,10,0.9); z-index:10000; align-items:center; justify-content:center;">
    <div id="cve-nse-confirm-modal" style="background:#1e1e1e; color:#e0e0e0; border-radius:6px; box-shadow:0 4px 32px #000d; padding:28px 32px 24px 32px; max-width:620px; width:94vw; margin:auto; display:flex; flex-direction:column; gap:16px; max-height:90vh;">
      <div style="display:flex; align-items:center; gap:10px; flex-shrink:0;">
        <span style="font-size:22px;">&#9888;&#65039;</span>
        <h2 style="color:#d68910; margin:0; font-size:15px; letter-spacing:.04em;">NOCTIS EDGE &mdash; CVE-NSE ESCALATION MODE</h2>
      </div>
      <div style="overflow-y:auto; flex:1; min-height:0; background:#141414; border:1px solid #3a3a3a; border-radius:4px; padding:14px 16px; font-size:11px; line-height:1.7; font-family:'Consolas','Courier New',monospace; color:#cfd8dc; white-space:pre-wrap;">You have requested --cve-nse. This mode enables targeted NSE script escalation for matched CVE candidates. These checks are more active than baseline discovery and may impact service availability on unstable or legacy systems.

By proceeding, you represent and warrant that:
  1. You are the owner of the target system(s), OR you have obtained prior, written, and explicit authorization from the system owner to perform active security testing.
  2. Your testing is conducted within approved scope and complies with applicable laws and contractual obligations.
  3. You accept full and sole responsibility for any direct or indirect consequences, including service disruption, data loss, or third-party impact.

Noctis Edge, its authors, contributors, and distributors provide this software "AS IS", without warranty of any kind, and disclaim all liability for any damage, loss, or legal action arising from its use. Use of --cve-nse constitutes acceptance of these terms.</div>
      <div style="display:flex; gap:12px; flex-shrink:0;">
        <button style="flex:1; background:#1a1a1a; color:#aaa; border:1px solid #555; border-radius:4px; padding:10px 0; font-size:12px; font-weight:bold; cursor:pointer; letter-spacing:.03em;" onclick="closeCveNseConfirmModal()">&#10005;&nbsp; DO NOT ESCALATE</button>
        <button style="flex:2; background:#d68910; color:#fff; border:none; border-radius:4px; padding:10px 0; font-size:12px; font-weight:bold; cursor:pointer; letter-spacing:.03em;" onclick="confirmCveNseAndStartScan()">&#9888;&nbsp; PROCEED &mdash; I HAVE EXPLICIT AUTHORITY</button>
      </div>
    </div>
  </div>

  <!-- UNSAFE CONFIRMATION MODAL -->
  <div id="unsafe-confirm-modal-overlay" style="display:none; position:fixed; left:0; top:0; right:0; bottom:0; background:rgba(10,10,10,0.92); z-index:10000; align-items:center; justify-content:center;">
    <div id="unsafe-confirm-modal" style="background:#1e1e1e; color:#e0e0e0; border-radius:6px; box-shadow:0 4px 32px #000d; padding:28px 32px 24px 32px; max-width:620px; width:94vw; margin:auto; display:flex; flex-direction:column; gap:16px; max-height:90vh;">
      <div style="display:flex; align-items:center; gap:10px; flex-shrink:0;">
        <span style="font-size:22px;">&#9888;&#65039;</span>
        <h2 style="color:#c0392b; margin:0; font-size:15px; letter-spacing:.04em;">NOCTIS EDGE &mdash; UNSAFE VERIFICATION MODE</h2>
      </div>
      <div style="overflow-y:auto; flex:1; min-height:0; background:#141414; border:1px solid #3a3a3a; border-radius:4px; padding:14px 16px; font-size:11px; line-height:1.7; font-family:'Consolas','Courier New',monospace; color:#cfd8dc; white-space:pre-wrap;">You have requested --unsafe verification. This mode enables intrusive verification techniques against the specified target, including relaxed sandbox restrictions on LLM-generated probes and the use of Metasploit auxiliary modules flagged as intrusive. These actions may impact the availability, integrity, or stability of the target system.

By proceeding, you represent and warrant that:
  1. You are the owner of the target system(s), OR you have
     obtained prior, written, and explicit authorisation from
     the system owner to perform offensive security testing.
  2. Your testing is conducted within the scope of that
     authorisation and complies with all applicable laws,
     regulations, and contractual obligations in your
     jurisdiction (including but not limited to the U.S.
     Computer Fraud and Abuse Act, the UK Computer Misuse
     Act, and EU Directive 2013/40/EU).
  3. You accept full and sole responsibility for any direct
     or indirect consequences of this scan, including but not
     limited to service disruption, data loss, or third-party
     impact.

Noctis Edge, its authors, contributors, and distributors provide this software "AS IS", without warranty of any kind, and disclaim all liability for any damage, loss, or legal action arising from its use. Use of --unsafe constitutes acceptance of these terms.</div>
      <div style="display:flex; gap:12px; flex-shrink:0;">
        <button style="flex:1; background:#1a1a1a; color:#aaa; border:1px solid #555; border-radius:4px; padding:10px 0; font-size:12px; font-weight:bold; cursor:pointer; letter-spacing:.03em;" onclick="closeUnsafeConfirmModal()">&#10005;&nbsp; DO NOT SCAN</button>
        <button style="flex:2; background:#c0392b; color:#fff; border:none; border-radius:4px; padding:10px 0; font-size:12px; font-weight:bold; cursor:pointer; letter-spacing:.03em;" onclick="confirmUnsafeAndStartScan()">&#9888;&nbsp; PROCEED &mdash; I HAVE EXPLICIT AUTHORITY TO SCAN THIS TARGET</button>
      </div>
    </div>
  </div>
  <label for="reply-input">Prompt reply:</label>
  <input id="reply-input" type="text" placeholder="Type y/n or free-text reply and press Enter…" autocomplete="off">
  <button id="btn-send" onclick="sendInput()">Send</button>
  <button id="btn-y" onclick="quickReply('y')">Y</button>
  <button id="btn-n" onclick="quickReply('n')">N</button>
</div>


<!-- Status bar -->
<div id="status-bar"><span id="status-text">Ready</span><span id="version-badge">{{ version }}</span></div>

<!-- CVE-NSE MODE WARNING BANNER -->
<div id="cve-nse-banner" style="display:none; flex-shrink:0; width:100%; background:#d68910; color:#1e1e1e; text-align:center; font-size:15px; font-weight:bold; padding:10px 0; letter-spacing:0.5px; box-shadow:0 -2px 12px #0007;">
  &#9888;&#65039; CVE-NSE ESCALATION SELECTED - ACTIVE NSE CHECKS WILL RUN FOR MATCHED CVEs &#9888;&#65039;
</div>

<!-- UNSAFE MODE WARNING BANNER -->
<div id="unsafe-banner" style="display:none; flex-shrink:0; width:100%; background:#c0392b; color:#fff; text-align:center; font-size:16px; font-weight:bold; padding:12px 0; letter-spacing:1px; box-shadow:0 -2px 16px #000a;">
  &#9888;&#65039; UNSAFE MODE SELECTED - ENSURE YOU HAVE EXPRESS PERMISSION TO SCAN THE TARGET &#9888;&#65039;
</div>

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


<!-- File picker modal (recon / firmware / creds — Resume-style) -->
<div id="filepicker-modal-overlay">
  <div id="filepicker-modal">
    <h2 id="filepicker-title">&#128193; Select file</h2>
    <div>
      <label for="filepicker-select" id="filepicker-label">File:</label>
      <select id="filepicker-select"><option value="">— loading… —</option></select>
    </div>
    <div id="filepicker-modal-footer">
      <button id="filepicker-modal-cancel" onclick="closeFilePicker()">Cancel</button>
      <button id="filepicker-modal-ok" onclick="submitFilePicker()">Select</button>
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
      <button id="btn-unsafe-modal" style="display:none; background:#c0392b; color:#fff;" onclick="openUnsafeModal()">Unsafe Verifier Results</button>
    </div>
  </div>
</div>

<!-- Unsafe Verifier modal (hidden by default) -->
<div id="unsafe-modal-overlay" style="display:none; position:fixed; left:0; top:0; right:0; bottom:0; background:rgba(30,30,30,0.85); z-index:10000; align-items:center; justify-content:center;">
  <div id="unsafe-modal" style="background:#252526; color:#fff; border-radius:6px; box-shadow:0 2px 16px #000a; padding:32px 32px 24px 32px; max-width:600px; margin:auto; text-align:left;">
    <h2 style="color:#c0392b;">Unsafe Verifier Results</h2>
    <div id="unsafe-modal-content">
      <!-- Populated by JS -->
    </div>
    <div id="unsafe-modal-footer" style="display:flex; gap:8px; justify-content:flex-end;">
      <button id="unsafe-modal-cancel" onclick="closeUnsafeModal()">Close</button>
    </div>
  </div>
</div>

<!-- Settings modal -->
<div id="settings-modal-overlay">
  <div id="settings-modal">
    <h2>&#9881; Community KB &amp; Settings</h2>
    <div>
      <p class="lic-status" id="lic-status-text">Checking…</p>
    </div>
    <div>
      <p style="opacity:.8">Community KB pulls are open access — no key required.
      The field below is legacy and ignored (reserved for a future tier).</p>
      <label for="lic-key-input">Legacy license key (optional, ignored):</label>
      <input id="lic-key-input" type="password" placeholder="XXXX-XXXX-XXXX-XXXX" spellcheck="false" autocomplete="off">
    </div>
    <div id="settings-modal-footer">
      <button id="settings-modal-cancel" onclick="closeSettingsModal()">Cancel</button>
      <button id="settings-modal-ok" onclick="saveLicenseKey()">Save</button>
    </div>
  </div>
</div>

<script>
// Show CVE-NSE / UNSAFE mode banners based on selected flags
function updateModeBanners() {
  const cveNseCb = document.getElementById('cve-nse-flag-cb');
  const cveNseBanner = document.getElementById('cve-nse-banner');
  const unsafeCb = document.getElementById('unsafe-flag-cb');
  const unsafeBanner = document.getElementById('unsafe-banner');
  if (cveNseCb && cveNseCb.checked) {
    cveNseBanner.style.display = 'block';
  } else {
    cveNseBanner.style.display = 'none';
  }
  if (unsafeCb && unsafeCb.checked) {
    unsafeBanner.style.display = 'block';
  } else {
    unsafeBanner.style.display = 'none';
  }
}
/* ── Flag manual (mirrors `noctis.py --man`) ─────────────────────────── */
function printFlagsMan() {
  appendLine('Noctis Edge — flag manual (same as `noctis.py --man`):');
  [...document.querySelectorAll('#flags-row .flag-cb')].forEach(cb => {
    const tip = cb.closest('label').querySelector('.tip');
    appendLine('  ' + cb.value + ' — ' + (tip ? tip.textContent.trim() : ''));
  });
  const rec = document.getElementById('profile-recon-rb');
  if (rec) appendLine('  [profile] Recon — default kickoff: discovery-only sweep, all flags greyed out, triage via recon file.');
  appendLine('  Presets — Recon:(none) Standard:(none) Full:(--nse-aggressive --dns-enum --msf-validate) OT:(none) Device:(phase 1, extras off)');
  const dev = document.getElementById('profile-device-rb');
  if (dev) appendLine('  [profile] Device — single-host embedded/IoT assessment; unlocks sweep phases + firmware intake, greys out --dns-enum.');
  appendLine('  --device-phase-1/2/3 — Device sweep phase: 1 surface only (disables --cve-test), 2 auth flow (default behaviour), 3 authenticated mapping (needs creds).');
  appendLine('  --firmware (checkbox) + file dropdown — offline firmware string scan; files live in firmware/ on the server.');
  appendLine('  --input (checkbox) + recon dropdown — second-sweep host selection from a recon.json file.');
  appendLine('  Creds file input — cookies-only JSON path sent as --creds-file for device Phase-3.');
}
document.addEventListener('DOMContentLoaded', function() {
  loadReconFiles();
  loadFirmwareFiles();
  updateModeUI();
  document.querySelectorAll('.profile-rb').forEach(rb => rb.addEventListener('change', () => {
    updateModeUI();
    applyPreset(rb.value);
  }));
  document.getElementById('firmware-flag-cb').addEventListener('change', updateFirmwareUI);
  const cveNseCb = document.getElementById('cve-nse-flag-cb');
  const unsafeCb = document.getElementById('unsafe-flag-cb');
  if (cveNseCb) {
    cveNseCb.addEventListener('change', updateModeBanners);
  }
  if (unsafeCb) {
    unsafeCb.addEventListener('change', updateModeBanners);
    updateModeBanners();
  }
});
// CVE-NSE confirmation modal logic
function openCveNseConfirmModal() {
  document.getElementById('cve-nse-confirm-modal-overlay').style.display = 'flex';
}
function closeCveNseConfirmModal() {
  document.getElementById('cve-nse-confirm-modal-overlay').style.display = 'none';
}
function confirmCveNseAndStartScan() {
  closeCveNseConfirmModal();
  actuallyStartScan();
}
// Unsafe confirmation modal logic
function openUnsafeConfirmModal() {
  document.getElementById('unsafe-confirm-modal-overlay').style.display = 'flex';
}
function closeUnsafeConfirmModal() {
  document.getElementById('unsafe-confirm-modal-overlay').style.display = 'none';
}
function confirmUnsafeAndStartScan() {
  closeUnsafeConfirmModal();
  const cveNseCb = document.getElementById('cve-nse-flag-cb');
  if (cveNseCb && cveNseCb.checked) {
    openCveNseConfirmModal();
    return;
  }
  actuallyStartScan();
}

/* ── Device / Recon file dropdowns + host triage ────────────────────── */
function loadReconFiles(then) {
  fetch('/api/recon-files').then(r => r.json()).then(list => {
    const sel = document.getElementById('recon-select');
    sel.innerHTML = '<option value="">— none —</option>';
    list.forEach(item => {
      const opt = document.createElement('option');
      opt.value = item.path;
      const fams = Object.entries(item.families || {}).map(([k, v]) => `${v} ${k}`).join(', ');
      opt.textContent = `${item.scope} — ${item.alive} alive${fams ? ' (' + fams + ')' : ''}`;
      sel.appendChild(opt);
    });
    if (then) then();
  });
}
function loadFirmwareFiles(then) {
  fetch('/api/firmware-files').then(r => r.json()).then(list => {
    const sel = document.getElementById('firmware-select');
    sel.innerHTML = '<option value="">— none —</option>';
    list.forEach(item => {
      const opt = document.createElement('option');
      opt.value = item.path;
      opt.textContent = item.label;
      sel.appendChild(opt);
    });
    if (then) then();
  });
}
function loadReconHosts() {
  const path = document.getElementById('recon-select').value;
  const box = document.getElementById('recon-hosts');
  if (!path) { box.innerHTML = '<span style="color:#888;">Select a recon file first.</span>'; return; }
  fetch('/api/recon-hosts?path=' + encodeURIComponent(path)).then(r => r.json()).then(d => {
    if (!d.ok) { box.innerHTML = '<span style="color:#c0392b;">Error: ' + d.error + '</span>'; return; }
    if (!d.hosts.length) { box.innerHTML = '<span style="color:#888;">No hosts in recon file.</span>'; return; }
    box.innerHTML = '';
    d.hosts.forEach((h, i) => {
      const row = document.createElement('div');
      row.style.cssText = 'padding:3px 6px; border-bottom:1px solid #333; cursor:pointer; display:flex; gap:8px; align-items:center;';
      row.title = (h.second_sweep_cmd || '') + (h.reason ? '\n' + h.reason : '');
      const pct = Math.round((h.device_likelihood || 0) * 100);
      const star = pct >= 65 ? ' ★' : '';
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.className = 'recon-host-cb';
      cb.checked = pct >= 65;
      cb.dataset.ip = h.ip;
      cb.dataset.profile = h.recommended_profile || 'standard';
      cb.dataset.cmd = h.second_sweep_cmd || '';
      const label = document.createElement('span');
      label.innerHTML = `<b>#${i + 1}</b> ${h.ip} <span style="color:#888;">[${h.family}]</span> ` +
        `<span style="color:${pct >= 65 ? '#7fd67f' : pct >= 40 ? '#d68910' : '#888'};">${pct}%${star}</span> ` +
        `<span style="color:#29b6f6;">→ ${h.recommended_profile}</span>`;
      row.appendChild(cb);
      row.appendChild(label);
      row.onclick = (e) => {
        if (e.target !== cb) cb.checked = !cb.checked;
        document.getElementById('target-input').value = h.ip;
      };
      box.appendChild(row);
    });
  });
}
function followupSpec(cb) {
  // Map a recon row's recommended profile to launch {profiles, flags}.
  const toks = (cb.dataset.profile || 'standard').split(/\s+/);
  const profiles = toks.filter(t => ['standard', 'full', 'ot'].includes(t));
  const flags = toks.filter(t => t.startsWith('--'));
  return { ip: cb.dataset.ip, profiles: profiles.length ? profiles : ['standard'], flags };
}
function followUpScan() {
  const picked = [...document.querySelectorAll('.recon-host-cb:checked')];
  if (!picked.length) { alert('Tick one or more recon hosts first.'); return; }
  const batch = document.getElementById('followup-batch-cb');
  if (batch && batch.checked) {
    if (!confirm(`Scan ${picked.length} host(s) as sequential unattended scans? Each gets its own session folder and report under sessions/followup_<timestamp>/.`)) return;
    fetch('/api/followup-batch', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ hosts: picked.map(followupSpec) }),
    }).then(r => r.json()).then(d => {
      if (!d.ok) { status.textContent = 'Error: ' + d.error; alert(d.error); }
      else appendLine(`[*] Follow-up batch queued: ${d.count} host(s) -> ${d.batch_dir}`);
    });
    return;
  }
  appendLine('[*] Follow-Up Scan — ' + picked.length + ' host(s) selected:');
  picked.forEach(cb => appendLine('    $ ' + (cb.dataset.cmd || ('python3 noctis.py ' + cb.dataset.ip))));
  const first = picked[0];
  document.getElementById('target-input').value = first.dataset.ip;
  if ((first.dataset.profile || '').includes('--device')) {
    const devRb = document.getElementById('profile-device-rb');
    if (devRb) { devRb.checked = true; updateModeUI(); }
  }
  appendLine('[*] Launching top pick: ' + first.dataset.ip + ' — stop it before striking the next host (one scan at a time).');
  startScan();
}
/* ── Resume-style file picker (recon / firmware / creds) ────────────── */
let filePickerKind = null;
const FILEPICKER_SRC = {
  recon:    { url: '/api/recon-files',    title: 'Select recon file — any previous recon session',
              label: 'recon.json files found:', fmt: (it) => it.label + '  [' + (it.scope || '?') + ']' },
  firmware: { url: '/api/firmware-files', title: 'Select firmware image — drop images into firmware/ on the server',
              label: 'firmware/ contents:', fmt: (it) => it.label },
  creds:    { url: '/api/creds-files',    title: 'Select creds file — cookies-only JSON (0600 recommended)',
              label: '*cred*.json files under sessions/:', fmt: (it) => it.label },
};
function openFilePicker(kind) {
  filePickerKind = kind;
  const cfg = FILEPICKER_SRC[kind];
  document.getElementById('filepicker-title').textContent = cfg.title;
  document.getElementById('filepicker-label').textContent = cfg.label;
  const sel = document.getElementById('filepicker-select');
  sel.innerHTML = '<option value="">— loading… —</option>';
  document.getElementById('filepicker-modal-overlay').classList.add('open');
  fetch(cfg.url).then(r => r.json()).then(list => {
    sel.innerHTML = '<option value="">— select a file —</option>';
    list.forEach(item => {
      const opt = document.createElement('option');
      opt.value = item.path;
      opt.textContent = cfg.fmt(item);
      sel.appendChild(opt);
    });
    if (!list.length) sel.innerHTML = '<option value="">(no files found)</option>';
  });
}
function closeFilePicker() {
  document.getElementById('filepicker-modal-overlay').classList.remove('open');
  filePickerKind = null;
}
function submitFilePicker() {
  const path = document.getElementById('filepicker-select').value;
  if (!path) { alert('Please select a file.'); return; }
  const kind = filePickerKind;
  closeFilePicker();
  if (kind === 'recon') {
    loadReconFiles(() => {
      document.getElementById('recon-select').value = path;
      const riCb = document.getElementById('recon-input-cb');
      if (riCb) riCb.checked = true;
      loadReconHosts();
    });
  } else if (kind === 'firmware') {
    loadFirmwareFiles(() => {
      document.getElementById('firmware-select').value = path;
    });
  } else if (kind === 'creds') {
    document.getElementById('creds-input').value = path;
  }
}
// Structural note: --device/--recon mutual exclusion is enforced by the
// profile radio group (one selection only) plus the backend 400 guard;
// no JS guard needed.

// Patch startScan to require confirmation for --unsafe
const origStartScan = startScan;
function startScan() {
  const unsafeCb = document.getElementById('unsafe-flag-cb');
  const cveNseCb = document.getElementById('cve-nse-flag-cb');
  if (unsafeCb && unsafeCb.checked) {
    openUnsafeConfirmModal();
    return;
  }
  if (cveNseCb && cveNseCb.checked) {
    openCveNseConfirmModal();
    return;
  }
  actuallyStartScan();
}

function selectedProfile() {
  const el = document.querySelector('.profile-rb:checked');
  return el ? el.value : 'standard';
}
function deviceModeSelected() {
  return selectedProfile() === '__device';
}
function reconModeSelected() {
  return selectedProfile() === '__recon';
}
// Flags inapplicable to a single-host device sweep are greyed out while
// Device is selected (mirrors CLI scope rules). Recon is the soft initial
// sweep: every flag is greyed out. Selections are preserved (disabled boxes
// are skipped at collect time) so toggling modes never loses your setup.
const DEVICE_GREYED_FLAGS = ['--recon', '--dns-enum'];
// Active probing has no place near safety systems: OT greys everything
// intrusive plus anything internet-dependent.
const OT_GREYED_FLAGS = ['--unsafe', '--cve-test', '--cve-nse', '--msf-validate', '--nse-aggressive', '--dns-enum'];
// Default flag presets per profile radio. NEVER includes --unsafe/--cve-nse
// (modal-gated conscious opt-ins) or --unattended (auto-approves everything).
// Note: Standard is deliberately empty — --cve-test would stall every scan
// at an approval prompt and raise the intrusiveness floor.
const PROFILE_PRESETS = {
  '__recon': [],
  'standard': [],
  'full': ['--nse-aggressive', '--dns-enum', '--msf-validate'],
  'ot': [],
  '__device': [],
};
function applyPreset(profile) {
  // Reset-to-preset on every radio switch: leaked flags (e.g. aggressive
  // toggles carried into OT or Device-phase-1) are dangerous or silently
  // dropped, so the radio is always truthful. Manual ticks stick until the
  // next switch.
  const want = PROFILE_PRESETS[profile] || [];
  [...document.querySelectorAll('.flag-cb')].forEach(cb => {
    if (!cb.disabled) cb.checked = want.includes(cb.value);
  });
  appendLine('[*] Profile preset flags: ' + (want.join(' ') || '(none — safe baseline)'));
}
function updateModeUI() {
  const dev = deviceModeSelected();
  const rec = reconModeSelected();
  const otm = selectedProfile() === 'ot';
  document.getElementById('dphase-row').style.display = dev ? 'flex' : 'none';
  [...document.querySelectorAll('.flag-cb')].forEach(cb => {
    const off = rec || (dev && DEVICE_GREYED_FLAGS.includes(cb.value)) ||
                (otm && OT_GREYED_FLAGS.includes(cb.value));
    cb.disabled = off;
    cb.closest('label').style.opacity = off ? '0.35' : '';
  });
  updateFirmwareUI();
}
function setRow(rowId, on) {
  // Grey out a whole Second-Sweep input row so irrelevant controls cannot
  // be spammed in. Disabled controls are skipped at collect time.
  const row = document.getElementById(rowId);
  if (!row) return;
  row.style.opacity = on ? '' : '0.35';
  row.querySelectorAll('input, select, button').forEach(el => { el.disabled = !on; });
}
function updateFirmwareUI() {
  const dev = deviceModeSelected();
  setRow('row-firmware', dev);
  setRow('row-creds', dev);
  const fwCb = document.getElementById('firmware-flag-cb');
  const fwSel = document.getElementById('firmware-select');
  // File dropdown wakes only when its --firmware flag is ticked (stays
  // disabled otherwise even though the row itself is enabled).
  fwSel.disabled = !(dev && fwCb && fwCb.checked);
}
function deviceFlags() {
  // Returns array of device-derived flags, or null (with alert) on bad input.
  if (!deviceModeSelected()) return [];
  const out = ['--device'];
  const ph = document.querySelector('.dphase-rb:checked');
  if (ph && ['1', '2', '3'].includes(ph.value)) out.push('--device-phase-' + ph.value);
  const fwCb = document.getElementById('firmware-flag-cb');
  if (fwCb && fwCb.checked && !document.getElementById('firmware-select').value) {
    alert('Pick a firmware file from the dropdown (--firmware selected).');
    return null;
  }
  if (ph && ph.value === '3' && !document.getElementById('creds-input').value.trim()) {
    alert('Phase 3 is authenticated mapping — supply a creds file first.');
    return null;
  }
  const unsafeCb = document.getElementById('unsafe-flag-cb');
  if (fwCb && fwCb.checked && unsafeCb && !unsafeCb.checked) {
    appendLine('[!] --firmware without --unsafe is a no-op (scan defers with a resume hint). Tick --unsafe for the P1 string scan.');
  }
  return out;
}
function scanExtras() {
  // Greyed-out (disabled) controls never contribute, even if still ticked
  // from an earlier mode — prevents spamming irrelevant inputs per scan.
  const fwCb = document.getElementById('firmware-flag-cb');
  const riCb = document.getElementById('recon-input-cb');
  const credsEl = document.getElementById('creds-input');
  return {
    recon_input: (riCb && riCb.checked && !riCb.disabled) ? document.getElementById('recon-select').value : '',
    firmware:    (fwCb && fwCb.checked && !fwCb.disabled) ? document.getElementById('firmware-select').value : '',
    creds_file:  (credsEl && !credsEl.disabled) ? credsEl.value.trim() : '',
  };
}
function collectFlags() {
  // Returns flag array, or null (with alert) on bad device input.
  // Disabled (greyed-out) boxes are skipped so mode toggles never leak flags.
  const flags = [...document.querySelectorAll('.flag-cb:checked')]
    .filter(cb => !cb.disabled).map(cb => cb.value);
  if (reconModeSelected()) {
    if (!flags.includes('--recon')) flags.push('--recon');
    return flags;
  }
  const dev = deviceFlags();
  if (dev === null) return null;
  for (const f of dev) if (!flags.includes(f)) flags.push(f);
  return flags;
}
function actuallyStartScan() {
  const target = document.getElementById('target-input').value.trim();
  if (!target) { alert('Please enter a target hostname or IP address.'); return; }

  const profileEl = document.querySelector('.profile-rb:checked');
  const profiles  = (profileEl && !['__device', '__recon'].includes(profileEl.value)) ? [profileEl.value] : ['standard'];
  const flags     = collectFlags();
  if (flags === null) return;

  // Always generate a unique session_dir for each scan (timestamp + random)
  const sessionDir = `sessions/webui_${Date.now()}_${Math.floor(Math.random()*1e6)}`;

  fetch('/api/start', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ target, profiles, flags, session_dir: sessionDir, ...scanExtras() }),
  }).then(r => r.json()).then(d => {
    if (!d.ok) { status.textContent = 'Error: ' + d.error; alert(d.error); }
  });
}
// Show/hide UNSAFE MODE banner when --unsafe is checked
/* ── WebSocket connection ─────────────────────────────────────────────── */
const term    = document.getElementById('terminal');
const status  = document.getElementById('status-text');
const cmdLbl  = document.getElementById('cmd-label');
const btnRun  = document.getElementById('btn-run');
const btnStop = document.getElementById('btn-stop');
const btnUpdate = document.getElementById('btn-update');
const btnResume = document.getElementById('btn-resume');
const licBadge  = document.getElementById('lic-badge');
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
  const profiles  = (profileEl && !['__device', '__recon'].includes(profileEl.value)) ? [profileEl.value] : ['standard'];
  const flags     = collectFlags();
  if (flags === null) return;

  // Always generate a unique session_dir for each scan (timestamp + random)
  const sessionDir = `sessions/webui_${Date.now()}_${Math.floor(Math.random()*1e6)}`;

  fetch('/api/start', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ target, profiles, flags, session_dir: sessionDir, ...scanExtras() }),
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
  const profiles   = (profileEl && profileEl.value !== '__device') ? [profileEl.value] : ['standard'];
  const flags      = collectFlags();
  if (flags === null) return;
  // Always inject --resume since the checkbox no longer exists
  const allFlags = flags.includes('--resume') ? flags : ['--resume', ...flags];
  fetch('/api/start', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ target, profiles, flags: allFlags, session_dir: path, ...scanExtras() }),
  }).then(r => r.json()).then(d => {
    if (!d.ok) { status.textContent = 'Error: ' + d.error; alert(d.error); }
  });
}

document.getElementById('resume-modal-overlay').addEventListener('click', e => {
  if (e.target === document.getElementById('resume-modal-overlay')) closeResumeModal();
});
document.getElementById('filepicker-modal-overlay').addEventListener('click', e => {
  if (e.target === document.getElementById('filepicker-modal-overlay')) closeFilePicker();
});


// ── Report modal ──────────────────────────────────────────────────────
let lastReportPath = null;
let lastUnsafeResults = null;
let lastUnsafeConfirmation = null;

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
  // Hide unsafe button by default
  document.getElementById('btn-unsafe-modal').style.display = 'none';
  lastReportPath = null;
  lastUnsafeResults = null;
  lastUnsafeConfirmation = null;
}

function closeReportModal() {
  document.getElementById('modal-overlay').classList.remove('open');
}

function submitReport() {
  const sel  = document.getElementById('report-select').value;
  const man  = document.getElementById('report-path').value.trim();
  const path = man || sel;
  if (!path) { alert('Please select or enter a JSON report path.'); return; }
  // Try to load the JSON and check for unsafe verifier results
  fetch(path).then(r => {
    if (!r.ok) throw new Error('Could not load report JSON');
    return r.json();
  }).then(report => {
    lastReportPath = path;
    lastUnsafeResults = report.unsafe_verification_results || null;
    lastUnsafeConfirmation = report.confirmation_used_unsafe || null;
    if (lastUnsafeResults && Array.isArray(lastUnsafeResults) && lastUnsafeResults.length > 0) {
      document.getElementById('btn-unsafe-modal').style.display = '';
    } else {
      document.getElementById('btn-unsafe-modal').style.display = 'none';
    }
    closeReportModal();
    // Also trigger the report generation as before
    fetch('/api/report', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ json_path: path }),
    }).then(r => r.json()).then(d => {
      if (!d.ok) alert('Error: ' + d.error);
    });
  }).catch(e => {
    alert('Could not load report JSON: ' + e.message);
    closeReportModal();
  });
}

// Close modal on overlay click
document.getElementById('modal-overlay').addEventListener('click', e => {
  if (e.target === document.getElementById('modal-overlay')) closeReportModal();
});

// ── Unsafe Verifier modal ─────────────────────────────────────────────
function openUnsafeModal() {
  if (!lastUnsafeResults || !Array.isArray(lastUnsafeResults) || lastUnsafeResults.length === 0) {
    alert('No unsafe verifier results found in this report.');
    return;
  }
  const overlay = document.getElementById('unsafe-modal-overlay');
  const content = document.getElementById('unsafe-modal-content');
  content.innerHTML = '';
  // Disclaimer
  const disclaimer = document.createElement('div');
  disclaimer.style = 'color:#c0392b; font-size:12px; margin-bottom:10px;';
  disclaimer.textContent = 'These results were obtained using operator-acknowledged unsafe actions. You must have authorisation to test these systems. Noctis bears no responsibility for any consequences.';
  content.appendChild(disclaimer);
  // Confirmation
  if (lastUnsafeConfirmation) {
    const conf = document.createElement('div');
    conf.style = 'color:#fff; background:#444; padding:6px 10px; border-radius:3px; margin-bottom:10px; font-size:11px;';
    conf.textContent = 'Operator confirmation: ' + lastUnsafeConfirmation;
    content.appendChild(conf);
  }
  // Results table
  const table = document.createElement('table');
  table.style = 'width:100%; border-collapse:collapse; margin-bottom:10px;';
  const thead = document.createElement('thead');
  thead.innerHTML = '<tr style="background:#222; color:#fff;"><th style="padding:4px 8px; border-bottom:1px solid #555;">CVE</th><th style="padding:4px 8px; border-bottom:1px solid #555;">Result</th><th style="padding:4px 8px; border-bottom:1px solid #555;">Details</th></tr>';
  table.appendChild(thead);
  const tbody = document.createElement('tbody');
  for (const r of lastUnsafeResults) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td style="padding:4px 8px; border-bottom:1px solid #333;">${r.cve_id || ''}</td><td style="padding:4px 8px; border-bottom:1px solid #333; color:${r.result==="VULNERABLE"?"#f44747":(r.result==="SAFE"?"#4ec9b0":"#fff")}">${r.result || ''}</td><td style="padding:4px 8px; border-bottom:1px solid #333;">${r.details || ''}</td>`;
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  content.appendChild(table);
  overlay.style.display = 'flex';
}

function closeUnsafeModal() {
  document.getElementById('unsafe-modal-overlay').style.display = 'none';
}

document.getElementById('unsafe-modal-overlay').addEventListener('click', e => {
  if (e.target === document.getElementById('unsafe-modal-overlay')) closeUnsafeModal();
});

/* ── Settings / Community KB modal (license field is legacy) ─────────── */
function loadLicenseStatus() {
  fetch('/api/license-key').then(r => r.json()).then(d => {
    const el = document.getElementById('lic-status-text');
    el.textContent = 'Community KB: open access — pulls require no key.'
      + (d.set ? ' (legacy key stored: ' + d.masked + ', ignored)' : '');
    el.className = 'lic-status active';
  }).catch(() => {
    licBadge.textContent = '';
  });
}

function openSettingsModal() {
  document.getElementById('lic-key-input').value = '';
  loadLicenseStatus();
  document.getElementById('settings-modal-overlay').classList.add('open');
}

function closeSettingsModal() {
  document.getElementById('settings-modal-overlay').classList.remove('open');
}

function saveLicenseKey() {
  const key = document.getElementById('lic-key-input').value.trim();
  fetch('/api/license-key', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ key }),
  }).then(r => r.json()).then(d => {
    if (d.ok) {
      loadLicenseStatus();
      closeSettingsModal();
    } else {
      alert('Error saving license key: ' + (d.error || 'unknown error'));
    }
  });
}

document.getElementById('settings-modal-overlay').addEventListener('click', e => {
  if (e.target === document.getElementById('settings-modal-overlay')) closeSettingsModal();
});

/* ── Sync run state on page load ─────────────────────────────────────── */
fetch('/api/status').then(r => r.json()).then(d => {
  running = d.running;
  setRunning(d.running);
  if (d.running) status.textContent = 'Running…';
});

loadLicenseStatus();
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
    port = 8888
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
    print("[*] Press Ctrl+C to stop the server\n")

    # use_reloader=False is important — the scanner subprocess must not be forked
    app.run(host=bind_host, port=port, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()
