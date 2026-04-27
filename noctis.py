#!/usr/bin/env python3
"""
Noctis Edge — Security Through Exposure
Implements: structured findings, verification,
approval gates, async execution, HTML/PDF reports,
service-specific enumerations, and risk scoring.
"""

import asyncio
import dataclasses
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

if __name__ == "__main__":
    _BOOTSTRAP_BASE = os.path.dirname(os.path.abspath(__file__))
    _BOOTSTRAP_VENV = os.path.join(_BOOTSTRAP_BASE, ".venv", "bin", "python3")
    _BOOTSTRAP_PREFIX = os.path.realpath(os.path.join(_BOOTSTRAP_BASE, ".venv"))
    if os.path.exists(_BOOTSTRAP_VENV) and os.path.realpath(sys.prefix) != _BOOTSTRAP_PREFIX:
        env = os.environ.copy()
        venv_bin = os.path.dirname(_BOOTSTRAP_VENV)
        env["PATH"] = venv_bin + os.pathsep + env.get("PATH", "")
        env["VIRTUAL_ENV"] = _BOOTSTRAP_PREFIX
        os.execve(_BOOTSTRAP_VENV, [_BOOTSTRAP_VENV, __file__, *sys.argv[1:]], env)

import requests
from jinja2 import Template

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
NIKTO_PL     = os.path.join(BASE_DIR, "nikto", "program", "nikto.pl")
RDPSCAN_PY   = os.path.join(BASE_DIR, "rdpscan", "RPDscan.py")
_WL_SECLISTS = "/snap/seclists/current/Discovery/Web-Content/common.txt"
_WL_BUNDLED  = os.path.join(BASE_DIR, "WordLists", "common.txt")
if os.path.exists(_WL_SECLISTS):
    WORDLIST = _WL_SECLISTS
elif os.path.exists(_WL_BUNDLED):
    WORDLIST = _WL_BUNDLED
else:
    print("[!] No web-path wordlist found. Install SecLists:")
    print("      sudo snap install seclists")
    sys.exit(1)
CVE_CSV      = os.path.join(BASE_DIR, "CVE", "cve-offline", "cve-summary.csv")
SESSION_FILE = os.path.join(BASE_DIR, "session.json")

OLLAMA_URL     = "http://localhost:11434/api/generate"
MODEL          = os.getenv("NOCTIS_OLLAMA_MODEL", "hf.co/RCorvalan/Qwen2.5-7B-Instruct-1M-Q4_K_M-GGUF")
OLLAMA_TIMEOUT = int(os.getenv("NOCTIS_OLLAMA_TIMEOUT", "300"))   # seconds — CPU-only inference can take 1-3 min per call
# Alternative models:
#"hf.co/RCorvalan/Qwen2.5-7B-Instruct-1M-Q4_K_M-GGUF"  (default — 4.68 GB, 1M context)
#"qwen2.5-coder:3b"                                      (lightweight — 1.9 GB, low-RAM machines)
#"qwen2.5-coder:7b-instruct-q4_k_m"                     (standard Ollama 7B coder)

MAX_OUTPUT      = 3000
MAX_ITERATIONS  = 10
MAX_LLM_RETRIES = 3
SAFE_MODE       = True   # can also be used with --aggressive flag for aggressive scanning an enumeration
AIRGAP_MODE     = True   # default on; --dns opts in to internet-dependent DNS enumeration tools
MSF_VALIDATE    = False  # set via --msf-validate; runs safe MSF check probes for each CVE match
CVE_TEST        = False  # set via --cve-test; LLM generates test scripts per matched CVE
CVE_KB_PATH     = os.path.join(BASE_DIR, "cve_knowledge_base.json")
CVE_TEST_ATTEMPTS = 15   # LLM attempts per CVE; KB scripts replayed first, new scripts fill remaining slots
CVE_VERIFY_ATTEMPTS = 2  # independent verifier scripts run when any attempt returns VULNERABLE

# Tools that rely on internet OSINT sources and should be skipped in airgap mode
INTERNET_ONLY_TOOLS = {"amass", "dnsenum", "dnsrecon"}

# ---------------------------------------------------------------------------
# TOOL CONFIDENCE WEIGHTS
# ---------------------------------------------------------------------------

TOOL_CONFIDENCE: dict = {
    "nuclei":    0.70,
    "nikto":     0.40,
    "curl":      0.90,
    "gobuster":  0.60,
    "ffuf":      0.60,
    "ssh-audit": 0.85,
    "rdpscan":   0.75,
    "nmap":      0.80,
    "dns":       0.75,
    "mysql":     0.80,
    "mssql":     0.80,
}

# Require explicit operator approval before running these
AGGRESSIVE_TOOLS = {"gobuster", "ffuf", "hydra", "nuclei_aggressive"}

# ---------------------------------------------------------------------------
# ASSESSMENT PROFILES
# ---------------------------------------------------------------------------

PROFILES = {
    "web": {
        "name":            "Web Application Assessment",
        "tools":           ["curl", "nikto", "nuclei", "gobuster", "ffuf"],
        "escalation":      ["nikto_full", "nuclei_aggressive"],
        "report_template": "web",
    },
    "internal_ad": {
        "name":            "Internal AD Assessment",
        "tools":           ["nmap", "nxc_smb", "nxc_ldap", "impacket"],
        "escalation":      ["hydra"],
        "report_template": "ad",
    },
    "external": {
        "name":            "External Perimeter Review",
        "tools":           ["nmap", "curl", "nuclei", "gobuster", "dns_enum"],
        "escalation":      ["nuclei_aggressive"],
        "report_template": "external",
    },
    "api": {
        "name":            "API Assessment",
        "tools":           ["curl", "nuclei", "ffuf"],
        "escalation":      ["nuclei_aggressive"],
        "report_template": "api",
    },
    "cloud": {
        "name":            "Cloud Exposure Review",
        "tools":           ["curl", "nuclei", "dns_enum"],
        "escalation":      [],
        "report_template": "cloud",
    },
}

# ---------------------------------------------------------------------------
# DATA MODELS
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    finding_id:          str
    tool:                str
    target:              str
    service:             str
    severity:            str
    title:               str
    evidence:            str
    confidence:          float
    verified:            bool
    timestamp:           str
    tags:                list = field(default_factory=list)
    verification_status: str  = "discovered"
    raw_output:          str  = ""
    cvss_score:          float = 0.0
    risk_score:          float = 0.0
    business_impact:     str  = ""
    references:          list = field(default_factory=list)
    description:         str  = ""
    matched_url:         str  = ""
    template_id:         str  = ""

    def to_dict(self):
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d):
        return cls(**d)


@dataclass
class TargetInfo:
    input_target:  str
    ip_address:    str = ""
    rdns_hostname: str = ""
    mac_address:   str = ""
    mac_vendor:    str = ""
    os_guess:      str = ""
    os_accuracy:   int = 0
    netbios_name:  str = ""
    asn:           str = ""
    org:           str = ""
    open_ports:    int = 0
    scan_time:     str = ""

    def to_dict(self):
        return dataclasses.asdict(self)


def make_finding_id(tool, target, title):
    raw = f"{tool}:{target}:{title}:{time.time()}"
    return "F-" + hashlib.sha256(raw.encode()).hexdigest()[:12].upper()


# ---------------------------------------------------------------------------
# OLLAMA LIFECYCLE
# ---------------------------------------------------------------------------

_ollama_proc: Optional[subprocess.Popen] = None

def ensure_ollama_running() -> bool:
    """Return True if Ollama is already serving or was successfully started.

    Checks http://localhost:11434/api/tags.  If it is not reachable, spawns
    `ollama serve` as a background process and waits up to 15 seconds for it
    to become available.  The process handle is kept in _ollama_proc so it is
    not garbage-collected and can be cleaned up at exit.
    """
    global _ollama_proc

    tags_url = "http://localhost:11434/api/tags"

    def _is_up() -> bool:
        try:
            r = requests.get(tags_url, timeout=3)
            return r.status_code == 200
        except Exception:
            return False

    if _is_up():
        print("[*] Ollama is already serving.")
        return True

    if shutil.which("ollama") is None:
        print("[!] 'ollama' binary not found in PATH. Please install Ollama:")
        print("      https://ollama.com/download")
        return False

    print("[*] Ollama is not running — starting 'ollama serve' in the background …")
    try:
        _ollama_proc = subprocess.Popen(
            ["ollama", "serve"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        print(f"[!] Failed to start Ollama: {exc}")
        return False

    deadline = time.time() + 15
    while time.time() < deadline:
        if _is_up():
            print("[*] Ollama is now serving.")
            return True
        time.sleep(0.5)

    print("[!] Ollama did not become ready within 15 seconds.")
    return False


def normalize_severity(sev):
    mapping = {
        "critical":      "critical",
        "crit":          "critical",
        "high":          "high",
        "medium":        "medium",
        "med":           "medium",
        "low":           "low",
        "info":          "info",
        "informational": "info",
        "none":          "info",
        "unknown":       "info",
    }
    return mapping.get(sev.lower().strip(), "info")


def calculate_risk_score(finding, internet_exposed=True):
    """severity_weight × confidence × exposure × tool_confidence"""
    severity_weights = {
        "critical": 1.0,
        "high":     0.8,
        "medium":   0.5,
        "low":      0.2,
        "info":     0.05,
    }
    sev_w     = severity_weights.get(finding.severity.lower(), 0.1)
    exposure  = 1.2 if internet_exposed else 1.0
    tool_conf = TOOL_CONFIDENCE.get(finding.tool, 0.5)
    return round(sev_w * finding.confidence * exposure * tool_conf, 3)


def auto_tag(finding):
    """Auto-generate tags from service / title / evidence"""
    combined = (finding.title + " " + finding.evidence + " " + finding.service).lower()
    tag_map = {
        "web":             ["http", "https", "web", "html", "url", "path"],
        "auth":            ["auth", "login", "password", "credential", "basic auth"],
        "rce":             ["rce", "remote code", "command injection", "exec", "shell"],
        "unauthenticated": ["unauthenticated", "no auth", "anonymous", "open access"],
        "external":        ["external", "internet", "public"],
        "internal":        ["internal", "intranet", "lan"],
        "ssl":             ["ssl", "tls", "certificate", "https"],
        "smb":             ["smb", "samba", "microsoft-ds", "netbios"],
        "ssh":             ["ssh", "openssh"],
        "rdp":             ["rdp", "remote desktop"],
        "dns":             ["dns", "zone transfer", "subdomain"],
        "sql":             ["sql", "mysql", "mssql", "postgresql", "database"],
        "api":             ["api", "rest", "graphql", "swagger", "openapi"],
    }
    tags = []
    for tag, keywords in tag_map.items():
        if any(kw in combined for kw in keywords):
            tags.append(tag)
    return list(set(tags))


def deduplicate_findings(findings):
    seen   = set()
    unique = []
    for f in findings:
        key = f"{f.title.lower()}:{f.target}:{f.service}"
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# ---------------------------------------------------------------------------
# TOOL VALIDATION
# ---------------------------------------------------------------------------

TOOL_REGISTRY = {
    "nmap":      ("nmap",      None),
    "nuclei":    ("nuclei",    os.path.join(os.path.expanduser("~"), "go", "bin", "nuclei")),
    "nikto":     ("nikto",     None),
    "curl":      ("curl",      None),
    "gobuster":  ("gobuster",  None),
    "ffuf":      ("ffuf",      None),
    "hydra":     ("hydra",     None),
    "ssh-audit": ("ssh-audit", None),
    "rdpscan":   ("rdpscan",   None),
    "amass":     ("amass",     None),
    "nxc":       ("nxc",       None),
    "dnsenum":   ("dnsenum",   None),
    "dnsrecon":  ("dnsrecon",  None),
    "msfconsole": ("msfconsole", None),
}


def validate_tools():
    available   = {}
    unavailable = []
    for name, (binary, explicit_path) in TOOL_REGISTRY.items():
        if name == "nikto":
            if os.path.exists(NIKTO_PL):
                available[name] = NIKTO_PL
            else:
                unavailable.append(name)
        elif name == "rdpscan":
            if os.path.exists(RDPSCAN_PY):
                available[name] = RDPSCAN_PY
            else:
                unavailable.append(name)
        else:
            path = (
                explicit_path
                if explicit_path and os.path.exists(explicit_path)
                else shutil.which(binary)
            )
            if path:
                available[name] = path
            else:
                unavailable.append(name)
    return available, unavailable


def print_tool_status(available, unavailable):
    print(f"\n{'=' * 52}")
    print("  TOOL VALIDATION")
    print(f"{'=' * 52}")
    for name in sorted(available):
        print(f"  [OK]      {name:<14} {available[name]}")
    for name in sorted(unavailable):
        print(f"  [MISSING] {name}")
    if not AIRGAP_MODE:
        print(f"\n  [DNS]     DNS enumeration enabled:")
        for name in sorted(INTERNET_ONLY_TOOLS):
            print(f"            {name}")
    print(f"{'=' * 52}\n")


# ---------------------------------------------------------------------------
# APPROVAL GATE
# ---------------------------------------------------------------------------

def request_approval(tool, args, risk_desc=""):
    if not SAFE_MODE:
        return True
    print(f"\n[!] APPROVAL REQUIRED")
    print(f"    Tool : {tool}")
    print(f"    Args : {args}")
    if risk_desc:
        print(f"    Risk : {risk_desc}")
    try:
        answer = input("    Approve aggressive action? [y/n]: ").strip().lower()
        return answer in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print("\n[!] No input — denying by default.")
        return False


# ---------------------------------------------------------------------------
# ASYNC TOOL EXECUTION
# ---------------------------------------------------------------------------

async def run_command_async(cmd, timeout=120):
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        out_buf = []
        timed_out_flag = [False]

        async def drain(stream):
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    timed_out_flag[0] = True
                    break
                try:
                    chunk = await asyncio.wait_for(
                        stream.read(65536), timeout=min(remaining, 5.0)
                    )
                    if not chunk:
                        break
                    out_buf.append(chunk.decode("utf-8", errors="replace"))
                except asyncio.TimeoutError:
                    timed_out_flag[0] = True
                    break

        await asyncio.gather(drain(proc.stdout), drain(proc.stderr))

        # Kill process if still running, then drain any remaining pipe buffer
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        for stream in (proc.stdout, proc.stderr):
            if stream is None:
                continue
            try:
                while True:
                    chunk = await asyncio.wait_for(stream.read(65536), timeout=2.0)
                    if not chunk:
                        break
                    out_buf.append(chunk.decode("utf-8", errors="replace"))
            except Exception:
                pass
        await proc.wait()

        out = "".join(out_buf)
        if timed_out_flag[0] and not out.strip():
            return f"[!] Command timed out after {timeout}s"
        return out[:MAX_OUTPUT]
    except Exception as e:
        return str(e)


async def run_curl_async(url):
    return await run_command_async(["curl", "-s", "-L", "-m", "15", url], timeout=20)


async def run_nikto_async(url, session_dir=None):
    # Capture findings via stdout so parse_nikto_output can see them.
    # -maxtime is a hint to nikto; asyncio timeout is the hard limit.
    raw = await run_command_async(
        ["perl", NIKTO_PL, "-h", url, "-Format", "txt",
         "-nointeractive", "-maxtime", "90s"],
        timeout=100,
    )
    # Print any Nikto administrative/version messages to terminal only — they must
    # not appear in the report (parse_nikto_output already filters them as findings,
    # but they would still surface in the execution log output preview).
    clean_lines = []
    for line in raw.splitlines():
        text = line.strip()
        if text.startswith("+ ") and any(p in text[2:].lower() for p in _NIKTO_ADMIN_PHRASES):
            print(f"[nikto] {text[2:]}")
        else:
            clean_lines.append(line)
    raw = "\n".join(clean_lines)
    # Save a copy into the session directory for reference.
    if session_dir:
        safe_url = re.sub(r"[^a-zA-Z0-9_-]", "_", url).strip("_")
        out_path = os.path.join(session_dir, f"nikto_{safe_url}.txt")
        try:
            with open(out_path, "w") as fh:
                fh.write(raw)
        except OSError:
            pass
    return raw


# ---------------------------------------------------------------------------
# NUCLEI JSON PARSING
# ---------------------------------------------------------------------------

async def run_nuclei_json_async(url, available_tools):
    nuclei_path = available_tools.get("nuclei", "nuclei")
    cmd = [
        nuclei_path,
        "-u", url,
        "-s", "low,medium,high,critical",
        "-silent",
        "-nc",
        "-timeout", "10",
        "-j",        # JSONL output (one JSON object per line)
        "-ot",       # omit encoded template to keep output compact
    ]
    if AIRGAP_MODE:
        cmd.append("-duc")   # nuclei v3: disable update check (replaces -no-update-templates)
    raw = await run_command_async(cmd, timeout=45)
    return raw, parse_nuclei_json(raw, url)


def parse_nuclei_json(raw_output, target):
    """Parse nuclei -json line-delimited output into Finding objects."""
    findings = []
    for line in raw_output.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        template_id = obj.get("template-id", "") or obj.get("templateID", "")
        severity    = normalize_severity(obj.get("info", {}).get("severity", "info"))
        title       = obj.get("info", {}).get("name", template_id) or template_id
        matched_url = obj.get("matched-at", "") or obj.get("host", target)
        description = obj.get("info", {}).get("description", "")
        references  = obj.get("info", {}).get("reference", []) or []
        if isinstance(references, str):
            references = [references]
        tags_raw = obj.get("info", {}).get("tags", "")
        tags = (
            [t.strip() for t in tags_raw.split(",")]
            if isinstance(tags_raw, str)
            else (tags_raw or [])
        )
        evidence_raw = obj.get("extracted-results", "") or obj.get("curl-command", "") or matched_url
        evidence     = evidence_raw if isinstance(evidence_raw, str) else str(evidence_raw)

        f = Finding(
            finding_id=make_finding_id("nuclei", target, template_id),
            tool="nuclei",
            target=target,
            service="http",
            severity=severity,
            title=title,
            evidence=evidence,
            confidence=TOOL_CONFIDENCE.get("nuclei", 0.7),
            verified=False,
            timestamp=datetime.now(timezone.utc).isoformat(),
            tags=tags,
            raw_output=line,
            description=description,
            matched_url=matched_url,
            template_id=template_id,
            references=references,
            verification_status="discovered",
        )
        f.tags = list(set(f.tags + auto_tag(f)))
        findings.append(f)
    return findings


# ---------------------------------------------------------------------------
# NIKTO FINDING PARSER
# ---------------------------------------------------------------------------

# Nikto lines that are administrative noise — should print to terminal, not appear in report.
_NIKTO_ADMIN_PHRASES = (
    "out of date",
    "git pull",
    "update to the latest version of nikto",
    "ssl info:",
    "target ip:",
    "target hostname:",
    "target port:",
    "start time:",
    "end time:",
    "host summary:",
)


def parse_nikto_output(output, target):
    findings = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped.startswith("+ "):
            continue
        if stripped.startswith("+ End") or stripped.startswith("+ 0 host"):
            continue
        text = stripped[2:]
        if len(text) < 15:
            continue
        # Skip Nikto admin/meta messages — they are printed to terminal by run_nikto_async
        if any(p in text.lower() for p in _NIKTO_ADMIN_PHRASES):
            continue
        f = Finding(
            finding_id=make_finding_id("nikto", target, text[:50]),
            tool="nikto",
            target=target,
            service="http",
            severity="info",
            title=text[:120],
            evidence=text[:400],
            confidence=TOOL_CONFIDENCE.get("nikto", 0.4),
            verified=False,
            timestamp=datetime.now(timezone.utc).isoformat(),
            tags=[],
            verification_status="discovered",
        )
        f.tags = auto_tag(f)
        findings.append(f)
    return findings[:15]


# ---------------------------------------------------------------------------
# GOBUSTER OUTPUT PARSER
# ---------------------------------------------------------------------------

def parse_gobuster_output(output, target):
    """Parse gobuster -q output lines like '/path (Status: 200) [Size: 123]' into findings."""
    findings = []
    for line in output.splitlines():
        line = line.strip()
        m = re.match(r'^(/\S*)\s+\(Status:\s*(\d+)\)', line)
        if not m:
            continue
        path   = m.group(1)
        status = int(m.group(2))
        if status in (301, 302):
            severity = "info"
        elif status == 401:
            severity = "low"
        elif status == 200:
            severity = "info"
        else:
            severity = "info"
        title = f"Web path found: {path} [{status}]"
        f = Finding(
            finding_id=make_finding_id("gobuster", target, path),
            tool="gobuster",
            target=target,
            service="http",
            severity=severity,
            title=title,
            evidence=line,
            confidence=TOOL_CONFIDENCE.get("gobuster", 0.5),
            verified=False,
            timestamp=datetime.now(timezone.utc).isoformat(),
            tags=["web", "directory-enum"],
            verification_status="discovered",
        )
        findings.append(f)
    return findings[:30]


# ---------------------------------------------------------------------------
# SSH ENUMERATION
# ---------------------------------------------------------------------------

async def run_ssh_enum(host, port, available_tools):
    findings = []
    outputs  = []

    if "ssh-audit" in available_tools:
        output = await run_command_async(["ssh-audit", "-p", port, host], timeout=30)
        outputs.append(f"[ssh-audit]\n{output}")
        warn_lines = [
            ln for ln in output.splitlines()
            if any(x in ln.lower() for x in ["warn", "fail", "crit", "rec"])
        ]
        if warn_lines:
            evidence = "\n".join(warn_lines[:10])
            sev = "high" if any("fail" in l.lower() or "crit" in l.lower() for l in warn_lines) else "medium"
            f = Finding(
                finding_id=make_finding_id("ssh-audit", host, "SSH Configuration Issues"),
                tool="ssh-audit",
                target=host,
                service=f"ssh:{port}",
                severity=sev,
                title="SSH Weak Configuration Detected",
                evidence=evidence[:500],
                confidence=TOOL_CONFIDENCE.get("ssh-audit", 0.85),
                verified=False,
                timestamp=datetime.now(timezone.utc).isoformat(),
                tags=["ssh", "auth"],
                verification_status="discovered",
                raw_output=output[:1000],
            )
            f.tags = list(set(f.tags + auto_tag(f)))
            findings.append(f)

    nmap_out = await run_command_async([
        "nmap", "-p", port, "--script", "ssh-auth-methods,ssh2-enum-algos",
        "-Pn", "--open", host,
    ], timeout=30)
    outputs.append(f"[nmap-ssh]\n{nmap_out}")

    # Only create SSH finding if the port actually runs SSH (not IPP, HTTP, etc.)
    port_is_ssh = (
        re.search(r"\d+/tcp\s+open\s+ssh", nmap_out, re.IGNORECASE) is not None
        or "ssh" in nmap_out.lower().split("service")[-1][:50]
    )
    if port_is_ssh and "password" in nmap_out.lower() and "supported" in nmap_out.lower():
        f = Finding(
            finding_id=make_finding_id("nmap", host, "SSH Password Auth"),
            tool="nmap",
            target=host,
            service=f"ssh:{port}",
            severity="medium",
            title="SSH Password Authentication Enabled",
            evidence=nmap_out[:400],
            confidence=TOOL_CONFIDENCE.get("nmap", 0.8),
            verified=False,
            timestamp=datetime.now(timezone.utc).isoformat(),
            tags=["ssh", "auth"],
            verification_status="discovered",
        )
        findings.append(f)

    return "\n\n".join(outputs), findings


# ---------------------------------------------------------------------------
# RDP ENUMERATION
# ---------------------------------------------------------------------------

async def run_rdp_enum(host, port, available_tools):
    """RDP enumeration using nmap scripts only"""
    findings = []
    outputs  = []

    nmap_out = await run_command_async([
        "nmap", "-p", port, "--script", "rdp-enum-encryption",
        "-Pn", "--open", host,
    ], timeout=30)
    outputs.append(f"[nmap-rdp]\n{nmap_out}")

    if "classic rdp security" in nmap_out.lower() or "rdp security layer" in nmap_out.lower():
        f = Finding(
            finding_id=make_finding_id("nmap", host, "RDP Weak Encryption"),
            tool="nmap",
            target=host,
            service=f"rdp:{port}",
            severity="medium",
            title="RDP Weak Encryption Level",
            evidence=nmap_out[:400],
            confidence=TOOL_CONFIDENCE.get("nmap", 0.8),
            verified=False,
            timestamp=datetime.now(timezone.utc).isoformat(),
            tags=["rdp"],
            verification_status="discovered",
        )
        findings.append(f)

    return "\n\n".join(outputs), findings


# ---------------------------------------------------------------------------
# DNS ENUMERATION
# ---------------------------------------------------------------------------

async def run_dns_enum(domain, available_tools):
    findings = []
    outputs  = []

    zone_out = await run_command_async(["dig", "axfr", domain], timeout=15)
    outputs.append(f"[dig-axfr]\n{zone_out}")

    if "transfer failed" not in zone_out.lower() and len(zone_out.strip()) > 100:
        f = Finding(
            finding_id=make_finding_id("dns", domain, "Zone Transfer"),
            tool="dns",
            target=domain,
            service="dns",
            severity="high",
            title="DNS Zone Transfer Possible",
            evidence=zone_out[:500],
            confidence=0.9,
            verified=True,
            timestamp=datetime.now(timezone.utc).isoformat(),
            tags=["dns", "external", "unauthenticated"],
            verification_status="confirmed",
        )
        findings.append(f)

    for rtype in ["A", "MX", "TXT", "NS", "CNAME"]:
        out = await run_command_async(["dig", rtype, domain, "+short"], timeout=10)
        if out.strip():
            outputs.append(f"[dig-{rtype}]\n{out}")

    if "dnsenum" in available_tools:
        dnsenum_out = await run_command_async(
            [available_tools["dnsenum"], domain],
            timeout=60,
        )
        if dnsenum_out.strip():
            outputs.append(f"[dnsenum]\n{dnsenum_out}")

    if "dnsrecon" in available_tools:
        dnsrecon_out = await run_command_async(
            [available_tools["dnsrecon"], "-d", domain],
            timeout=60,
        )
        if dnsrecon_out.strip():
            outputs.append(f"[dnsrecon]\n{dnsrecon_out}")

    return "\n\n".join(outputs), findings


# ---------------------------------------------------------------------------
# MYSQL ENUMERATION
# ---------------------------------------------------------------------------

async def run_mysql_enum(host, port, available_tools):
    findings = []
    outputs  = []

    nmap_out = await run_command_async([
        "nmap", "-p", port, "--script", "mysql-info,mysql-empty-password,mysql-enum",
        "-Pn", "--open", host,
    ], timeout=30)
    outputs.append(f"[nmap-mysql]\n{nmap_out}")

    if "empty password" in nmap_out.lower() or "anonymous" in nmap_out.lower():
        f = Finding(
            finding_id=make_finding_id("nmap", host, "MySQL No Auth"),
            tool="nmap",
            target=host,
            service=f"mysql:{port}",
            severity="critical",
            title="MySQL Anonymous / Empty Password Access",
            evidence=nmap_out[:400],
            confidence=TOOL_CONFIDENCE.get("nmap", 0.8),
            verified=False,
            timestamp=datetime.now(timezone.utc).isoformat(),
            tags=["sql", "unauthenticated", "auth"],
            verification_status="discovered",
        )
        findings.append(f)

    if "mysql" in nmap_out.lower() and any(v in nmap_out for v in ["5.", "8.", "10."]):
        f = Finding(
            finding_id=make_finding_id("nmap", host, "MySQL Version"),
            tool="nmap",
            target=host,
            service=f"mysql:{port}",
            severity="low",
            title="MySQL Version Information Disclosed",
            evidence=nmap_out[:300],
            confidence=TOOL_CONFIDENCE.get("nmap", 0.8),
            verified=True,
            timestamp=datetime.now(timezone.utc).isoformat(),
            tags=["sql"],
            verification_status="confirmed",
        )
        findings.append(f)

    return "\n\n".join(outputs), findings


# ---------------------------------------------------------------------------
# MSSQL ENUMERATION
# ---------------------------------------------------------------------------

async def run_mssql_enum(host, port, available_tools):
    findings = []
    outputs  = []

    nmap_out = await run_command_async([
        "nmap", "-p", port, "--script", "ms-sql-info,ms-sql-config,ms-sql-empty-password",
        "-Pn", "--open", host,
    ], timeout=30)
    outputs.append(f"[nmap-mssql]\n{nmap_out}")

    if "ms-sql" in nmap_out.lower():
        f = Finding(
            finding_id=make_finding_id("nmap", host, "MSSQL Info"),
            tool="nmap",
            target=host,
            service=f"mssql:{port}",
            severity="info",
            title="MSSQL Service Information Disclosed",
            evidence=nmap_out[:400],
            confidence=TOOL_CONFIDENCE.get("nmap", 0.8),
            verified=True,
            timestamp=datetime.now(timezone.utc).isoformat(),
            tags=["sql", "mssql"],
            verification_status="confirmed",
        )
        findings.append(f)

    # NetExec preferred over legacy CrackMapExec
    if "nxc" in available_tools:
        nxc_out = await run_command_async(
            ["nxc", "mssql", host, "-p", port], timeout=20
        )
        outputs.append(f"[nxc-mssql]\n{nxc_out}")

    return "\n\n".join(outputs), findings


# ---------------------------------------------------------------------------
# CVE LOOKUP
# ---------------------------------------------------------------------------
# CVE ENRICHMENT METADATA
# ---------------------------------------------------------------------------

_VULN_TYPE_PATTERNS = [
    (["buffer overflow", "stack overflow", "heap overflow"],                        "Buffer Overflow"),
    (["path traversal", "directory traversal", "../"],                              "Path Traversal"),
    (["sql injection", "sql query"],                                                "SQL Injection"),
    (["cross-site scripting", " xss"],                                              "XSS"),
    (["execute arbitrary code", "arbitrary commands", "remote code execution"],     "RCE"),
    (["command injection"],                                                         "Command Injection"),
    (["denial of service", "cause a denial", "cause the server to crash"],          "DoS"),
    (["privilege escalation", "gain privilege", "elevated privilege"],              "Privilege Escalation"),
    (["authentication bypass", "bypass authentication", "without authentication"],  "Authentication Bypass"),
    (["information disclosure", "sensitive information", "disclose"],               "Information Disclosure"),
    (["xml external entity", "xxe"],                                                "XXE"),
    (["deserialization"],                                                            "Insecure Deserialization"),
    (["format string"],                                                              "Format String"),
    (["use after free", "use-after-free"],                                          "Use-After-Free"),
    (["integer overflow", "integer underflow"],                                     "Integer Overflow"),
    (["open redirect"],                                                              "Open Redirect"),
    (["server-side request forgery", "ssrf"],                                       "SSRF"),
]

_SAFE_VALIDATION = {
    "Buffer Overflow":        "Version banner check / service fingerprint only",
    "Path Traversal":         "HTTP traversal probe with benign read-only path",
    "SQL Injection":          "Time-based blind probe or error-based check on test parameter",
    "XSS":                    "Reflected non-executing payload in non-destructive parameter",
    "RCE":                    "DNS callback / canary file probe — no code execution",
    "Command Injection":      "DNS callback or time-delay probe",
    "DoS":                    "Version banner check only — do not trigger on production",
    "Privilege Escalation":   "Enumerate SUID binaries and sudo rules",
    "Authentication Bypass":  "Attempt unauthenticated GET to protected resource",
    "Information Disclosure": "Unauthenticated GET to sensitive endpoint",
    "XXE":                    "Out-of-band XML entity with DNS callback",
    "Insecure Deserialization": "ysoserial gadget chain probe with DNS callback",
    "Format String":          "Version banner check — do not send format strings to production",
    "Use-After-Free":         "Version banner check only",
    "Integer Overflow":       "Version banner check only",
    "Open Redirect":          "Redirect to benign external host and inspect Location header",
    "SSRF":                   "Probe with internal address that returns a known response",
    "Unknown":                "Version banner check and manual review",
}

_PROOF_OF_IMPACT = {
    "Buffer Overflow":        "Service crash or unexpected code execution indicator",
    "Path Traversal":         "Read access to /etc/passwd or equivalent sensitive file",
    "SQL Injection":          "Database version string or row data in response",
    "XSS":                    "Script executes in browser context",
    "RCE":                    "Command output returned or DNS callback received",
    "Command Injection":      "Command output returned or DNS callback received",
    "DoS":                    "Service becomes unavailable or returns 5xx",
    "Privilege Escalation":   "Access to root/admin resource confirmed",
    "Authentication Bypass":  "Authenticated resource accessed without credentials",
    "Information Disclosure": "Sensitive file content or credential in response",
    "XXE":                    "Internal file content or SSRF response in XML reply",
    "Insecure Deserialization": "Code execution confirmed or DNS callback received",
    "Format String":          "Memory content leaked in response",
    "Use-After-Free":         "Service crash or unexpected behaviour observed",
    "Integer Overflow":       "Unexpected behaviour or crash observed",
    "Open Redirect":          "Browser redirected to attacker-controlled host",
    "SSRF":                   "Response contains internal resource content",
    "Unknown":                "Manual verification required",
}

_BUSINESS_IMPACT = {
    ("critical", "RCE"):                    "Full system compromise with potential lateral movement",
    ("critical", "Buffer Overflow"):        "Full system compromise",
    ("critical", "Authentication Bypass"):  "Unrestricted access to all system resources",
    ("critical", "Insecure Deserialization"): "Full system compromise",
    ("high",     "Path Traversal"):         "Sensitive file disclosure and potential credential exposure",
    ("high",     "Authentication Bypass"):  "Unauthorised access to protected systems and data",
    ("high",     "SQL Injection"):          "Database contents exposed or modified",
    ("high",     "Command Injection"):      "Arbitrary command execution on the host",
    ("high",     "RCE"):                    "Remote code execution — full host compromise possible",
    ("high",     "Buffer Overflow"):        "Potential remote code execution",
    ("medium",   "Information Disclosure"): "Sensitive configuration or credential data exposed",
    ("medium",   "XSS"):                    "Session hijacking or phishing vector against users",
    ("medium",   "SSRF"):                   "Internal network scanning and service exposure",
    ("medium",   "Open Redirect"):          "Phishing vector; credential harvesting risk",
    ("low",      "DoS"):                    "Service availability impact during exploitation",
}
_BUSINESS_IMPACT_DEFAULT = {
    "critical": "Critical impact — immediate remediation required",
    "high":     "High impact — significant risk to confidentiality or integrity",
    "medium":   "Moderate impact — risk to data exposure or system integrity",
    "low":      "Low impact — limited exposure",
    "unknown":  "Impact unknown — manual review required",
}


def _infer_vuln_type(summary: str) -> str:
    s = summary.lower()
    for keywords, label in _VULN_TYPE_PATTERNS:
        if any(kw in s for kw in keywords):
            return label
    return "Unknown"


def _infer_version_range(summary: str) -> str:
    """Extract an affected version range from free-text CVE summary."""
    s = summary
    # e.g. "1.1.5 through 1.1.17" or "1.x through 1.2.3"
    m = re.search(r'([\d][.\dx]+)\s+through\s+([\d][.\dx]+)', s, re.IGNORECASE)
    if m:
        return f"{m.group(1)} \u2013 {m.group(2)}"
    # "before 2.4.50" / "prior to 2.4.50"
    m = re.search(r'(?:before|prior to)\s+([\d][.\dx]+)', s, re.IGNORECASE)
    if m:
        return f"< {m.group(1)}"
    # "1.1.14 through 1.1.17" already caught above; also catch standalone "< X"
    m = re.search(r'<\s*([\d][.\dx]+)', s)
    if m:
        return f"< {m.group(1)}"
    return "See NVD advisory"


def enrich_cve(cve: dict, service: dict) -> dict:
    """Return a copy of the CVE dict with additional metadata fields."""
    summary      = cve.get("summary", "")
    severity     = cve.get("severity", "unknown").lower()
    summary_low  = summary.lower()

    vuln_type    = _infer_vuln_type(summary)
    remote       = "remote" in summary_low
    requires_auth = not any(
        phrase in summary_low
        for phrase in ("without authentication", "unauthenticated", "no authentication",
                       "anonymous", "without login")
    )
    product  = service.get("product") or service.get("name", "")
    version  = service.get("version", "")

    business_key = (severity, vuln_type)
    business_impact = (
        _BUSINESS_IMPACT.get(business_key)
        or _BUSINESS_IMPACT_DEFAULT.get(severity, _BUSINESS_IMPACT_DEFAULT["unknown"])
    )

    return {
        "cve_id":                cve["id"],
        "severity":              cve["severity"],
        "cvss_score":            cve.get("cvss_score", 0.0),
        "product":               product,
        "version_affected":      version if version else "unknown",
        "version_range":         _infer_version_range(summary),
        "vulnerability_type":    vuln_type,
        "requires_auth":         requires_auth,
        "remote":                remote,
        "safe_validation_method": _SAFE_VALIDATION.get(vuln_type, _SAFE_VALIDATION["Unknown"]),
        "proof_of_impact":       _PROOF_OF_IMPACT.get(vuln_type, _PROOF_OF_IMPACT["Unknown"]),
        "business_impact":       business_impact,
        "summary":               summary,
    }


# ---------------------------------------------------------------------------
# METASPLOIT VALIDATION
# ---------------------------------------------------------------------------
# Static CVE → (msf_module, default_options) map.
# RHOSTS is always set from the target; RPORT is overridden by the actual
# discovered service port at runtime.

CVE_MSF_MAP: dict = {
    # Windows SMB
    "CVE-2017-0144": ("exploit/windows/smb/ms17_010_eternalblue",          {"RPORT": "445"}),
    "CVE-2017-0145": ("exploit/windows/smb/ms17_010_psexec",               {"RPORT": "445"}),
    "CVE-2008-4250": ("exploit/windows/smb/ms08_067_netapi",               {"RPORT": "445"}),
    # Windows RDP
    "CVE-2019-0708": ("exploit/windows/rdp/cve_2019_0708_bluekeep_rce",    {"RPORT": "3389"}),
    # Apache
    "CVE-2021-41773": ("exploit/multi/http/apache_normalize_path_rce",     {"RPORT": "80",  "TARGETURI": "/"}),
    "CVE-2021-42013": ("exploit/multi/http/apache_normalize_path_rce",     {"RPORT": "80",  "TARGETURI": "/"}),
    "CVE-2014-6271":  ("exploit/multi/http/apache_mod_cgi_bash_env_exec",  {"RPORT": "80",  "TARGETURI": "/cgi-bin/test.cgi"}),
    # OpenSSL Heartbleed
    "CVE-2014-0160":  ("auxiliary/scanner/ssl/openssl_heartbleed",         {"RPORT": "443"}),
    # Log4Shell
    "CVE-2021-44228": ("exploit/multi/misc/log4shell_header_injection",    {"RPORT": "8080"}),
    # Exchange ProxyLogon / ProxyShell
    "CVE-2021-26855": ("exploit/windows/http/exchange_proxylogon_rce",     {"RPORT": "443", "SSL": "true"}),
    "CVE-2021-34473": ("exploit/windows/http/exchange_proxyshell_rce",     {"RPORT": "443", "SSL": "true"}),
    # MySQL
    "CVE-2012-2122":  ("auxiliary/scanner/mysql/mysql_authbypass_hashdump",{"RPORT": "3306"}),
    # vsFTPd backdoor
    "CVE-2011-2523":  ("exploit/unix/ftp/vsftpd_234_backdoor",             {"RPORT": "21"}),
    # libssh auth bypass
    "CVE-2018-10933": ("auxiliary/scanner/ssh/libssh_auth_bypass",         {"RPORT": "22"}),
    # Samba
    "CVE-2017-7494":  ("exploit/linux/samba/is_known_pipename",            {"RPORT": "445"}),
    # CUPS (remote code execution chain - 2024)
    "CVE-2024-47076": ("auxiliary/scanner/misc/cups_ipp_bsc",              {"RPORT": "631"}),
    "CVE-2024-47175": ("auxiliary/scanner/misc/cups_ipp_bsc",              {"RPORT": "631"}),
    "CVE-2024-47176": ("auxiliary/scanner/misc/cups_ipp_bsc",              {"RPORT": "631"}),
    "CVE-2024-47177": ("auxiliary/scanner/misc/cups_ipp_bsc",              {"RPORT": "631"}),
    # Drupal
    "CVE-2018-7600":  ("exploit/unix/webapp/drupal_drupalgeddon2",         {"RPORT": "80",  "TARGETURI": "/"}),
    # Spring4Shell
    "CVE-2022-22965": ("exploit/multi/http/spring_framework_rce_spring4shell", {"RPORT": "8080"}),
    # Citrix
    "CVE-2019-19781": ("exploit/multi/http/citrix_dir_traversal_rce",      {"RPORT": "443", "SSL": "true"}),
}


async def _msf_search_module(cve_id: str, msf_path: str) -> str | None:
    """Search msfconsole for a module matching the given CVE. Returns first result or None."""
    cmd    = [msf_path, "-q", "-x", f"search cve:{cve_id}; exit"]
    output = await run_command_async(cmd, timeout=60)
    for line in output.splitlines():
        m = re.match(r'\s*\d+\s+((?:exploit|auxiliary|post)/\S+)', line)
        if m:
            return m.group(1)
    return None


async def _msf_run_check(module: str, options: dict, target: str, msf_path: str) -> dict:
    """
    Run MSF 'check' for a single module against the target.
    Uses non-destructive check command ONLY — no exploit/run ever called.
    """
    set_cmds = "; ".join(f"set {k} {v}" for k, v in options.items())
    x_cmd    = f"use {module}; set RHOSTS {target}; {set_cmds}; set ConnectTimeout 10; check; exit"
    output   = await run_command_async([msf_path, "-q", "-x", x_cmd], timeout=90)

    vulnerable  = None
    result_text = "No result returned from check"
    lower       = output.lower()

    if "the target appears to be vulnerable" in lower:
        vulnerable = True
        for ln in output.splitlines():
            if "appears to be vulnerable" in ln.lower():
                result_text = ln.strip()
                break
    elif "the target is not exploitable" in lower or "not vulnerable" in lower:
        vulnerable = False
        for ln in output.splitlines():
            if "not exploitable" in ln.lower() or "not vulnerable" in ln.lower():
                result_text = ln.strip()
                break
    elif "does not support check" in lower:
        result_text = "Module does not support safe check — manual verification required"
    elif "check failed" in lower:
        result_text = "Check failed — target may be unreachable or the service is not running"
    elif "failed to load" in lower or "no module loaded" in lower:
        result_text = "Module failed to load in MSF"

    return {
        "module":      module,
        "vulnerable":  vulnerable,
        "result":      result_text,
        "method":      "Metasploit check (non-destructive — no payload executed)",
        "raw_output":  output[:600],
    }


async def run_msf_validation(report: dict, target: str, session_dir: str,
                              available_tools: dict) -> dict:
    """
    Enrich each cve_match in the report with an MSF check result.
    Mutates and returns the report dict.
    Only runs 'check' — never 'exploit' or 'run'.
    """
    msf_path = available_tools.get("msfconsole")
    if not msf_path:
        print("[!] msfconsole not found in PATH — skipping MSF validation")
        return report

    cve_matches = report.get("cve_matches", [])
    if not cve_matches:
        print("[MSF] No CVE matches to validate.")
        return report

    if SAFE_MODE:
        print(f"\n[!] MSF VALIDATION — APPROVAL REQUIRED")
        print(f"    {len(cve_matches)} CVE(s) will be probed using 'check' (non-destructive).")
        print(f"    No exploit payloads will be executed. Target: {target}")
        try:
            answer = input("    Proceed with MSF validation? [y/n]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"
        if answer not in ("y", "yes"):
            print("[!] MSF validation denied by operator.")
            return report

    print(f"\n{'=' * 52}")
    print(f"  MSF EXPLOITATION VALIDATION")
    print(f"  Target : {target}  |  CVEs to check : {len(cve_matches)}")
    print(f"  Method : check only — no payload executed")
    print(f"{'=' * 52}")

    validated = 0
    for cve in cve_matches:
        cve_id   = cve["cve_id"]
        svc_port = re.match(r'(\d+)/', cve.get("service", ""))
        port     = svc_port.group(1) if svc_port else "80"

        module_entry = CVE_MSF_MAP.get(cve_id)
        if module_entry:
            module, default_opts = module_entry
            options = {**default_opts, "RPORT": port}
        else:
            print(f"  [MSF] {cve_id} — not in static map, searching MSF ...")
            module  = await _msf_search_module(cve_id, msf_path)
            options = {"RPORT": port}

        if not module:
            print(f"  [MSF] {cve_id} — no module found, skipping")
            cve["msf_validation"] = {
                "module":     None,
                "vulnerable": None,
                "result":     "No Metasploit module found for this CVE",
                "method":     "none",
                "raw_output": "",
            }
            continue

        print(f"  [MSF] {cve_id} → {module}  (port {port}) ...", end=" ", flush=True)
        result = await _msf_run_check(module, options, target, msf_path)
        cve["msf_validation"] = result
        validated += 1

        verdict = ("VULNERABLE"      if result["vulnerable"] is True  else
                   "NOT EXPLOITABLE" if result["vulnerable"] is False else
                   "UNCONFIRMED")
        print(verdict)

    if validated > 0 and "msfconsole" not in report.get("tools_run", []):
        report["tools_run"].append("msfconsole")

    print(f"[+] MSF validation complete — {validated} check(s) executed\n")
    return report


# ---------------------------------------------------------------------------

_CVE_DB = None


def _load_cve_db():
    global _CVE_DB
    if _CVE_DB is not None:
        return _CVE_DB
    _CVE_DB = []
    if not os.path.exists(CVE_CSV):
        print(f"[!] CVE database not found at {CVE_CSV}")
        return _CVE_DB
    with open(CVE_CSV, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",", 2)
            if len(parts) == 3:
                _CVE_DB.append({
                    "id":         parts[0].strip(),
                    "severity":   parts[1].strip(),
                    "summary":    parts[2].strip().strip('"'),
                    "cvss_score": 0.0,
                })
    print(f"[+] CVE database loaded: {len(_CVE_DB)} entries")
    return _CVE_DB


def search_cves(keywords, max_results=5):
    db = _load_cve_db()
    if not db or not keywords:
        return []
    # Only use keywords of 4+ chars to avoid false matches on short strings like "ipp"
    kw_lower = [k.lower() for k in keywords if k and len(k) >= 4]
    if not kw_lower:
        return []
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}
    # Require each keyword to appear as a whole word (surrounded by non-alphanumerics)
    import re as _re
    def _matches(summary):
        s = summary.lower()
        return all(_re.search(r'(?<![a-z0-9])' + _re.escape(k) + r'(?![a-z0-9])', s)
                   for k in kw_lower)
    matches = [r for r in db if _matches(r["summary"])]
    matches.sort(key=lambda r: sev_order.get(r["severity"].upper(), 5))
    return matches[:max_results]


def cves_for_service(service):
    name    = service.get("name", "")
    product = service.get("product", "")
    version = service.get("version", "")
    results = []
    seen    = set()

    def _add(kws):
        for cve in search_cves(kws):
            if cve["id"] not in seen:
                seen.add(cve["id"])
                results.append(cve)

    if product and version:
        _add([product, version])
    if product:
        _add([product])
    if name and name not in ("unknown", ""):
        # Map well-known service names to their real product names for better CVE matches
        SERVICE_PRODUCT_MAP = {
            "ipp": ["cups"],
            "http": ["apache", "nginx"],
            "ms-wbt-server": ["rdp"],
            "microsoft-ds": ["smb"],
        }
        mapped = SERVICE_PRODUCT_MAP.get(name.lower(), [name])
        for kw in mapped:
            _add([kw])
    return results[:5]


# ---------------------------------------------------------------------------
# NMAP
# ---------------------------------------------------------------------------

def run_nmap(target):
    """Fast open-port discovery — no -sV/-sC to avoid hanging on non-standard
    services (e.g. CUPS/IPP).  Phase-1 already carries nmap's built-in service
    names which is sufficient for CVE lookup and tool dispatch."""
    print(f"[+] Running nmap on {target}")
    try:
        result = subprocess.run(
            ["nmap", "-Pn", "-T5", "--open", "-oX", "-", target],
            capture_output=True, text=True, timeout=60,
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        print("[!] nmap timed out")
        return ""
    except Exception as e:
        return str(e)


def parse_nmap(xml_data):
    services = []
    try:
        root = ET.fromstring(xml_data)
        for port in root.findall(".//port"):
            state_el = port.find("state")
            if state_el is not None and state_el.attrib.get("state") != "open":
                continue
            service_el = port.find("service")
            if service_el is not None:
                services.append({
                    "port":      port.attrib.get("portid"),
                    "protocol":  port.attrib.get("protocol", "tcp"),
                    "name":      service_el.attrib.get("name", ""),
                    "product":   service_el.attrib.get("product", ""),
                    "version":   service_el.attrib.get("version", ""),
                    "extrainfo": service_el.attrib.get("extrainfo", ""),
                })
    except ET.ParseError as e:
        print(f"[!] Failed to parse nmap XML: {e}")
    return services


# ---------------------------------------------------------------------------
# SERVICE RANKING
# ---------------------------------------------------------------------------

SERVICE_PRIORITY = {
    "http": 10, "https": 10, "http-alt": 9, "ssl/http": 9,
    "mysql": 8, "mssql": 8, "postgresql": 8,
    "smb": 8, "microsoft-ds": 8,
    "ftp": 7, "rdp": 7, "vnc": 7,
    "telnet": 6,
    "smtp": 5, "ssh": 5,
    "dns": 4, "netbios": 4,
}


def _service_priority(service):
    name = service.get("name", "").lower()
    for key, score in SERVICE_PRIORITY.items():
        if key in name:
            return score
    return 1


def _tools_for_service(service_name):
    name = service_name.lower()
    if "http" in name or "ssl" in name or "ipp" in name:
        return ["curl", "nikto", "nuclei", "gobuster", "ffuf"]
    if "ssh" in name:
        return ["ssh_enum"]
    if "rdp" in name or "remote desktop" in name:
        return ["rdp_enum"]
    if "mysql" in name:
        return ["mysql_enum"]
    if "mssql" in name or "ms-sql" in name:
        return ["mssql_enum"]
    if "dns" in name:
        return ["dns_enum"]
    if "ftp" in name or "smtp" in name:
        return ["curl"]
    return []


def rank_and_annotate_services(services):
    annotated = []
    for s in services:
        annotated.append({
            **s,
            "priority":          _service_priority(s),
            "recommended_tools": _tools_for_service(s.get("name", "")),
            "cves":              [],
        })
    return sorted(annotated, key=lambda x: x["priority"], reverse=True)


# ---------------------------------------------------------------------------
# VERIFICATION STAGE
# ---------------------------------------------------------------------------

async def verify_finding(finding):
    """Auto-verify via HTTP check or evidence length heuristic."""
    if finding.matched_url and finding.matched_url.startswith("http"):
        output = await run_curl_async(finding.matched_url)
        if output and not output.startswith("[!]") and len(output) > 20:
            finding.verified            = True
            finding.verification_status = "verified"
            finding.confidence          = min(finding.confidence + 0.1, 1.0)
    elif finding.verification_status == "discovered" and len(finding.evidence) > 80:
        finding.verified            = True
        finding.verification_status = "verified"
    return finding


async def verify_findings_batch(findings):
    if not findings:
        return findings
    print(f"[+] Verifying {len(findings)} finding(s) ...")
    return list(await asyncio.gather(*[verify_finding(f) for f in findings]))


# ---------------------------------------------------------------------------
# LLM
# ---------------------------------------------------------------------------

def query_llm(context, broken_tools=None, available_tools=None, used_actions=None):
    if broken_tools    is None: broken_tools    = set()
    if available_tools is None: available_tools = {}
    if used_actions    is None: used_actions    = set()

    all_tool_descs = {
        "curl":       'curl: "http://target:port"',
        "nikto":      'nikto: "http://target:port"',
        "nuclei":     'nuclei: "http://target:port"',
        "gobuster":   f'gobuster: {{"url": "...", "wordlist": "{WORDLIST}"}}',
        "ffuf":       f'ffuf: {{"url": "...", "wordlist": "{WORDLIST}"}}',
        "ssh_enum":   'ssh_enum: {"host": "...", "port": "22"}',
        "rdp_enum":   'rdp_enum: {"host": "...", "port": "3389"}',
        "dns_enum":   'dns_enum: {"domain": "..."}',
        "mysql_enum": 'mysql_enum: {"host": "...", "port": "3306"}',
        "mssql_enum": 'mssql_enum: {"host": "...", "port": "1433"}',
    }

    available_descs = []
    for name, desc in all_tool_descs.items():
        if name in broken_tools:
            continue
        if name == "ssh_enum"  and "ssh-audit" not in available_tools:
            continue
        if name == "rdp_enum"  and "rdpscan"   not in available_tools:
            continue
        available_descs.append(f"- {desc}")

    tools_block = "\n".join(available_descs)

    ctx_summary = {
        "target":          context["target"],
        "services":        context["services"],
        "history_count":   len(context.get("history", [])),
        "last_3_actions":  context.get("history", [])[-3:],
        "findings_so_far": len(context.get("findings", [])),
        "disabled_tools":  sorted(broken_tools),
        "already_run":     sorted(used_actions),
    }

    prompt = f"""You are a penetration testing assistant.

STRICT RULES:
- Only respond in valid JSON — no prose, no markdown
- Only use the tools listed below
- Prefer tools from each service's "recommended_tools"
- Services sorted by priority (highest = richest attack surface)

AVAILABLE TOOLS:
{tools_block}

Context:
{json.dumps(ctx_summary, indent=2)}

IMPORTANT: Do NOT use any tool listed in context.disabled_tools.
Do NOT repeat any tool+args combination listed in context.already_run — those have already run.
If all useful tools are exhausted, return {{"tool": "none"}}.

Return EXACTLY ONE JSON object:
{{"tool": "<name>", "args": <value>}}

Or if done:
{{"tool": "none"}}"""

    raw = ""
    _t0 = time.monotonic()
    _sp = _Spinner("[ LLM ]  Deciding next action ...").start()
    try:
        for attempt in range(MAX_LLM_RETRIES):
            try:
                response = requests.post(
                    OLLAMA_URL,
                    json={"model": MODEL, "prompt": prompt, "stream": False},
                    timeout=OLLAMA_TIMEOUT,
                )
                payload = response.json()
                if "error" in payload or "response" not in payload:
                    continue
                raw = payload["response"]
                stripped = raw.strip()
                if stripped.startswith("```"):
                    stripped = stripped.split("\n", 1)[-1]
                    stripped = stripped.rsplit("```", 1)[0]
                action = json.loads(stripped.strip())
                if validate_action(action):
                    return action
            except json.JSONDecodeError:
                pass
            except Exception as e:
                print(f"[!] LLM error (attempt {attempt + 1}): {e}")
    finally:
        _sp.stop(f" done ({_fmt_dur(time.monotonic() - _t0)})")  # always clears the line

    print("[!] LLM retries exhausted — stopping.")
    return {"tool": "none"}


# ---------------------------------------------------------------------------
# ACTION VALIDATION
# ---------------------------------------------------------------------------

KNOWN_TOOLS = {
    "curl", "nikto", "nuclei", "gobuster", "ffuf",
    "ssh_enum", "rdp_enum", "dns_enum", "mysql_enum", "mssql_enum",
}

BROKEN_TOOL_SIGNALS = [
    "No such file or directory",
    "Required module not found",
    "command not found",
    "cannot find",
    "flag provided but not defined",    # nuclei unknown flag
    # NOTE: "not found" removed — too broad (matches HTTP 404 response text)
    # NOTE: "context deadline exceeded" removed — gobuster timeout, not broken
]


def is_tool_broken(result):
    return any(sig.lower() in result.lower() for sig in BROKEN_TOOL_SIGNALS)


def validate_action(action):
    if not isinstance(action, dict):
        return False
    tool = action.get("tool")
    if not isinstance(tool, str):
        return False
    if tool == "none":
        return True
    if tool not in KNOWN_TOOLS:
        return False

    args = action.get("args")

    if tool in ("curl", "nikto", "nuclei"):
        if isinstance(args, dict):
            url = args.get("url") or args.get("host") or args.get("target") or ""
        elif isinstance(args, str):
            # Extract the actual http(s):// URL from anywhere in the string
            # (LLM often prepends flags like -u or -target before the URL)
            m = re.search(r'https?://[^\s"\']+', args)
            url = m.group(0) if m else args.split()[0] if args.strip() else ""
        else:
            return False
        # Normalise: ensure http scheme, strip trailing junk after domain+path
        if url and not url.startswith("http"):
            url = f"http://{url}"
        url = re.sub(r'\s.*$', '', url)  # drop anything after whitespace
        if url.startswith("http"):
            action["args"] = url
            return True
        return False

    if tool in ("gobuster", "ffuf"):
        if not (isinstance(args, dict) and "url" in args and isinstance(args["url"], str)):
            return False
        action["args"]["wordlist"] = WORDLIST
        return True

    if tool in ("ssh_enum", "rdp_enum"):
        return isinstance(args, dict) and "host" in args

    if tool == "dns_enum":
        return isinstance(args, dict) and "domain" in args

    if tool in ("mysql_enum", "mssql_enum"):
        return isinstance(args, dict) and "host" in args

    return False


# ---------------------------------------------------------------------------
# ASYNC EXECUTION DISPATCHER
# ---------------------------------------------------------------------------

def _describe_cmd(tool, args, available_tools):
    """Return the actual command line that execute_async will run for this action."""
    if tool == "nmap":
        return f"nmap -Pn -T5 --open -oX - {args}"
    if tool == "curl":
        return f"curl -s -L -m 15 {args}"
    if tool == "nikto":
        return f"perl {NIKTO_PL} -h {args} -Format txt -nointeractive -maxtime 90s"
    if tool == "nuclei":
        nuclei_path = available_tools.get("nuclei", "nuclei")
        return f"{nuclei_path} -u {args} -s low,medium,high,critical -silent -j -ot"
    if tool == "gobuster":
        url = args.get("url", "") if isinstance(args, dict) else str(args)
        wl  = args.get("wordlist", WORDLIST) if isinstance(args, dict) else WORDLIST
        return f"gobuster dir -u {url} -w {wl} -q -t 20 --timeout 10s"
    if tool == "ffuf":
        url = args.get("url", "") if isinstance(args, dict) else str(args)
        wl  = args.get("wordlist", WORDLIST) if isinstance(args, dict) else WORDLIST
        return f"ffuf -u {url}/FUZZ -w {wl} -mc 200 -t 20 -maxtime 30"
    if tool == "ssh_enum":
        host = args.get("host", "") if isinstance(args, dict) else str(args)
        port = args.get("port", "22") if isinstance(args, dict) else "22"
        return f"ssh-audit -p {port} {host}  +  nmap -p {port} --script ssh-auth-methods,ssh2-enum-algos -Pn {host}"
    if tool == "rdp_enum":
        host = args.get("host", "") if isinstance(args, dict) else str(args)
        port = args.get("port", "3389") if isinstance(args, dict) else "3389"
        return f"nmap -p {port} --script rdp-enum-encryption -Pn --open {host}"
    if tool == "dns_enum":
        domain = args.get("domain", "") if isinstance(args, dict) else str(args)
        return f"dig axfr {domain}  +  dig A/MX/TXT/NS/CNAME {domain} +short"
    if tool == "mysql_enum":
        host = args.get("host", "") if isinstance(args, dict) else str(args)
        port = args.get("port", "3306") if isinstance(args, dict) else "3306"
        return f"nmap -p {port} --script mysql-info,mysql-empty-password,mysql-enum -Pn --open {host}"
    if tool == "mssql_enum":
        host = args.get("host", "") if isinstance(args, dict) else str(args)
        port = args.get("port", "1433") if isinstance(args, dict) else "1433"
        return f"nmap -p {port} --script ms-sql-info,ms-sql-config,ms-sql-empty-password -Pn --open {host}"
    return f"{tool} {args}"


async def execute_async(action, available_tools, session_dir=None):
    """Dispatch an action. Returns (raw_output, findings_list)."""
    tool = action["tool"]
    args = action.get("args", "")

    if tool == "none":
        return None, []

    if not validate_action(action):
        print("[!] Invalid action blocked")
        return None, []

    if tool in AGGRESSIVE_TOOLS:
        if not request_approval(tool, args, "Directory brute-force / aggressive scan"):
            print(f"[!] {tool} denied by operator.")
            return f"[DENIED] {tool} not approved.", []

    print(f"[+] Executing: {tool}  |  args: {args}")

    if tool == "curl":
        output = await run_curl_async(args)
        return output, []

    if tool == "nikto":
        output   = await run_nikto_async(args, session_dir=session_dir)
        findings = parse_nikto_output(output, args) if not is_tool_broken(output) else []
        return output, findings

    if tool == "nuclei":
        return await run_nuclei_json_async(args, available_tools)

    if tool == "gobuster":
        output = await run_command_async(
            ["gobuster", "dir", "-u", args["url"], "-w", args["wordlist"],
             "-q", "-t", "20", "--timeout", "10s"],
            timeout=60,
        )
        findings = parse_gobuster_output(output, args["url"])
        return output, findings

    if tool == "ffuf":
        output = await run_command_async(
            ["ffuf", "-u", f"{args['url']}/FUZZ", "-w", args["wordlist"],
             "-mc", "200", "-t", "20", "-maxtime", "30"],
            timeout=40,
        )
        return output, []

    if tool == "ssh_enum":
        return await run_ssh_enum(args.get("host", ""), args.get("port", "22"), available_tools)

    if tool == "rdp_enum":
        return await run_rdp_enum(args.get("host", ""), args.get("port", "3389"), available_tools)

    if tool == "dns_enum":
        return await run_dns_enum(args.get("domain", ""), available_tools)

    if tool == "mysql_enum":
        return await run_mysql_enum(args.get("host", ""), args.get("port", "3306"), available_tools)

    if tool == "mssql_enum":
        return await run_mssql_enum(args.get("host", ""), args.get("port", "1433"), available_tools)

    return "[!] Unknown tool", []


# ---------------------------------------------------------------------------
# SESSION MANAGEMENT
# ---------------------------------------------------------------------------

def save_session(state):
    with open(SESSION_FILE, "w") as fh:
        json.dump(state, fh, indent=2, default=str)
    print(f"[+] Session saved → {SESSION_FILE}")


def load_session():
    if not os.path.exists(SESSION_FILE):
        return None
    try:
        with open(SESSION_FILE) as fh:
            return json.load(fh)
    except Exception:
        return None


def find_latest_session_dir(target):
    """Return (session_dir, state) for the most-recent session matching target."""
    sessions_root = os.path.join(BASE_DIR, "sessions")
    if not os.path.isdir(sessions_root):
        return None, None
    best_mtime, best_dir, best_state = 0, None, None
    for entry in os.scandir(sessions_root):
        if not entry.is_dir():
            continue
        sf = os.path.join(entry.path, "session.json")
        if not os.path.exists(sf):
            continue
        try:
            with open(sf) as fh:
                state = json.load(fh)
        except Exception:
            continue
        if state.get("target") != target:
            continue
        mtime = os.path.getmtime(sf)
        if mtime > best_mtime:
            best_mtime, best_dir, best_state = mtime, entry.path, state
    return best_dir, best_state


# ---------------------------------------------------------------------------
# HTML / PDF REPORTING
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Noctis Edge Report — {{ target }}</title>
<style>
  body{font-family:'Segoe UI',Arial,sans-serif;background:#1a1a2e;color:#e0e0e0;margin:0;padding:24px}
  h1{color:#00d4ff;border-bottom:2px solid #00d4ff;padding-bottom:10px}
  h2{color:#00d4ff;margin-top:30px}
  .grid{display:grid;grid-template-columns:repeat(4,1fr);gap:15px;margin:20px 0}
  .box{background:#16213e;border-radius:8px;padding:15px;text-align:center;border:1px solid #0f3460}
  .num{font-size:2.4em;font-weight:bold}
  .critical{color:#ff4757}.high{color:#ff6b35}.medium{color:#ffa502}.low{color:#2ed573}.info{color:#70a1ff}
  table{width:100%;border-collapse:collapse;margin:15px 0}
  th{background:#0f3460;color:#00d4ff;padding:10px;text-align:left}
  td{padding:8px 10px;border-bottom:1px solid #0f3460;vertical-align:top}
  tr:hover{background:#16213e}
  .badge{padding:2px 8px;border-radius:12px;font-size:.8em;font-weight:bold}
  .badge-critical{background:#ff4757;color:#fff}
  .badge-high{background:#ff6b35;color:#fff}
  .badge-medium{background:#ffa502;color:#000}
  .badge-low{background:#2ed573;color:#000}
  .badge-info{background:#70a1ff;color:#000}
  .ev{font-family:monospace;font-size:.82em;background:#0d1117;padding:8px;border-radius:4px;
      max-height:90px;overflow-y:auto;white-space:pre-wrap;word-break:break-all}
  .tag{background:#0f3460;color:#00d4ff;padding:1px 6px;border-radius:8px;font-size:.75em;
       margin:1px;display:inline-block}
  .ok{color:#2ed573}.pend{color:#ffa502}
  .conclusion{background:#16213e;border-left:4px solid #00d4ff;padding:15px 20px;
              border-radius:0 8px 8px 0;margin:20px 0}
  footer{margin-top:40px;color:#555;font-size:.85em;text-align:center}
  .header{display:flex;align-items:center;gap:18px;border-bottom:2px solid #00d4ff;padding-bottom:10px;margin-bottom:6px}
  .header img{height:64px;width:64px;object-fit:contain;flex-shrink:0}
  .header h1{color:#00d4ff;margin:0;border:none;padding:0}
</style>
</head>
<body>
<div class="header">
{% if logo_b64 %}<img src="data:image/png;base64,{{ logo_b64 }}" alt="Noctis Edge logo">{% endif %}
<h1>Noctis Edge Penetration Test Report</h1>
</div>
<p><strong>Target:</strong> {{ target }}{% if target_info and target_info.ip_address and target_info.ip_address != target %} ({{ target_info.ip_address }}){% endif %} &nbsp;|&nbsp;
   <strong>Generated:</strong> {{ generated_at }} &nbsp;|&nbsp;
   <strong>Profile:</strong> {{ profile }}</p>

{% if target_info %}
<h2>Target Summary</h2>
<table>
  <tr><th>Field</th><th>Value</th></tr>
  <tr><td>Input Target</td><td>{{ target_info.input_target }}</td></tr>
  <tr><td>IP Address</td><td>{{ target_info.ip_address or target }}</td></tr>
  {% if target_info.rdns_hostname %}<tr><td>Reverse DNS</td><td>{{ target_info.rdns_hostname }}</td></tr>{% endif %}
  {% if target_info.mac_address %}<tr><td>MAC Address</td><td>{{ target_info.mac_address }}{% if target_info.mac_vendor %} ({{ target_info.mac_vendor }}){% endif %}</td></tr>{% endif %}
  {% if target_info.os_guess %}<tr><td>OS Guess</td><td>{{ target_info.os_guess }} ({{ target_info.os_accuracy }}% accuracy)</td></tr>{% endif %}
  {% if target_info.netbios_name %}<tr><td>NetBIOS Name</td><td>{{ target_info.netbios_name }}</td></tr>{% endif %}
  {% if target_info.asn or target_info.org %}<tr><td>ASN / Org</td><td>{{ target_info.asn }} {{ target_info.org }}</td></tr>{% endif %}
  <tr><td>Open Ports</td><td>{{ target_info.open_ports }}</td></tr>
  <tr><td>Scan Time</td><td>{{ target_info.scan_time }}</td></tr>
</table>
{% endif %}

<h2>Executive Summary</h2>
<div class="grid">
  <div class="box"><div class="num critical">{{ counts.critical }}</div><div>Critical</div></div>
  <div class="box"><div class="num high">{{ counts.high }}</div><div>High</div></div>
  <div class="box"><div class="num medium">{{ counts.medium }}</div><div>Medium</div></div>
  <div class="box"><div class="num low">{{ counts.low + counts.info }}</div><div>Low / Info</div></div>
</div>

<h2>Services Discovered</h2>
<table>
  <tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product / Version</th><th>Priority</th><th>CVEs</th></tr>
  {% for s in services %}
  <tr>
    <td>{{ s.port }}</td><td>{{ s.protocol }}</td><td>{{ s.name }}</td>
    <td>{{ s.product }} {{ s.version }}</td><td>{{ s.priority }}</td>
    <td>{% for c in s.cves %}<span class="badge badge-{{ c.severity|lower }}">{{ c.id }}</span> {% endfor %}</td>
  </tr>
  {% endfor %}
</table>

<h2>Findings ({{ findings|length }})</h2>
{% if findings %}
<table>
  <tr><th>Severity</th><th>Title</th><th>Tool</th><th>Service</th><th>Confidence</th><th>Risk</th><th>Status</th><th>Tags</th><th>Evidence</th></tr>
  {% for f in findings %}
  <tr>
    <td><span class="badge badge-{{ f.severity }}">{{ f.severity|upper }}</span></td>
    <td>{{ f.title }}</td><td>{{ f.tool }}</td><td>{{ f.service }}</td>
    <td>{{ "%.0f%%"|format(f.confidence * 100) }}</td>
    <td>{{ "%.2f"|format(f.risk_score) }}</td>
    <td class="{{ 'ok' if f.verified else 'pend' }}">{{ f.verification_status }}</td>
    <td>{% for t in f.tags %}<span class="tag">{{ t }}</span>{% endfor %}</td>
    <td><div class="ev">{{ f.evidence[:200] }}</div></td>
  </tr>
  {% endfor %}
</table>
{% else %}<p>No findings detected.</p>{% endif %}

<h2>CVE Matches ({{ cve_matches|length }})</h2>
{% if cve_matches %}
<table>
  <tr>
    <th>CVE ID</th><th>Severity</th><th>Service</th><th>Type</th>
    <th>Remote</th><th>Auth Required</th><th>Version Range</th>
    <th>Safe Validation</th><th>Proof of Impact</th><th>Business Impact</th>
  </tr>
  {% for c in cve_matches %}
  <tr>
    <td>{{ c.cve_id }}</td>
    <td><span class="badge badge-{{ c.severity|lower }}">{{ c.severity }}</span></td>
    <td>{{ c.service }}</td>
    <td>{{ c.vulnerability_type }}</td>
    <td>{{ "Yes" if c.remote else "No" }}</td>
    <td>{{ "Yes" if c.requires_auth else "No" }}</td>
    <td style="font-family:monospace;font-size:.85em">{{ c.version_range }}</td>
    <td>{{ c.safe_validation_method }}</td>
    <td>{{ c.proof_of_impact }}</td>
    <td>{{ c.business_impact }}</td>
  </tr>
  {% endfor %}
</table>
{% else %}<p>No CVE matches found.</p>{% endif %}

<h2>Exploitation Validation</h2>
{% set msf_run = cve_matches | selectattr("msf_validation", "defined") | list %}
{% if msf_run %}
<p style="color:#aaa;font-size:.9em;margin-bottom:14px">
  Each CVE was probed using Metasploit's <code>check</code> command — a non-destructive test that
  confirms exploitability without executing a payload. This demonstrates how a malicious actor
  would verify the vulnerability before launching an attack.
</p>
<table>
  <tr>
    <th>CVE</th><th>Verdict</th><th>Vuln Type</th><th>MSF Module</th>
    <th>Test Method</th><th>Proof of Impact</th><th>Business Impact</th>
  </tr>
  {% for c in msf_run %}
  {% set v = c.msf_validation %}
  <tr>
    <td><strong>{{ c.cve_id }}</strong><br><span style="color:#888;font-size:.8em">{{ c.service }}</span></td>
    <td>
      {% if v.vulnerable is sameas true %}
        <span class="badge badge-critical">VULNERABLE</span>
      {% elif v.vulnerable is sameas false %}
        <span class="badge badge-low">NOT EXPLOITABLE</span>
      {% elif v.module %}
        <span class="badge badge-info">UNCONFIRMED</span>
      {% else %}
        <span class="badge badge-info">NO MODULE</span>
      {% endif %}
      <div style="font-size:.78em;color:#aaa;margin-top:4px">{{ v.result[:120] }}</div>
    </td>
    <td>{{ c.vulnerability_type }}</td>
    <td style="font-family:monospace;font-size:.82em;word-break:break-all">{{ v.module or "—" }}</td>
    <td>{{ v.method }}</td>
    <td>{{ c.proof_of_impact }}</td>
    <td>{{ c.business_impact }}</td>
  </tr>
  {% endfor %}
</table>
{% else %}
<p style="color:#aaa;font-size:.9em">MSF validation was not run. Re-scan with <code>--msf-validate</code> to enable.</p>
{% endif %}

<h2>CVE Test Results</h2>
{% if cve_test_results %}
{% for r in cve_test_results %}
<div style="margin-bottom:1.5em;border:1px solid #333;border-radius:6px;padding:1em">
  <div style="display:flex;align-items:center;gap:1em;margin-bottom:.5em;flex-wrap:wrap">
    <span style="font-size:1.05em;font-weight:600;color:#e0e0e0">{{ r.cve_id }}</span>
    <span style="font-size:.8em;color:#aaa">{{ r.vulnerability_type }}</span>
    <span style="font-size:.8em;color:#aaa">{{ r.service }}</span>
    {% if r.overall_verdict == "CONFIRMED_VULNERABLE" %}
    <span style="background:#b71c1c;color:#fff;padding:2px 10px;border-radius:4px;font-size:.82em;font-weight:700;border:2px solid #ff1744">&#10003; CONFIRMED VULNERABLE</span>
    {% elif r.overall_verdict == "VULNERABLE" %}
    <span style="background:#e65100;color:#fff;padding:2px 8px;border-radius:4px;font-size:.82em;font-weight:700">VULNERABLE (unverified)</span>
    {% elif r.overall_verdict == "NOT_VULNERABLE" %}
    <span style="background:#1b5e20;color:#fff;padding:2px 8px;border-radius:4px;font-size:.82em;font-weight:700">NOT VULNERABLE</span>
    {% else %}
    <span style="background:#4a4a4a;color:#fff;padding:2px 8px;border-radius:4px;font-size:.82em;font-weight:700">INCONCLUSIVE</span>
    {% endif %}
    <span style="font-size:.78em;color:#777">{{ r.attempts_run }} attempts &mdash; V:{{ r.verdict_counts.VULNERABLE }} N:{{ r.verdict_counts.NOT_VULNERABLE }} I:{{ r.verdict_counts.INCONCLUSIVE }} &mdash; KB replayed:{{ r.kb_replayed }}</span>
  </div>

  {% if r.verification_results %}
  <div style="background:#1a2a1a;border-left:3px solid {% if r.verified %}#4caf50{% else %}#ff9800{% endif %};padding:.6em .8em;margin-bottom:.6em;border-radius:0 4px 4px 0;font-size:.85em">
    <strong style="color:{% if r.verified %}#4caf50{% else %}#ff9800{% endif %}">
      {% if r.verified %}&#10003; False-Positive Check: CONFIRMED{% else %}&#9888; False-Positive Check: UNCONFIRMED (possible false positive){% endif %}
    </strong>
    <div style="margin-top:.4em">
    {% for v in r.verification_results %}
      <span style="margin-right:.8em">
        V{{ v.verifier_num }}: <em>{{ v.strategy[:60] }}</em> &rarr;
        {% if v.verdict == "VULNERABLE" %}<span style="color:#ef9a9a">VULNERABLE</span>
        {% elif v.verdict == "NOT_VULNERABLE" %}<span style="color:#a5d6a7">NOT_VULNERABLE</span>
        {% else %}<span style="color:#ffcc80">INCONCLUSIVE</span>{% endif %}
      </span>
    {% endfor %}
    </div>
  </div>
  {% endif %}

  {% for a in r.attempts %}
  <details style="margin:.4em 0;font-size:.85em">
    <summary style="cursor:pointer;color:#90caf9">
      [{{ "%02d"|format(a.attempt_num) }}]
      {% if a.get('source') == 'kb_replay' %}<span style="color:#ce93d8;font-size:.8em">[KB]</span>{% endif %}
      {% if a.verdict == "VULNERABLE" %}<span style="color:#ef9a9a">&#9679;</span>
      {% elif a.verdict == "NOT_VULNERABLE" %}<span style="color:#a5d6a7">&#9679;</span>
      {% else %}<span style="color:#ffcc80">&#9679;</span>{% endif %}
      {{ a.verdict }} &mdash; {{ a.strategy[:80] }} ({{ a.language }})
    </summary>
    <pre style="background:#1a1a1a;color:#ccc;padding:.6em;border-radius:4px;overflow-x:auto;white-space:pre-wrap;font-size:.8em">{{ a.output }}</pre>
    <details style="margin-top:.3em">
      <summary style="cursor:pointer;color:#78909c;font-size:.9em">View script</summary>
      <pre style="background:#111;color:#b2dfdb;padding:.6em;border-radius:4px;overflow-x:auto;white-space:pre-wrap;font-size:.78em">{{ a.script }}</pre>
    </details>
  </details>
  {% endfor %}

  {% if r.remediation %}
  <div style="background:#0d2137;border-left:3px solid #29b6f6;padding:.7em .9em;margin-top:.6em;border-radius:0 4px 4px 0;font-size:.87em">
    <strong style="color:#29b6f6">&#128295; Suggested Remediation</strong>
    <div style="color:#cfd8dc;margin-top:.45em;white-space:pre-wrap;line-height:1.55">{{ r.remediation }}</div>
    <div style="color:#546e7a;font-size:.78em;margin-top:.4em;font-style:italic">AI-generated guidance — verify against vendor advisories before applying.</div>
  </div>
  {% endif %}
</div>
{% endfor %}
{% else %}
<p style="color:#aaa;font-size:.9em">CVE testing was not run. Re-scan with <code>--cve-test</code> to enable.</p>
{% endif %}

<h2>Conclusion</h2>
<div class="conclusion">{{ conclusion }}</div>

<h2>Execution Log</h2>
<table>
  <tr><th>#</th><th>Tool</th><th>Command</th><th>Status</th><th>Findings</th><th>Output Preview</th></tr>
  {% for e in execution_log %}
  <tr>
    <td>{{ loop.index }}</td>
    <td>{{ e.tool }}</td>
    <td style="font-family:monospace;font-size:.8em;word-break:break-all">{{ e.cmd }}</td>
    <td class="{{ 'ok' if e.status == 'ok' else 'pend' }}">{{ e.status }}</td>
    <td>{{ e.findings }}</td>
    <td><div class="ev">{{ e.output }}</div></td>
  </tr>
  {% endfor %}
</table>

<h2>Tools Used</h2>
<p>{{ tools_run | join(', ') }}</p>

<footer>Generated by Noctis Edge &bull; {{ generated_at }}</footer>
</body>
</html>"""


def generate_html_report(report_data):
    import base64
    logo_b64 = ""
    logo_path = os.path.join(BASE_DIR, "noctis_logo.png")
    if os.path.isfile(logo_path):
        with open(logo_path, "rb") as fh:
            logo_b64 = base64.b64encode(fh.read()).decode()
    data = dict(report_data, logo_b64=logo_b64)
    return Template(HTML_TEMPLATE).render(**data)


def generate_pdf_report(html_content, pdf_path):
    """Try weasyprint then pdfkit."""
    try:
        import weasyprint
        weasyprint.HTML(string=html_content).write_pdf(pdf_path)
        return True
    except Exception:
        pass
    try:
        import pdfkit
        pdfkit.from_string(html_content, pdf_path)
        return True
    except Exception as e:
        print(f"[!] PDF generation failed: {e}")
        return False


# ---------------------------------------------------------------------------
# STRUCTURED REPORT BUILDER
# ---------------------------------------------------------------------------

def generate_report(target, services, all_findings, scan_records, profile="web", target_info=None):
    print("\n[+] Generating report ...")

    all_findings = deduplicate_findings(all_findings)
    for f in all_findings:
        f.risk_score = calculate_risk_score(f)
    all_findings.sort(key=lambda f: f.risk_score, reverse=True)

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        counts[f.severity.lower()] = counts.get(f.severity.lower(), 0) + 1

    cve_matches = []
    for s in services:
        for c in s.get("cves", []):
            enriched = enrich_cve(c, s)
            enriched["service"] = f"{s['port']}/{s.get('name', '')}"
            cve_matches.append(enriched)

    _TOOL_DISPLAY = {
        "ssh_enum":   "ssh-audit / nmap",
        "rdp_enum":   "nmap (rdp-enum-encryption)",
        "dns_enum":   "dig / dnsenum / dnsrecon",
        "mysql_enum": "nmap (mysql-scripts)",
        "mssql_enum": "nmap (ms-sql-scripts)",
    }
    tools_run = list(dict.fromkeys(
        _TOOL_DISPLAY.get(r["tool"], r["tool"])
        for r in scan_records
        if r.get("tool") and r["tool"] != "none"
    ))

    mini_summary = {
        "target":         target,
        "services":       [f"{s['port']}/{s.get('name','')} {s.get('product','')} {s.get('version','')}".strip() for s in services],
        "tools_run":      tools_run,
        "finding_counts": counts,
        "cves":           [f"{c['cve_id']} ({c['severity']}) on {c['service']}" for c in cve_matches[:5]],
    }

    conclusion = "No conclusion generated."
    _t0 = time.monotonic()
    _sp = _Spinner("[ LLM ]  Writing conclusion ...").start()
    try:
        for attempt in range(MAX_LLM_RETRIES):
            try:
                resp    = requests.post(
                    OLLAMA_URL,
                    json={"model": MODEL, "stream": False,
                          "prompt": f"Write a two-sentence penetration testing conclusion. Be concise. Data: {json.dumps(mini_summary, separators=(',', ':'))}"},
                    timeout=OLLAMA_TIMEOUT,
                )
                payload = resp.json()
                if "response" in payload:
                    conclusion = payload["response"].strip()
                    break
            except Exception as e:
                print(f"[!] Conclusion LLM error: {e}")
                break
    finally:
        _sp.stop(f" done ({_fmt_dur(time.monotonic() - _t0)})")

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    execution_log = [
        {
            "iteration": r.get("iteration", 0),
            "tool":      r.get("tool", ""),
            "cmd":       r.get("cmd", f"{r.get('tool','')} {r.get('args','')}"),
            "status":    r.get("status", "ok"),
            "findings":  r.get("findings_count", 0),
            "output":    (r.get("output", "") or "")[:400],
        }
        for r in scan_records
        if r.get("tool") and r["tool"] != "none"
    ]

    return {
        "target":        target,
        "profile":       profile,
        "generated_at":  generated_at,
        "counts":        counts,
        "services":      services,
        "findings":      [dataclasses.asdict(f) for f in all_findings],
        "cve_matches":   cve_matches,
        "tools_run":     tools_run,
        "execution_log": execution_log,
        "conclusion":    conclusion,
        "cve_test_results": [],
        "msf_validation": [],
        "target_info":   target_info.to_dict() if target_info else {},
    }


# ---------------------------------------------------------------------------
# CVE KNOWLEDGE BASE  (--cve-test)
# ---------------------------------------------------------------------------

def _load_cve_kb() -> dict:
    """Load the persistent CVE knowledge base, returning {} on missing or corrupt file."""
    if not os.path.exists(CVE_KB_PATH):
        return {}
    try:
        with open(CVE_KB_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as e:
        print(f"[!] CVE KB load error ({e}) — starting with empty KB.")
        return {}


def _save_cve_kb(kb: dict):
    """Atomically write the CVE knowledge base to disk."""
    tmp = CVE_KB_PATH + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(kb, fh, indent=2, default=str)
        os.replace(tmp, CVE_KB_PATH)
    except Exception as e:
        print(f"[!] CVE KB save error: {e}")


def _run_script(script: str, language: str, cwd: str, timeout: int = 30) -> dict:
    """Write script to a temp file, execute it, return result dict."""
    import uuid
    ext  = ".py" if language == "python" else ".sh"
    path = os.path.join(cwd, f"_tmp_{uuid.uuid4().hex}{ext}")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(script)
        os.chmod(path, 0o700)
        runner = ["python3", path] if language == "python" else ["bash", path]
        result = subprocess.run(
            runner,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        combined = (result.stdout or "") + (result.stderr or "")
        return {"output": combined, "returncode": result.returncode, "timed_out": False, "error": ""}
    except subprocess.TimeoutExpired:
        return {"output": "", "returncode": -1, "timed_out": True, "error": f"Timed out after {timeout}s"}
    except Exception as e:
        return {"output": "", "returncode": -1, "timed_out": False, "error": str(e)}
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def _generate_cve_test_script(cve: dict, target: str, previous_attempts: list,
                               kb_entry: dict | None, iteration: int) -> dict | None:
    """
    Ask the LLM to generate a single safe test script for the given CVE.
    Returns {language, strategy, script} or None on failure.
    """
    prior_strategies = [
        f"  - Attempt {a['attempt_num']}: {a['strategy']} → {a['verdict']}"
        for a in previous_attempts
    ]
    prior_block = "\n".join(prior_strategies) if prior_strategies else "  (none yet)"

    kb_block = ""
    if kb_entry and kb_entry.get("scripts"):
        # Give the LLM up to 3 previously successful/inconclusive scripts from the KB
        useful = [s for s in kb_entry["scripts"] if s.get("verdict") in ("VULNERABLE", "INCONCLUSIVE")]
        if useful:
            kb_items = []
            for s in useful[:3]:
                kb_items.append(
                    f"  Strategy: {s['strategy']}\n"
                    f"  Language: {s['language']}\n"
                    f"  Verdict:  {s['verdict']}\n"
                    f"  Context:  {s.get('target_context', 'unknown')}\n"
                    f"  Script:\n{s['script'][:800]}"
                )
            kb_block = (
                "\n\nKNOWLEDGE BASE — prior scripts from previous engagements "
                "(adapt or build on these):\n" + "\n---\n".join(kb_items)
            )

    prompt = f"""You are a penetration testing assistant generating a SAFE, READ-ONLY vulnerability test script.

CVE DETAILS:
  ID:               {cve.get('cve_id', '')}
  Summary:          {cve.get('summary', '')[:300]}
  Vulnerability:    {cve.get('vulnerability_type', '')}
  Affected product: {cve.get('product', '')} {cve.get('version_range', '')}
  Safe test method: {cve.get('safe_validation_method', '')}
  Proof of impact:  {cve.get('proof_of_impact', '')}

TARGET:
  Host:    {target}
  Service: {cve.get('service', '')}

STRATEGIES ALREADY TRIED THIS SESSION (choose a DIFFERENT approach):
{prior_block}{kb_block}

SAFE PROBING RULES — YOU MUST FOLLOW THESE:
  ALLOWED:  HTTP GET/HEAD requests, TCP banner grabs (socket connect + recv), DNS lookups,
            version string comparison, reading public endpoints, timing checks
  FORBIDDEN: Any payload that writes/deletes files on the target, reverse shells, credential
             brute-force, denial-of-service, buffer overflows, actual exploit code

SCRIPT REQUIREMENTS:
  - The script MUST print exactly one line containing one of:
      VERDICT: VULNERABLE
      VERDICT: NOT_VULNERABLE
      VERDICT: INCONCLUSIVE
  - The script must be self-contained (import only stdlib + requests if needed)
  - Timeout any network calls (max 10 seconds per call)
  - Do not hard-code credentials

Respond with ONLY a single JSON object (no markdown, no prose):
{{"language": "python", "strategy": "<one sentence>", "script": "<full script>"}}

or

{{"language": "bash", "strategy": "<one sentence>", "script": "<full script>"}}"""

    _t0 = time.monotonic()
    _sp = _Spinner(f"[ LLM ]  Generating test script for {cve.get('cve_id', 'CVE')} ...").start()
    try:
        for attempt in range(MAX_LLM_RETRIES):
            try:
                resp = requests.post(
                    OLLAMA_URL,
                    json={"model": MODEL, "prompt": prompt, "stream": False},
                    timeout=180,
                )
                payload = resp.json()
                raw = payload.get("response", "")
                stripped = raw.strip()
                if stripped.startswith("```"):
                    stripped = re.sub(r"^```[a-z]*\n?", "", stripped)
                    stripped = re.sub(r"\n?```$", "", stripped.strip())
                obj = json.loads(stripped)
                if (
                    isinstance(obj, dict)
                    and obj.get("language") in ("python", "bash")
                    and isinstance(obj.get("strategy"), str)
                    and isinstance(obj.get("script"), str)
                    and len(obj["script"]) > 20
                ):
                    return obj
            except requests.exceptions.Timeout:
                break  # no point retrying a timeout — LLM is too slow right now
            except Exception:
                pass
    finally:
        _sp.stop(f" done ({_fmt_dur(time.monotonic() - _t0)})")
    return None


def _generate_verification_script(cve: dict, target: str, triggering_attempt: dict) -> dict | None:
    """
    Generate a verification script that uses a DIFFERENT technique from the triggering attempt
    to confirm or deny a VULNERABLE result and reduce false positives.
    Returns {language, strategy, script} or None on failure.
    """
    prompt = f"""You are a penetration testing assistant performing FALSE-POSITIVE VERIFICATION.

A previous test script returned VULNERABLE for the following CVE. Your job is to INDEPENDENTLY
CONFIRM or DENY this result using a completely different technique.

CVE DETAILS:
  ID:               {cve.get('cve_id', '')}
  Summary:          {cve.get('summary', '')[:300]}
  Vulnerability:    {cve.get('vulnerability_type', '')}
  Affected product: {cve.get('product', '')} {cve.get('version_range', '')}
  Safe test method: {cve.get('safe_validation_method', '')}

TARGET:
  Host:    {target}
  Service: {cve.get('service', '')}

TRIGGERING RESULT (DO NOT REPEAT THIS TECHNIQUE):
  Strategy: {triggering_attempt.get('strategy', '')}
  Language: {triggering_attempt.get('language', '')}
  Output:   {triggering_attempt.get('output', '')[:300]}

VERIFICATION REQUIREMENTS — CRITICAL:
  - You MUST use a DIFFERENT method, endpoint, or protocol layer than the triggering attempt
  - If the triggering attempt used HTTP headers → use a different request type or port
  - If the triggering attempt checked a version string → probe the actual vulnerable behaviour
  - If the triggering attempt used a timing side-channel → use a content-based check instead
  - Think: "what second independent piece of evidence would confirm this is truly vulnerable?"

SAFE PROBING RULES:
  ALLOWED:  HTTP GET/HEAD requests, TCP banner grabs, DNS lookups, version string comparison,
            reading public endpoints, timing/behaviour probes, canary/oracle requests
  FORBIDDEN: Any payload that writes/deletes files on the target, reverse shells, credential
             brute-force, denial-of-service, buffer overflows, actual exploit code

SCRIPT REQUIREMENTS:
  - The script MUST print exactly one line containing one of:
      VERDICT: VULNERABLE
      VERDICT: NOT_VULNERABLE
      VERDICT: INCONCLUSIVE
  - Self-contained, stdlib + requests only, network calls max 10s timeout

Respond with ONLY a single JSON object:
{{"language": "python", "strategy": "<one sentence describing the DIFFERENT technique>", "script": "<full script>"}}
or
{{"language": "bash", "strategy": "<one sentence describing the DIFFERENT technique>", "script": "<full script>"}}"""

    _t0 = time.monotonic()
    _sp = _Spinner("[ LLM ]  Generating verification script ...").start()
    try:
        for attempt in range(MAX_LLM_RETRIES):
            try:
                resp = requests.post(
                    OLLAMA_URL,
                    json={"model": MODEL, "prompt": prompt, "stream": False},
                    timeout=180,
                )
                payload = resp.json()
                raw = payload.get("response", "")
                stripped = raw.strip()
                if stripped.startswith("```"):
                    stripped = re.sub(r"^```[a-z]*\n?", "", stripped)
                    stripped = re.sub(r"\n?```$", "", stripped.strip())
                obj = json.loads(stripped)
                if (
                    isinstance(obj, dict)
                    and obj.get("language") in ("python", "bash")
                    and isinstance(obj.get("strategy"), str)
                    and isinstance(obj.get("script"), str)
                    and len(obj["script"]) > 20
                ):
                    return obj
            except requests.exceptions.Timeout:
                break
            except Exception:
                pass
    finally:
        _sp.stop(f" done ({_fmt_dur(time.monotonic() - _t0)})")
    return None


class _Spinner:
    """Inline terminal spinner for long blocking steps (no extra deps)."""
    _FRAMES = ("|", "/", "-", "\\")

    def __init__(self, prefix: str):
        self._prefix = prefix
        self._stop   = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        i = 0
        while not self._stop.wait(0.25):
            sys.stdout.write(f"\r  {self._prefix} {self._FRAMES[i % 4]}")
            sys.stdout.flush()
            i += 1

    def start(self):
        self._thread.start()
        return self

    def stop(self, suffix: str = ""):
        self._stop.set()
        self._thread.join()
        sys.stdout.write(f"\r  {self._prefix}{suffix}\n")
        sys.stdout.flush()


def _check_internet(host: str = "8.8.8.8", port: int = 53, timeout: float = 3.0) -> bool:
    """Return True if we can reach the internet (DNS port on Google's resolver)."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _fmt_dur(secs: float) -> str:
    """Format a duration in seconds as 'Xm Ys' or 'Xs'."""
    secs = max(0, int(secs))
    m, s = divmod(secs, 60)
    return f"{m}m {s:02d}s" if m else f"{s}s"


def _print_timing(start: float, done: int, total: int) -> None:
    elapsed = time.monotonic() - start
    avg     = elapsed / done if done else 0
    remain  = avg * (total - done)
    eta_str = f"~{_fmt_dur(remain)}" if done < total else "done"
    print(f"  Elapsed: {_fmt_dur(elapsed)}  |  ETA: {eta_str}  ({done}/{total} attempts)")


async def run_cve_tests(cve_matches: list, target: str,
                        session_dir: str, kb: dict) -> tuple[list, dict]:
    """
    For each CVE:
      1. Replay any scripts already in the knowledge base (different techniques proven in prior runs).
      2. Generate up to CVE_TEST_ATTEMPTS new LLM scripts to fill remaining slots.
      3. On the first VULNERABLE result, run CVE_VERIFY_ATTEMPTS independent verifier scripts
         using a different technique to confirm and avoid false positives.
    Returns (cve_test_results, updated_kb).
    """
    cve_tests_dir = os.path.join(session_dir, "cve_tests")
    os.makedirs(cve_tests_dir, exist_ok=True)

    cve_test_results = []
    total_cves    = len(cve_matches)
    scan_start    = time.monotonic()

    for cve_idx, cve in enumerate(cve_matches, 1):
        cve_start = time.monotonic()
        cve_id    = cve.get("cve_id", "UNKNOWN")
        kb_entry  = kb.get(cve_id)
        kb_scripts = kb_entry["scripts"] if kb_entry else []
        kb_count   = len(kb_scripts)
        kb_label   = f"{kb_count} prior script(s) in KB" if kb_count else "new to KB"

        print(f"\n{'=' * 52}")
        print(f"  CVE TEST: {cve_id}  [{cve_idx}/{total_cves}]")
        print(f"  Type    : {cve.get('vulnerability_type', '?')}")
        print(f"  KB      : {kb_label}")
        print(f"{'=' * 52}")

        attempts: list       = []
        verdict_counts       = {"VULNERABLE": 0, "NOT_VULNERABLE": 0, "INCONCLUSIVE": 0}
        vulnerable_found     = False
        verification_results: list = []
        verified             = False  # True if ≥1 verifier independently confirms VULNERABLE

        # ------------------------------------------------------------------
        # Phase 1: Replay KB scripts (proven techniques from prior runs)
        # ------------------------------------------------------------------
        if kb_scripts:
            print(f"  [KB] Replaying {kb_count} known script(s) ...")
        for kb_idx, kb_script in enumerate(kb_scripts, 1):
            language   = kb_script.get("language", "python")
            strategy   = kb_script.get("strategy", "KB replay")
            script     = kb_script.get("script", "")
            if not script:
                continue
            ext        = ".py" if language == "python" else ".sh"
            safe_cve   = re.sub(r"[^a-zA-Z0-9_-]", "_", cve_id)
            script_path = os.path.join(cve_tests_dir, f"{safe_cve}_kb_{kb_idx:02d}{ext}")
            with open(script_path, "w", encoding="utf-8") as fh:
                fh.write(script)

            attempt_num = len(attempts) + 1
            sp = _Spinner(f"[KB {kb_idx:02d}/{kb_count:02d}] Replaying ({language}) ...").start()
            run_result = await asyncio.get_event_loop().run_in_executor(
                None, lambda s=script, l=language: _run_script(s, l, cve_tests_dir, timeout=30)
            )
            output = run_result["output"]
            if run_result["timed_out"]:
                output = f"[TIMED OUT]\n{output}"
            elif run_result["error"]:
                output = f"[ERROR: {run_result['error']}]\n{output}"
            m       = re.search(r"VERDICT:\s*(VULNERABLE|NOT_VULNERABLE|INCONCLUSIVE)", output)
            verdict = m.group(1) if m else "INCONCLUSIVE"
            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
            if verdict == "VULNERABLE":
                vulnerable_found = True
            sp.stop(f" {verdict}")

            attempts.append({
                "attempt_num": attempt_num,
                "source":      "kb_replay",
                "strategy":    f"[KB] {strategy}",
                "language":    language,
                "script":      script,
                "script_path": script_path,
                "output":      output[:600],
                "verdict":     verdict,
            })

        # ------------------------------------------------------------------
        # Phase 2: Generate new LLM scripts to fill remaining slots
        # ------------------------------------------------------------------
        new_slots   = max(0, CVE_TEST_ATTEMPTS - len(attempts))
        done_new    = 0
        for i in range(1, new_slots + 1):
            attempt_num = len(attempts) + 1
            sp = _Spinner(f"[{i:02d}/{new_slots:02d}] Generating script ...").start()
            generated = _generate_cve_test_script(cve, target, attempts, kb_entry, attempt_num)
            if not generated:
                sp.stop(" SKIPPED (LLM parse failure)")
                done_new += 1
                attempts.append({
                    "attempt_num": attempt_num,
                    "source":      "llm_generated",
                    "strategy":    "LLM parse failure",
                    "language":    "", "script": "", "script_path": "",
                    "output":      "", "verdict": "INCONCLUSIVE",
                })
                verdict_counts["INCONCLUSIVE"] += 1
                continue
            sp.stop()

            language = generated["language"]
            strategy = generated["strategy"]
            script   = generated["script"]
            ext      = ".py" if language == "python" else ".sh"
            safe_cve = re.sub(r"[^a-zA-Z0-9_-]", "_", cve_id)
            script_fname = f"{safe_cve}_attempt_{attempt_num:02d}{ext}"
            script_path  = os.path.join(cve_tests_dir, script_fname)
            with open(script_path, "w", encoding="utf-8") as fh:
                fh.write(script)

            print(f"  Strategy: {strategy}")
            print(f"  ---- script ({language}) ----")
            for line in script.splitlines():
                print(f"  {line}")
            print(f"  ---- end script ----")

            sp2 = _Spinner(f"[{i:02d}/{new_slots:02d}] Running ({language}) ...").start()
            run_result = await asyncio.get_event_loop().run_in_executor(
                None, lambda s=script, l=language: _run_script(s, l, cve_tests_dir, timeout=30)
            )
            output = run_result["output"]
            if run_result["timed_out"]:
                output = f"[TIMED OUT]\n{output}"
            elif run_result["error"]:
                output = f"[ERROR: {run_result['error']}]\n{output}"
            m       = re.search(r"VERDICT:\s*(VULNERABLE|NOT_VULNERABLE|INCONCLUSIVE)", output)
            verdict = m.group(1) if m else "INCONCLUSIVE"
            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
            if verdict == "VULNERABLE":
                vulnerable_found = True
            sp2.stop(f" {verdict}")
            done_new += 1

            attempt_record = {
                "attempt_num": attempt_num,
                "source":      "llm_generated",
                "strategy":    strategy,
                "language":    language,
                "script":      script,
                "script_path": script_path,
                "output":      output[:600],
                "verdict":     verdict,
            }
            attempts.append(attempt_record)

            # Update KB
            script_hash = hashlib.sha256(script.encode()).hexdigest()[:16]
            if cve_id not in kb:
                kb[cve_id] = {
                    "first_tested":   datetime.now(timezone.utc).isoformat(),
                    "last_tested":    datetime.now(timezone.utc).isoformat(),
                    "test_count":     0,
                    "best_verdict":   "INCONCLUSIVE",
                    "verdict_counts": {"VULNERABLE": 0, "NOT_VULNERABLE": 0, "INCONCLUSIVE": 0},
                    "scripts":        [],
                }
            entry = kb[cve_id]
            entry["last_tested"] = datetime.now(timezone.utc).isoformat()
            entry["test_count"]  = entry.get("test_count", 0) + 1
            vc = entry.setdefault("verdict_counts", {"VULNERABLE": 0, "NOT_VULNERABLE": 0, "INCONCLUSIVE": 0})
            vc[verdict] = vc.get(verdict, 0) + 1
            existing_hashes = {s["script_hash"] for s in entry["scripts"]}
            if script_hash not in existing_hashes:
                entry["scripts"].append({
                    "script_hash":    script_hash,
                    "strategy":       strategy,
                    "language":       language,
                    "script":         script,
                    "verdict":        verdict,
                    "output_sample":  output[:400],
                    "target_context": f"{cve.get('product', '')} {cve.get('service', '')}".strip(),
                    "tested_at":      datetime.now(timezone.utc).isoformat(),
                })
            _verdict_rank = {"VULNERABLE": 3, "INCONCLUSIVE": 2, "NOT_VULNERABLE": 1}
            if _verdict_rank.get(verdict, 0) > _verdict_rank.get(entry["best_verdict"], 0):
                entry["best_verdict"] = verdict

        # ------------------------------------------------------------------
        # Phase 3: False-positive verification — triggered by ANY VULNERABLE
        # ------------------------------------------------------------------
        if vulnerable_found:
            triggering = next((a for a in attempts if a["verdict"] == "VULNERABLE"), None)
            print(f"\n  [VERIFY] VULNERABLE found — running {CVE_VERIFY_ATTEMPTS} independent verifier(s) ...")
            verify_confirmed = 0
            for v_i in range(1, CVE_VERIFY_ATTEMPTS + 1):
                sp = _Spinner(f"  [V{v_i}/{CVE_VERIFY_ATTEMPTS}] Generating verifier ...").start()
                v_gen = _generate_verification_script(cve, target, triggering)
                if not v_gen:
                    sp.stop(" SKIPPED (LLM parse failure)")
                    verification_results.append({
                        "verifier_num": v_i, "strategy": "LLM parse failure",
                        "language": "", "script": "", "output": "", "verdict": "INCONCLUSIVE",
                    })
                    continue
                sp.stop()

                v_lang   = v_gen["language"]
                v_strat  = v_gen["strategy"]
                v_script = v_gen["script"]
                v_ext    = ".py" if v_lang == "python" else ".sh"
                safe_cve = re.sub(r"[^a-zA-Z0-9_-]", "_", cve_id)
                v_path   = os.path.join(cve_tests_dir, f"{safe_cve}_verify_{v_i:02d}{v_ext}")
                with open(v_path, "w", encoding="utf-8") as fh:
                    fh.write(v_script)

                print(f"  Verifier strategy: {v_strat}")
                sp2 = _Spinner(f"  [V{v_i}/{CVE_VERIFY_ATTEMPTS}] Running verifier ({v_lang}) ...").start()
                v_result = await asyncio.get_event_loop().run_in_executor(
                    None, lambda s=v_script, l=v_lang: _run_script(s, l, cve_tests_dir, timeout=30)
                )
                v_output = v_result["output"]
                if v_result["timed_out"]:
                    v_output = f"[TIMED OUT]\n{v_output}"
                elif v_result["error"]:
                    v_output = f"[ERROR: {v_result['error']}]\n{v_output}"
                vm = re.search(r"VERDICT:\s*(VULNERABLE|NOT_VULNERABLE|INCONCLUSIVE)", v_output)
                v_verdict = vm.group(1) if vm else "INCONCLUSIVE"
                if v_verdict == "VULNERABLE":
                    verify_confirmed += 1
                sp2.stop(f" {v_verdict}")

                verification_results.append({
                    "verifier_num": v_i,
                    "strategy":    v_strat,
                    "language":    v_lang,
                    "script":      v_script,
                    "output":      v_output[:600],
                    "verdict":     v_verdict,
                })

            verified = verify_confirmed >= 1
            if verified:
                print(f"  [VERIFY] CONFIRMED ({verify_confirmed}/{CVE_VERIFY_ATTEMPTS} verifiers agree)")
            else:
                print(f"  [VERIFY] UNCONFIRMED — possible false positive "
                      f"({verify_confirmed}/{CVE_VERIFY_ATTEMPTS} verifiers agree)")

        # ------------------------------------------------------------------
        # Overall verdict
        # ------------------------------------------------------------------
        if vulnerable_found and verified:
            overall = "CONFIRMED_VULNERABLE"
        elif vulnerable_found:
            overall = "VULNERABLE"
        elif verdict_counts["NOT_VULNERABLE"] >= max(1, len(attempts) // 2 + 1):
            overall = "NOT_VULNERABLE"
        else:
            overall = "INCONCLUSIVE"

        cve_elapsed = _fmt_dur(time.monotonic() - cve_start)
        print(f"  Overall : {overall}  "
              f"(V:{verdict_counts['VULNERABLE']} N:{verdict_counts['NOT_VULNERABLE']} "
              f"I:{verdict_counts['INCONCLUSIVE']}, KB:{kb_count} replayed)  "
              f"[CVE time: {cve_elapsed}]")

        cve_test_results.append({
            "cve_id":               cve_id,
            "vulnerability_type":   cve.get("vulnerability_type", ""),
            "service":              cve.get("service", ""),
            "overall_verdict":      overall,
            "verdict_counts":       verdict_counts,
            "attempts_run":         len(attempts),
            "kb_replayed":          kb_count,
            "verified":             verified,
            "verification_results": verification_results,
            "attempts":             attempts,
        })

    return cve_test_results, kb


# ---------------------------------------------------------------------------
# CVE REMEDIATION SUGGESTIONS
# ---------------------------------------------------------------------------

def _generate_remediation(cve: dict) -> str:
    """
    Ask the LLM for a concise remediation path for a single confirmed-vulnerable CVE.
    Returns a plain-text remediation string, or a short fallback on failure.
    """
    prompt = (
        f"You are a security engineer writing a remediation guide for a penetration test report.\n\n"
        f"CVE ID:        {cve.get('cve_id', 'Unknown')}\n"
        f"Description:   {cve.get('summary', '')[:400]}\n"
        f"Affected:      {cve.get('product', '')} {cve.get('version_range', '')}\n"
        f"Service:       {cve.get('service', '')}\n"
        f"Vuln type:     {cve.get('vulnerability_type', '')}\n\n"
        "Write a concise remediation path with three short sections:\n"
        "1. Immediate mitigation (quick workaround to reduce exposure now)\n"
        "2. Permanent fix (patch, config change, or upgrade path)\n"
        "3. Verification (how to confirm the fix was applied)\n\n"
        "Keep each section to 1-3 sentences. Plain text only — no markdown, no bullet symbols."
    )
    _t0 = time.monotonic()
    _sp = _Spinner(f"[ LLM ]  Generating remediation for {cve.get('cve_id', 'CVE')} ...").start()
    try:
        resp = requests.post(
            OLLAMA_URL,
            json={"model": MODEL, "prompt": prompt, "stream": False},
            timeout=OLLAMA_TIMEOUT,
        )
        payload = resp.json()
        text = payload.get("response", "").strip()
        return text if text else "Remediation guidance unavailable."
    except Exception as e:
        return f"Remediation guidance unavailable ({e})."
    finally:
        _sp.stop(f" done ({_fmt_dur(time.monotonic() - _t0)})")


def generate_cve_remediations(cve_test_results: list, cve_matches: list) -> None:
    """
    For each CVE test result that is VULNERABLE or CONFIRMED_VULNERABLE, look up the
    original CVE match record (for full metadata) and call _generate_remediation().
    Attaches a 'remediation' key to the result dict in-place.
    """
    # Build a quick lookup from cve_id → original cve_match record
    cve_meta = {c["cve_id"]: c for c in cve_matches}

    vulnerable_verdicts = {"CONFIRMED_VULNERABLE", "VULNERABLE"}
    targets = [r for r in cve_test_results if r.get("overall_verdict") in vulnerable_verdicts]
    if not targets:
        return

    print(f"\n[REMEDIATION] Generating LLM remediation suggestions for "
          f"{len(targets)} vulnerable CVE(s) ...")
    for result in targets:
        cve_id  = result["cve_id"]
        cve_rec = cve_meta.get(cve_id, {"cve_id": cve_id})
        result["remediation"] = _generate_remediation(cve_rec)
        print(f"  [+] Remediation written for {cve_id}")


async def _run_cve_test_phase(report: dict, target: str, session_dir: str) -> dict:
    """Approval gate + run_cve_tests + KB save + merge into report."""
    cve_matches = report.get("cve_matches", [])
    if not cve_matches:
        print("[CVE-TEST] No CVE matches to test.")
        return report

    if SAFE_MODE:
        print(f"\n{'!' * 52}")
        print(f"  CVE TEST — APPROVAL REQUIRED")
        print(f"  {len(cve_matches)} CVE(s) will be tested with LLM-generated scripts.")
        print(f"  Scripts are read-only probes — no destructive payloads.")
        print(f"  Target: {target}")
        print(f"{'!' * 52}")
        try:
            answer = input("  Proceed with CVE testing? [y/n]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"
        if answer not in ("y", "yes"):
            print("[CVE-TEST] Denied by operator.")
            return report

    kb = _load_cve_kb()
    cve_test_results, updated_kb = await run_cve_tests(cve_matches, target, session_dir, kb)
    _save_cve_kb(updated_kb)
    print(f"[+] CVE knowledge base updated → {CVE_KB_PATH}")

    # Generate LLM remediation suggestions for each confirmed/vulnerable CVE
    generate_cve_remediations(cve_test_results, cve_matches)

    report["cve_test_results"] = cve_test_results
    return report


# ---------------------------------------------------------------------------
# TARGET IDENTITY ENRICHMENT
# ---------------------------------------------------------------------------

async def gather_target_info(target: str, available_tools: dict, airgap: bool = False) -> TargetInfo:
    """Resolve enriched identity information for a target (IP, rDNS, MAC, OS, NetBIOS, ASN/Org)."""
    info = TargetInfo(input_target=target)
    info.scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Step 1: Resolve IP address
    try:
        ip = socket.gethostbyname(target)
        info.ip_address = ip
    except Exception:
        ip = target
        info.ip_address = target

    # Step 2: Reverse DNS (synchronous stdlib call — fast enough)
    try:
        rdns_result = socket.gethostbyaddr(ip)
        info.rdns_hostname = rdns_result[0]
    except Exception:
        pass

    nmap_path = available_tools.get("nmap")

    async def _get_mac_and_vendor(ip_addr):
        """Returns (mac, vendor) or ('', '').

        MAC address is only visible on the local subnet when nmap is run as root.
        """
        _NULL_MAC = "00:00:00:00:00:00"
        if nmap_path:
            try:
                proc = await asyncio.create_subprocess_exec(
                    nmap_path, "-sn", "-PR", ip_addr,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
                text = stdout.decode(errors="replace")
                m = re.search(r"MAC Address:\s+([0-9A-F:]+)\s+\(([^)]*)\)", text, re.IGNORECASE)
                if m:
                    return m.group(1), m.group(2)
            except Exception:
                pass
        # Fallback: /proc/net/arp (Linux only, same subnet)
        try:
            if os.path.exists("/proc/net/arp"):
                with open("/proc/net/arp") as fh:
                    for line in fh:
                        parts = line.split()
                        if len(parts) >= 4 and parts[0] == ip_addr:
                            mac = parts[3]
                            if mac != _NULL_MAC:
                                return mac, ""
        except Exception:
            pass
        return "", ""

    async def _get_os(ip_addr):
        """Returns (os_name, accuracy_int) or ('', 0)."""
        if not nmap_path:
            return "", 0
        try:
            proc = await asyncio.create_subprocess_exec(
                nmap_path, "-Pn", "-O", "--osscan-guess", "--max-os-tries", "1",
                "-oX", "-", ip_addr,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=45)
            text = stdout.decode(errors="replace")
            m = re.search(r'<osmatch name="([^"]+)" accuracy="(\d+)"', text)
            if m:
                return m.group(1), int(m.group(2))
        except Exception:
            pass
        return "", 0

    async def _get_netbios(ip_addr):
        """Returns NetBIOS name string or ''."""
        if not nmap_path:
            return ""
        try:
            proc = await asyncio.create_subprocess_exec(
                nmap_path, "-p", "137", "--script", "nbstat", "-Pn", ip_addr,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
            text = stdout.decode(errors="replace")
            m = re.search(r"NetBIOS name:\s+(\S+)", text, re.IGNORECASE)
            if m:
                return m.group(1).strip("<>").strip()
        except Exception:
            pass
        return ""

    async def _get_asn_org(ip_addr):
        """Returns (asn, org) or ('', ''). Skipped in airgap mode."""
        if airgap:
            return "", ""
        if nmap_path:
            try:
                proc = await asyncio.create_subprocess_exec(
                    nmap_path, "--script", "whois-ip", "-sn", ip_addr,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
                text = stdout.decode(errors="replace")
                asn, org = "", ""
                for line in text.splitlines():
                    if line.startswith("|"):
                        low = line.lower()
                        if not asn and ("asn" in low or "originas" in low):
                            m = re.search(r"AS\d+", line, re.IGNORECASE)
                            if m:
                                asn = m.group(0)
                        if not org and ("orgname" in low or "org-name" in low or "organisation" in low):
                            parts = line.split(":", 1)
                            if len(parts) > 1:
                                org = parts[1].strip()
                if asn or org:
                    return asn, org
            except Exception:
                pass
        # Fallback: whois command
        try:
            proc = await asyncio.create_subprocess_exec(
                "whois", ip_addr,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
            text = stdout.decode(errors="replace")
            asn, org = "", ""
            for line in text.splitlines():
                low = line.lower()
                if not org and (low.startswith("orgname:") or low.startswith("org-name:")):
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        org = parts[1].strip()
                if not asn and low.startswith("originas:"):
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        asn = parts[1].strip()
            return asn, org
        except Exception:
            pass
        return "", ""

    # Run independent enrichment tasks in parallel
    results = await asyncio.gather(
        _get_mac_and_vendor(ip),
        _get_os(ip),
        _get_netbios(ip),
        _get_asn_org(ip),
        return_exceptions=True,
    )

    mac_result, os_result, nb_result, asn_result = results

    if isinstance(mac_result, tuple):
        info.mac_address, info.mac_vendor = mac_result
    if isinstance(os_result, tuple):
        info.os_guess, info.os_accuracy = os_result
    if isinstance(nb_result, str):
        info.netbios_name = nb_result
    if isinstance(asn_result, tuple):
        info.asn, info.org = asn_result

    return info


# ---------------------------------------------------------------------------
# MAIN ASYNC LOOP
# ---------------------------------------------------------------------------

async def main_async():
    global SAFE_MODE, AIRGAP_MODE, MSF_VALIDATE, CVE_TEST, SESSION_FILE

    if len(sys.argv) < 2:
        print("Usage: python3 noctis.py <target> [profile ...] [--resume] [--aggressive] [--dns] [--msf-validate] [--cve-test]")
        print("       python3 noctis.py --report <json_file>")
        print("Profiles (one or more):", ", ".join(PROFILES))
        sys.exit(1)

    target        = sys.argv[1]
    profile_names: list = []
    resume        = False

    for arg in sys.argv[2:]:
        if arg in PROFILES:
            profile_names.append(arg)
        elif arg == "--resume":
            resume = True
        elif arg == "--aggressive":
            SAFE_MODE = False
        elif arg == "--dns":
            AIRGAP_MODE = False
        elif arg == "--msf-validate":
            MSF_VALIDATE = True
        elif arg == "--cve-test":
            CVE_TEST = True

    # Ensure Ollama is running before we attempt any LLM calls
    if not ensure_ollama_running():
        print("[!] Cannot continue without a running Ollama instance. Exiting.")
        sys.exit(1)

    if not profile_names:
        profile_names = ["web"]

    # Merge selected profiles (deduplicated union of tools + escalation)
    _merged_tools:      list = []
    _merged_escalation: list = []
    _seen: set = set()
    for _pname in profile_names:
        for _t in PROFILES[_pname]["tools"]:
            if _t not in _seen:
                _merged_tools.append(_t)
                _seen.add(_t)
        for _t in PROFILES[_pname]["escalation"]:
            if _t not in _seen:
                _merged_escalation.append(_t)
                _seen.add(_t)

    profile_name = "+".join(profile_names)
    profile = {
        "name":       " + ".join(PROFILES[n]["name"] for n in profile_names),
        "tools":      _merged_tools,
        "escalation": _merged_escalation,
    }
    safe_tgt = re.sub(r"[^a-zA-Z0-9_-]", "_", target)

    # Determine session directory
    if resume:
        session_dir, resume_state = find_latest_session_dir(target)
        if session_dir:
            session_id = os.path.basename(session_dir)
        else:
            resume_state = None
            session_id = f"{safe_tgt}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            session_dir = os.path.join(BASE_DIR, "sessions", session_id)
    else:
        resume_state = None
        session_id = f"{safe_tgt}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        session_dir = os.path.join(BASE_DIR, "sessions", session_id)

    os.makedirs(session_dir, exist_ok=True)
    SESSION_FILE = os.path.join(session_dir, "session.json")

    print(f"\n{'=' * 60}")
    print("  Noctis Edge — Security Through Exposure")
    print(f"{'=' * 60}")
    print(f"  Target  : {target}")
    print(f"  Profile : {profile['name']}")
    mode_str = "AGGRESSIVE" if not SAFE_MODE else "SAFE (approval required for aggressive tools)"
    print(f"  Mode    : {mode_str}")
    if not AIRGAP_MODE:
        print(f"  DNS     : ENABLED — {', '.join(sorted(INTERNET_ONLY_TOOLS))} active")
    else:
        print(f"  DNS     : disabled (use --dns to enable DNS enumeration)")
    print(f"  Session : {session_id}")
    print(f"  Dir     : {session_dir}")

    # Tool validation
    available_tools, unavailable_tools = validate_tools()
    if AIRGAP_MODE:
        for t in INTERNET_ONLY_TOOLS:
            available_tools.pop(t, None)
    print_tool_status(available_tools, unavailable_tools)

    # Session resume
    if resume:
        if resume_state:
            print(f"[+] Resuming session for {resume_state.get('target', target)} "
                  f"(iteration {resume_state.get('iteration', '?')})")
        else:
            print("[!] No saved session found — starting fresh.")

    # Nmap
    nmap_xml = run_nmap(target)
    services = parse_nmap(nmap_xml)

    if not services:
        print("[!] No open services found. Exiting.")
        sys.exit(0)

    services = rank_and_annotate_services(services)

    print("[+] Gathering target identity information ...")
    target_info = await gather_target_info(target, available_tools, airgap=AIRGAP_MODE)
    target_info.open_ports = len(services)

    # CVE lookup
    print("[+] Searching CVE database ...")
    for s in services:
        s["cves"] = cves_for_service(s)
        if s["cves"]:
            label = s.get("product") or s.get("name", "?")
            print(f"    {s['port']}/{s['name']} ({label}): {len(s['cves'])} CVE(s)")
            for c in s["cves"]:
                print(f"      [{c['severity']:8}] {c['id']}: {c['summary'][:80]}...")
        else:
            print(f"    {s['port']}/{s['name']}: no CVEs matched")

    svc_summary = ", ".join(
        f"{s['port']}/{s['name']}(p{s['priority']})" for s in services
    )
    print(f"[+] Ranked services: {svc_summary}")

    context = {
        "target":   target,
        "services": services,
        "history":  [],
        "findings": [],
    }

    broken_tools = set()
    scan_records = [{"tool": "nmap", "args": target, "cmd": f"nmap -Pn -T5 --open -oX - {target}", "status": "ok", "findings_count": 0}]
    all_findings = []
    used_actions: set = set()  # deduplicate tool+args combos
    loop_start = time.monotonic()

    # Main LLM-driven loop
    for i in range(MAX_ITERATIONS):
        print(f"\n{'=' * 52}")
        print(f"  Iteration {i + 1} / {MAX_ITERATIONS}  |  Target: {target}  |  Elapsed: {_fmt_dur(time.monotonic() - loop_start)}")
        print(f"{'=' * 52}")
        if broken_tools:
            print(f"  Disabled : {', '.join(sorted(broken_tools))}")
        if all_findings:
            print(f"  Findings : {len(all_findings)} so far")

        sp = _Spinner("Asking LLM ...").start()
        action = query_llm(context, broken_tools, available_tools, used_actions)
        sp.stop()
        tool   = action.get("tool", "none")
        args   = action.get("args", "")

        if tool == "none":
            print("[LLM] No further actions suggested — stopping.")
            break

        # Skip exact duplicate tool+args combos
        action_key = f"{tool}:{str(args)}"
        if action_key in used_actions:
            print(f"[!] '{tool}' with same args already ran — skipping duplicate.")
            context["history"].append({
                "action": action,
                "result": "[skipped: duplicate action]",
            })
            continue
        used_actions.add(action_key)

        print(f"[LLM] Tool : {tool}")
        print(f"      Args : {args}")

        save_session({
            "target":         target,
            "profile":        profile_name,
            "iteration":      i + 1,
            "history_len":    len(context["history"]),
            "findings_count": len(all_findings),
        })

        start_time           = time.time()
        output, findings     = await execute_async(action, available_tools, session_dir=session_dir)
        duration             = time.time() - start_time

        if output is None:
            print("[+] Stopping.")
            break

        timed_out = "Command timed out" in output
        broken = is_tool_broken(output)
        # gobuster/ffuf/nikto may time out on slow targets but still produce results;
        # only disable them if they're actually broken (error signals), not just slow.
        output_only_tools = {"gobuster", "ffuf", "nikto"}
        if broken or (timed_out and not findings and tool not in output_only_tools):
            reason = "timed out with no findings" if (timed_out and not broken) else "appears broken"
            print(f"[!] '{tool}' {reason} — disabling for this session.")
            broken_tools.add(tool)
        else:
            preview = output.strip()[:300].replace("\n", " | ")
            print(f"\n[>] Result: {preview}")
            if findings:
                print(f"[+] {len(findings)} structured finding(s) extracted")

        # Verification stage
        if findings and not broken:
            findings = await verify_findings_batch(findings)
            all_findings.extend(findings)
            for f in findings:
                f.tags = list(set(f.tags + auto_tag(f)))
            context["findings"] = [dataclasses.asdict(f) for f in all_findings[-5:]]

        scan_records.append({
            "iteration":      i + 1,
            "tool":           tool,
            "args":           args,
            "cmd":            _describe_cmd(tool, args, available_tools),
            "status":         "broken" if broken else "ok",
            "output":         output,
            "findings_count": len(findings) if not broken else 0,
        })

        context["history"].append({
            "action":   action,
            "result":   output[:300],
            "findings": len(findings) if not broken else 0,
        })

    print(f"\n{'=' * 52}")
    print(f"[+] Done — {len(context['history'])} action(s) on {target}")
    print(f"[+] {len(all_findings)} total findings collected")
    print(f"[+] Total scan time: {_fmt_dur(time.monotonic() - loop_start)}")
    print(f"{'=' * 52}")

    report = generate_report(target, services, all_findings, scan_records, profile_name, target_info=target_info)

    # Save final session state (includes target_info)
    save_session({
        "target":         target,
        "profile":        profile_name,
        "findings_count": len(all_findings),
        "target_info":    target_info.to_dict(),
    })

    if MSF_VALIDATE:
        report = await run_msf_validation(report, target, session_dir, available_tools)

    json_path = os.path.join(session_dir, f"report_{safe_tgt}.json")
    html_path = os.path.join(session_dir, f"report_{safe_tgt}.html")
    pdf_path  = os.path.join(session_dir, f"report_{safe_tgt}.pdf")

    # Save base report immediately so it survives an interrupted CVE test phase
    with open(json_path, "w") as fh:
        json.dump(report, fh, indent=2, default=str)
    print(f"[+] JSON report → {json_path}")

    html_content = generate_html_report(report)
    with open(html_path, "w") as fh:
        fh.write(html_content)
    print(f"[+] HTML report → {html_path}")

    if CVE_TEST:
        report = await _run_cve_test_phase(report, target, session_dir)
        # Overwrite with updated report containing CVE test results
        with open(json_path, "w") as fh:
            json.dump(report, fh, indent=2, default=str)
        html_content = generate_html_report(report)
        with open(html_path, "w") as fh:
            fh.write(html_content)
        print(f"[+] Reports updated with CVE test results")

    pdf_ok = generate_pdf_report(html_content, pdf_path)
    if pdf_ok:
        print(f"[+] PDF  report → {pdf_path}")

    # Console summary
    print(f"\n{'=' * 52}")
    print("  REPORT SUMMARY")
    print(f"{'=' * 52}")
    _ip_str = f"  ({target_info.ip_address})" if target_info.ip_address and target_info.ip_address != target else ""
    _rdns_str = f"  [{target_info.rdns_hostname}]" if target_info.rdns_hostname else ""
    print(f"  Target    : {target}{_ip_str}{_rdns_str}")
    if target_info.mac_address:
        print(f"  MAC       : {target_info.mac_address}  {target_info.mac_vendor}".rstrip())
    if target_info.os_guess:
        print(f"  OS Guess  : {target_info.os_guess}")
    if target_info.netbios_name:
        print(f"  NetBIOS   : {target_info.netbios_name}")
    if target_info.asn or target_info.org:
        print(f"  ASN / Org : {target_info.asn}  {target_info.org}".rstrip())
    print(f"  Profile   : {profile['name']}")
    svc_strs = [f"{s['name']}:{s['port']}" for s in report.get("services", [])]
    print(f"  Services  : {', '.join(svc_strs) or 'none'}")
    print(f"  Tools     : {', '.join(report.get('tools_run', [])) or 'none'}")

    counts = report.get("counts", {})
    print("\n  Severity Breakdown:")
    print(f"    Critical : {counts.get('critical', 0)}")
    print(f"    High     : {counts.get('high', 0)}")
    print(f"    Medium   : {counts.get('medium', 0)}")
    print(f"    Low      : {counts.get('low', 0)}")
    print(f"    Info     : {counts.get('info', 0)}")

    cve_matches = report.get("cve_matches", [])
    if cve_matches:
        print(f"\n  CVE Matches: {len(cve_matches)}")
        for c in cve_matches[:5]:
            print(f"    [{c.get('severity','?'):8}] {c.get('cve_id','')} — {c.get('summary','')[:60]}")

    msf_results = [c for c in cve_matches if c.get("msf_validation")]
    if msf_results:
        proven = sum(1 for c in msf_results if c["msf_validation"].get("vulnerable") is True)
        print(f"\n  MSF Validation: {len(msf_results)} checked  |  {proven} CONFIRMED VULNERABLE")

    top = [f for f in report.get("findings", []) if f.get("severity") in ("critical", "high")][:5]
    if top:
        print("\n  Top Findings:")
        for f in top:
            v = "v" if f.get("verified") else "?"
            print(f"    [{f.get('severity','?').upper():8}] [{v}] {f.get('title','')[:60]}")

    print(f"\n  Conclusion : {report.get('conclusion', '')}")
    print(f"\n  Reports:")
    print(f"    JSON : {json_path}")
    print(f"    HTML : {html_path}")
    if pdf_ok:
        print(f"    PDF  : {pdf_path}")
    print(f"{'=' * 52}")


# ---------------------------------------------------------------------------
# REPORT-FROM-JSON
# ---------------------------------------------------------------------------

def _report_from_json(json_path: str):
    """Load an existing JSON report and regenerate HTML/PDF outputs."""
    if not os.path.isfile(json_path):
        print(f"[-] File not found: {json_path}")
        sys.exit(1)

    print(f"[*] Loading report from: {json_path}")
    with open(json_path, encoding="utf-8") as fh:
        report = json.load(fh)

    base      = os.path.splitext(os.path.abspath(json_path))[0]
    html_path = base + ".html"
    pdf_path  = base + ".pdf"

    html_content = generate_html_report(report)
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html_content)
    print(f"[+] HTML report → {html_path}")

    pdf_ok = generate_pdf_report(html_content, pdf_path)
    if pdf_ok:
        print(f"[+] PDF  report → {pdf_path}")

    target = report.get("target", "unknown")
    counts = report.get("counts", {})
    print(f"\n{'=' * 52}")
    print("  REPORT SUMMARY")
    print(f"{'=' * 52}")
    print(f"  Target    : {target}")
    print(f"  Profile   : {report.get('profile', 'unknown')}")
    svc_strs = [f"{s.get('name', '')}:{s.get('port', '')}" for s in report.get("services", [])]
    print(f"  Services  : {', '.join(svc_strs) or 'none'}")
    print(f"\n  Severity Breakdown:")
    print(f"    Critical : {counts.get('critical', 0)}")
    print(f"    High     : {counts.get('high', 0)}")
    print(f"    Medium   : {counts.get('medium', 0)}")
    print(f"    Low      : {counts.get('low', 0)}")
    print(f"    Info     : {counts.get('info', 0)}")

    cve_matches = report.get("cve_matches", [])
    if cve_matches:
        print(f"\n  CVE Matches: {len(cve_matches)}")
        for c in cve_matches[:5]:
            print(f"    [{c.get('severity', '?'):8}] {c.get('cve_id', '')} — {c.get('summary', '')[:60]}")

    print(f"\n  Conclusion : {report.get('conclusion', '')}")
    print(f"\n  Reports:")
    print(f"    JSON : {json_path}")
    print(f"    HTML : {html_path}")
    if pdf_ok:
        print(f"    PDF  : {pdf_path}")
    print(f"{'=' * 52}")


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------

def main():
    if "--report" in sys.argv:
        idx = sys.argv.index("--report")
        if idx + 1 >= len(sys.argv):
            print("Usage: python3 noctis.py --report <json_file>")
            sys.exit(1)
        _report_from_json(sys.argv[idx + 1])
    else:
        asyncio.run(main_async())


if __name__ == "__main__":
    main()
