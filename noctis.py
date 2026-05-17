#!/usr/bin/env python3
# Copyright (C) 2026 Pearce Technologies Pty Ltd
# SPDX-License-Identifier: AGPL-3.0-or-later
# <https://www.gnu.org/licenses/agpl-3.0.html>
"""
Noctis Edge — Security Through Exposure  v0.8.4
Implements: structured findings, verification,
approval gates, async execution, HTML reports,
service-specific enumerations, risk scoring,
5-phase nmap discovery with LLM-informed NSE scripting,
EPSS exploit-probability scoring, NVD CVSS offline database,
NIST CSF 2.0 compliance mapping, and OT/ICS asset classification.
"""

VERSION = "v0.9.4"

import asyncio
import dataclasses
import hashlib
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
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
from jinja2 import Environment as _JinjaEnv

# Force line-buffered stdout so output is visible immediately when piped/tee'd
sys.stdout.reconfigure(line_buffering=True)

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

OLLAMA_URL     = os.getenv("NOCTIS_OLLAMA_URL", "http://localhost:11434/api/generate")
# Three-role model split — tasks are always sequential, never concurrent, so RAM peaks at
# one loaded model at a time (~2 GB).  Two models can coexist in Ollama's model cache on
# systems with ≥6 GB free RAM without any swap pressure.
#
#   Two-model architecture:
#   qwen2.5-coder:3b-instruct (~2 GB)  — planning, structured JSON decisions, CVE probe scripts
#   qwen3:4b (~2.6 GB)                 — narrative prose: report conclusion, remediation guidance
#   Peak concurrent RAM during --cve-test: ~4.6 GB. 8 GB RAM recommended.
#   MODEL            — structured JSON tool-selection decisions
#   SCRIPT_MODEL     — Python exploit / verification script generation
#   CVE_SCRIPT_MODEL — CVE exploit/test script generation (falls back to SCRIPT_MODEL)
#   REPORT_MODEL     — narrative prose: attacker perspective, remediation
MODEL            = os.getenv("NOCTIS_OLLAMA_MODEL",            "qwen2.5-coder:3b-instruct")
SCRIPT_MODEL     = os.getenv("NOCTIS_OLLAMA_SCRIPT_MODEL",     "qwen2.5-coder:3b-instruct")
CVE_SCRIPT_MODEL = os.getenv("NOCTIS_OLLAMA_CVE_SCRIPT_MODEL", SCRIPT_MODEL)
REPORT_MODEL     = os.getenv("NOCTIS_OLLAMA_REPORT_MODEL",     "qwen3:4b")
OLLAMA_TIMEOUT = int(os.getenv("NOCTIS_OLLAMA_TIMEOUT", "360"))   # seconds — 360s covers cold model reload (~3 min) after RAM eviction

# Ollama inference options applied to all planning/decision calls.
# num_ctx:     2048 — bumped from 1024 to accommodate richer prompts when the
#              tool manifest TOOL REFERENCE block is injected (~300 extra tokens).
# temperature: 0    — deterministic; no creativity needed for tool selection JSON
# top_p:       1    — with temp=0 this is irrelevant, set explicitly for clarity
# num_thread:  0    — let Ollama auto-detect optimal thread count for the CPU
_OLLAMA_PLAN_OPTIONS = {"num_ctx": 2048, "temperature": 0, "top_p": 1, "num_thread": 0}
# keep_alive value sent with every request — keeps model weights resident between scan phases.
# "1h" is a valid Go time.Duration string accepted by all Ollama versions.
# Override via NOCTIS_OLLAMA_KEEP_ALIVE env var (e.g. "30m", "2h").
_OLLAMA_KEEP_ALIVE: str = os.getenv("NOCTIS_OLLAMA_KEEP_ALIVE", "1h")

MAX_OUTPUT           = 3000
MAX_ITERATIONS       = 10  # floor — minimum iterations regardless of target size
MAX_ITERATIONS_CAP   = 40  # hard ceiling — dynamic budget and extensions cannot exceed this
MAX_EXTEND_ONCE      = 20  # one-time operator-approved overage above hard ceiling (interactive only)
MAX_EXTENSION_BUDGET = 8   # max extra iterations auto-granted from uninvestigated findings
                           # rate: +2 per uninvestigated finding, consumed until this budget runs out
MAX_PARALLEL_ACTIONS      = int(os.getenv("NOCTIS_MAX_PARALLEL_ACTIONS",      "4"))
PROBE_BATCH_SIZE          = int(os.getenv("NOCTIS_PROBE_BATCH_SIZE",          "4"))  # services per concurrent batch
MAX_ROUNDS_PER_SERVICE    = int(os.getenv("NOCTIS_MAX_ROUNDS_PER_SERVICE",    "5"))  # probe rounds per service
EXTRA_ROUNDS_PER_FINDING  = 2   # extension rounds granted per uninvestigated finding
MAX_EXTRA_ROUNDS          = 4   # per-service cap on auto-granted extra rounds
MAX_LLM_RETRIES           = 3
SAFE_MODE       = True   # can also be used with --aggressive flag for aggressive scanning an enumeration
AIRGAP_MODE     = True   # default on; --dns opts in to internet-dependent DNS enumeration tools
MSF_VALIDATE    = False  # set via --msf-validate; runs safe MSF check probes for each CVE match
CVE_TEST        = False  # set via --cve-test; LLM generates test scripts per matched CVE
UNATTENDED      = False  # set via --unattended; auto-approves all prompts (no user input required)
CVE_KB_PATH          = os.path.join(BASE_DIR, "cve_knowledge_base.json")
NUCLEI_KB_PATH       = os.path.join(BASE_DIR, "nuclei_kb.json")
TOOL_KB_PATH         = os.path.join(BASE_DIR, "tool_knowledge_base.json")
TOOL_MANIFEST_PATH   = os.path.join(BASE_DIR, "tool_manifest.json")
_TOOL_MANIFEST: "dict | None" = None  # lazy-loaded on first call to _load_tool_manifest()

# Offline threat-intelligence databases (built by scripts/build_epss_db.py,
# scripts/build_nvd_cvss.py, scripts/build_cwe_db.py and scripts/build_kev_db.py;
# refreshed by update.sh)
_EPSS_CSV     = os.path.join(BASE_DIR, "CVE", "epss-scores.csv")
_NVD_CVSS_CSV = os.path.join(BASE_DIR, "CVE", "nvd-cvss.csv")
_CWE_DATA_CSV = os.path.join(BASE_DIR, "CVE", "cwe-data.csv")
_KEV_CSV      = os.path.join(BASE_DIR, "CVE", "kev-catalog.csv")
# Lazy-loaded lookup dicts — populated on first call
_EPSS_DB: "dict | None" = None
_CVSS_DB: "dict | None" = None
_CWE_DB:  "dict | None" = None
_KEV_DB:  "dict | None" = None


def _load_epss_db() -> dict:
    """Lazy-load CVE/epss-scores.csv → {cve_id: (epss_score, percentile)}."""
    global _EPSS_DB
    if _EPSS_DB is not None:
        return _EPSS_DB
    _EPSS_DB = {}
    if not os.path.isfile(_EPSS_CSV):
        return _EPSS_DB
    try:
        import csv as _csv
        with open(_EPSS_CSV, newline="", encoding="utf-8") as fh:
            for row in _csv.DictReader(fh):
                cve = row.get("cve", "").upper()
                if cve:
                    _EPSS_DB[cve] = (
                        float(row.get("epss", 0) or 0),
                        float(row.get("percentile", 0) or 0),
                    )
    except Exception:
        pass
    return _EPSS_DB


def _load_cvss_db() -> dict:
    """Lazy-load CVE/nvd-cvss.csv → {cve_id: (v3_score, v3_vector, v3_severity, v4_score, v4_vector, cwe_id)}."""
    global _CVSS_DB
    if _CVSS_DB is not None:
        return _CVSS_DB
    _CVSS_DB = {}
    if not os.path.isfile(_NVD_CVSS_CSV):
        return _CVSS_DB
    try:
        import csv as _csv
        with open(_NVD_CVSS_CSV, newline="", encoding="utf-8") as fh:
            for row in _csv.DictReader(fh):
                cve = row.get("cve_id", "").upper()
                if cve:
                    _CVSS_DB[cve] = (
                        float(row.get("cvss_v3_score", 0) or 0),
                        row.get("cvss_v3_vector", ""),
                        row.get("cvss_v3_severity", ""),
                        float(row.get("cvss_v4_score", 0) or 0),
                        row.get("cvss_v4_vector", ""),
                        row.get("cwe_id", ""),          # extracted from NVD weaknesses
                    )
    except Exception:
        pass
    return _CVSS_DB


def _load_cwe_db() -> dict:
    """Lazy-load CVE/cwe-data.csv → {cwe_id: {name, abstraction, description, likelihood, consequences, mitigation}}."""
    global _CWE_DB
    if _CWE_DB is not None:
        return _CWE_DB
    _CWE_DB = {}
    if not os.path.isfile(_CWE_DATA_CSV):
        return _CWE_DB
    try:
        import csv as _csv
        with open(_CWE_DATA_CSV, newline="", encoding="utf-8") as fh:
            for row in _csv.DictReader(fh):
                cid = row.get("cwe_id", "").strip()
                if cid:
                    _CWE_DB[cid] = {
                        "name":         row.get("name", ""),
                        "abstraction":  row.get("abstraction", ""),
                        "description":  row.get("description", ""),
                        "likelihood":   row.get("likelihood", ""),
                        "consequences": row.get("consequences", ""),
                        "mitigation":   row.get("mitigation", ""),
                    }
    except Exception:
        pass
    return _CWE_DB
def _load_kev_db() -> dict:
    """Lazy-load CVE/kev-catalog.csv → {cve_id: {vendor, product, date_added, due_date, action}}.

    Build with: python scripts/build_kev_db.py
    Refresh via update.sh.
    """
    global _KEV_DB
    if _KEV_DB is not None:
        return _KEV_DB
    _KEV_DB = {}
    if not os.path.isfile(_KEV_CSV):
        return _KEV_DB
    try:
        import csv as _csv
        with open(_KEV_CSV, newline="", encoding="utf-8") as fh:
            for row in _csv.DictReader(fh):
                cve = row.get("cveID", "").upper()
                if cve:
                    _KEV_DB[cve] = {
                        "vendor":     row.get("vendorProject", ""),
                        "product":    row.get("product", ""),
                        "date_added": row.get("dateAdded", ""),
                        "due_date":   row.get("dueDate", ""),
                        "action":     row.get("requiredAction", ""),
                    }
    except Exception:
        pass
    return _KEV_DB


CVE_FRESH_ATTEMPTS  = 5   # fresh LLM-generated scripts per CVE (on top of known-exploit + KB replays)
CVE_VERIFY_ATTEMPTS = 2  # independent verifier scripts run when any attempt returns VULNERABLE
CVE_BATCH_SIZE      = 5  # prompt user to continue after this many CVEs (runaway guard)

# Tools that rely on internet OSINT sources and should be skipped in airgap mode
INTERNET_ONLY_TOOLS = {"amass", "dnsenum", "dnsrecon"}

# ---------------------------------------------------------------------------
# TOOL CONFIDENCE WEIGHTS
# ---------------------------------------------------------------------------

TOOL_CONFIDENCE: dict = {
    "nuclei":    0.70,
    "nikto":     0.40,
    "nikto_cgi": 0.40,
    "curl":      0.90,
    "ffuf":      0.60,
    "ssh-audit": 0.85,
    "rdpscan":   0.75,
    "nmap":      0.80,
    "dns":       0.75,
    "mysql":     0.80,
    "mssql":     0.80,
}

# Require explicit operator approval before running these
AGGRESSIVE_TOOLS = {"ffuf", "hydra", "nuclei_aggressive"}

# Keywords expected in an HTTP response body to confirm each vuln type.
# Used by verify_finding() to avoid marking a finding "verified" just because
# any curl response came back.  vuln_type values not listed here fall back to
# the legacy heuristic (any response > 20 chars = verified).
_VULN_BODY_KEYWORDS: dict = {
    "Information Disclosure": ["server:", "x-powered-by:", "version", "powered by", "apache/", "nginx/", "php/", "iis/"],
    "XSS":                    ["<script", "javascript:", "onerror=", "alert(", "document.cookie"],
    "SQL Injection":          ["sql syntax", "mysql_fetch", "ora-0", "unclosed quotation", "syntax error"],
    "Directory Traversal":    ["root:x:", "etc/passwd", "[boot loader]", "win.ini", "[extensions]"],
    "RCE":                    ["uid=0", "root@", "windows nt", "/bin/sh", "command not found"],
    "Open Redirect":          ["location:", "moved permanently", "301 moved", "302 found"],
    "SSRF":                   ["169.254.", "127.0.0.1", "localhost", "internal server"],
    "File Inclusion":         ["root:x:", "etc/passwd", "<?php", "warning: include", "failed to open stream"],
    "Authentication Bypass":  ["welcome", "dashboard", "admin panel", "logged in", "access granted"],
    "Misconfiguration":       ["index of /", "directory listing", "options +indexes", "autoindex on"],
    "Weak SSL/TLS":           ["tls 1.0", "ssl 2.0", "rc4", "des-cbc", "export cipher"],
}

# ---------------------------------------------------------------------------
# SAFE ARG VALIDATION — enumeration-only guardrails
# ---------------------------------------------------------------------------
# Tools accept optional extra fields from the LLM. Every field is validated
# against an allowlist before being used in subprocess.exec args to prevent
# injection and ensure no tool ever modifies server state or exploits targets.

_RE_EXTENSIONS  = re.compile(r'^[a-zA-Z0-9]+(,[a-zA-Z0-9]+)*$')          # e.g. "php,html,txt"
_RE_TAGS        = re.compile(r'^[a-zA-Z0-9_,/.-]+$')                      # nuclei template tags
_RE_MATCH_CODES = re.compile(r'^\d+(,\d+)*$')                              # e.g. "200,301,403"
_RE_SEVERITY    = re.compile(r'^(info|low|medium|high|critical)(,(info|low|medium|high|critical))*$', re.I)
_RE_HEADER_NAME = re.compile(r'^[a-zA-Z0-9_-]+$')

# HTTP methods that are read-only / do not modify server state
_SAFE_HTTP_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST"})
# PUT, DELETE, PATCH, CONNECT are excluded — they write/remove resources


def _sanitise_url(raw_url: str) -> str:
    """Strip LLM-introduced artifacts from URLs before passing to tools.

    The LLM sometimes appends '*', 'FUZZ', '/FUZZ', '/' or similar when it
    has seen ffuf examples in context.  Remove all of these so the actual
    tool receives a clean base URL.
    """
    u = raw_url.strip()
    # Strip trailing FUZZ variants and wildcards
    for suffix in ("/FUZZ", "FUZZ", "*", "/"):
        while u.endswith(suffix):
            u = u[:-len(suffix)]
    return u.strip()


def _safe_tool_args(tool: str, raw) -> dict:
    """Normalise and validate LLM-provided tool args.

    Only allowlisted fields are kept.  Anything with unexpected format is
    dropped and a warning is printed.  Guarantees that no exploit-class flags
    or server-modifying HTTP methods can reach subprocess.exec.
    """
    # Legacy: plain string means it's a URL/target
    if not isinstance(raw, dict):
        return {"url": str(raw)}

    cleaned: dict = {}

    if tool == "ffuf":
        cleaned["url"]      = _sanitise_url(str(raw.get("url", "")))
        cleaned["wordlist"] = str(raw.get("wordlist", WORDLIST))

        exts = str(raw.get("extensions", "")).strip()
        if exts:
            if _RE_EXTENSIONS.match(exts):
                cleaned["extensions"] = exts
            else:
                print(f"[!] [safe-args] unsafe 'extensions' value dropped: {exts!r}")

        method = str(raw.get("method", "GET")).upper()
        if method in _SAFE_HTTP_METHODS:
            cleaned["method"] = method
        else:
            print(f"[!] [safe-args] HTTP method {method!r} not allowed — defaulting to GET")
            cleaned["method"] = "GET"

        mc = str(raw.get("match_codes", "")).strip()
        if mc:
            if _RE_MATCH_CODES.match(mc):
                cleaned["match_codes"] = mc
            else:
                print(f"[!] [safe-args] unsafe 'match_codes' dropped: {mc!r}")

        # Safe numeric caps — LLM may suggest values, but we hard-limit them
        try:
            cleaned["threads"] = max(5, min(int(raw.get("threads", 8)), 15))
        except (ValueError, TypeError):
            cleaned["threads"] = 8
        try:
            rate = int(raw.get("rate", 25))
            cleaned["rate"] = max(10, min(rate if rate > 0 else 25, 50))
        except (ValueError, TypeError):
            cleaned["rate"] = 25
        try:
            cleaned["timeout"] = max(5, min(int(raw.get("timeout", 8)), 15))
        except (ValueError, TypeError):
            cleaned["timeout"] = 8
        try:
            cleaned["retries"] = max(0, min(int(raw.get("retries", 1)), 2))
        except (ValueError, TypeError):
            cleaned["retries"] = 1
        try:
            cleaned["maxtime"] = max(60, min(int(raw.get("maxtime", 300)), 600))
        except (ValueError, TypeError):
            cleaned["maxtime"] = 300

        # Optional response filters (integers only)
        for fkey in ("filter_size", "filter_words"):
            fval = raw.get(fkey)
            if fval is not None:
                try:
                    cleaned[fkey] = int(fval)
                except (ValueError, TypeError):
                    pass

    elif tool == "nuclei":
        cleaned["url"] = _sanitise_url(str(raw.get("url", raw.get("_raw", ""))))

        tags = str(raw.get("tags", "")).strip()
        if tags:
            if _RE_TAGS.match(tags):
                cleaned["tags"] = tags
            else:
                print(f"[!] [safe-args] unsafe 'tags' value dropped: {tags!r}")

        sev = str(raw.get("severity", "")).strip()
        if sev:
            if _RE_SEVERITY.match(sev):
                cleaned["severity"] = sev.lower()
            else:
                print(f"[!] [safe-args] unsafe 'severity' dropped: {sev!r}")

    elif tool == "curl":
        cleaned["url"] = _sanitise_url(str(raw.get("url", raw.get("_raw", ""))))

        method = str(raw.get("method", "GET")).upper()
        if method in _SAFE_HTTP_METHODS:
            cleaned["method"] = method
        else:
            print(f"[!] [safe-args] HTTP method {method!r} not allowed — defaulting to GET")
            cleaned["method"] = "GET"

        hdrs = raw.get("headers", {})
        safe_hdrs: dict = {}
        if isinstance(hdrs, dict):
            for k, v in hdrs.items():
                k, v = str(k), str(v)
                if _RE_HEADER_NAME.match(k):
                    # Strip CR/LF to prevent CRLF-injection in header values
                    safe_hdrs[k] = v.replace("\r", "").replace("\n", "")
                else:
                    print(f"[!] [safe-args] unsafe header name dropped: {k!r}")
        cleaned["headers"] = safe_hdrs

    elif tool in ("nikto", "nikto_cgi"):
        cleaned["url"] = _sanitise_url(str(raw.get("url", raw.get("_raw", ""))))
        cleaned["ssl"] = bool(raw.get("ssl", False))

    else:
        # ssh_enum, rdp_enum, mysql_enum, mssql_enum, dns_enum — pass-through known fields
        for key in ("host", "port", "domain"):
            if key in raw:
                cleaned[key] = str(raw[key])

    return cleaned

# ---------------------------------------------------------------------------
# ASSESSMENT PROFILES
# ---------------------------------------------------------------------------

PROFILES = {
    "standard": {
        "name":            "Standard Assessment",
        "tools":           ["curl", "nikto", "nuclei", "ffuf", "dns_enum",
                            "ssh_enum", "rdp_enum", "mysql_enum", "mssql_enum"],
        "escalation":      ["nikto_full", "nuclei_aggressive"],
        "report_template": "web",
    },
    "full": {
        "name":            "Full Authorised Assessment",
        "tools":           ["curl", "nikto", "nuclei", "ffuf", "dns_enum",
                            "ssh_enum", "rdp_enum", "mysql_enum", "mssql_enum",
                            "nxc_smb", "nxc_ldap", "impacket"],
        "escalation":      ["nikto_full", "nuclei_aggressive", "hydra"],
        "report_template": "web",
    },
    "ot": {
        "name":            "Industrial / OT Assessment",
        "tools":           ["nmap"],
        "escalation":      [],
        "report_template": "ot",
    },
}

# ---------------------------------------------------------------------------
# OT / ICS ASSET CLASSIFICATION
# ---------------------------------------------------------------------------

_OT_PORTS: dict = {
    102:   {"protocol": "S7comm",         "standard": "IEC 62443"},
    502:   {"protocol": "Modbus",         "standard": "IEC 61511"},
    4840:  {"protocol": "OPC-UA",         "standard": "IEC 62443"},
    20000: {"protocol": "DNP3",           "standard": "IEC 60870-5"},
    47808: {"protocol": "BACnet",         "standard": "ASHRAE 135"},
    44818: {"protocol": "EtherNet/IP",    "standard": "IEC 62443"},
    789:   {"protocol": "Red Lion Data",  "standard": "IEC 62443"},
    1089:  {"protocol": "FF-HSE",         "standard": "IEC 61804"},
    1090:  {"protocol": "FF-HSE",         "standard": "IEC 61804"},
    1091:  {"protocol": "FF-HSE",         "standard": "IEC 61804"},
    2222:  {"protocol": "EtherNet/IP IO", "standard": "IEC 62443"},
    9600:  {"protocol": "OMRON FINS",     "standard": "IEC 62443"},
    18245: {"protocol": "GE SRTP",        "standard": "IEC 62443"},
    18246: {"protocol": "GE SRTP",        "standard": "IEC 62443"},
    34962: {"protocol": "PROFInet",       "standard": "IEC 61158"},
}

_OT_PRODUCT_KEYWORDS: tuple = (
    "siemens", "schneider", "rockwell", "allen-bradley", "abb",
    "honeywell", "emerson", "ge digital", "yokogawa", "mitsubishi",
    "scada", "hmi", "plc", "dcs", "rtu",
    "historian", "wonderware", "factorytalk", "wincc", "intouch",
)


def _classify_asset(service: dict) -> str:
    """Return 'OT' if service appears to be an industrial/OT asset, else 'IT'."""
    try:
        port = int(service.get("port", 0))
    except (ValueError, TypeError):
        port = 0
    if port in _OT_PORTS:
        return "OT"
    product_lower = (
        str(service.get("product", "")) + " " + str(service.get("name", ""))
    ).lower()
    if any(kw in product_lower for kw in _OT_PRODUCT_KEYWORDS):
        return "OT"
    return "IT"

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
    cmd:                 str  = ""  # Full command string for transparency
    http_response:       str  = ""  # Raw HTTP response/headers for evidence
    vuln_type:           str  = ""  # Inferred vulnerability type (e.g. RCE, XSS)
    cwe_id:              str  = ""  # CWE identifier (e.g. CWE-89)
    compliance_controls: list = field(default_factory=list)  # PCI-DSS, SOC2, ISO 27001
    manual_review:       bool = False  # True when nikto/scanner flags a finding that warrants manual verification
    verifier_tool:       str  = ""   # Tool dispatched to verify this finding (set when probe_inconclusive)
    detection_method:    str  = ""   # How detected: banner_analysis, template_match, service_probe, exploit_confirmed
    llm_remediation_short: str = ""  # LLM-generated immediate workaround (set during report generation for Unknown vuln_type)
    llm_remediation_long:  str = ""  # LLM-generated permanent fix (set during report generation for Unknown vuln_type)

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


def _ollama_is_up() -> bool:
    """Return True if Ollama is reachable and responding on OLLAMA_URL."""
    base_url = OLLAMA_URL.split("/api/")[0]
    tags_url = f"{base_url}/api/tags"
    assert isinstance(tags_url, str) and tags_url.startswith("http"), \
        "OLLAMA_URL must be a valid HTTP URL"
    try:
        r = requests.get(tags_url, timeout=3)
        assert r is not None, "requests.get returned None"
        return r.status_code == 200
    except Exception:
        return False


def ensure_ollama_running() -> bool:
    """Return True if Ollama is already serving or was successfully started.

    Checks http://localhost:11434/api/tags.  If it is not reachable, spawns
    `ollama serve` as a background process and waits up to 30 seconds for it
    to become available.  The process handle is kept in _ollama_proc so it is
    not garbage-collected and can be cleaned up at exit.
    """
    global _ollama_proc

    # Derive the health-check URL from OLLAMA_URL so Docker/remote configs work
    base_url  = OLLAMA_URL.split("/api/")[0]  # e.g. http://ollama:11434
    tags_url  = f"{base_url}/api/tags"
    is_remote = ("localhost" not in base_url and "127.0.0.1" not in base_url)

    def _is_up() -> bool:
        try:
            r = requests.get(tags_url, timeout=3)
            return r.status_code == 200
        except Exception:
            return False

    if _is_up():
        print("[*] Ollama is already serving.")
        _warmup_models()
        return True

    # When pointing at a remote/container Ollama host, don't try to spawn locally
    if is_remote:
        print(f"[!] Cannot reach Ollama at {base_url} — is the Ollama container running?")
        return False

    if shutil.which("ollama") is None:
        print("[!] 'ollama' binary not found in PATH. Please install Ollama:")
        print("      https://ollama.com/download")
        return False

    print("[*] Ollama is not running — starting 'ollama serve' in the background …")
    try:
        # Pass OLLAMA_KEEP_ALIVE so the server-level default matches our per-request value.
        # Without this, models evict after 5 min regardless of per-request keep_alive.
        serve_env = os.environ.copy()
        serve_env.setdefault("OLLAMA_KEEP_ALIVE", _OLLAMA_KEEP_ALIVE)
        _ollama_proc = subprocess.Popen(
            ["ollama", "serve"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env=serve_env,
        )
    except OSError as exc:
        print(f"[!] Failed to start Ollama: {exc}")
        return False

    deadline = time.time() + 30
    while time.time() < deadline:
        if _is_up():
            print("[*] Ollama is now serving.")
            _warmup_models()
            return True
        time.sleep(0.5)

    print("[!] Ollama did not become ready within 30 seconds.")
    return False


def _warmup_models() -> None:
    """Pre-load MODEL and SCRIPT_MODEL into Ollama's memory before the scan starts.

    Sends a tiny prompt to each model with keep_alive=-1 so the weights stay
    resident for the entire scan.  This eliminates the cold-load delay (typically
    30-90 seconds on CPU-only hardware) that otherwise hits the first real LLM call.
    """
    base_url = OLLAMA_URL.split("/api/")[0]
    gen_url  = f"{base_url}/api/generate"
    tags_url = f"{base_url}/api/tags"
    warmup_prompt = "Reply with the single word: ready"

    # Fetch the set of locally available model names once.
    try:
        _tags_resp = requests.get(tags_url, timeout=5)
        _local_models: set = {
            m["name"] for m in (_tags_resp.json().get("models") or [])
        } if _tags_resp.status_code == 200 else set()
    except Exception:
        _local_models = set()

    for model in set([MODEL, SCRIPT_MODEL, CVE_SCRIPT_MODEL]):
        # Pull the model if it is not available locally.
        _model_present = any(
            m == model or m.startswith(model + ":")
            for m in _local_models
        )
        if not _model_present:
            print(f"[*] Model '{model}' not found locally — pulling from Ollama library …")
            ollama_bin = shutil.which("ollama")
            if ollama_bin:
                pull_result = subprocess.run(
                    [ollama_bin, "pull", model],
                    timeout=600,
                )
                if pull_result.returncode != 0:
                    print(f"[!] 'ollama pull {model}' failed — LLM calls may not work.")
                else:
                    print(f"[*] Model '{model}' pulled successfully.")
            else:
                print(f"[!] Cannot pull '{model}': ollama binary not found.")
        try:
            print(f"[*] Pre-loading model '{model}' into memory …")
            resp = requests.post(
                gen_url,
                json={
                    "model":      model,
                    "prompt":     warmup_prompt,
                    "stream":     False,
                    "keep_alive": _OLLAMA_KEEP_ALIVE,
                    "options":    {"num_ctx": 64, "num_predict": 4, "temperature": 0},
                },
                timeout=120,
            )
            if resp.status_code == 200:
                print(f"[*] Model '{model}' loaded and warm.")
            else:
                print(f"[!] Warmup for '{model}' returned HTTP {resp.status_code} — continuing anyway.")
        except Exception as e:
            print(f"[!] Warmup for '{model}' failed: {e} — continuing anyway.")


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


def calculate_risk_score(finding, internet_exposed=True, epss_score: float = 0.0):
    """Composite risk score: CVSS-derived (70%) + EPSS exploit-probability (30%).

    Also applies a detection-method confidence modifier so that banner-only
    findings score lower than actively probed or exploit-confirmed findings.
    Formula (values 0-1.0 scale):
        base = sev_weight * finding.confidence * exposure * tool_conf * det_mod
        score = (base * 0.70) + (epss_score * 0.30)
    """
    severity_weights = {
        "critical": 1.0,
        "high":     0.8,
        "medium":   0.5,
        "low":      0.2,
        "info":     0.05,
    }
    # Detection method modifies trust in the base score
    _det_modifiers = {
        "exploit_confirmed": 1.00,
        "service_probe":     0.85,
        "template_match":    0.80,
        "banner_analysis":   0.65,
    }
    sev_w    = severity_weights.get(finding.severity.lower(), 0.1)
    exposure = 1.2 if internet_exposed else 1.0
    tool_conf = TOOL_CONFIDENCE.get(finding.tool, 0.5)
    det_mod   = _det_modifiers.get(getattr(finding, "detection_method", ""), 0.70)
    base  = sev_w * finding.confidence * exposure * tool_conf * det_mod
    # EPSS component: probability of exploitation in the wild (0-1) weighted at 30%
    score = (base * 0.70) + (epss_score * 0.30)
    return round(score, 3)


# ---------------------------------------------------------------------------
# CALIBRATED SEVERITY — report-layer downgrade/upgrade (no scan-loop impact)
# ---------------------------------------------------------------------------
# Finding.severity is NEVER mutated. effective_severity is computed at
# generate_report() time and lives only in the report context dict.

_SEV_LEVELS = ("info", "low", "medium", "high", "critical")


def _cap_severity(raw: str, cap: str) -> str:
    """Return the lower of raw and cap severity strings."""
    raw_i = _SEV_LEVELS.index(raw.lower())  if raw.lower()  in _SEV_LEVELS else 2
    cap_i = _SEV_LEVELS.index(cap.lower())  if cap.lower()  in _SEV_LEVELS else 2
    return _SEV_LEVELS[min(raw_i, cap_i)]


def _effective_severity_rules(f) -> str | None:
    """Apply deterministic rules. Return effective severity string or None (= needs LLM).

    None means the finding is ambiguous and should be sent to the LLM batch.
    """
    sev = f.severity.lower()

    # Hard keep — authoritative evidence
    if f.verification_status == "confirmed":
        return sev
    if getattr(f, "detection_method", "") == "exploit_confirmed":
        return sev
    # High-confidence non-nikto tools — trust their severity
    if (
        f.confidence >= 0.85
        and f.tool in ("curl", "nmap", "ssh-audit", "rdpscan", "mysql", "mssql")
    ):
        return sev

    # Banner / heuristic tools — hard cap at medium
    if getattr(f, "detection_method", "") == "banner_analysis":
        return _cap_severity(sev, "medium")
    if f.tool == "nikto":
        return _cap_severity(sev, "medium")

    # Nuclei unverified high/critical → ambiguous, send to LLM
    if f.tool == "nuclei" and not f.verified and sev in ("high", "critical"):
        return None

    # Low confidence high/critical → ambiguous
    if f.confidence < 0.50 and sev in ("high", "critical"):
        return None

    return sev


def _preload_report_model() -> None:
    """Fire a minimal one-token request to REPORT_MODEL so Ollama loads it into
    RAM before the first real prose call (executive summary).  On short scans the
    planning model (MODEL) is the only model that was ever used; without this
    warm-up the cold-load of qwen3:4b alone can exceed the 360 s OLLAMA_TIMEOUT.
    Non-fatal — any error is silently ignored."""
    try:
        requests.post(
            OLLAMA_URL,
            json={
                "model":      REPORT_MODEL,
                "prompt":     "/no_think\n.",
                "stream":     False,
                "keep_alive": _OLLAMA_KEEP_ALIVE,
                "options":    {"num_predict": 1, "num_ctx": 512},
            },
            timeout=OLLAMA_TIMEOUT,
        )
    except Exception:
        pass


def _llm_recalibrate_severities(findings: list) -> dict:
    """Batch LLM re-rating for ambiguous findings (temperature=0, structured JSON).

    Uses MODEL (qwen2.5-coder:3b-instruct) — same as tool-selection calls.
    Returns {finding_id: effective_severity_string}.
    Falls back to conservative cap (medium) on any error or timeout.
    """
    if not findings:
        return {}

    fallback = {f.finding_id: _cap_severity(f.severity, "medium") for f in findings}

    items = [
        {
            "id":       f.finding_id,
            "tool":     f.tool,
            "title":    f.title[:120],
            "evidence": (f.evidence or "")[:200],
            "severity": f.severity,
            "confidence": round(f.confidence, 2),
            "verified": f.verified,
            "detection_method": getattr(f, "detection_method", ""),
        }
        for f in findings
    ]

    prompt = (
        "You are a security severity calibration assistant. "
        "Re-rate each finding's effective severity based on the quality of evidence. "
        "Rules: if evidence only proves version/banner detection with no exploit confirmed, "
        "downgrade high→medium and critical→high. "
        "If the evidence shows an actual exploit payload succeeded or a dangerous "
        "misconfiguration is directly confirmed, keep the original severity. "
        "Reply with ONLY a JSON array, no prose, no markdown fences. "
        "Each element: {\"id\": \"F-...\", \"effective_severity\": \"medium\", "
        "\"reason\": \"one sentence\"}. "
        f"Findings: {json.dumps(items, separators=(',', ':'))}"
    )

    try:
        resp = requests.post(
            OLLAMA_URL,
            json={
                "model":      MODEL,
                "stream":     False,
                "keep_alive": _OLLAMA_KEEP_ALIVE,
                "options":    _OLLAMA_PLAN_OPTIONS,
                "prompt":     prompt,
            },
            timeout=60,
        )
        raw = resp.json().get("response", "").strip()
        # Strip optional markdown fences
        raw = re.sub(r'^```[^\n]*\n?', '', raw).rstrip('`').strip()
        parsed = json.loads(raw)
        result = {}
        for item in parsed:
            fid = item.get("id", "")
            sev = item.get("effective_severity", "").lower()
            if fid and sev in _SEV_LEVELS:
                result[fid] = sev
        # Back-fill any missing IDs with conservative fallback
        for f in findings:
            if f.finding_id not in result:
                result[f.finding_id] = fallback[f.finding_id]
        return result
    except Exception as e:
        print(f"[!] Severity recalibration LLM error: {e} — using conservative fallback")
        return fallback


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


def _enrich_finding_metadata(title: str, evidence: str, service: str):
    """Return (vuln_type, cwe_id, compliance_controls) inferred from finding text.

    All three dicts (_infer_vuln_type, _CWE_MAPPING, _COMPLIANCE_MAPPING) are
    defined later in this module; Python resolves them at call time, not at
    definition time, so forward references are safe.
    """
    text                = f"{title} {evidence} {service}"
    vuln_type           = _infer_vuln_type(text)
    cwe_id              = _CWE_MAPPING.get(vuln_type, "")
    compliance_controls = list(_COMPLIANCE_MAPPING.get(vuln_type, []))
    return vuln_type, cwe_id, compliance_controls


def deduplicate_findings(findings):
    seen   = set()
    unique = []
    for f in findings:
        key = f"{f.title.lower()}:{f.target}:{f.service}"
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def _confidence_label(confidence: float) -> str:
    """Map a confidence float to a human-readable tier label."""
    if confidence >= 0.95:
        return "Validated"
    if confidence >= 0.75:
        return "Strong Fingerprint"
    if confidence >= 0.40:
        return "Banner / Heuristic"
    return "Weak Inference"


# ---------------------------------------------------------------------------
# TOOL VALIDATION
# ---------------------------------------------------------------------------

TOOL_REGISTRY = {
    "nmap":      ("nmap",      None),
    "nuclei":    ("nuclei",    os.path.join(os.path.expanduser("~"), "go", "bin", "nuclei")),
    "nikto":     ("nikto",     None),
    "curl":      ("curl",      None),
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
    if UNATTENDED:
        print(f"[*] UNATTENDED: auto-approving {tool}")
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


async def run_nikto_async(url, session_dir=None, extra_flags=None):
    # Capture findings via stdout so parse_nikto_output can see them.
    # -maxtime is a hint to nikto; asyncio timeout is the hard limit.
    cmd = ["perl", NIKTO_PL, "-h", url, "-Format", "txt",
           "-nointeractive", "-maxtime", "90s"]
    if extra_flags:
        cmd.extend(extra_flags)
    raw = await run_command_async(cmd, timeout=100)
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

async def run_nuclei_json_async(url, available_tools, tags=None, severity=None):
    nuclei_path = available_tools.get("nuclei", "nuclei")
    cmd = [
        nuclei_path,
        "-u", url,
        "-s", severity or "low,medium,high,critical",
        "-silent",
        "-nc",
        "-timeout", "10",
        "-j",        # JSONL output (one JSON object per line)
        "-ot",       # omit encoded template to keep output compact
    ]
    if tags:
        cmd += ["-tags", tags]
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

        # Use per-template confidence from nuclei_kb if available (lazy-loaded once).
        _nkb_cache = _load_nuclei_kb()  # cheap: returns cached if unchanged
        _tmpl_confidence = _nkb_cache.get(template_id, {}).get("confidence_weight")
        _confidence = _tmpl_confidence if _tmpl_confidence is not None else TOOL_CONFIDENCE.get("nuclei", 0.7)

        f = Finding(
            finding_id=make_finding_id("nuclei", target, template_id),
            tool="nuclei",
            target=target,
            service="http",
            severity=severity,
            title=title,
            evidence=evidence,
            confidence=_confidence,
            verified=False,
            timestamp=datetime.now(timezone.utc).isoformat(),
            tags=tags,
            raw_output=line,
            description=description,
            matched_url=matched_url,
            template_id=template_id,
            references=references,
            verification_status="discovered",
            detection_method="template_match",
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

# Nikto severity upgrades: (substring_to_match, new_severity, title_prefix)
# Evaluated in order — first match wins.  All findings default to 'info' unless matched.
# Patterns are matched case-insensitively against the full finding text.
_NIKTO_SEVERITY_UPGRADES: list[tuple[str, str, str]] = [
    # Critical — direct exploitation / authentication bypass
    ("cve-",                        "medium", "CVE-Match:"),  # banner/version match only — no exploit attempted
    ("remote code execution",        "critical", "RCE:"),
    ("command injection",            "critical", "Injection:"),
    ("sql injection",                "critical", "SQLi:"),
    ("shellshock",                   "critical", "Shellshock:"),
    # High — dangerous misconfigs and active exploitable conditions
    ("http trace",                   "medium", "XST:"),      # theoretical; dead in modern browsers without existing XSS
    ("trace method",                 "medium", "XST:"),
    ("allowed method",               "medium", "Methods:"),
    ("put method",                   "medium", "Upload:"),   # OPTIONS only — actual write untested
    ("delete method",                "high",   "Dangerous:"),
    ("directory indexing",           "medium", "Dir-Listing:"),
    ("directory listing",            "medium", "Dir-Listing:"),
    ("index of /",                   "medium", "Dir-Listing:"),
    ("basic authentication",         "medium", "Weak-Auth:"),
    ("default password",             "high",   "Default-Creds:"),
    ("default credential",           "high",   "Default-Creds:"),
    ("default login",                "high",   "Default-Creds:"),
    ("admin interface",              "medium", "Admin:"),
    ("/admin",                       "medium", "Admin:"),
    ("phpinfo()",                    "medium", "Info-Leak:"),
    ("phpinfo",                      "medium", "Info-Leak:"),
    ("server-status",                "medium", "Info-Leak:"),
    ("server-info",                  "medium", "Info-Leak:"),
    ("web.config",                   "high",   "Config-Leak:"),
    (".git/",                        "high",   "Source-Leak:"),
    (".svn/",                        "high",   "Source-Leak:"),
    ("backup file",                  "medium", "Backup:"),
    (".bak",                         "low",    "Backup:"),
    ("x-powered-by",                 "low",    "Header:"),
    ("server header",                "low",    "Header:"),
    ("anti-clickjacking",            "low",    "Header:"),
    ("x-content-type-options",       "low",    "Header:"),
    ("x-xss-protection",             "low",    "Header:"),
    ("content-security-policy",      "low",    "Header:"),
    ("cross-site scripting",         "high",   "XSS:"),
    ("xss",                          "high",   "XSS:"),
    ("path traversal",               "high",   "Traversal:"),
    ("file inclusion",               "high",   "LFI:"),
    ("ssrf",                         "high",   "SSRF:"),
    ("open redirect",                "medium", "Redirect:"),
    ("robots.txt",                   "low",    "Recon:"),
    ("sitemap.xml",                  "low",    "Recon:"),
]


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
        # Sanitize Perl stringified array refs before they reach report titles
        text = re.sub(r'ARRAY\(0x[0-9a-f]+\)', '[array]', text)
        # Apply severity upgrades — first matching pattern wins
        severity = "info"
        title_prefix = ""
        text_lower = text.lower()
        for pattern, new_sev, prefix in _NIKTO_SEVERITY_UPGRADES:
            if pattern in text_lower:
                severity = new_sev
                title_prefix = prefix
                break
        # Prefix the title so the severity is self-evident in reports
        display_title = f"{title_prefix} {text[:120]}".strip() if title_prefix else text[:120]
        manual_review = severity != "info"  # flag anything above info for human follow-up
        # Derive vuln_type from the title_prefix so this finding is not sent to LLM enrichment
        _NIKTO_PREFIX_VULN_TYPE = {
            "Header:": "Missing Security Header",
            "Recon:": "Information Disclosure",
            "Dir-Listing:": "Directory Listing",
            "Admin:": "Exposed Admin Interface",
            "Config-Leak:": "Information Disclosure",
            "Source-Leak:": "Information Disclosure",
            "Backup:": "Information Disclosure",
            "Platform:": "Information Disclosure",
            "Server:": "Information Disclosure",
            "XSS:": "XSS",
            "Traversal:": "Path Traversal",
            "LFI:": "File Inclusion",
            "SSRF:": "SSRF",
            "Redirect:": "Open Redirect",
        }
        _vuln_type = _NIKTO_PREFIX_VULN_TYPE.get(title_prefix) or _infer_vuln_type(text)
        if not _vuln_type or _vuln_type == "Unknown":
            _vuln_type = "Misconfiguration"
        f = Finding(
            finding_id=make_finding_id("nikto", target, text[:50]),
            tool="nikto",
            target=target,
            service="http",
            severity=severity,
            title=display_title,
            evidence=text[:400],
            confidence=TOOL_CONFIDENCE.get("nikto", 0.4),
            verified=False,
            timestamp=datetime.now(timezone.utc).isoformat(),
            tags=[],
            verification_status="discovered",
            manual_review=manual_review,
            detection_method="banner_analysis",
            vuln_type=_vuln_type,
        )
        f.tags = auto_tag(f)
        findings.append(f)
    return findings[:30]


# ---------------------------------------------------------------------------
# GOBUSTER OUTPUT PARSER
# ---------------------------------------------------------------------------

def parse_ffuf_output(output, target):
    """Parse ffuf -s (silent) output lines into findings.

    ffuf silent mode prints one result per line:
        /path                   [Status: 200, Size: 1234, Words: 56, Lines: 78, ...]
    Lines starting with '[' are metadata/warnings — skip them.
    """
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("["):
            continue
        # Match: /path  [Status: 200, ...]
        m = re.match(r'^(\S+)\s+\[Status:\s*(\d+)', line)
        if not m:
            continue
        path   = m.group(1)
        status = int(m.group(2))
        severity = "low" if status == 401 else "info"
        title = f"Web path found: {path} [{status}]"
        f = Finding(
            finding_id=make_finding_id("ffuf", target, path),
            tool="ffuf",
            target=target,
            service="http",
            severity=severity,
            title=title,
            evidence=line,
            confidence=TOOL_CONFIDENCE.get("ffuf", 0.6),
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
                detection_method="service_probe",
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
            detection_method="service_probe",
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
    (["tls 1.0", "ssl 2.0", "ssl 3.0", "rc4", "des-cbc", "export cipher", "weak cipher", "weak ssl", "weak tls", "deprecated protocol", "poodle", "beast", "drown"],  "Weak SSL/TLS"),
    (["password authentication", "password-based auth", "brute-force", "weak credential", "default password", "default credential", "default login", "no mfa", "weak password"],  "Weak Authentication"),
    (["misconfiguration", "insecure configuration", "directory listing", "index of /", "server-status", "server-info", "debug mode", "options +indexes"],  "Misconfiguration"),
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
    "SSRF":                    "Probe with internal address that returns a known response",
    "Weak SSL/TLS":           "Confirm via TLS handshake — connect with a client restricted to the weak protocol/cipher",
    "Weak Authentication":    "Attempt login with common default credentials or observe authentication mechanism",
    "Misconfiguration":       "Unauthenticated GET to the misconfigured endpoint and observe response",
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
    "Weak SSL/TLS":           "Successful handshake using the weak protocol or cipher confirmed",
    "Weak Authentication":    "Unauthorised access or successful login with guessed/default credentials confirmed",
    "Misconfiguration":       "Sensitive resource accessible or service configuration exposed without authentication",
    "Unknown":                "Manual verification required",
}

# Effort estimate for each vulnerability type — how hard is this to fix?
# Low    = configuration change or setting toggle (< 1 hour)
# Medium = software patch, minor code change, or policy update (hours to days)
# High   = architectural change, upgrade, or replacement required (days to weeks)
_REMEDIATION_EFFORT = {
    "Buffer Overflow":          "High",
    "Path Traversal":           "Medium",
    "SQL Injection":            "Medium",
    "XSS":                      "Medium",
    "RCE":                      "High",
    "Command Injection":        "High",
    "DoS":                      "Medium",
    "Privilege Escalation":     "Medium",
    "Authentication Bypass":    "Low",
    "Information Disclosure":   "Low",
    "XXE":                      "Medium",
    "Insecure Deserialization": "High",
    "Format String":            "High",
    "Use-After-Free":           "High",
    "Integer Overflow":         "High",
    "Open Redirect":            "Low",
    "SSRF":                     "Medium",
    "Weak SSL/TLS":             "Low",
    "Weak Authentication":      "Low",
    "Misconfiguration":         "Low",
    "Unknown":                  "Medium",
}

# Estimated calendar time to fully remediate (patch + test + deploy).
# Assumes a typical enterprise with a standard change-management cycle.
_REMEDIATION_TIME_ESTIMATE = {
    "Buffer Overflow":          "1–4 weeks (vendor patch + regression testing)",
    "Path Traversal":           "1–3 days (config hardening or patch application)",
    "SQL Injection":            "3–5 days (code changes + QA cycle)",
    "XSS":                      "2–5 days (code changes + CSP deployment)",
    "RCE":                      "2–4 weeks (vendor patch + full regression testing)",
    "Command Injection":        "3–7 days (code changes + QA cycle)",
    "DoS":                      "1–3 days (rate-limiting or patch application)",
    "Privilege Escalation":     "3–7 days (config audit + policy update)",
    "Authentication Bypass":    "< 1 day (config change or policy enforcement)",
    "Information Disclosure":   "< 1 day (config change or endpoint restriction)",
    "XXE":                      "1–3 days (parser config change + testing)",
    "Insecure Deserialization": "1–3 weeks (code refactor + safe serialisation migration)",
    "Format String":            "1–2 weeks (code audit + patch)",
    "Use-After-Free":           "1–4 weeks (vendor patch + regression testing)",
    "Integer Overflow":         "1–2 weeks (code changes + vendor patch)",
    "Open Redirect":            "< 1 day (allowlist config or code change)",
    "SSRF":                     "2–5 days (egress firewall rules + code changes)",
    "Weak SSL/TLS":             "< 1 day (server config change + service restart)",
    "Weak Authentication":      "< 1 day (config change) to 2–3 days (MFA rollout)",
    "Misconfiguration":         "< 1 day (config change or endpoint restriction)",
    "Unknown":                  "Varies — consult vendor advisory",
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


def _parse_semver(v: str) -> tuple:
    """Parse a version string into a comparable tuple of ints.

    Handles: '10.0', '9.8p1', '2.4.50', '1.0.0-beta', '5.0.0+dfsg1'.
    Splits on any non-digit run and collects all leading integer segments.
    """
    if not v:
        return (0,)
    v = re.sub(r'[+~].*$', '', v)   # strip build metadata
    parts = re.split(r'[^0-9]+', v)
    result = tuple(int(p) for p in parts if p)
    return result if result else (0,)


def _extract_fixed_version(summary: str) -> str:
    """Return the patched/fixed version string from a CVE summary, or '' if not determinable.

    Only handles 'before X' / 'prior to X' / '< X' patterns where the fixed version is
    explicit.  Range patterns ('X through Y') are skipped — the upper bound alone is
    insufficient without knowing whether it is inclusive or exclusive.
    """
    m = re.search(r'(?:before|prior to)\s+([\d][.\d\w]+)', summary, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r'<\s*([\d][.\d\w]+)', summary)
    if m:
        return m.group(1)
    return ""


def _version_is_suppressed(detected_ver: str, fixed_ver: str) -> bool:
    """Return True if detected_ver >= fixed_ver (CVE has been patched on this host).

    Returns False when either version is empty, unparseable, or the comparison
    is ambiguous (e.g. a single-component version that matches identically).
    """
    if not detected_ver or not fixed_ver:
        return False
    try:
        det = _parse_semver(detected_ver)
        fix = _parse_semver(fixed_ver)
        if det in ((0,), ()) or fix in ((0,), ()):
            return False
        return det >= fix
    except Exception:
        return False


# ---------------------------------------------------------------------------
# CWE MAPPING — Vulnerability Type to Common Weakness Enumeration
# ---------------------------------------------------------------------------

_CWE_MAPPING = {
    "Buffer Overflow":           "CWE-120 (Buffer Copy without Checking Size)",
    "Path Traversal":            "CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)",
    "SQL Injection":             "CWE-89 (SQL Injection)",
    "XSS":                       "CWE-79 (Improper Neutralization of Input During Web Page Generation)",
    "RCE":                       "CWE-94 (Improper Control of Generation of Code)",
    "Command Injection":         "CWE-78 (OS Command Injection)",
    "DoS":                       "CWE-400 (Uncontrolled Resource Consumption)",
    "Privilege Escalation":      "CWE-269 (Improper Access Control)",
    "Authentication Bypass":     "CWE-287 (Improper Authentication)",
    "Information Disclosure":    "CWE-200 (Information Exposure)",
    "XXE":                       "CWE-611 (Improper Restriction of XML External Entity)",
    "Insecure Deserialization": "CWE-502 (Deserialization of Untrusted Data)",
    "Format String":             "CWE-134 (Use of Externally-Controlled Format String)",
    "Use-After-Free":            "CWE-416 (Use After Free)",
    "Integer Overflow":          "CWE-190 (Integer Overflow or Wraparound)",
    "Open Redirect":             "CWE-601 (URL Redirection to Untrusted Site)",
    "SSRF":                      "CWE-918 (Server-Side Request Forgery)",
    "Weak SSL/TLS":              "CWE-326 (Inadequate Encryption Strength)",
    "Weak Authentication":       "CWE-521 (Weak Password Requirements) / CWE-308 (Use of Single-factor Authentication)",
    "Misconfiguration":          "CWE-16 (Configuration)",
    "Unknown":                   "See NVD for CWE information",
}


# ---------------------------------------------------------------------------
# CVSS v3.1 VECTOR STRINGS
# ---------------------------------------------------------------------------

def _get_cvss_vector(severity: str, vuln_type: str) -> str:
    """Return a representative CVSS v3.1 vector string based on severity and type."""
    vectors = {
        ("critical", "RCE"):                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ("critical", "Buffer Overflow"):        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ("critical", "Authentication Bypass"):  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ("critical", "Insecure Deserialization"): "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ("high", "Path Traversal"):             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        ("high", "SQL Injection"):              "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        ("high", "Command Injection"):          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ("high", "RCE"):                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ("high", "Buffer Overflow"):            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ("medium", "Information Disclosure"):  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        ("medium", "XSS"):                      "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
        ("medium", "SSRF"):                     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        ("medium", "Open Redirect"):            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        ("low", "DoS"):                         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        ("low", "Information Disclosure"):     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    }
    # Return default for unmatched pairs
    return vectors.get((severity.lower(), vuln_type), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")


# ---------------------------------------------------------------------------
# EXPLOIT MATURITY ASSESSMENT
# ---------------------------------------------------------------------------

def _get_exploit_maturity(cve_id: str, vuln_type: str) -> str:
    """Estimate exploit maturity based on vulnerability type.
    
    In production, this would query Exploit-DB and Metasploit APIs for actual PoC data.
    """
    highly_exploited = {
        "RCE", "SQL Injection", "Authentication Bypass", 
        "Path Traversal", "XSS", "Command Injection", "Buffer Overflow"
    }
    moderately_exploited = {
        "Privilege Escalation", "Information Disclosure", "SSRF", "XXE"
    }
    
    if vuln_type in highly_exploited:
        return "Proof of Concept (PoC) Available"
    elif vuln_type in moderately_exploited:
        return "PoC Availability Unknown"
    return "Check Exploit-DB and Metasploit for latest PoCs"


# ---------------------------------------------------------------------------
# COMPLIANCE & REFERENCE MAPPING
# ---------------------------------------------------------------------------

_COMPLIANCE_MAPPING = {
    "Information Disclosure":   ["PCI-DSS 6.5.10", "SOC2 CC7.2", "ISO27001 A.18.1",   "NIST CSF DE.CM-4",  "NIST CSF RS.MI-2"],
    "Authentication Bypass":    ["PCI-DSS 6.5.10", "SOC2 CC6.2", "ISO27001 A.9.2",    "NIST CSF PR.AA-1",  "NIST CSF DE.CM-1"],
    "SQL Injection":            ["PCI-DSS 6.5.1",  "SOC2 CC7.2", "ISO27001 A.14.2",   "NIST CSF PR.DS-2",  "NIST CSF DE.AE-2"],
    "XSS":                      ["PCI-DSS 6.5.1",  "SOC2 CC7.2", "ISO27001 A.14.2",   "NIST CSF PR.DS-2",  "NIST CSF DE.AE-2"],
    "RCE":                      ["PCI-DSS 6.5.2",  "SOC2 CC7.2", "ISO27001 A.14.2",   "NIST CSF RS.MI-2",  "NIST CSF PR.PS-1"],
    "Command Injection":        ["PCI-DSS 6.5.2",  "SOC2 CC7.2", "ISO27001 A.14.2",   "NIST CSF RS.MI-2",  "NIST CSF PR.PS-1"],
    "Buffer Overflow":          ["PCI-DSS 6.5.2",  "SOC2 CC7.2", "ISO27001 A.14.2",   "NIST CSF PR.PS-1",  "NIST CSF RS.MI-2"],
    "Path Traversal":           ["PCI-DSS 6.5.8",  "SOC2 CC7.2", "ISO27001 A.14.2",   "NIST CSF PR.DS-5",  "NIST CSF DE.CM-4"],
    "Open Redirect":            ["PCI-DSS 6.5.10", "SOC2 CC7.2", "ISO27001 A.14.2",   "NIST CSF PR.AA-5"],
    "SSRF":                     ["PCI-DSS 6.5.10", "SOC2 CC7.2", "ISO27001 A.14.2",   "NIST CSF PR.PS-4",  "NIST CSF DE.CM-4"],
    "DoS":                      ["PCI-DSS 6.5.10", "SOC2 CC7.1", "ISO27001 A.12.6",   "NIST CSF DE.AE-4",  "NIST CSF RS.MI-1"],
    "Privilege Escalation":     ["PCI-DSS 6.5.10", "SOC2 CC6.1", "ISO27001 A.9.4",    "NIST CSF PR.AA-3",  "NIST CSF DE.CM-4"],
    "XXE":                      ["PCI-DSS 6.5.1",  "SOC2 CC7.2", "ISO27001 A.14.2",   "NIST CSF PR.DS-2",  "NIST CSF DE.AE-2"],
    "Insecure Deserialization":  ["PCI-DSS 6.5.2",  "SOC2 CC7.2", "ISO27001 A.14.2",   "NIST CSF PR.DS-2",  "NIST CSF RS.MI-2"],
    "Format String":            ["PCI-DSS 6.5.2",  "SOC2 CC7.2", "ISO27001 A.14.2",   "NIST CSF PR.PS-1",  "NIST CSF RS.MI-2"],
    "Use-After-Free":           ["PCI-DSS 6.5.2",  "SOC2 CC7.2", "ISO27001 A.14.2",   "NIST CSF PR.PS-1",  "NIST CSF RS.MI-2"],
    "Integer Overflow":         ["PCI-DSS 6.5.2",  "SOC2 CC7.2", "ISO27001 A.14.2",   "NIST CSF PR.PS-1",  "NIST CSF RS.MI-2"],
}

# One-sentence explanation of WHY each compliance control applies.
# Used in the HTML report to give auditors and stakeholders context.
_COMPLIANCE_REASONING = {
    "PCI-DSS 6.5.1":      "Requires validation and sanitisation of all input to prevent injection flaws",
    "PCI-DSS 6.5.2":      "Requires protection against buffer overflows and unsafe memory operations in custom code",
    "PCI-DSS 6.5.8":      "Requires proper access controls to prevent path traversal and improper object references",
    "PCI-DSS 6.5.10":     "Requires protection against broken authentication, session management, and information exposure",
    "SOC2 CC6.1":         "Logical access controls must restrict system resources to authorised users and processes",
    "SOC2 CC6.2":         "Identity must be registered and authorised before system credentials are issued",
    "SOC2 CC7.1":         "The system must detect threats to availability and respond to protect service continuity",
    "SOC2 CC7.2":         "Security incidents and anomalies must be identified, analysed, and communicated",
    "ISO27001 A.9.2":     "User access management — access rights must be provisioned, reviewed, and revoked appropriately",
    "ISO27001 A.9.4":     "System and application access controls must restrict access to authorised users only",
    "ISO27001 A.12.6":    "Technical vulnerabilities must be identified and remediated in a timely manner",
    "ISO27001 A.14.2":    "Security must be built into development and change processes including secure coding practices",
    "ISO27001 A.18.1":    "Legal and contractual requirements for information protection must be identified and met",
    "NIST CSF PR.AA-1":   "Identities and credentials for authorised devices, users, and processes must be managed",
    "NIST CSF PR.AA-3":   "Users, devices, and services must be authenticated proportionate to the risk",
    "NIST CSF PR.AA-5":   "Access permissions must be managed incorporating the principle of least privilege",
    "NIST CSF PR.DS-2":   "Data in transit must be protected against unauthorised access and modification",
    "NIST CSF PR.DS-5":   "Protections against data leaks must be implemented and maintained",
    "NIST CSF PR.PS-1":   "Configuration management practices must be established and maintained for all technology assets",
    "NIST CSF PR.PS-4":   "Log records must be generated and retained to support continuous monitoring",
    "NIST CSF DE.AE-2":   "Potentially adverse events must be analysed to characterise the threats involved",
    "NIST CSF DE.AE-4":   "The estimated impact and scope of adverse events must be understood",
    "NIST CSF DE.CM-1":   "Networks and services must be monitored to detect adverse events",
    "NIST CSF DE.CM-4":   "Malicious code must be detected and its introduction prevented",
    "NIST CSF RS.MI-1":   "Incidents must be contained to limit their impact on systems and data",
    "NIST CSF RS.MI-2":   "Incidents must be eradicated — the underlying causes must be fully eliminated",
}

_REMEDIATION_REFERENCES = {
    "Information Disclosure":  ["https://owasp.org/www-community/Information_Exposure", "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_References_Cheat_Sheet.html"],
    "Authentication Bypass":   ["https://owasp.org/www-community/attacks/Authentication_Bypass", "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"],
    "SQL Injection":           ["https://owasp.org/www-community/attacks/SQL_Injection", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
    "XSS":                     ["https://owasp.org/www-community/attacks/xss/", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
    "RCE":                     ["https://owasp.org/www-community/attacks/Code_Injection", "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html"],
    "Command Injection":       ["https://owasp.org/www-community/attacks/Command_Injection", "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html"],
    "Buffer Overflow":         ["https://owasp.org/www-community/attacks/Buffer_Overflow", "https://cwe.mitre.org/data/definitions/120.html"],
    "Path Traversal":          ["https://owasp.org/www-community/attacks/Path_Traversal", "https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Cheat_Sheet.html"],
    "Open Redirect":           ["https://owasp.org/www-community/attacks/Open_Redirect", "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
    "SSRF":                    ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery", "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"],
    "DoS":                     ["https://owasp.org/www-community/attacks/Denial_of_Service", "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Prevention_Cheat_Sheet.html"],
    "Privilege Escalation":    ["https://owasp.org/www-community/attacks/Privilege_Escalation", "https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html"],
    "XXE":                     ["https://owasp.org/www-community/attacks/XML_External_Entity", "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"],
    "Insecure Deserialization": ["https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data", "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"],
    "Format String":           ["https://owasp.org/www-community/attacks/Format_string_attack", "https://cwe.mitre.org/data/definitions/134.html"],
    "Use-After-Free":          ["https://owasp.org/www-community/attacks/Use_After_Free", "https://cwe.mitre.org/data/definitions/416.html"],
    "Integer Overflow":        ["https://owasp.org/www-community/attacks/Integer_Overflow", "https://cwe.mitre.org/data/definitions/190.html"],
    "Weak SSL/TLS":            ["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html", "https://cwe.mitre.org/data/definitions/326.html"],
    "Weak Authentication":     ["https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html", "https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html"],
    "Misconfiguration":        ["https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration", "https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html"],
}

# Short-term workarounds: immediate tactical mitigations (firewall, WAF, config)
_REMEDIATION_SHORT_TERM = {
    "Buffer Overflow":          "Apply vendor patch immediately. If unavailable, implement a WAF rule blocking abnormally large payloads, or firewall the affected service port.",
    "Path Traversal":           "Block requests containing `../`, `..\\`, or URL-encoded traversal sequences (`%2e%2e`) at the WAF or reverse proxy.",
    "SQL Injection":            "Deploy WAF rules to block SQL metacharacters. Restrict the database account to the minimum required privileges (read-only where possible).",
    "XSS":                      "Enable a strict Content-Security-Policy header. Apply WAF XSS filter rules to affected endpoints.",
    "RCE":                      "Block inbound traffic to the affected port/service at the perimeter firewall until a patch is applied.",
    "Command Injection":        "Disable or firewall the affected endpoint. If the endpoint must remain live, strip shell metacharacters at the WAF.",
    "DoS":                      "Rate-limit connections to the affected endpoint. Enable DDoS protection upstream if available.",
    "Privilege Escalation":     "Remove SUID bits from non-essential binaries (`chmod -s`). Restrict sudo rules to specific, named commands.",
    "Authentication Bypass":    "Add IP allowlisting or require VPN access for the affected endpoint. Temporarily disable the endpoint if not business-critical.",
    "Information Disclosure":   "Disable directory listing. Require authentication on all sensitive endpoints. Remove debug/error pages from production.",
    "XXE":                      "Disable XML external entity (XXE) processing in the parser configuration. Reject XML input that contains DOCTYPE declarations at the WAF.",
    "Insecure Deserialization": "Disable deserialisation of untrusted data. Add an input-validation layer to reject unexpected serialised payloads.",
    "Format String":            "Block untrusted format-string input at the WAF. Restrict network exposure of the affected service.",
    "Use-After-Free":           "Firewall the affected service. Apply any vendor-supplied mitigations or backport patches.",
    "Integer Overflow":         "Validate and clamp all numeric inputs at the application boundary. Apply vendor patch.",
    "Open Redirect":            "Add a redirect-destination allowlist at the web layer. Log and alert on redirect attempts to external hosts.",
    "SSRF":                     "Block outbound requests from the application server using egress firewall rules. Deny access to internal/metadata IP ranges.",
    "Weak SSL/TLS":             "Disable weak protocols and ciphers in the server configuration immediately. For Apache: set SSLProtocol, SSLCipherSuite. For nginx: set ssl_protocols, ssl_ciphers. Restart the service after changes.",
    "Weak Authentication":      "Disable password-based authentication where key-based or token-based auth is available (e.g. set PasswordAuthentication no in sshd_config). Force a service restart. Rotate any credentials that may have been exposed.",
    "Misconfiguration":         "Disable directory listing and remove or restrict access to exposed admin/debug endpoints. Apply the minimum necessary permissions (principle of least exposure) and restart the affected service.",
    "Unknown":                  "Apply the vendor-recommended workaround. If unavailable, restrict network access to the affected service until patched.",
}

# Long-term fixes: permanent remediation (patching, code changes, architecture)
_REMEDIATION_LONG_TERM = {
    "Buffer Overflow":          "Upgrade to the patched version. Adopt memory-safe languages for new components. Enable OS-level mitigations: ASLR, DEP/NX, stack canaries.",
    "Path Traversal":           "Upgrade to the patched version. Implement strict server-side path canonicalisation and validate that resolved paths begin with an allowed base directory.",
    "SQL Injection":            "Migrate all database interactions to parameterised queries or ORM frameworks. Perform a full code audit. Use least-privilege DB accounts.",
    "XSS":                      "Adopt a templating framework with context-aware auto-escaping. Implement a strict Content-Security-Policy. Conduct developer training on output encoding.",
    "RCE":                      "Upgrade to the patched version. Enforce strict input validation and use least-privilege execution contexts for all application processes.",
    "Command Injection":        "Replace shell invocations with native library calls. Upgrade to the patched version. Perform a full audit of all subprocess/exec calls in the codebase.",
    "DoS":                      "Upgrade to the patched version. Implement connection throttling, request-size limits, and resource quotas at the application level.",
    "Privilege Escalation":     "Upgrade to the patched version. Adopt the principle of least privilege across all services. Conduct periodic SUID/sudo rule audits.",
    "Authentication Bypass":    "Upgrade to the patched version. Implement MFA. Conduct a full audit of all authentication code paths and session management.",
    "Information Disclosure":   "Upgrade to the patched version. Audit all endpoints for unintended data exposure. Remove unnecessary debug endpoints from production builds.",
    "XXE":                      "Upgrade the XML parser to a patched version. Migrate to JSON APIs where possible. Disable DTD processing globally.",
    "Insecure Deserialization": "Migrate to a safe serialisation format (JSON, protobuf). Upgrade to the patched version. Implement integrity checks (HMAC) on serialised data.",
    "Format String":            "Upgrade to the patched version. Audit all printf-family calls in the codebase. Never pass user input directly as a format string.",
    "Use-After-Free":           "Upgrade to the patched version. Adopt memory-safe languages or enable address sanitizers in development and staging pipelines.",
    "Integer Overflow":         "Upgrade to the patched version. Add explicit bounds checking throughout the codebase. Use checked-arithmetic primitives.",
    "Open Redirect":            "Remove dynamic redirect destinations entirely. Use fixed route mappings inside the application. Validate all redirect targets server-side.",
    "SSRF":                     "Upgrade to the patched version. Implement a strict URL allowlist for all outbound requests from the application server.",
    "Weak SSL/TLS":             "Audit all TLS endpoints and enforce TLS 1.2 as the minimum (TLS 1.3 preferred). Remove all RC4, 3DES, and export-grade ciphers. Implement HSTS and review certificate validity periods.",
    "Weak Authentication":      "Migrate entirely to public key or token-based authentication. Enforce MFA across all privileged access paths. Establish a credential rotation policy and conduct a periodic access review. Remove or disable all default accounts and credentials.",
    "Misconfiguration":         "Conduct a full configuration audit against a hardening baseline (CIS Benchmarks or vendor security guides). Disable all non-essential features, endpoints, and services. Integrate configuration drift detection into the CI/CD pipeline.",
    "Unknown":                  "Apply the vendor security update. Review the OWASP guidelines and NVD advisory for the affected component. Conduct a targeted code review.",
}

# Reproduction steps: curl/shell snippets for independent developer verification
# {target} and {port} are literal placeholders for the reader to substitute.
_STEPS_TO_REPRODUCE = {
    "Buffer Overflow":          "# Version-banner fingerprint only — do not send overflow payloads to production\ncurl -v \"http://{target}:{port}/\" -I | grep -i server",
    "Path Traversal":           "curl -v \"http://{target}:{port}/../../../../etc/passwd\"\n# Also try URL-encoded: /%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "SQL Injection":            "curl -v \"http://{target}:{port}/search?q=1%27+OR+%271%27%3D%271\"\n# Check response for DB errors or unexpected rows",
    "XSS":                      "curl -v \"http://{target}:{port}/page?input=%3Cscript%3Ealert(1)%3C%2Fscript%3E\"\n# Check if payload is reflected unescaped in the response",
    "RCE":                      "curl -v \"http://{target}:{port}/\" -d \"cmd=id\"\n# Verify response contains uid= to confirm command execution",
    "Command Injection":        "curl -v \"http://{target}:{port}/?input=%3Bid\"\n# Check response for uid= output",
    "DoS":                      "# Version-banner fingerprint only — never trigger DoS against production\ncurl -v \"http://{target}:{port}/\" -I | grep -i server",
    "Privilege Escalation":     "# Local access required\nfind / -perm -4000 -type f 2>/dev/null\nsudo -l",
    "Authentication Bypass":    "curl -v \"http://{target}:{port}/admin/\" --head\n# A 200 response without credentials confirms bypass",
    "Information Disclosure":   "curl -v \"http://{target}:{port}/server-status\"\ncurl -v \"http://{target}:{port}/.env\"\ncurl -v \"http://{target}:{port}/phpinfo.php\"",
    "XXE":                      "curl -v \"http://{target}:{port}/api\" \\\n  -H 'Content-Type: application/xml' \\\n  -d '<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY test \"xxe-test\">]><x>&test;</x>'\n# Check if entity value appears in response",
    "Insecure Deserialization": "# Check for Java deserialization endpoint:\ncurl -v \"http://{target}:{port}/\" \\\n  -H 'Content-Type: application/x-java-serialized-object' --head",
    "Format String":            "# Version-banner fingerprint only — never send format strings to production\ncurl -v \"http://{target}:{port}/\" -I | grep -i server",
    "Use-After-Free":           "# Version-banner fingerprint only\ncurl -v \"http://{target}:{port}/\" -I | grep -i server",
    "Integer Overflow":         "# Version-banner fingerprint only\ncurl -v \"http://{target}:{port}/\" -I | grep -i server",
    "Open Redirect":            "curl -v \"http://{target}:{port}/redirect?url=https://example.com\" -L\n# Check the Location header — confirm redirect leaves the target domain",
    "SSRF":                     "curl -v \"http://{target}:{port}/fetch?url=http://169.254.169.254/latest/meta-data/\"\n# A non-empty response confirms the server fetches internal URLs",
    "Unknown":                  "curl -v \"http://{target}:{port}/\" -I\n# Review server banner and response headers for version disclosure",
}


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

    # EPSS lookup
    epss_db = _load_epss_db()
    epss_entry = epss_db.get(cve["id"].upper(), (0.0, 0.0))
    epss_score      = epss_entry[0]
    epss_percentile = epss_entry[1]

    # CISA KEV lookup
    kev_db    = _load_kev_db()
    kev_entry = kev_db.get(cve["id"].upper())
    kev_listed   = kev_entry is not None
    kev_due_date = (kev_entry or {}).get("due_date", "")

    # NVD CVSS lookup — prefer authoritative NVD data over derived estimates
    cvss_db    = _load_cvss_db()
    cvss_entry = cvss_db.get(cve["id"].upper())
    if cvss_entry:
        nvd_v3_score, nvd_v3_vector, nvd_v3_severity, nvd_v4_score, nvd_v4_vector, nvd_cwe_id = cvss_entry
        # Use NVD score if it's non-zero; fall back to passed-in value
        resolved_cvss_score  = nvd_v3_score or cve.get("cvss_score", 0.0)
        resolved_cvss_vector = nvd_v3_vector or _get_cvss_vector(severity, vuln_type)
    else:
        nvd_v3_score = nvd_v3_vector = nvd_v3_severity = ""
        nvd_v4_score = nvd_v4_vector = nvd_cwe_id = ""
        resolved_cvss_score  = cve.get("cvss_score", 0.0)
        resolved_cvss_vector = _get_cvss_vector(severity, vuln_type)

    # CWE resolution: NVD-extracted beats inferred-from-vuln-type
    inferred_cwe = _CWE_MAPPING.get(vuln_type, "")
    resolved_cwe = nvd_cwe_id or (inferred_cwe.split(" ")[0] if inferred_cwe else "")

    # CWE detail lookup from offline dictionary
    cwe_db   = _load_cwe_db()
    cwe_info = cwe_db.get(resolved_cwe, {})

    return {
        "cve_id":                cve["id"],
        "severity":              cve["severity"],
        "cvss_score":            resolved_cvss_score,
        "cvss_vector":           resolved_cvss_vector,
        "nvd_cvss_v3_score":     nvd_v3_score,
        "nvd_cvss_v3_vector":    nvd_v3_vector,
        "nvd_cvss_v3_severity":  nvd_v3_severity,
        "nvd_cvss_v4_score":     nvd_v4_score,
        "nvd_cvss_v4_vector":    nvd_v4_vector,
        "epss_score":            epss_score,
        "epss_percentile":       epss_percentile,
        "kev_listed":            kev_listed,
        "kev_due_date":          kev_due_date,
        "cwe_id":                resolved_cwe or _CWE_MAPPING.get(vuln_type, "See NVD for CWE information"),
        "cwe_name":              cwe_info.get("name", ""),
        "cwe_description":       cwe_info.get("description", ""),
        "cwe_consequences":      cwe_info.get("consequences", ""),
        "cwe_likelihood":        cwe_info.get("likelihood", ""),
        "cwe_mitigation":        cwe_info.get("mitigation", ""),
        "cwe_abstraction":       cwe_info.get("abstraction", ""),
        "exploit_maturity":      _get_exploit_maturity(cve["id"], vuln_type),
        "product":               product,
        "version_affected":      version if version else "unknown",
        "version_range":         _infer_version_range(summary),
        "vulnerability_type":    vuln_type,
        "requires_auth":         requires_auth,
        "remote":                remote,
        "compliance_controls":   _COMPLIANCE_MAPPING.get(vuln_type, ["See compliance frameworks"]),
        "effort":                _REMEDIATION_EFFORT.get(vuln_type, "Medium"),
        "time_to_fix":           _REMEDIATION_TIME_ESTIMATE.get(vuln_type, _REMEDIATION_TIME_ESTIMATE["Unknown"]),
        "references":            _REMEDIATION_REFERENCES.get(vuln_type, ["https://nvd.nist.gov/", "https://owasp.org/"]),
        "safe_validation_method": _SAFE_VALIDATION.get(vuln_type, _SAFE_VALIDATION["Unknown"]),
        "proof_of_impact":       _PROOF_OF_IMPACT.get(vuln_type, _PROOF_OF_IMPACT["Unknown"]),
        "business_impact":       business_impact,
        "summary":               summary,
        "remediation_short":     _REMEDIATION_SHORT_TERM.get(vuln_type, _REMEDIATION_SHORT_TERM["Unknown"]),
        "remediation_long":      _REMEDIATION_LONG_TERM.get(vuln_type, _REMEDIATION_LONG_TERM["Unknown"]),
        "steps_to_reproduce":    _STEPS_TO_REPRODUCE.get(vuln_type, _STEPS_TO_REPRODUCE["Unknown"]),
    }


# ---------------------------------------------------------------------------
# METASPLOIT VALIDATION
# ---------------------------------------------------------------------------
# Module registry: CVE → module metadata including safety profile and scoring.
# Every entry is vetted. Only modules that pass _msf_decision() are ever run.
# RHOSTS is always set from the target; RPORT is overridden by the actual
# discovered service port at runtime.
#
# Safety fields:
#   intrusive       — check action itself can modify state or cause instability
#   dos_risk        — "low" | "medium" | "high" risk of disrupting the target
#   check_supported — exploit modules: does 'check' work without a payload?
#                     auxiliary modules: always False (use 'run' instead)
#
# Scoring fields (final_score = confidence_score - risk_score):
#   >= 0.5  → auto-run
#   0.2–0.5 → restricted run (tighter timeouts / thread limits)
#   < 0.2   → skip
#
# Hard overrides (enforced in _msf_decision — cannot be bypassed):
#   dos_risk == "high"                             → always block
#   intrusive == True                              → always block
#   type == "exploit" and check_supported == False → always block

MSF_MODULE_REGISTRY: dict = {
    # Windows SMB
    "CVE-2017-0144": {
        "module": "exploit/windows/smb/ms17_010_eternalblue",
        "type": "exploit", "default_opts": {"RPORT": "445"},
        "check_supported": True, "intrusive": False, "dos_risk": "low",
        "confidence_score": 0.95, "risk_score": 0.40,
        "tags": ["smb", "windows", "rce"],
    },
    "CVE-2017-0145": {
        "module": "exploit/windows/smb/ms17_010_psexec",
        "type": "exploit", "default_opts": {"RPORT": "445"},
        "check_supported": True, "intrusive": False, "dos_risk": "low",
        "confidence_score": 0.90, "risk_score": 0.40,
        "tags": ["smb", "windows", "rce"],
    },
    "CVE-2008-4250": {
        "module": "exploit/windows/smb/ms08_067_netapi",
        "type": "exploit", "default_opts": {"RPORT": "445"},
        "check_supported": True, "intrusive": False, "dos_risk": "low",
        "confidence_score": 0.90, "risk_score": 0.35,
        "tags": ["smb", "windows", "rce"],
    },
    # Windows RDP — BlueKeep check is known to trigger crashes on some systems
    "CVE-2019-0708": {
        "module": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
        "type": "exploit", "default_opts": {"RPORT": "3389"},
        "check_supported": True, "intrusive": True, "dos_risk": "high",
        "confidence_score": 0.90, "risk_score": 0.90,
        "tags": ["rdp", "windows", "rce"],
    },
    # Apache
    "CVE-2021-41773": {
        "module": "exploit/multi/http/apache_normalize_path_rce",
        "type": "exploit", "default_opts": {"RPORT": "80", "TARGETURI": "/"},
        "check_supported": True, "intrusive": False, "dos_risk": "low",
        "confidence_score": 0.90, "risk_score": 0.30,
        "tags": ["http", "apache", "rce", "path-traversal"],
    },
    "CVE-2021-42013": {
        "module": "exploit/multi/http/apache_normalize_path_rce",
        "type": "exploit", "default_opts": {"RPORT": "80", "TARGETURI": "/"},
        "check_supported": True, "intrusive": False, "dos_risk": "low",
        "confidence_score": 0.90, "risk_score": 0.30,
        "tags": ["http", "apache", "rce", "path-traversal"],
    },
    "CVE-2014-6271": {
        "module": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
        "type": "exploit", "default_opts": {"RPORT": "80", "TARGETURI": "/cgi-bin/test.cgi"},
        "check_supported": True, "intrusive": False, "dos_risk": "low",
        "confidence_score": 0.85, "risk_score": 0.35,
        "tags": ["http", "shellshock", "rce"],
    },
    # OpenSSL Heartbleed — auxiliary scanner, uses 'run' not 'check'
    "CVE-2014-0160": {
        "module": "auxiliary/scanner/ssl/openssl_heartbleed",
        "type": "auxiliary", "default_opts": {"RPORT": "443"},
        "check_supported": False, "intrusive": False, "dos_risk": "low",
        "confidence_score": 0.95, "risk_score": 0.05,
        "tags": ["ssl", "heartbleed", "memory-disclosure"],
    },
    # Log4Shell
    "CVE-2021-44228": {
        "module": "exploit/multi/misc/log4shell_header_injection",
        "type": "exploit", "default_opts": {"RPORT": "8080"},
        "check_supported": True, "intrusive": False, "dos_risk": "low",
        "confidence_score": 0.90, "risk_score": 0.25,
        "tags": ["log4j", "java", "rce", "jndi"],
    },
    # Exchange
    "CVE-2021-26855": {
        "module": "exploit/windows/http/exchange_proxylogon_rce",
        "type": "exploit", "default_opts": {"RPORT": "443", "SSL": "true"},
        "check_supported": True, "intrusive": False, "dos_risk": "low",
        "confidence_score": 0.90, "risk_score": 0.30,
        "tags": ["http", "exchange", "ssrf", "rce"],
    },
    "CVE-2021-34473": {
        "module": "exploit/windows/http/exchange_proxyshell_rce",
        "type": "exploit", "default_opts": {"RPORT": "443", "SSL": "true"},
        "check_supported": True, "intrusive": False, "dos_risk": "low",
        "confidence_score": 0.90, "risk_score": 0.30,
        "tags": ["http", "exchange", "rce"],
    },
    # MySQL
    "CVE-2012-2122": {
        "module": "auxiliary/scanner/mysql/mysql_authbypass_hashdump",
        "type": "auxiliary", "default_opts": {"RPORT": "3306"},
        "check_supported": False, "intrusive": False, "dos_risk": "low",
        "confidence_score": 0.80, "risk_score": 0.15,
        "tags": ["mysql", "auth-bypass"],
    },
    # vsFTPd backdoor
    "CVE-2011-2523": {
        "module": "exploit/unix/ftp/vsftpd_234_backdoor",
        "type": "exploit", "default_opts": {"RPORT": "21"},
        "check_supported": True, "intrusive": False, "dos_risk": "low",
        "confidence_score": 0.90, "risk_score": 0.35,
        "tags": ["ftp", "backdoor", "rce"],
    },
    # libssh auth bypass — auxiliary scanner
    "CVE-2018-10933": {
        "module": "auxiliary/scanner/ssh/libssh_auth_bypass",
        "type": "auxiliary", "default_opts": {"RPORT": "22"},
        "check_supported": False, "intrusive": False, "dos_risk": "low",
        "confidence_score": 0.85, "risk_score": 0.10,
        "tags": ["ssh", "auth-bypass"],
    },
    # Samba
    "CVE-2017-7494": {
        "module": "exploit/linux/samba/is_known_pipename",
        "type": "exploit", "default_opts": {"RPORT": "445"},
        "check_supported": True, "intrusive": False, "dos_risk": "low",
        "confidence_score": 0.85, "risk_score": 0.40,
        "tags": ["smb", "samba", "linux", "rce"],
    },
    # CUPS 2024 chain — auxiliary scanners
    "CVE-2024-47076": {
        "module": "auxiliary/scanner/misc/cups_ipp_bsc",
        "type": "auxiliary", "default_opts": {"RPORT": "631"},
        "check_supported": False, "intrusive": False, "dos_risk": "low",
        "confidence_score": 0.80, "risk_score": 0.10,
        "tags": ["cups", "ipp", "rce"],
    },
    "CVE-2024-47175": {
        "module": "auxiliary/scanner/misc/cups_ipp_bsc",
        "type": "auxiliary", "default_opts": {"RPORT": "631"},
        "check_supported": False, "intrusive": False, "dos_risk": "low",
        "confidence_score": 0.80, "risk_score": 0.10,
        "tags": ["cups", "ipp", "rce"],
    },
    "CVE-2024-47176": {
        "module": "auxiliary/scanner/misc/cups_ipp_bsc",
        "type": "auxiliary", "default_opts": {"RPORT": "631"},
        "check_supported": False, "intrusive": False, "dos_risk": "low",
        "confidence_score": 0.80, "risk_score": 0.10,
        "tags": ["cups", "ipp", "rce"],
    },
    "CVE-2024-47177": {
        "module": "auxiliary/scanner/misc/cups_ipp_bsc",
        "type": "auxiliary", "default_opts": {"RPORT": "631"},
        "check_supported": False, "intrusive": False, "dos_risk": "low",
        "confidence_score": 0.80, "risk_score": 0.10,
        "tags": ["cups", "ipp", "rce"],
    },
    # Drupal
    "CVE-2018-7600": {
        "module": "exploit/unix/webapp/drupal_drupalgeddon2",
        "type": "exploit", "default_opts": {"RPORT": "80", "TARGETURI": "/"},
        "check_supported": True, "intrusive": False, "dos_risk": "low",
        "confidence_score": 0.90, "risk_score": 0.30,
        "tags": ["http", "drupal", "rce"],
    },
    # Spring4Shell
    "CVE-2022-22965": {
        "module": "exploit/multi/http/spring_framework_rce_spring4shell",
        "type": "exploit", "default_opts": {"RPORT": "8080"},
        "check_supported": True, "intrusive": False, "dos_risk": "low",
        "confidence_score": 0.85, "risk_score": 0.30,
        "tags": ["http", "spring", "java", "rce"],
    },
    # Citrix
    "CVE-2019-19781": {
        "module": "exploit/multi/http/citrix_dir_traversal_rce",
        "type": "exploit", "default_opts": {"RPORT": "443", "SSL": "true"},
        "check_supported": True, "intrusive": False, "dos_risk": "medium",
        "confidence_score": 0.85, "risk_score": 0.35,
        "tags": ["http", "citrix", "path-traversal", "rce"],
    },
}


def _msf_decision(entry: dict) -> str:
    """Determine execution tier for a registry entry.

    Hard overrides (non-negotiable — enforced before scoring):
    - dos_risk == "high"                              → "block"
    - intrusive == True                               → "block"
    - type == "exploit" and check_supported == False  → "block"

    Scoring model:
    - final_score = confidence_score - risk_score
    - >= 0.5  → "auto"
    - 0.2–0.5 → "restricted"
    - < 0.2   → "block"
    """
    if entry.get("dos_risk") == "high":
        return "block"
    if entry.get("intrusive"):
        return "block"
    if entry.get("type") == "exploit" and not entry.get("check_supported"):
        return "block"

    final_score = entry.get("confidence_score", 0.5) - entry.get("risk_score", 0.5)
    if final_score >= 0.5:
        return "auto"
    if final_score >= 0.2:
        return "restricted"
    return "block"


def _msf_apply_restrictions(options: dict) -> dict:
    """Tighten connection parameters for 'restricted' tier modules."""
    restricted = dict(options)
    restricted["ConnectTimeout"] = "5"
    restricted["Threads"] = "2"
    return restricted


async def _msf_search_module(cve_id: str, msf_path: str) -> str | None:
    """Search msfconsole for a module matching the given CVE. Returns first result or None."""
    cmd    = [msf_path, "-q", "-x", f"search cve:{cve_id}; exit"]
    output = await run_command_async(cmd, timeout=60)
    for line in output.splitlines():
        m = re.match(r'\s*\d+\s+((?:exploit|auxiliary|post)/\S+)', line)
        if m:
            return m.group(1)
    return None


async def _msf_run_check(module: str, options: dict, target: str, msf_path: str,
                          use_run: bool = False) -> dict:
    """Run a single MSF module against the target.

    - exploit modules  → 'check' only (non-destructive, no payload)
    - auxiliary modules → 'run' (scanners are inherently non-destructive)

    Never calls 'exploit' or 'run' on an exploit module.
    """
    action   = "run" if use_run else "check"
    set_cmds = "; ".join(f"set {k} {v}" for k, v in options.items())
    x_cmd    = f"use {module}; set RHOSTS {target}; {set_cmds}; set ConnectTimeout 10; {action}; exit"
    output   = await run_command_async([msf_path, "-q", "-x", x_cmd], timeout=90)

    vulnerable  = None
    result_text = f"No result returned from {action}"
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
        "method":      f"Metasploit {action} (non-destructive — no payload executed)",
        "raw_output":  output[:600],
    }


async def run_msf_validation(report: dict, target: str, session_dir: str,
                              available_tools: dict) -> dict:
    """
    Enrich each cve_match in the report with an MSF check result.
    Mutates and returns the report dict.

    Execution tiers (from _msf_decision):
      auto       — run immediately (high confidence, low risk)
      restricted — run with tighter timeouts and thread cap
      block      — skip entirely (high dos_risk, intrusive, or unsafe check)

    Never calls 'exploit' or 'run' on an exploit module.
    Auxiliary modules are run with 'run' (scanners are non-destructive by design).
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
        if UNATTENDED:
            print("[*] UNATTENDED: auto-approving MSF validation.")
            answer = "y"
        else:
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
    print(f"  Method : scored allowlist — check/run only, no payloads")
    print(f"{'=' * 52}")

    validated = 0
    for cve in cve_matches:
        cve_id   = cve["cve_id"]
        svc_port = re.match(r'(\d+)/', cve.get("service", ""))
        port     = svc_port.group(1) if svc_port else "80"

        registry_entry = MSF_MODULE_REGISTRY.get(cve_id)
        if registry_entry:
            tier    = _msf_decision(registry_entry)
            module  = registry_entry["module"]
            mod_type = registry_entry["type"]
            options = {**registry_entry["default_opts"], "RPORT": port}
            final_score = (registry_entry["confidence_score"]
                           - registry_entry["risk_score"])

            if tier == "block":
                dos = registry_entry.get("dos_risk", "")
                why = ("dos_risk=high" if dos == "high" else
                       "intrusive"     if registry_entry.get("intrusive") else
                       "exploit with no safe check")
                print(f"  [MSF] {cve_id} — BLOCKED ({why}, score {final_score:.2f})")
                cve["msf_validation"] = {
                    "module": module, "vulnerable": None,
                    "result": f"Blocked by safety policy: {why}",
                    "method": "blocked", "raw_output": "",
                    "tier": "block", "final_score": round(final_score, 2),
                }
                continue

            if tier == "restricted":
                options = _msf_apply_restrictions(options)
                print(f"  [MSF] {cve_id} — RESTRICTED run (score {final_score:.2f}) "
                      f"→ {module}  (port {port}) ...", end=" ", flush=True)
            else:
                print(f"  [MSF] {cve_id} — AUTO run (score {final_score:.2f}) "
                      f"→ {module}  (port {port}) ...", end=" ", flush=True)

            use_run = (mod_type == "auxiliary")
        else:
            # CVE not in registry — search MSF, treat as restricted with unknown metadata
            print(f"  [MSF] {cve_id} — not in registry, searching MSF ...")
            module  = await _msf_search_module(cve_id, msf_path)
            options = {"RPORT": port}
            use_run = False
            tier    = "restricted"
            final_score = None

            if not module:
                print(f"  [MSF] {cve_id} — no module found, skipping")
                cve["msf_validation"] = {
                    "module": None, "vulnerable": None,
                    "result": "No Metasploit module found for this CVE",
                    "method": "none", "raw_output": "",
                    "tier": "skip", "final_score": None,
                }
                continue

            # Apply restrictions for unvetted modules found by search
            options = _msf_apply_restrictions(options)
            print(f"  [MSF] {cve_id} — RESTRICTED (unvetted) → {module}  (port {port}) ...",
                  end=" ", flush=True)

        result = await _msf_run_check(module, options, target, msf_path, use_run=use_run)
        result["tier"]        = tier
        result["final_score"] = round(final_score, 2) if final_score is not None else None
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
        # Attempt to self-heal: build the CSV on the fly.
        build_script = os.path.join(BASE_DIR, "scripts", "build_cve_db.py")
        if os.path.exists(build_script):
            print(f"[!] CVE database not found at {CVE_CSV} — attempting to build it now ...")
            import subprocess
            result = subprocess.run(
                [sys.executable, build_script],
                cwd=BASE_DIR,
            )
            if result.returncode != 0 or not os.path.exists(CVE_CSV):
                sys.exit(
                    f"[FATAL] CVE database could not be built.\n"
                    f"        Run:  python3 scripts/build_cve_db.py\n"
                    f"        Expected output: {CVE_CSV}"
                )
            print("[+] CVE database built successfully")
        else:
            sys.exit(
                f"[FATAL] CVE database not found at {CVE_CSV}\n"
                f"        and build script is missing at {build_script}"
            )
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

    # Strip generic OS/vendor prefixes ("Microsoft Windows ", "Apple macOS ", etc.)
    # before deciding how to search. If the remainder is too short or generic we
    # fall straight through to Priority 3 (service-name product map).
    VENDOR_PREFIXES = [
        "microsoft windows ", "microsoft ", "apple macos ", "apple ", "google ",
        "sun ", "novell ", "ibm ", "hp ", "oracle ",
    ]
    effective_product = product.lower()
    for pfx in VENDOR_PREFIXES:
        if effective_product.startswith(pfx):
            effective_product = effective_product[len(pfx):].strip()
            break
    TRIVIAL_WORDS = {"rpc", "ssn", "server", "client", "service", "host", "daemon"}
    searchable_product = product if (len(effective_product) >= 5 and effective_product not in TRIVIAL_WORDS) else ""

    # Priority 1: exact product + version match (most precise)
    if searchable_product and version:
        _add([searchable_product, version])

    # Priority 2: product name only
    if searchable_product and len(results) < 5:
        _add([searchable_product])
        # For compound names like "Werkzeug httpd" or "Golang net/http server",
        # also try just the distinguishing first word if it's specific enough.
        parts = searchable_product.split()
        if len(parts) > 1:
            first = parts[0]
            GENERIC_WORDS = {
                "the", "this", "open", "free", "net", "web", "http", "server",
                # vendor/OS names too broad to search alone:
                "microsoft", "windows", "linux", "unix", "gnu", "apple", "google",
                "cisco", "oracle", "ibm", "hp", "sun", "novell", "redhat", "debian",
            }
            if len(first) >= 5 and first.lower() not in GENERIC_WORDS:
                if version:
                    _add([first, version])
                if len(results) < 5:
                    _add([first])

    # Priority 3: service-specific product keyword mapping.
    # Used when no searchable product was detected or results still < 5.
    if not searchable_product and name and name not in ("unknown", ""):
        SERVICE_PRODUCT_MAP = {
            "ipp":            ["cups"],
            "ms-wbt-server":  ["rdp", "remote desktop"],
            "microsoft-ds":   ["smb", "samba"],
            "netbios-ssn":    ["netbios", "samba"],
            "msrpc":          ["ms-rpc", "dcerpc"],
            "ssh":            ["openssh"],
            "ftp":            ["vsftpd", "proftpd"],
            "smtp":           ["postfix", "sendmail", "exim"],
            "mysql":          ["mysql", "mariadb"],
            "mssql":          ["ms-sql"],
            "ms-sql":         ["ms-sql"],
            "rdp":            ["rdp", "remote desktop"],
            "vnc":            ["vnc", "tightvnc", "realvnc"],
            "ldap":           ["openldap", "active directory"],
            "snmp":           ["snmp", "net-snmp"],
        }
        for kw in SERVICE_PRODUCT_MAP.get(name.lower(), []):
            if len(results) < 5:
                _add([kw])

    # Version suppression — filter out CVEs where the detected version is known
    # to be at or above the fixed/patched version stated in the CVE summary.
    # Suppressed CVEs are returned separately so the report can show them in a
    # collapsed section rather than silently dropping them.
    active     = []
    suppressed = []
    for cve in results:
        fixed_ver = _extract_fixed_version(cve.get("summary", ""))
        if fixed_ver and version and _version_is_suppressed(version, fixed_ver):
            suppressed.append({
                **cve,
                "_suppression_reason": (
                    f"Detected version {version} \u2265 fixed {fixed_ver} "
                    f"(per CVE summary)"
                ),
            })
        else:
            active.append(cve)

    return active[:5], suppressed


# ---------------------------------------------------------------------------
# NMAP
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 5-PHASE NMAP DISCOVERY
# ---------------------------------------------------------------------------

def _nmap_run(args: list, timeout: int = 120) -> str:
    """Execute nmap with the given args and return stdout. Returns '' on error."""
    try:
        result = subprocess.run(
            ["nmap"] + args,
            capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        print("[!] nmap timed out")
        return ""
    except Exception as e:
        print(f"[!] nmap error: {e}")
        return ""


def _parse_nmap_xml(xml_data: str) -> list:
    """Parse nmap XML output into a list of service dicts."""
    services = []
    try:
        root = ET.fromstring(xml_data)
        for port in root.findall(".//port"):
            state_el = port.find("state")
            if state_el is not None and state_el.attrib.get("state") != "open":
                continue
            service_el = port.find("service")
            portid    = port.attrib.get("portid", "")
            protocol  = port.attrib.get("protocol", "tcp")
            name      = ""
            product   = ""
            version   = ""
            extrainfo = ""
            tunnel    = ""
            if service_el is not None:
                name      = service_el.attrib.get("name", "")
                product   = service_el.attrib.get("product", "")
                version   = service_el.attrib.get("version", "")
                extrainfo = service_el.attrib.get("extrainfo", "")
                tunnel    = service_el.attrib.get("tunnel", "")
            # Normalise SSL/TLS services so downstream logic can detect HTTPS
            if tunnel in ("ssl", "tls") and name and "ssl" not in name:
                name = f"ssl/{name}"
            services.append({
                "port":      portid,
                "protocol":  protocol,
                "name":      name,
                "product":   product,
                "version":   version,
                "extrainfo": extrainfo,
            })
    except ET.ParseError as e:
        print(f"[!] Failed to parse nmap XML: {e}")
    return services


def _nmap_extract_script_output(xml_data: str, batch_ports: list | None = None) -> dict:
    """Return {port: {script_id: output}} from nmap XML that contains script results.

    Host-level scripts (e.g. SMB scripts that run against the host rather than
    a specific port) are attributed to the first port in batch_ports, or to the
    special key 'host' when batch_ports is not supplied.
    """
    results: dict = {}
    try:
        root = ET.fromstring(xml_data)
        # Per-port scripts
        for port_el in root.findall(".//port"):
            portid = port_el.attrib.get("portid", "?")
            for script_el in port_el.findall("script"):
                sid    = script_el.attrib.get("id", "")
                output = script_el.attrib.get("output", "")
                results.setdefault(portid, {})[sid] = output
        # Host-level scripts (SMB, OS detection scripts etc.)
        host_key = batch_ports[0] if batch_ports else "host"
        for script_el in root.findall(".//hostscript/script"):
            sid    = script_el.attrib.get("id", "")
            output = script_el.attrib.get("output", "")
            results.setdefault(host_key, {})[sid] = output
    except ET.ParseError:
        pass
    return results


# Map service name → NSE scripts that give the most decision-making value.
# These are used by Phase 3 to build targeted script batches per service.
# Safe/discovery scripts only — no DoS, no active exploitation, no brute-force,
# no scripts requiring external API keys.
_NSE_SCRIPT_MAP = {
    # ── HTTP (plain) ─────────────────────────────────────────────────
    "http": (
        "http-title,http-headers,http-methods,http-auth-finder,http-server-header,"
        "http-security-headers,http-robots.txt,http-cookie-flags,http-cors,http-git,"
        "http-config-backup,http-internal-ip-disclosure,http-php-version,"
        "http-generator,http-favicon,http-waf-detect,http-apache-server-status,"
        "http-devframework"
    ),
    # ── HTTPS / SSL ─────────────────────────────────────────────────
    "ssl/http": (
        "http-title,http-headers,http-methods,http-auth-finder,http-server-header,"
        "http-security-headers,http-robots.txt,ssl-cert,ssl-enum-ciphers,"
        "http-cookie-flags,http-cors,http-git,http-config-backup,"
        "http-internal-ip-disclosure,http-php-version,http-generator,http-favicon,"
        "http-waf-detect,http-apache-server-status,http-devframework,"
        "ssl-heartbleed,ssl-dh-params,ssl-poodle,sslv2-drown,ssl-ccs-injection,"
        "tls-ticketbleed"
    ),
    "https": (
        "http-title,http-headers,http-methods,http-auth-finder,http-server-header,"
        "http-security-headers,http-robots.txt,ssl-cert,ssl-enum-ciphers,"
        "http-cookie-flags,http-cors,http-git,http-config-backup,"
        "http-internal-ip-disclosure,http-php-version,http-generator,http-favicon,"
        "http-waf-detect,http-apache-server-status,http-devframework,"
        "ssl-heartbleed,ssl-dh-params,ssl-poodle,sslv2-drown,ssl-ccs-injection,"
        "tls-ticketbleed"
    ),
    # ── Alternate / proxy HTTP ────────────────────────────────────────────
    "http-alt": (
        "http-title,http-headers,http-methods,http-auth-finder,http-server-header,"
        "http-security-headers,http-robots.txt,http-cookie-flags,http-cors,http-git,"
        "http-config-backup,http-internal-ip-disclosure,http-php-version,"
        "http-generator,http-favicon,http-waf-detect,http-apache-server-status,"
        "http-devframework"
    ),
    "http-proxy": (
        "http-title,http-headers,http-methods,http-auth-finder,http-server-header,"
        "http-security-headers,http-robots.txt,http-cookie-flags,http-cors,http-git,"
        "http-config-backup,http-internal-ip-disclosure,http-php-version,"
        "http-generator,http-favicon,http-waf-detect,http-apache-server-status,"
        "http-devframework"
    ),
    # ── SSH ───────────────────────────────────────────────────────────────────
    "ssh":         "ssh-auth-methods,ssh2-enum-algos,ssh-hostkey,sshv1",
    # ── FTP ───────────────────────────────────────────────────────────────────
    "ftp":         "ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor,ftp-proftpd-backdoor,ftp-vuln-cve2010-4221",
    # ── SMTP ──────────────────────────────────────────────────────────────────
    "smtp":        "smtp-open-relay,smtp-commands,smtp-enum-users,smtp-ntlm-info,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764",
    # ── SMB ───────────────────────────────────────────────────────────────────
    "smb":         "smb-security-mode,smb2-security-mode,smb-enum-shares,smb-os-discovery,smb-protocols,smb2-capabilities,smb-enum-users,smb-vuln-ms17-010,smb-vuln-cve-2017-7494,smb-double-pulsar-backdoor",
    "microsoft-ds":"smb-security-mode,smb2-security-mode,smb-enum-shares,smb-os-discovery,smb-protocols,smb2-capabilities,smb-enum-users,smb-vuln-ms17-010,smb-vuln-cve-2017-7494,smb-double-pulsar-backdoor",
    # ── Databases ─────────────────────────────────────────────────────────────
    "mysql":       "mysql-info,mysql-empty-password,mysql-enum",
    "mssql":       "ms-sql-info,ms-sql-config,ms-sql-empty-password",
    "ms-sql":      "ms-sql-info,ms-sql-config,ms-sql-empty-password",
    "redis":       "redis-info",
    "mongodb":     "mongodb-info,mongodb-databases",
    "couchdb":     "couchdb-databases,couchdb-stats",
    "oracle":      "oracle-tns-version",
    # ── Remote access ─────────────────────────────────────────────────────────
    "rdp":         "rdp-enum-encryption,rdp-ntlm-info,rdp-vuln-ms12-020",
    "vnc":         "vnc-info,vnc-brute,realvnc-auth-bypass",
    "telnet":      "telnet-encryption,telnet-ntlm-info",
    # ── DNS ───────────────────────────────────────────────────────────────────
    "dns":         "dns-zone-transfer,dns-service-discovery,dns-recursion,dns-random-srcport,dns-random-txid,dns-nsid,dns-update",
    # ── Directory / LDAP ──────────────────────────────────────────────────────
    "ldap":        "ldap-rootdse,ldap-novell-getpass,ldap-search",
    # ── Mail protocols ─────────────────────────────────────────────────────────
    "pop3":        "pop3-capabilities",
    "imap":        "imap-capabilities",
    # ── SNMP ──────────────────────────────────────────────────────────────────
    "snmp":        "snmp-info,snmp-sysdescr,snmp-brute,snmp-interfaces,snmp-processes,snmp-netstat,snmp-win32-services,snmp-win32-users",
    # ── Printing / IPP ─────────────────────────────────────────────────────────
    "ipp":         "http-title,http-headers,http-methods,http-server-header",
    # ── File / storage services ─────────────────────────────────────────────────
    "nfs":         "nfs-showmount,nfs-ls,nfs-statfs",
    "rpcbind":     "rpcinfo",
    "rsync":       "rsync-list-modules",
    "memcached":   "memcached-info",
    # ── Java / application servers ──────────────────────────────────────────────
    "ajp":         "ajp-headers,ajp-methods",
    "jdwp":        "jdwp-version,jdwp-info",
    # ── Infrastructure ───────────────────────────────────────────────────────────
    "ipmi":        "ipmi-version,ipmi-cipher-zero",
    "docker":      "docker-version",
    "x11":         "x11-access",
    "irc":         "irc-info,irc-unrealircd-backdoor",
}


def _select_nse_scripts(service_name: str) -> str:
    """Return a comma-separated NSE script string for a given service name."""
    name = service_name.lower()
    for key, scripts in _NSE_SCRIPT_MAP.items():
        if key in name:
            return scripts
    return ""


def run_nmap_discovery(target: str, pinned_ports: str | None = None) -> tuple:
    """Five-phase nmap discovery pipeline.

    Parameters
    ----------
    target : str
        Hostname or IP address to scan.
    pinned_ports : str | None
        Comma-separated port number(s) to scan exclusively (e.g. "8080" or
        "80,443,8080").  When set, Phase 1 skips the full -p- scan and probes
        only the specified ports.  Supplied by parsing host:port syntax on the
        CLI or web UI (e.g. "localhost:8080" or "192.168.0.1:80,443").

    Phase 1 — Host discovery + open port list
    Phase 2 — Service/version enumeration on discovered ports
    Phase 3 — LLM-informed NSE script execution per service
    Phase 4 — OS detection
    Phase 5 — Normalise all data into a unified service list

    Returns
    -------
    services : list[dict]
        Fully annotated service records ready for CVE lookup and tool dispatch.
    nmap_meta : dict
        Raw phase outputs and OS information for inclusion in the report.
    """
    nmap_meta: dict = {
        "phase1_raw": "",
        "phase2_raw": "",
        "phase3_scripts": {},
        "phase4_os": {},
        "open_ports": [],
    }

    # ------------------------------------------------------------------ #
    # Phase 1 — Host discovery + open port list                           #
    # ------------------------------------------------------------------ #
    if pinned_ports:
        # Port-pinned mode: user supplied host:port or host:p1,p2,...
        # Skip the full -p- scan — probe only the specified port(s).
        print(f"\n[+] Nmap Phase 1 — Port-pinned scan ({target} / ports {pinned_ports})")
        p1_xml = _nmap_run([
            "-Pn", "-T4", "--open",
            "-p", pinned_ports,
            "--max-retries", "2",
            "-oX", "-",
            target,
        ], timeout=60)
        nmap_meta["phase1_raw"] = p1_xml
    else:
        print(f"\n[+] Nmap Phase 1 — Host discovery & port list ({target})")
        p1_xml = _nmap_run([
            "-Pn", "-T4", "--open",
            "-p-",                      # all 65 535 ports
            "--min-rate", "2000",       # speed — safe on LAN, capped by congestion
            "--max-retries", "1",
            "-oX", "-",
            target,
        ], timeout=300)
        nmap_meta["phase1_raw"] = p1_xml

        # Fall back to top-1000 scan if the full-port run produced nothing
        if not p1_xml.strip() or not _parse_nmap_xml(p1_xml):
            print("[!] Full-port scan returned nothing — falling back to top-1000")
            p1_xml = _nmap_run(["-Pn", "-T4", "--open", "-oX", "-", target], timeout=120)
            nmap_meta["phase1_raw"] = p1_xml

    p1_services = _parse_nmap_xml(p1_xml)
    if not p1_services:
        if pinned_ports:
            print(f"[!] Phase 1: port(s) {pinned_ports} appear closed or filtered on {target}.")
        else:
            print("[!] Phase 1: no open ports found.")
        return [], nmap_meta

    open_ports = [s["port"] for s in p1_services]
    ports_arg  = ",".join(open_ports)
    nmap_meta["open_ports"] = open_ports
    print(f"[+] Phase 1 complete — {len(open_ports)} open port(s): {ports_arg}")

    # ------------------------------------------------------------------ #
    # Phase 2 — Port & service enumeration (version + default scripts)    #
    # ------------------------------------------------------------------ #
    print(f"[+] Nmap Phase 2 — Service/version enumeration")
    p2_xml = _nmap_run([
        "-Pn", "-sV", "-sC",
        "-T4",
        "-p", ports_arg,
        "--version-intensity", "7",
        "-oX", "-",
        target,
    ], timeout=180)
    nmap_meta["phase2_raw"] = p2_xml

    p2_services = _parse_nmap_xml(p2_xml) if p2_xml.strip() else []

    # Retry once with a lighter scan if Phase 2 returned nothing at all
    # (full timeout on high-latency targets, or -sC scripts hung).
    if not p2_services:
        print("[!] Phase 2: no version data returned — retrying with lighter scan (no -sC, intensity 5)")
        p2_xml = _nmap_run([
            "-Pn", "-sV",
            "-T4",
            "-p", ports_arg,
            "--version-intensity", "5",
            "-oX", "-",
            target,
        ], timeout=120)
        nmap_meta["phase2_raw"] = p2_xml
        p2_services = _parse_nmap_xml(p2_xml) if p2_xml.strip() else []
        if not p2_services:
            print("[!] Phase 2 retry also returned nothing — continuing with port-only data")

    # Merge Phase-2 version info back onto Phase-1 records.
    # Any port that Phase 2 did not enrich gets flagged with version_unknown=True
    # so downstream (CVE lookup, LLM prompt, tool selection) can treat it explicitly.
    p2_by_port: dict = {s["port"]: s for s in p2_services}
    for svc in p1_services:
        p2 = p2_by_port.get(svc["port"])
        if p2:
            svc["name"]            = p2["name"]      or svc["name"]
            svc["product"]         = p2["product"]   or svc.get("product", "")
            svc["version"]         = p2["version"]   or svc.get("version", "")
            svc["extrainfo"]       = p2["extrainfo"] or svc.get("extrainfo", "")
            svc["version_unknown"] = False
        else:
            svc.setdefault("name",      "")
            svc.setdefault("product",   "")
            svc.setdefault("version",   "")
            svc.setdefault("extrainfo", "")
            svc["version_unknown"] = True

    unenriched = [s["port"] for s in p1_services if s.get("version_unknown")]
    if unenriched:
        print(f"[!] Phase 2: {len(unenriched)} port(s) not enriched — "
              f"CVE matching may be incomplete: {', '.join(unenriched)}")

    print(f"[+] Phase 2 complete — version data enriched on {len(p2_services)} port(s)")

    # ------------------------------------------------------------------ #
    # Phase 3 — Targeted NSE scripts per service                         #
    # ------------------------------------------------------------------ #
    print(f"[+] Nmap Phase 3 — Targeted NSE script execution")
    # Group ports by service family to batch NSE calls
    script_groups: dict = {}  # scripts_csv -> [port, ...]
    for svc in p1_services:
        scripts = _select_nse_scripts(svc.get("name", ""))
        if scripts:
            script_groups.setdefault(scripts, []).append(svc["port"])

    nse_results: dict = {}  # port -> {script_id: output}
    for scripts, ports in script_groups.items():
        batch_ports = ",".join(ports)
        batch_xml = _nmap_run([
            "-Pn", "-sT", "-sV", "--version-intensity", "2", "-T4",
            "-p", batch_ports,
            "--script", scripts,
            "--script-timeout", "30s",
            "-oX", "-",
            target,
        ], timeout=180)
        if batch_xml:
            batch_results = _nmap_extract_script_output(batch_xml, batch_ports=ports)
            for port, scripts_out in batch_results.items():
                nse_results.setdefault(port, {}).update(scripts_out)

    nmap_meta["phase3_scripts"] = nse_results

    # Attach NSE output to the matching service record
    for svc in p1_services:
        port_scripts = nse_results.get(svc["port"], {})
        if port_scripts:
            svc["nse_output"] = port_scripts
            # Flatten to a readable string for LLM context
            svc["nse_summary"] = "; ".join(
                f"{sid}: {out[:200]}" for sid, out in port_scripts.items()
            )
        else:
            svc["nse_output"]  = {}
            svc["nse_summary"] = ""

    nse_port_count = sum(1 for p in nse_results if nse_results[p])
    print(f"[+] Phase 3 complete — NSE data on {nse_port_count} port(s)")

    # Backfill product/version from http-server-header NSE output when nmap's
    # -sV fingerprint left them blank (common for non-standard ports like 8080
    # that nmap labels "http-proxy" or "http-alt" without banner parsing).
    _SVC_HEADER_PATTERNS = [
        (re.compile(r'Apache/(\S+)',        re.IGNORECASE), "Apache httpd"),
        (re.compile(r'nginx/(\S+)',         re.IGNORECASE), "nginx"),
        (re.compile(r'Microsoft-IIS/(\S+)', re.IGNORECASE), "Microsoft IIS"),
        (re.compile(r'lighttpd/(\S+)',      re.IGNORECASE), "lighttpd"),
        (re.compile(r'LiteSpeed/(\S+)',     re.IGNORECASE), "LiteSpeed"),
        (re.compile(r'Werkzeug/(\S+)',      re.IGNORECASE), "Werkzeug"),
        (re.compile(r'Jetty/(\S+)',         re.IGNORECASE), "Jetty"),
        (re.compile(r'Tomcat/(\S+)',        re.IGNORECASE), "Apache Tomcat"),
        (re.compile(r'openresty/(\S+)',     re.IGNORECASE), "OpenResty"),
        (re.compile(r'Caddy/(\S+)',         re.IGNORECASE), "Caddy"),
    ]
    for svc in p1_services:
        if svc.get("product"):
            continue  # already detected by -sV, trust nmap
        header_val = svc.get("nse_output", {}).get("http-server-header", "")
        if not header_val:
            continue
        for _pat, _prod in _SVC_HEADER_PATTERNS:
            _m = _pat.search(header_val)
            if _m:
                svc["product"] = _prod
                # Strip trailing OS/extra info like "(Unix)" "(Ubuntu)"
                svc["version"] = _m.group(1).split()[0].rstrip("(),;")
                break

    # ------------------------------------------------------------------ #
    # Phase 4 — OS detection                                              #
    # ------------------------------------------------------------------ #
    print(f"[+] Nmap Phase 4 — OS detection")
    p4_xml = _nmap_run([
        "-Pn", "-O",
        "--osscan-guess",
        "--max-os-tries", "2",
        "-p", ports_arg,
        "-oX", "-",
        target,
    ], timeout=60)

    os_info: dict = {"name": "", "accuracy": 0, "type": "", "vendor": ""}
    if p4_xml:
        try:
            root = ET.fromstring(p4_xml)
            best = None
            for osmatch in root.findall(".//osmatch"):
                acc = int(osmatch.attrib.get("accuracy", "0"))
                if best is None or acc > best["accuracy"]:
                    best = {
                        "name":     osmatch.attrib.get("name", ""),
                        "accuracy": acc,
                    }
                    osclass = osmatch.find("osclass")
                    if osclass is not None:
                        best["type"]   = osclass.attrib.get("type", "")
                        best["vendor"] = osclass.attrib.get("vendor", "")
            if best:
                os_info = best
        except ET.ParseError:
            pass
    nmap_meta["phase4_os"] = os_info
    if os_info.get("name"):
        print(f"[+] Phase 4 complete — OS: {os_info['name']} ({os_info['accuracy']}% confidence)")
    else:
        print("[+] Phase 4 complete — OS fingerprint not determined")

    # ------------------------------------------------------------------ #
    # Phase 5 — Normalise all data                                        #
    # ------------------------------------------------------------------ #
    print(f"[+] Nmap Phase 5 — Normalising discovery data")
    # p1_services now carries merged Phase-2 version data and Phase-3 NSE output.
    # Add OS context to each service so the LLM has full host context per record.
    os_str = os_info.get("name", "")
    for svc in p1_services:
        svc.setdefault("product",   "")
        svc.setdefault("version",   "")
        svc.setdefault("extrainfo", "")
        svc["os_context"] = os_str

    port_summary = ", ".join(
        f"{s['port']}/{s.get('name', '?')} {s.get('product', '')} {s.get('version', '')}".strip()
        for s in p1_services
    )
    print(f"[+] Phase 5 complete — {len(p1_services)} service(s) normalised: {port_summary}")

    return p1_services, nmap_meta


def run_nmap(target):
    """Compatibility shim — calls the 5-phase discovery pipeline and discards metadata."""
    services, _ = run_nmap_discovery(target)
    # Convert back to XML-based flow is no longer needed; return sentinel so
    # callers that expect XML can detect the change.
    return services


def parse_nmap(xml_data):
    """Legacy XML parser — kept for backward compatibility with any callers that
    still pass raw XML.  Returns an empty list when given a list (new path)."""
    if isinstance(xml_data, list):
        return xml_data
    return _parse_nmap_xml(xml_data)


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


def _tools_for_service(service_name, port=None):
    """Return the list of tools appropriate for *service_name*.

    Stage 1: consult the tool manifest (if loaded) for any tool whose
    service_keywords contain *service_name* as a substring (case-insensitive).
    A keyword of "*" matches every service.

    Stage 2 (fallback): built-in if/elif rules, retained for backward
    compatibility when the manifest is absent.

    Stage 3 (catch-all): if nothing matched, return ["curl"] so the LLM
    always has *something* to try on unknown ports.  Previously this returned
    [], which caused Phase-1 parallel scan to silently skip those services.
    """
    name = service_name.lower()
    manifest = _load_tool_manifest()

    if manifest:
        matched_tools = []
        for tool_name, entry in manifest.items():
            if tool_name.startswith("_"):
                continue
            for kw in entry.get("service_keywords", []):
                if kw == "*" or kw.lower() in name or name in kw.lower():
                    if tool_name not in matched_tools:
                        matched_tools.append(tool_name)
                    break
        if matched_tools:
            return matched_tools
        # Manifest present but no entry matched
        port_str = f" (port {port})" if port else ""
        print(
            f"[*] No manifest entry matched service '{service_name}'{port_str} — "
            f"defaulting to curl probe.  Add a matching service_keyword to "
            f"tool_manifest.json to improve routing."
        )
        return ["curl"]

    # ── Manifest absent: built-in rules ──────────────────────────────────
    # ffuf is a directory fuzzer — only useful on real HTTP/HTTPS services.
    if "http" in name or "ssl" in name:
        return ["curl", "nikto", "nuclei", "ffuf"]
    if "ipp" in name:
        return ["curl", "nikto", "nuclei"]
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
    # Catch-all — curl is always better than nothing
    return ["curl"]


def rank_and_annotate_services(services):
    annotated = []
    for s in services:
        try:
            port_int = int(s.get("port", 0))
        except (ValueError, TypeError):
            port_int = 0
        ot_info = _OT_PORTS.get(port_int, {})
        asset_type = _classify_asset(s)
        annotated.append({
            **s,
            "priority":          _service_priority(s),
            "recommended_tools": _tools_for_service(s.get("name", "")),
            "cves":              [],
            "asset_type":        asset_type,
            "ot_protocol":       ot_info.get("protocol", ""),
            "ot_standard":       ot_info.get("standard", ""),
        })
    return sorted(annotated, key=lambda x: x["priority"], reverse=True)


# ---------------------------------------------------------------------------
# VERIFICATION STAGE
# ---------------------------------------------------------------------------

async def verify_finding(finding):
    """Verify a finding via HTTP keyword check or evidence heuristic.

    Low-confidence tool findings (TOOL_CONFIDENCE < 0.65: nikto, ffuf) that
    cannot be confirmed are marked probe_inconclusive so the LLM can re-probe
    with a better tool and the report can flag them for manual inspection.
    """
    # Already confirmed by the tool itself (e.g. confirmed ssh-audit paths)
    if finding.verification_status == "confirmed":
        finding.verified = True
        return finding

    tool_conf      = TOOL_CONFIDENCE.get(finding.tool, 0.5)
    low_confidence = tool_conf < 0.65

    if finding.matched_url and finding.matched_url.startswith("http"):
        output = await run_curl_async(finding.matched_url)
        if output and not output.startswith("[!]") and len(output) > 20:
            keywords   = _VULN_BODY_KEYWORDS.get(finding.vuln_type, [])
            body_lower = output.lower()
            if not keywords or any(kw.lower() in body_lower for kw in keywords):
                finding.verified            = True
                finding.verification_status = "verified"
                finding.confidence          = min(finding.confidence + 0.1, 1.0)
            else:
                # Response came back but no confirming keyword — inconclusive
                finding.verification_status = "probe_inconclusive"
                finding.verifier_tool       = "curl"
                finding.manual_review       = True
        elif low_confidence:
            # No usable response AND low-confidence tool — cannot verify
            finding.verification_status = "probe_inconclusive"
            finding.verifier_tool       = "curl"
            finding.manual_review       = True
    elif low_confidence:
        # No matched_url and low-confidence tool — flag for manual follow-up
        finding.verification_status = "probe_inconclusive"
        finding.manual_review       = True
    elif finding.verification_status == "discovered" and len(finding.evidence) > 80:
        # High-confidence tool with substantial evidence — accept as verified
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

def query_llm(context, broken_tools=None, available_tools=None, used_actions=None, timed_out_tools=None):
    if broken_tools    is None: broken_tools    = set()
    if available_tools is None: available_tools = {}
    if used_actions    is None: used_actions    = set()
    if timed_out_tools is None: timed_out_tools = {}

    all_tool_descs = {
        "curl":       'curl: "http://target:port"',
        "nikto":      'nikto: {"url": "http://target:port", "ssl": false}  — optional: ssl:true to force SSL',
        "nikto_cgi":  'nikto_cgi: {"url": "http://target:port", "ssl": false}  — nikto with -C all (scan ALL CGI directories); use after plain nikto if more coverage needed',
        "nuclei":     'nuclei: {"url": "http://target:port", "tags": "cve,lfi,sqli", "severity": "medium,high,critical"}  — optional: tags (template filter), severity filter',
        "ffuf":       f'ffuf: {{"url": "http://target:port", "wordlist": "{WORDLIST}", "extensions": "php,html", "method": "GET", "match_codes": "200,301,302,401,403"}}  — IMPORTANT: url must be a plain base URL with NO slash, NO asterisk, NO FUZZ suffix (FUZZ is appended automatically). Optional: extensions, method (GET/POST/HEAD/OPTIONS), match_codes, threads (5-15), rate (10-50), filter_size, filter_words, maxtime (60-600s, default 300)',
        "curl":       'curl: {"url": "http://target:port/path", "method": "GET", "headers": {"Authorization": "Bearer token"}}  — optional: method (GET/POST/HEAD/OPTIONS), headers dict',
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
        "target":         context["target"],
        "services":       [
            f"{s['port']}/{s.get('name','unknown')} {s.get('product','').split()[0] if s.get('product') else ''}".strip()
            + (" [VERSION UNKNOWN — probe with curl or nmap]" if s.get("version_unknown") else "")
            for s in context["services"]
        ],
        "last_3_actions": context.get("history", [])[-3:],
        "findings_count": len(context.get("findings", [])),
        "needs_verification": [
            {
                "title":     f.get("title", ""),
                "service":   f.get("service", ""),
                "tool":      f.get("tool", ""),
                "vuln_type": f.get("vuln_type", ""),
                "evidence":  f.get("evidence", "")[:120],
            }
            for f in context.get("findings", [])
            if f.get("verification_status") == "probe_inconclusive"
        ],
        "already_run":    sorted(used_actions),
    }

    kb_block = context.get("tool_kb_text", "")
    kb_section = f"\n{kb_block}\n" if kb_block else ""

    nse_block = context.get("nse_context", "")
    nse_section = f"\nNSE SCRIPT RESULTS (from nmap Phase 3 — use to prioritise paths):\n{nse_block}\n" if nse_block else ""

    # Inject a TOOL REFERENCE block only when the manifest is loaded AND there are
    # services that are untested or have no recommended_tools.  This keeps the
    # prompt lean for normal iterations where the LLM already has context.
    manifest = _load_tool_manifest()
    _svc_list = context.get("services", [])
    _needs_guidance = any(
        s.get("status") == "NOT_YET_TESTED" or not s.get("recommended_tools")
        for s in _svc_list
    )
    if manifest and _needs_guidance:
        _ref_lines = ["TOOL REFERENCE (capability guide — use for NOT_YET_TESTED or no-recommendation services):"]
        for _tn, _te in manifest.items():
            if _tn.startswith("_"):
                continue
            _kws = ", ".join(_te.get("service_keywords", [])[:6])
            _ref_lines.append(f"  {_tn}: use_when={_te.get('use_when','')[:80]}  keywords=[{_kws}]")
        tool_ref_section = "\n" + "\n".join(_ref_lines) + "\n"
    else:
        tool_ref_section = ""

    # Format already_run as a clear block-list the model can't miss
    already_run_sorted = sorted(used_actions)
    already_run_block = (
        "ALREADY RUN — DO NOT REPEAT ANY OF THESE:\n"
        + "\n".join(f"  - {a}" for a in already_run_sorted)
        if already_run_sorted else "ALREADY RUN: (none yet)"
    )
    disabled_block = (
        "DISABLED TOOLS — DO NOT USE:\n"
        + "\n".join(f"  - {t}" for t in sorted(broken_tools))
        if broken_tools else "DISABLED TOOLS: (none)"
    )
    if timed_out_tools:
        _to_lines = [
            f"  - {t} (timed out with no findings on: {', '.join(sorted(sks))})"
            for t, sks in sorted(timed_out_tools.items())
        ]
        disabled_block += (
            "\nTIMED OUT PER SERVICE (still usable on other service types — avoid repeating on listed services):\n"
            + "\n".join(_to_lines)
        )

    prompt = f"""/no_think
### SCAN STATE — READ FIRST:
{already_run_block}

{disabled_block}

You are a penetration testing assistant. Reply with a single JSON object only.

### RULES:
1. RESPONSE MUST BE VALID JSON ONLY — no prose, no markdown, no explanation.
2. Only use tools listed in AVAILABLE TOOLS.
3. NEVER suggest a tool+args pair from ALREADY RUN above.
4. NEVER suggest a tool from DISABLED TOOLS above.
5. Prefer tools from each service's "recommended_tools" list — use higher KB success rate tools first.  For NOT_YET_TESTED services, consult the TOOL REFERENCE block to select the most appropriate tool.
6. Use NSE SCRIPT RESULTS to choose specific URLs, paths, or auth methods to test.
7. If all recommended tools are exhausted, try a general tool (curl, nmap) with a new endpoint or argument.
8. If there is nothing new to try, return {{"tool": "none"}}.
9. If NEEDS_VERIFICATION findings appear in CURRENT FINDINGS, prioritise re-probing each with a different higher-confidence tool matched to its vuln_type and service (e.g. curl for HTTP header issues, nuclei for web vulns, ssh-audit for SSH) before exploring new areas.

AVAILABLE TOOLS:
{tools_block}
{kb_section}{nse_section}{tool_ref_section}
CURRENT FINDINGS:
{json.dumps(ctx_summary, indent=2)}

Return EXACTLY ONE JSON object:
{{"tool": "<name>", "args": <value>}}

Or if exhausted:
{{"tool": "none"}}"""

    raw = ""
    _t0 = time.monotonic()
    _sp = _Spinner("[ LLM ]  Deciding next action ...").start()
    try:
        for attempt in range(MAX_LLM_RETRIES):
            try:
                response = requests.post(
                    OLLAMA_URL,
                    json={
                        "model":      MODEL,
                        "prompt":     prompt,
                        "stream":     False,
                        "format":     "json",
                        "keep_alive": _OLLAMA_KEEP_ALIVE,
                        "options":    _OLLAMA_PLAN_OPTIONS,
                    },
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
# FAST-PATH TOOL SELECTOR
# Pre-emptively maps well-known nmap service names → the correct first tool.
# This fires before the LLM is consulted, eliminating LLM latency for every
# service the model would have reasoned to the same answer anyway.
# Entries are ordered: first match wins.  Use the most specific key first.
# ---------------------------------------------------------------------------
_FAST_PATH: list[tuple[str, str, dict]] = [
    # (service_name_substring, tool_name, args_template)
    # Keys match against service["name"].lower()
    # {target} and {port} are substituted at call time.
    ("microsoft-ds",    "nxc_smb",    {"host": "{target}", "port": "445"}),
    ("netbios-ssn",     "nxc_smb",    {"host": "{target}", "port": "{port}"}),
    ("msrpc",           "curl",       {"url": "http://{target}:{port}"}),
    ("ssl/vmware-auth", "curl",       {"url": "https://{target}:{port}"}),
    ("vmware-auth",     "curl",       {"url": "https://{target}:{port}"}),
    ("ssl/http",        "nikto",      {"url": "https://{target}:{port}", "ssl": True}),
    ("https",           "nikto",      {"url": "https://{target}:{port}", "ssl": True}),
    ("http-alt",        "nikto",      {"url": "http://{target}:{port}", "ssl": False}),
    ("http",            "nikto",      {"url": "http://{target}:{port}", "ssl": False}),
    ("ipp",             "curl",       {"url": "http://{target}:{port}"}),
    ("vnc",             "curl",       {"url": "http://{target}:{port}"}),
    ("rfb",             "curl",       {"url": "http://{target}:{port}"}),
    ("kerberos",        "curl",       {"url": "http://{target}:{port}"}),
    ("netassistant",    "curl",       {"url": "http://{target}:{port}"}),
    ("apple-remote",    "curl",       {"url": "http://{target}:{port}"}),
    ("ssh",             "ssh_enum",   {"host": "{target}", "port": "{port}"}),
    ("rdp",             "rdp_enum",   {"host": "{target}", "port": "{port}"}),
    ("ftp",             "curl",       {"url": "ftp://{target}:{port}"}),
    ("smtp",            "curl",       {"url": "smtp://{target}:{port}"}),
    ("mysql",           "mysql_enum", {"host": "{target}", "port": "{port}"}),
    ("ms-sql-s",        "mssql_enum", {"host": "{target}", "port": "{port}"}),
    ("mssql",           "mssql_enum", {"host": "{target}", "port": "{port}"}),
    ("domain",          "dns_enum",   {"domain": "{target}"}),
    ("dns",             "dns_enum",   {"domain": "{target}"}),
    ("snmp",            "curl",       {"url": "udp://{target}:{port}"}),
    ("ldap",            "nxc_ldap",   {"host": "{target}", "port": "{port}"}),
]


def _fast_path_actions(
    services: list,
    target: str,
    broken_tools: set,
    available_tools: dict,
    used_actions: set,
    timed_out_tools: dict | None = None,
) -> list[dict]:
    """Return a list of validated tool actions derived from the fast-path table.

    For each service, find the first matching fast-path entry whose tool is not
    broken, not already used, and is present in available_tools.  Returns only
    actions for services that have a clear fast-path match; services with no
    match are left for the LLM.
    """
    timed_out_tools = timed_out_tools or {}
    actions: list[dict] = []
    seen: set = set()
    for svc in services:
        svc_name = svc.get("name", "").lower()
        port     = svc.get("port", "")
        for name_key, tool, args_tmpl in _FAST_PATH:
            if name_key not in svc_name:
                continue
            if tool in broken_tools:
                break  # try next fast-path entry for this service
            # Skip if this tool already timed out on this service type
            if svc_name and svc_name in timed_out_tools.get(tool, set()):
                break
            # Tool availability checks (mirrors query_llm logic)
            if tool == "ssh_enum"  and "ssh-audit" not in available_tools:
                break
            if tool == "rdp_enum"  and "rdpscan"   not in available_tools:
                break
            if tool in ("nxc_smb", "nxc_ldap") and "nxc" not in available_tools:
                break
            # Substitute template vars
            def _sub(v):
                if isinstance(v, str):
                    return v.replace("{target}", target).replace("{port}", port)
                return v
            resolved_args = {k: _sub(v) for k, v in args_tmpl.items()}
            key = f"{tool}:{str(resolved_args)}"
            if key in used_actions or key in seen:
                break
            seen.add(key)
            actions.append({"tool": tool, "args": resolved_args})
            break  # one tool per service
    return actions


def _untested_service_fallback(
    services: list,
    target: str,
    used_actions: set,
    broken_tools: set,
    available_tools: dict | None = None,
    timed_out_tools: dict | None = None,
) -> "dict | None":
    """Rule-based escape hatch for when the LLM is stuck repeating the same action.

    Scans the service list for the first port that has no entry in *used_actions*,
    then returns an appropriate tool action for it.  Priority:
      1. Service's recommended_tools (from manifest-driven routing)
      2. curl as universal catch-all

    Returns an action dict like {\"tool\": ..., \"args\": ...} or None if every
    service has been touched already.  Never makes an LLM call.
    """
    if available_tools  is None: available_tools  = {}
    if timed_out_tools  is None: timed_out_tools  = {}
    for svc in services:
        port     = str(svc.get("port", ""))
        svc_name = svc.get("name", "")
        svc_key  = svc_name.lower()
        # Has any tool been run against this port yet?
        if any(port in ak for ak in used_actions):
            continue
        # Pick the best tool from the service's recommended list
        rec_tools = svc.get("recommended_tools", []) or ["curl"]
        for tool in rec_tools:
            if tool in broken_tools:
                continue
            # Skip tools that already timed out with no findings on this service type
            if svc_key and svc_key in timed_out_tools.get(tool, set()):
                continue
            if tool == "ssh_enum"  and "ssh-audit" not in available_tools:
                continue
            if tool == "rdp_enum"  and "rdpscan"   not in available_tools:
                continue
            if tool in ("nxc_smb", "nxc_ldap") and "nxc" not in available_tools:
                continue
            # Build minimal args for the chosen tool
            proto = "https" if ("ssl" in svc_name.lower() or "https" in svc_name.lower()) else "http"
            if tool in ("nikto", "nikto_cgi", "nuclei", "ffuf", "curl"):
                args = {"url": f"{proto}://{target}:{port}"}
            elif tool == "ssh_enum":
                args = {"host": target, "port": port}
            elif tool == "rdp_enum":
                args = {"host": target, "port": port}
            elif tool in ("mysql_enum", "mssql_enum"):
                args = {"host": target, "port": port}
            elif tool in ("nxc_smb", "nxc_ldap"):
                args = {"host": target, "port": port}
            elif tool == "dns_enum":
                args = {"domain": target}
            else:
                args = {"url": f"http://{target}:{port}"}
            action_key = f"{tool}:{str(args)}"
            if action_key not in used_actions:
                print(f"[*] Fallback: pivoting to untested service {svc_name} port {port} with {tool}")
                return {"tool": tool, "args": args}
    return None  # all services tested


def query_llm_parallel(context, broken_tools=None, available_tools=None, used_actions=None, timed_out_tools=None):
    """Phase-1 LLM call: plan ONE initial action per discovered service simultaneously.

    Returns a validated, deduplicated list of action dicts.
    Falls back to an empty list on LLM failure so the caller can continue
    with the sequential loop.
    """
    if broken_tools    is None: broken_tools    = set()
    if available_tools is None: available_tools = {}
    if used_actions    is None: used_actions    = set()
    if timed_out_tools is None: timed_out_tools = {}

    target   = context["target"]
    services = context.get("services", [])

    # ------------------------------------------------------------------
    # Fast-path: deterministically assign tools for well-known services.
    # This runs at zero LLM cost and correctly handles the vast majority
    # of real-world services (SMB, HTTP, SSH, RDP, VMware, etc.).
    # ------------------------------------------------------------------
    fast_actions = _fast_path_actions(services, target, broken_tools, available_tools, used_actions, timed_out_tools)
    fast_covered_ports = {
        str(a["args"].get("port") or (a["args"].get("url", "").split(":")[-1].split("/")[0]))
        for a in fast_actions
    }

    # Identify services that were NOT covered by the fast path
    unmatched = [
        s for s in services
        if s.get("port") not in fast_covered_ports and s.get("recommended_tools")
    ]

    if fast_actions:
        covered = ", ".join(
            f"{a['tool']}→{a['args'].get('host') or a['args'].get('url','')}" for a in fast_actions
        )
        print(f"[+] Fast-path assigned {len(fast_actions)} action(s): {covered}")

    # If all services are covered, skip the LLM entirely
    if not unmatched:
        return fast_actions

    # ------------------------------------------------------------------
    # LLM fallback: only for services not handled by the fast path.
    # ------------------------------------------------------------------
    all_tool_descs = {
        "curl":       'curl: {"url": "http://target:port/path", "method": "GET", "headers": {}}',
        "nikto":      'nikto: {"url": "http://target:port", "ssl": false}',
        "nikto_cgi":  'nikto_cgi: {"url": "http://target:port", "ssl": false}',
        "nuclei":     'nuclei: {"url": "http://target:port", "tags": "cve,lfi,sqli", "severity": "medium,high,critical"}',
        "ffuf":       f'ffuf: {{"url": "http://target:port", "wordlist": "{WORDLIST}", "extensions": "php,html", "method": "GET", "match_codes": "200,301,302,401,403", "maxtime": 300}}',
        "ssh_enum":   'ssh_enum: {"host": "...", "port": "22"}',
        "rdp_enum":   'rdp_enum: {"host": "...", "port": "3389"}',
        "dns_enum":   'dns_enum: {"domain": "..."}',
        "mysql_enum": 'mysql_enum: {"host": "...", "port": "3306"}',
        "mssql_enum": 'mssql_enum: {"host": "...", "port": "1433"}',
    }
    available_descs = [
        f"- {desc}" for name, desc in all_tool_descs.items()
        if name not in broken_tools
        and not (name == "ssh_enum"  and "ssh-audit" not in available_tools)
        and not (name == "rdp_enum"  and "rdpscan"   not in available_tools)
    ]
    tools_block = "\n".join(available_descs)

    # Compact service list for unmatched services only
    services_block = "\n".join(
        f"  Port {s['port']}/{s.get('name', '')} {s.get('product','').split()[0] if s.get('product') else ''}"
        for s in unmatched
    )

    # Minimal context summary — no full findings dump to keep prompt short
    already_run_block = (
        "DO NOT REPEAT: " + ", ".join(sorted(used_actions)) if used_actions else "ALREADY RUN: (none)"
    )

    prompt = f"""/no_think
You are a penetration tester. Reply with valid JSON only, no prose.

{already_run_block}

TARGET: {target}
UNRECOGNISED SERVICES (assign one tool each):
{services_block}

AVAILABLE TOOLS:
{tools_block}

Return: {{"actions": [{{"tool": "<name>", "args": <value>}}, ...]}}
If no suitable tool exists: {{"actions": []}}"""

    _t0 = time.monotonic()
    _sp  = _Spinner(f"[ LLM ]  Planning {len(unmatched)} unmatched service(s) ...").start()
    try:
        for attempt in range(MAX_LLM_RETRIES):
            try:
                response = requests.post(
                    OLLAMA_URL,
                    json={
                        "model":      MODEL,
                        "prompt":     prompt,
                        "stream":     False,
                        "format":     "json",
                        "keep_alive": _OLLAMA_KEEP_ALIVE,
                        "options":    _OLLAMA_PLAN_OPTIONS,
                    },
                    timeout=OLLAMA_TIMEOUT,
                )
                payload = response.json()
                if "error" in payload or "response" not in payload:
                    continue
                raw = payload["response"].strip()
                if raw.startswith("```"):
                    raw = raw.split("\n", 1)[-1].rsplit("```", 1)[0]
                data    = json.loads(raw.strip())
                actions = data.get("actions", [])
                if not isinstance(actions, list):
                    continue
                valid = []
                seen  = set()
                for action in actions:
                    if not isinstance(action, dict):
                        continue
                    if not validate_action(action):
                        continue
                    key = f"{action['tool']}:{str(action.get('args', ''))}"
                    if key in used_actions or key in seen:
                        continue
                    seen.add(key)
                    valid.append(action)
                # Merge fast-path + LLM results
                return fast_actions + valid
            except json.JSONDecodeError:
                pass
            except Exception as e:
                print(f"[!] Parallel LLM error (attempt {attempt + 1}): {e}")
    finally:
        _sp.stop(f" done ({_fmt_dur(time.monotonic() - _t0)})")

    print("[!] Parallel LLM planning returned no valid actions for unmatched services.")
    # Return fast-path results even if LLM failed
    return fast_actions


# ---------------------------------------------------------------------------
# ACTION VALIDATION
# ---------------------------------------------------------------------------

KNOWN_TOOLS = {
    "curl", "nikto", "nikto_cgi", "nuclei", "ffuf",
    "ssh_enum", "rdp_enum", "dns_enum", "mysql_enum", "mssql_enum",
    "nxc_smb", "nxc_ldap",
}

BROKEN_TOOL_SIGNALS = [
    "No such file or directory",
    "Required module not found",
    "command not found",
    "cannot find",
    "flag provided but not defined",    # nuclei unknown flag
    # NOTE: "not found" removed — too broad (matches HTTP 404 response text)

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

    if tool in ("curl", "nikto", "nikto_cgi", "nuclei"):
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

    if tool == "ffuf":
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

    if tool in ("nxc_smb", "nxc_ldap"):
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
        a   = _safe_tool_args("curl", args)
        url = a["url"]
        m   = a.get("method", "GET")
        hdrs = " ".join(f'-H "{k}: {v}"' for k, v in a.get("headers", {}).items())
        return f"curl -s -L -m 15{' -X ' + m if m != 'GET' else ''}{' ' + hdrs if hdrs else ''} {url}"
    if tool in ("nikto", "nikto_cgi"):
        a   = _safe_tool_args(tool, args)
        url = a["url"]
        ssl = " -ssl" if a.get("ssl") else ""
        cgi = " -C all" if tool == "nikto_cgi" else ""
        return f"perl {NIKTO_PL} -h {url}{ssl}{cgi} -Format txt -nointeractive -maxtime 90s"
    if tool == "nuclei":
        a          = _safe_tool_args("nuclei", args)
        url        = a["url"]
        nuclei_path = available_tools.get("nuclei", "nuclei")
        sev        = a.get("severity", "low,medium,high,critical")
        tags_part  = f" -tags {a['tags']}" if a.get("tags") else ""
        return f"{nuclei_path} -u {url} -s {sev}{tags_part} -silent -j -ot"
    if tool == "ffuf":
        a    = _safe_tool_args("ffuf", args)
        url  = a["url"]
        wl   = a["wordlist"]
        mc   = a.get("match_codes", "200,301,302,401,403")
        t    = a.get("threads", 8)
        rate = a.get("rate", 25)
        tmo  = a.get("timeout", 8)
        ret  = a.get("retries", 1)
        maxt = a.get("maxtime", 300)
        ext  = f" -e .{a['extensions'].replace(',', ',.')}" if a.get("extensions") else ""
        meth = f" -X {a['method']}" if a.get("method", "GET") != "GET" else ""
        fs   = f" -fs {a['filter_size']}" if a.get("filter_size") else ""
        fw   = f" -fw {a['filter_words']}" if a.get("filter_words") else ""
        return f"ffuf -u {url}/FUZZ -w {wl} -ac -mc {mc} -t {t} -rate {rate} -timeout {tmo} -maxtime {maxt}{ext}{meth}{fs}{fw}"
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

    # Sanitise and validate all LLM-provided args before use
    args = _safe_tool_args(tool, args)

    if tool in AGGRESSIVE_TOOLS:
        if not request_approval(tool, args, "Directory brute-force / aggressive scan"):
            print(f"[!] {tool} denied by operator.")
            return f"[DENIED] {tool} not approved.", []

    print(f"[+] Executing: {tool}  |  args: {args}")

    if tool == "curl":
        url  = args["url"]
        meth = args.get("method", "GET")
        hdrs = args.get("headers", {})
        cmd  = ["curl", "-s", "-L", "-m", "15"]
        if meth != "GET":
            cmd += ["-X", meth]
        for k, v in hdrs.items():
            cmd += ["-H", f"{k}: {v}"]
        cmd.append(url)
        output = await run_command_async(cmd, timeout=20)
        return output, []

    if tool in ("nikto", "nikto_cgi"):
        url   = args["url"]
        extra = ["-ssl"] if args.get("ssl") else []
        if tool == "nikto_cgi":
            extra = extra + ["-C", "all"]
        output   = await run_nikto_async(url, session_dir=session_dir, extra_flags=extra)
        findings = parse_nikto_output(output, url) if not is_tool_broken(output) else []
        return output, findings

    if tool == "nuclei":
        url  = args["url"]
        tags = args.get("tags")
        sev  = args.get("severity", "low,medium,high,critical")
        return await run_nuclei_json_async(url, available_tools, tags=tags, severity=sev)

    if tool == "ffuf":
        url  = args["url"]
        wl   = args["wordlist"]
        mc   = args.get("match_codes", "200,301,302,401,403")
        meth = args.get("method", "GET")
        # Enforce safe caps — never allow unlimited or above-threshold values
        threads  = min(int(args.get("threads",  8)),   15)
        rate     = min(int(args.get("rate",    25)),   50)
        timeout  = min(int(args.get("timeout",  8)),   15)
        retries  = min(int(args.get("retries",  1)),    2)
        maxtime  = min(int(args.get("maxtime", 300)), 600)
        if rate == 0:
            rate = 25   # hard block on unlimited rate
        cmd = [
            "ffuf",
            "-u",       f"{url}/FUZZ",
            "-w",       wl,
            "-ac",                             # auto-calibration always on
            "-mc",      mc,
            "-fc",      "404,400",
            "-t",       str(threads),
            "-rate",    str(rate),
            "-timeout", str(timeout),
            "-maxtime", str(maxtime),
            "-s",                              # silent — suppress banner noise
        ]
        if args.get("extensions"):
            ext_str = ",".join(f".{e}" for e in args["extensions"].split(","))
            cmd += ["-e", ext_str]
        if meth != "GET":
            cmd += ["-X", meth]
        if args.get("filter_size"):
            cmd += ["-fs", str(args["filter_size"])]
        if args.get("filter_words"):
            cmd += ["-fw", str(args["filter_words"])]
        # Timeout: maxtime + 30s buffer for ffuf startup/shutdown
        output   = await run_command_async(cmd, timeout=maxtime + 30)
        findings = parse_ffuf_output(output, url)
        return output, findings

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

    if tool == "nxc_smb":
        host = args.get("host", "")
        port = str(args.get("port", "445"))
        cmd  = ["nxc", "smb", host, "-p", port, "--shares", "--users", "--groups", "--pass-pol"]
        output = await run_command_async(cmd, timeout=60)
        return output, []

    if tool == "nxc_ldap":
        host = args.get("host", "")
        port = str(args.get("port", "389"))
        cmd  = ["nxc", "ldap", host, "-p", port, "--users", "--groups"]
        output = await run_command_async(cmd, timeout=60)
        return output, []

    return "[!] Unknown tool", []


def query_llm_for_service(
    svc: dict,
    target: str,
    svc_history: list,
    svc_findings: list,
    shared_findings: list,
    broken_tools: set,
    available_tools: dict,
    used_actions: set,
    timed_out_tools: dict,
) -> dict:
    """Plan the next action for a single service during the batched probe loop.

    Returns a single validated action dict, or {"tool": "none"} when exhausted.
    Uses the fast planning model (PLANNING_MODEL / gemma3:4b) for low latency.
    """
    port    = svc.get("port", "?")
    name    = svc.get("name", "unknown")
    product = svc.get("product", "")
    version = svc.get("version", "")
    svc_label = f"{port}/{name}" + (f" ({product} {version})".rstrip() if product else "")

    all_tool_descs = {
        "curl":       'curl: {"url": "http://target:port/path", "method": "GET", "headers": {}}  — optional: method, headers dict',
        "nikto":      'nikto: {"url": "http://target:port", "ssl": false}  — optional: ssl:true',
        "nikto_cgi":  'nikto_cgi: {"url": "http://target:port", "ssl": false}  — nikto with -C all',
        "nuclei":     f'nuclei: {{"url": "http://target:port", "tags": "cve,lfi,sqli", "severity": "medium,high,critical"}}',
        "ffuf":       f'ffuf: {{"url": "http://target:port", "wordlist": "{WORDLIST}", "extensions": "php,html", "method": "GET", "match_codes": "200,301,302,401,403", "maxtime": 300}}',
        "ssh_enum":   'ssh_enum: {"host": "...", "port": "22"}',
        "rdp_enum":   'rdp_enum: {"host": "...", "port": "3389"}',
        "dns_enum":   'dns_enum: {"domain": "..."}',
        "mysql_enum": 'mysql_enum: {"host": "...", "port": "3306"}',
        "mssql_enum": 'mssql_enum: {"host": "...", "port": "1433"}',
    }
    available_descs = [
        f"- {desc}" for tname, desc in all_tool_descs.items()
        if tname not in broken_tools
        and not (tname == "ssh_enum" and "ssh-audit"  not in available_tools)
        and not (tname == "rdp_enum" and "rdpscan"    not in available_tools)
    ]
    tools_block = "\n".join(available_descs)

    # Build already-run block scoped to this service's port
    svc_run = sorted(
        a for a in used_actions
        if f":{port}" in a or f":{target}" in a
    )
    already_run_block = (
        "ALREADY RUN ON THIS SERVICE — DO NOT REPEAT:\n"
        + "\n".join(f"  - {a}" for a in svc_run)
        if svc_run else "ALREADY RUN ON THIS SERVICE: (none yet)"
    )
    disabled_block = (
        "DISABLED TOOLS — DO NOT USE: " + ", ".join(sorted(broken_tools))
        if broken_tools else ""
    )

    # Compact history for this service (last 3 actions)
    history_lines = []
    for h in svc_history[-3:]:
        act    = h.get("action", {})
        result = h.get("result", "")[:150]
        nf     = h.get("findings", 0)
        history_lines.append(f"  {act.get('tool','?')} → {result} [{nf} finding(s)]")
    history_block = "\n".join(history_lines) if history_lines else "  (no history yet)"

    # Compact findings for this service
    svc_findings_lines = [
        f"  [{f.get('severity','?').upper()}] {f.get('title','')} — {f.get('verification_status','')}"
        for f in svc_findings[-5:]
    ]
    svc_findings_block = "\n".join(svc_findings_lines) if svc_findings_lines else "  (none yet)"

    # Cross-service context (findings from other services)
    shared_lines = [
        f"  [{f.get('severity','?').upper()}] {f.get('service','')} — {f.get('title','')}"
        for f in shared_findings[-5:]
    ]
    shared_block = (
        "FINDINGS FROM OTHER SERVICES (context only — do not repeat these probes):\n"
        + "\n".join(shared_lines)
        if shared_lines else ""
    )

    # Recommended tools from manifest
    rec_tools = svc.get("recommended_tools", [])
    rec_block  = ("RECOMMENDED TOOLS (ordered by KB success rate): "
                  + ", ".join(t["tool"] for t in rec_tools[:4])
                  if rec_tools else "")

    prompt = f"""/no_think
### SERVICE PROBE — Reply with ONE JSON object only.

{already_run_block}
{disabled_block}

TARGET SERVICE: {svc_label}  (host: {target})
{rec_block}

RECENT ACTIONS ON THIS SERVICE:
{history_block}

FINDINGS ON THIS SERVICE SO FAR:
{svc_findings_block}

{shared_block}

AVAILABLE TOOLS:
{tools_block}

RULES:
1. JSON only — no prose, no markdown.
2. Choose the single most useful next action for THIS SERVICE.
3. Never repeat a tool+args from ALREADY RUN ON THIS SERVICE.
4. If you have exhausted all useful actions for this service, return {{"tool": "none"}}.
5. Prefer recommended tools; use higher success-rate tools first.

Return EXACTLY:
{{"tool": "<name>", "args": <value>}}
or
{{"tool": "none"}}"""

    raw = ""
    _t0 = time.monotonic()
    _sp = _Spinner(f"[ LLM ]  Planning {svc_label} ...").start()
    try:
        for attempt in range(MAX_LLM_RETRIES):
            try:
                response = requests.post(
                    OLLAMA_URL,
                    json={
                        "model":      MODEL,
                        "prompt":     prompt,
                        "stream":     False,
                        "format":     "json",
                        "keep_alive": _OLLAMA_KEEP_ALIVE,
                        "options":    _OLLAMA_PLAN_OPTIONS,
                    },
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
            except Exception as exc:
                print(f"  [hc] LLM error for {svc_label} (attempt {attempt + 1}): {exc}")
    finally:
        _sp.stop(f" done ({_fmt_dur(time.monotonic() - _t0)})")

    return {"tool": "none"}


async def run_service_probe_batch(
    services_batch: list,
    target: str,
    all_findings: list,
    used_actions: set,
    tool_kb: dict,
    available_tools: dict,
    session_dir: str,
    broken_tools: set,
    timed_out_tools: dict,
    scan_records: list,
    batch_idx: int,
    total_batches: int,
) -> list:
    """Run concurrent per-service probing for a batch of services.

    Each service gets its own LLM query each round.  Services are dropped when
    the LLM returns 'none' or they exhaust their round budget.  Shared findings
    are passed into every per-service prompt so cross-port correlation is preserved.

    Returns a list of Finding objects discovered during this batch.
    """
    # Per-service state
    class _SvcState:
        __slots__ = ("svc", "history", "findings", "rounds_left", "extra_used", "label")
        def __init__(self, svc):
            self.svc        = svc
            self.history    = []
            self.findings   = []
            self.rounds_left = MAX_ROUNDS_PER_SERVICE
            self.extra_used  = 0
            port    = svc.get("port", "?")
            name    = svc.get("name", "")
            product = svc.get("product", "")
            self.label = f"{port}/{name}" + (f" ({product.split()[0]})" if product else "")

    active = [_SvcState(s) for s in services_batch]
    batch_findings: list = []
    round_num = 0

    while active:
        round_num += 1

        # --- Print batch/round header -------------------------------------------
        svc_labels = "  Â·  ".join(st.label for st in active)
        print(f"\n{'=' * 52}")
        print(f"  Batch {batch_idx + 1}/{total_batches}  Round {round_num}  |  "
              f"Target: {target}  |  Services: {len(active)}")
        print(f"  Probing: {svc_labels}")
        print(f"{'=' * 52}")

        # Shared findings summary for cross-service context (max 5, most recent)
        shared_summary = [dataclasses.asdict(f) for f in all_findings[-5:]] if all_findings else []

        # --- Concurrent LLM queries for all active services ---------------------
        loop = asyncio.get_event_loop()
        llm_futures = [
            loop.run_in_executor(
                None,
                query_llm_for_service,
                st.svc, target, st.history, st.findings, shared_summary,
                broken_tools, available_tools, used_actions, timed_out_tools,
            )
            for st in active
        ]
        actions_raw = await asyncio.gather(*llm_futures, return_exceptions=True)

        # --- Collect non-none actions, print per-service decision ---------------
        wave_actions  = []
        active_states = []
        none_states   = []

        for st, action in zip(active, actions_raw):
            if isinstance(action, Exception):
                action = {"tool": "none"}
            tool = action.get("tool", "none")
            if tool == "none":
                print(f"  [{st.label:<18}]  none — exhausted")
                none_states.append(st)
                continue
            action_key = f"{tool}:{str(action.get('args', ''))}"
            if action_key in used_actions:
                print(f"  [{st.label:<18}]  {tool} — duplicate, skipping")
                st.rounds_left -= 1
                if st.rounds_left > 0:
                    active_states.append(st)
                continue
            used_actions.add(action_key)
            # Tag the action with the service so we can route results back
            action["_svc_label"] = st.label
            action["_svc_state"] = st
            wave_actions.append(action)
            active_states.append(st)
            args_preview = str(action.get("args", ""))[:60]
            print(f"  [{st.label:<18}]  {tool} → {args_preview}")

        # --- Execute all planned actions in a parallel wave ---------------------
        if wave_actions:
            # Strip internal routing keys before passing to execute_async
            clean_actions = [
                {k: v for k, v in a.items() if not k.startswith("_")}
                for a in wave_actions
            ]
            wave_results, wave_scan_records = await run_parallel_wave(
                clean_actions, available_tools, session_dir
            )
            scan_records.extend(wave_scan_records)

            # Route results back to the correct per-service state
            # wave_results is list of (action, output, findings, broken)
            for orig_action, (_, output, findings, broken) in zip(wave_actions, wave_results):
                tool = orig_action.get("tool", "?")
                st   = orig_action["_svc_state"]

                timed_out_w = "Command timed out" in (output or "")
                _record_tool_outcome(
                    tool_kb, tool,
                    _svc_key(tool, orig_action.get("args", ""), services_batch),
                    len(findings) if findings else 0,
                    broken, timed_out_w,
                )

                if broken:
                    broken_tools.add(tool)
                    print(f"  [!] '{tool}' appears broken — disabling.")
                elif timed_out_w and not findings and tool not in {"ffuf", "nikto"}:
                    _ban_key = _svc_key(tool, orig_action.get("args", ""), services_batch)
                    timed_out_tools.setdefault(tool, set()).add(_ban_key)

                st.history.append({
                    "action":   orig_action,
                    "result":   (output or "")[:200],
                    "findings": len(findings) if findings else 0,
                })

                if findings and not broken:
                    st.findings.extend([dataclasses.asdict(f) for f in findings])
                    batch_findings.extend(findings)
                    all_findings.extend(findings)
                    print(f"  [+] {len(findings)} finding(s) from {tool} on {st.label}")

            # Re-sync active_states based on wave results
            # (broken tools may have caused some states to need re-evaluation)

        # --- Extension mechanic — grant extra rounds for uninvestigated findings -
        for st in active_states:
            uninvestigated = [
                f for f in st.findings
                if f.get("verification_status") == "probe_inconclusive"
            ]
            if uninvestigated and st.extra_used < MAX_EXTRA_ROUNDS:
                grant = min(
                    len(uninvestigated) * EXTRA_ROUNDS_PER_FINDING,
                    MAX_EXTRA_ROUNDS - st.extra_used,
                )
                st.rounds_left += grant
                st.extra_used  += grant
                print(f"  [+] {st.label}: +{grant} extra round(s) for {len(uninvestigated)} uninvestigated finding(s)")

        # --- Decrement rounds and drop exhausted services -----------------------
        next_active = []
        for st in active_states:
            st.rounds_left -= 1
            if st.rounds_left > 0:
                next_active.append(st)
            else:
                print(f"  [~] {st.label}: round budget exhausted — moving on")

        active = next_active

    return batch_findings


async def run_parallel_wave(actions, available_tools, session_dir):
    """Execute multiple tool actions concurrently, bounded by MAX_PARALLEL_ACTIONS.

    Returns:
        wave_results  : list of (action, output, findings, broken)
        scan_records  : list of scan-record dicts (one per action)
    """
    if not actions:
        return [], []

    wave_results = []
    scan_records = []

    for i in range(0, len(actions), MAX_PARALLEL_ACTIONS):
        batch = actions[i : i + MAX_PARALLEL_ACTIONS]
        print(f"\n[+] Parallel wave: running {len(batch)} tool(s) concurrently ...")
        for a in batch:
            print(f"    {a['tool']:12} → {str(a.get('args', ''))[:70]}")

        t0          = time.time()
        raw_results = await asyncio.gather(
            *[execute_async(a, available_tools, session_dir) for a in batch],
            return_exceptions=True,
        )
        print(f"[+] Parallel wave complete in {time.time() - t0:.1f}s")

        for action, result in zip(batch, raw_results):
            tool = action["tool"]
            args = action.get("args", "")

            if isinstance(result, Exception):
                output, findings = f"[!] Exception: {result}", []
            else:
                output, findings = result
            output = output or ""
            broken = is_tool_broken(output)

            if findings and not broken:
                for f in findings:
                    if not f.vuln_type:
                        f.vuln_type, f.cwe_id, f.compliance_controls = (
                            _enrich_finding_metadata(f.title, f.evidence, f.service)
                        )
                findings = await verify_findings_batch(findings)
                for f in findings:
                    f.tags = list(set(f.tags + auto_tag(f)))

            wave_results.append((action, output, findings, broken))
            scan_records.append({
                "tool":           tool,
                "args":           args,
                "cmd":            _describe_cmd(tool, args, available_tools),
                "status":         "broken" if broken else "ok",
                "timed_out":      (not broken) and ("Command timed out" in output),
                "output":         output[:400],
                "findings_count": len(findings) if not broken else 0,
                "phase":          "parallel-wave",
            })

    return wave_results, scan_records


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

# Inline SVG logo — replicates the Noctis Edge brand mark (shield + N + circuit dots).
# Pure XML text: no binary, no external references, no scripts.  Safe for DLP/air-gap.
_LOGO_SVG = """
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1254 960" role="img" aria-label="Noctis Edge — Security Through Exposure" style="width:200px;height:auto;display:block">
<path d="M 631,638 L 631,667 L 630,668 L 629,667 L 629,748 L 629,741 L 630,740 L 631,741 L 631,751 Z" fill="#8d9daa" stroke="none"/>
<path d="M 586,400 L 588,402 L 589,401 L 592,405 L 591,406 L 592,405 L 595,409 L 594,410 L 595,411 L 596,410 L 599,413 L 600,415 L 599,416 L 600,417 L 601,416 L 604,420 L 603,421 L 604,422 L 605,421 L 608,424 L 607,426 L 609,428 L 610,427 L 613,431 L 612,432 L 613,433 L 614,432 L 617,436 L 616,437 L 617,438 L 618,437 L 621,441 L 620,442 L 626,446 L 624,447 L 626,449 L 627,447 L 628,448 L 628,452 L 629,453 L 630,452 L 627,446 L 624,443 L 624,442 L 620,439 L 621,438 L 620,437 L 619,438 L 618,437 L 618,436 L 615,433 L 616,432 L 615,432 L 611,428 L 612,427 L 607,423 L 608,422 L 607,421 L 606,422 L 602,417 L 603,416 L 602,415 L 601,416 L 598,412 L 599,411 L 598,410 L 597,411 L 594,407 L 595,406 L 594,405 L 593,406 L 589,401 L 590,400 L 589,401 L 588,400 L 587,401 Z" fill="#8d9daa" stroke="none"/>
<path d="M 528,398 L 530,448 L 530,588 L 530,416 Z" fill="#8d9daa" stroke="none"/>
<path d="M 527,327 L 472,326 L 491,344 L 491,365 L 488,364 L 488,361 L 489,520 L 491,389 L 495,397 L 509,392 L 517,394 L 519,390 L 526,386 L 527,388 L 528,384 L 543,380 L 541,377 L 545,377 L 543,375 L 548,374 L 550,369 L 556,369 L 558,365 L 560,367 L 549,357 L 551,356 Z" fill="#8d9daa" stroke="none"/>
<path d="M 598,229 L 537,260 L 530,242 L 475,263 L 402,284 L 401,336 L 403,300 L 406,306 L 404,315 L 412,322 L 414,335 L 418,336 L 416,342 L 421,348 L 423,339 L 423,357 L 425,328 L 424,386 L 425,299 L 466,289 L 518,270 Z" fill="#8d9daa" stroke="none"/>
<path d="M 634,180 L 635,326 L 638,326 L 639,318 L 644,314 L 658,318 L 663,314 L 659,312 L 666,308 L 667,332 L 668,259 L 669,354 L 669,259 L 685,269 L 683,258 L 686,248 L 690,246 L 698,255 L 695,278 L 699,256 Z" fill="#8d9daa" stroke="none"/>
<path d="M 627,170 L 627,323 L 627,318 L 629,317 L 630,320 L 631,296 L 632,327 L 631,231 L 631,239 L 629,239 L 629,236 L 629,269 L 627,269 Z" fill="#8d9daa" stroke="none"/>
<path d="M 599,927 L 604,927 L 605,928 L 611,928 L 612,929 L 617,929 L 618,930 L 633,930 L 634,929 L 640,929 L 641,930 L 645,930 L 646,929 L 652,929 L 653,928 L 655,928 L 656,927 L 661,927 L 645,927 L 644,928 L 632,928 L 631,929 L 624,929 L 623,928 L 615,928 L 614,927 Z" fill="#26445c" stroke="none"/>
<path d="M 846,925 L 925,925 L 926,924 L 936,924 L 856,924 L 855,925 Z" fill="#26445c" stroke="none"/>
<path d="M 326,924 L 331,924 L 332,925 L 398,925 L 393,925 L 392,924 Z" fill="#26445c" stroke="none"/>
<path d="M 590,922 L 606,922 L 607,921 L 618,921 L 619,920 L 637,920 L 638,921 L 649,921 L 650,922 L 666,922 L 652,922 L 651,921 L 652,920 L 654,920 L 644,920 L 643,919 L 617,919 L 616,920 L 604,920 L 605,921 L 604,922 Z" fill="#26445c" stroke="none"/>
<path d="M 692,661 L 690,661 L 689,662 L 688,662 L 689,662 L 690,663 L 689,664 L 689,665 L 688,666 L 688,667 L 687,668 L 687,669 L 686,670 L 685,670 L 685,672 L 684,673 L 684,676 L 683,677 L 684,678 L 681,681 L 682,682 L 681,683 L 682,682 L 681,681 L 684,678 L 685,678 L 686,679 L 685,680 L 687,678 L 686,677 L 688,675 L 689,675 L 691,673 L 692,673 Z" fill="#26445c" stroke="none"/>
<path d="M 550,652 L 566,667 L 566,669 L 569,672 L 570,671 L 573,673 L 572,674 L 574,676 L 575,675 L 576,677 L 579,680 L 580,679 L 582,682 L 583,682 L 586,685 L 590,687 L 593,690 L 594,690 L 596,692 L 600,694 L 603,697 L 603,696 L 601,694 L 598,693 L 593,688 L 592,688 L 589,685 L 588,685 L 584,681 L 583,681 L 579,677 L 578,677 L 574,673 L 573,673 L 568,668 L 567,668 Z" fill="#26445c" stroke="none"/>
<path d="M 687,643 L 687,644 L 688,645 L 688,647 L 687,648 L 687,651 L 686,652 L 686,657 L 685,658 L 686,658 L 687,659 L 689,659 L 690,658 L 693,658 L 692,657 L 692,651 L 693,650 L 693,643 Z" fill="#26445c" stroke="none"/>
<path d="M 678,625 L 678,631 L 679,632 L 679,640 L 678,641 L 689,641 L 687,641 L 686,640 L 687,639 L 692,639 L 692,637 L 691,637 L 690,638 L 689,637 L 689,629 L 690,628 L 690,627 L 691,626 L 692,626 L 690,626 L 689,625 L 690,624 L 692,624 L 681,624 L 680,625 Z" fill="#26445c" stroke="none"/>
<path d="M 704,588 L 705,588 L 706,589 L 705,590 L 704,590 L 704,592 L 705,592 L 706,593 L 706,601 L 705,602 L 705,603 L 706,604 L 705,605 L 720,605 L 720,588 Z" fill="#26445c" stroke="none"/>
<path d="M 678,585 L 678,605 L 685,605 L 685,604 L 686,603 L 691,603 L 690,603 L 688,601 L 688,600 L 687,599 L 687,588 L 686,587 L 687,586 L 692,586 L 681,586 L 680,585 Z" fill="#26445c" stroke="none"/>
<path d="M 678,548 L 678,566 L 693,566 L 694,567 L 694,577 L 694,567 L 693,566 L 693,547 L 684,547 L 683,548 Z" fill="#26445c" stroke="none"/>
<path d="M 831,529 L 830,528 L 825,534 L 824,533 L 822,535 L 823,536 L 816,544 L 814,543 L 730,543 L 729,545 L 730,546 L 774,546 L 775,545 L 781,545 L 782,546 L 784,545 L 810,545 L 811,546 L 814,545 L 815,546 L 829,533 Z" fill="#26445c" stroke="none"/>
<path d="M 852,475 L 850,475 L 840,485 L 839,485 L 835,489 L 834,488 L 830,492 L 831,493 L 829,495 L 828,494 L 824,498 L 825,499 L 823,501 L 822,501 L 806,517 L 821,502 L 822,502 L 823,503 L 822,504 L 828,498 L 829,498 L 850,477 L 849,476 L 850,475 Z" fill="#26445c" stroke="none"/>
<path d="M 817,466 L 817,476 L 826,476 L 826,466 Z" fill="#26445c" stroke="none"/>
<path d="M 836,437 L 830,437 L 829,438 L 828,438 L 825,441 L 824,440 L 813,451 L 814,452 L 814,453 L 813,454 L 812,454 L 811,453 L 807,457 L 808,458 L 809,458 L 811,456 L 812,457 L 814,455 L 813,454 L 814,453 L 815,453 L 821,447 L 822,447 L 828,441 L 827,440 L 828,439 L 829,439 L 830,438 L 836,438 Z" fill="#26445c" stroke="none"/>
<path d="M 679,433 L 678,525 L 684,527 L 681,528 L 681,535 L 684,538 L 684,545 L 692,545 L 693,542 L 694,545 L 692,541 L 693,525 L 683,525 L 686,523 L 693,523 L 693,506 L 685,507 L 683,505 L 685,504 L 685,493 L 691,490 L 691,488 L 687,486 L 686,472 L 691,469 L 690,470 L 685,466 L 684,453 L 688,450 L 691,450 L 692,434 L 693,448 L 695,449 L 693,450 L 709,450 L 695,449 L 693,445 L 693,434 Z" fill="#26445c" stroke="none"/>
<path d="M 794,424 L 794,433 L 795,434 L 794,435 L 797,435 L 798,434 L 805,434 L 804,433 L 804,424 L 796,424 L 796,433 L 795,434 L 794,433 Z" fill="#26445c" stroke="none"/>
<path d="M 527,423 L 526,454 L 525,448 L 524,451 L 516,451 L 512,449 L 513,451 L 511,452 L 508,448 L 506,449 L 505,447 L 502,447 L 503,448 L 500,451 L 497,449 L 498,450 L 495,452 L 494,451 L 493,454 L 492,434 L 491,508 L 492,502 L 493,510 L 499,506 L 504,510 L 511,510 L 513,507 L 517,511 L 523,508 L 524,505 L 522,502 L 524,502 L 523,501 L 525,499 L 526,518 Z" fill="#26445c" stroke="none"/>
<path d="M 742,422 L 741,423 L 729,423 L 728,424 L 728,425 L 729,426 L 729,427 L 730,428 L 731,427 L 732,428 L 732,429 L 735,429 L 736,430 L 737,429 L 738,429 L 739,430 L 738,431 L 738,432 L 737,433 L 737,434 L 736,435 L 730,435 L 736,435 L 737,434 L 738,435 L 738,436 L 738,435 L 737,434 L 738,433 L 738,431 L 739,430 L 742,430 Z" fill="#26445c" stroke="none"/>
<path d="M 879,417 L 876,414 L 870,416 L 868,418 L 869,419 L 871,417 L 872,417 L 871,416 L 872,415 L 874,415 L 875,416 L 874,417 L 876,416 L 878,419 L 877,420 L 877,422 L 878,423 L 875,426 L 874,425 L 872,425 L 871,426 L 868,424 L 869,422 L 868,423 L 868,425 L 866,427 L 865,426 L 857,434 L 864,427 L 865,428 L 865,429 L 858,436 L 856,437 L 843,437 L 848,437 L 849,438 L 856,438 L 857,437 L 858,438 L 869,427 L 871,428 L 875,428 L 877,427 L 880,423 L 880,420 L 878,419 Z" fill="#26445c" stroke="none"/>
<path d="M 405,413 L 412,460 L 418,484 L 421,488 L 420,491 L 427,507 L 426,509 L 428,509 L 430,514 L 434,513 L 437,518 L 434,518 L 434,525 L 438,534 L 438,526 L 440,527 L 445,522 L 446,524 L 447,522 L 450,523 L 451,530 L 454,527 L 456,530 L 457,528 L 453,524 L 454,521 L 451,519 L 452,516 L 449,514 L 448,506 L 446,506 L 447,503 L 445,503 L 446,500 L 444,500 L 445,497 L 443,497 L 444,494 L 442,494 L 441,485 L 439,485 L 438,474 L 436,474 L 437,471 L 434,466 L 427,422 L 428,440 L 425,429 L 424,431 L 423,429 L 414,431 L 420,430 L 421,434 L 419,436 L 417,433 L 414,437 L 413,433 L 409,436 L 406,426 L 409,421 L 406,420 Z" fill="#26445c" stroke="none"/>
<path d="M 708,405 L 707,406 L 706,405 L 702,405 L 701,406 L 696,406 L 696,417 L 702,417 L 703,416 L 704,417 L 706,417 L 707,416 L 708,416 Z" fill="#26445c" stroke="none"/>
<path d="M 727,405 L 727,413 L 728,414 L 728,416 L 727,417 L 727,418 L 741,418 L 742,417 L 743,417 L 743,404 L 740,404 L 739,405 L 732,405 L 731,404 L 728,404 Z" fill="#26445c" stroke="none"/>
<path d="M 631,404 L 631,408 L 630,409 L 629,408 L 629,407 L 629,416 L 628,417 L 627,416 L 627,409 L 627,428 L 628,429 L 628,432 L 631,432 L 632,433 L 632,409 L 631,408 Z" fill="#26445c" stroke="none"/>
<path d="M 584,399 L 598,417 L 576,424 L 579,429 L 569,435 L 573,442 L 567,447 L 564,437 L 561,439 L 555,431 L 613,510 L 620,512 L 617,515 L 625,511 L 621,506 L 624,494 L 630,498 L 630,494 L 634,497 L 644,491 L 642,496 L 649,496 L 645,500 L 657,509 L 659,526 L 667,534 L 667,578 L 668,381 L 667,438 L 666,407 L 662,409 L 660,399 L 650,393 L 635,404 L 634,390 L 633,459 Z" fill="#26445c" stroke="none"/>
<path d="M 710,380 L 710,392 L 709,393 L 710,392 L 711,393 L 725,393 L 724,392 L 724,379 L 723,380 L 716,380 L 715,379 L 712,379 L 711,380 Z" fill="#26445c" stroke="none"/>
<path d="M 679,363 L 679,375 L 678,376 L 678,378 L 693,378 L 693,363 L 692,364 L 685,364 L 684,363 Z" fill="#26445c" stroke="none"/>
<path d="M 747,335 L 747,338 L 748,339 L 748,347 L 747,348 L 747,349 L 746,350 L 748,348 L 749,349 L 760,349 L 760,335 Z" fill="#26445c" stroke="none"/>
<path d="M 723,312 L 724,313 L 726,313 L 728,315 L 728,321 L 727,322 L 726,322 L 725,321 L 724,322 L 723,322 L 722,321 L 721,322 L 720,322 L 719,321 L 717,321 L 719,321 L 722,324 L 723,324 L 728,329 L 730,329 L 731,328 L 731,327 L 732,326 L 732,325 L 733,324 L 731,322 L 729,322 L 728,321 L 728,315 L 726,313 L 724,313 Z" fill="#26445c" stroke="none"/>
<path d="M 693,303 L 693,310 L 691,312 L 681,312 L 680,311 L 679,312 L 679,324 L 681,324 L 682,323 L 685,323 L 687,321 L 688,321 L 689,322 L 691,322 L 692,321 L 693,322 L 693,319 L 693,320 L 692,321 L 690,319 L 690,314 L 689,313 L 690,312 L 692,312 L 693,311 Z" fill="#26445c" stroke="none"/>
<path d="M 736,286 L 736,288 L 742,294 L 742,295 L 743,296 L 744,296 L 745,297 L 745,300 L 745,297 L 744,296 L 744,295 L 745,294 L 747,294 L 748,295 L 749,295 L 751,293 L 752,293 L 753,292 L 753,290 L 752,289 L 751,290 L 750,289 L 749,290 L 748,290 L 745,293 L 744,292 L 743,293 L 740,290 L 740,287 L 739,286 L 740,285 L 739,285 L 738,286 Z" fill="#26445c" stroke="none"/>
<path d="M 695,229 L 695,230 L 696,231 L 696,234 L 695,235 L 695,237 L 697,237 L 698,238 L 702,238 L 702,233 L 701,232 L 701,230 L 697,230 L 696,229 Z" fill="#26445c" stroke="none"/>
<path d="M 578,214 L 580,216 L 579,217 L 578,217 L 576,215 L 578,217 L 575,219 L 574,218 L 572,219 L 571,221 L 570,220 L 566,223 L 552,230 L 560,226 L 562,228 L 561,229 L 562,230 L 561,231 L 558,230 L 559,230 L 560,232 L 561,232 L 562,234 L 563,234 L 566,237 L 564,238 L 567,238 L 569,240 L 571,240 L 572,241 L 568,243 L 566,245 L 563,246 L 582,237 L 584,235 L 585,235 L 586,233 L 587,234 L 586,233 L 587,232 L 589,233 L 588,232 L 591,230 L 592,231 L 591,230 L 592,229 L 594,230 L 593,228 L 591,229 L 590,228 L 591,227 L 590,228 L 589,227 L 587,227 L 586,225 L 582,222 L 583,220 L 581,216 L 580,216 Z" fill="#26445c" stroke="none"/>
<path d="M 590,924 L 601,924 L 602,925 L 603,924 L 606,924 L 607,925 L 649,925 L 650,924 L 658,924 L 638,924 L 637,923 L 621,923 L 620,924 Z" fill="#e5ecef" stroke="none"/>
<path d="M 619,811 L 614,819 L 613,830 L 616,839 L 622,845 L 632,848 L 670,848 L 677,854 L 678,861 L 676,866 L 669,871 L 617,871 L 614,880 L 671,880 L 679,877 L 685,870 L 687,863 L 686,851 L 679,842 L 672,839 L 630,838 L 623,831 L 623,823 L 629,816 L 682,815 L 685,806 L 631,806 Z" fill="#e5ecef" stroke="none"/>
<path d="M 571,806 L 571,823 L 572,824 L 572,868 L 571,869 L 571,876 L 572,877 L 572,879 L 571,880 L 581,880 L 581,806 Z" fill="#e5ecef" stroke="none"/>
<path d="M 461,806 L 461,815 L 493,815 L 495,817 L 495,878 L 496,879 L 495,880 L 505,880 L 505,817 L 507,815 L 508,816 L 539,815 L 539,806 Z" fill="#e5ecef" stroke="none"/>
<path d="M 367,812 L 361,823 L 361,864 L 364,871 L 372,878 L 378,880 L 432,880 L 432,871 L 381,871 L 372,865 L 370,859 L 370,828 L 372,822 L 377,817 L 384,815 L 432,815 L 432,806 L 380,806 Z" fill="#e5ecef" stroke="none"/>
<path d="M 249,815 L 245,825 L 245,862 L 249,872 L 253,876 L 262,880 L 312,880 L 319,877 L 324,873 L 327,868 L 329,859 L 329,828 L 327,819 L 321,811 L 314,807 L 309,806 L 265,806 L 254,810 Z M 264,819 L 273,817 L 303,819 L 306,819 L 311,821 L 315,827 L 316,833 L 316,854 L 315,860 L 314,864 L 310,866 L 305,868 L 271,869 L 264,867 L 260,864 L 258,857 L 258,830 L 261,823 Z" fill="#e5ecef" fill-rule="evenodd" stroke="none"/>
<path d="M 134,806 L 134,880 L 144,880 L 145,821 L 203,880 L 212,880 L 212,806 L 203,806 L 202,864 L 144,806 Z" fill="#e5ecef" stroke="none"/>
<path d="M 471,325 L 527,326 L 613,432 L 610,429 L 611,427 L 615,431 L 607,425 L 608,423 L 610,425 L 529,325 Z" fill="#e5ecef" stroke="none"/>
<path d="M 670,260 L 670,494 L 671,379 L 674,389 L 676,367 L 676,270 Z" fill="#e5ecef" stroke="none"/>
<path d="M 551,229 L 526,241 L 481,259 L 437,273 L 402,281 L 432,275 L 475,262 L 511,248 Z" fill="#e5ecef" stroke="none"/>
<path d="M 628,171 L 628,269 L 628,236 L 630,239 L 630,231 L 632,231 L 633,334 L 633,180 L 639,184 L 682,235 Z" fill="#e5ecef" stroke="none"/>
<path d="M 603,925 L 653,926 L 781,924 L 638,923 L 658,923 L 658,925 L 649,926 Z" fill="#6dc0ef" stroke="none"/>
<path d="M 620,923 L 478,924 L 601,925 L 590,925 L 589,924 L 590,923 Z" fill="#6dc0ef" stroke="none"/>
<path d="M 1146,806 L 1145,807 L 1144,806 L 1143,807 L 1080,807 L 1080,809 L 1079,810 L 1079,814 L 1080,815 L 1143,815 L 1144,813 L 1144,811 L 1145,810 L 1145,807 Z" fill="#6dc0ef" stroke="none"/>
<path d="M 1046,807 L 1045,806 L 1043,807 L 995,807 L 994,808 L 990,807 L 989,809 L 987,808 L 986,810 L 985,809 L 984,811 L 983,810 L 980,815 L 977,817 L 978,818 L 976,819 L 975,822 L 975,853 L 975,829 L 976,828 L 977,829 L 977,835 L 981,834 L 982,831 L 983,832 L 983,844 L 984,846 L 984,825 L 989,818 L 997,815 L 1042,815 L 1044,814 Z" fill="#6dc0ef" stroke="none"/>
<path d="M 867,806 L 868,813 L 867,815 L 920,815 L 928,817 L 934,823 L 935,826 L 935,854 L 936,835 L 937,834 L 938,837 L 943,834 L 944,835 L 944,860 L 944,823 L 942,818 L 936,811 L 932,810 L 931,808 L 929,809 L 928,807 L 922,808 L 921,807 L 868,807 Z" fill="#6dc0ef" stroke="none"/>
<path d="M 765,806 L 765,880 L 834,880 L 834,871 L 833,880 L 766,879 L 767,834 L 768,839 L 773,834 L 775,839 L 829,840 L 828,847 L 776,847 L 774,852 L 776,847 L 829,847 L 830,839 L 776,839 L 775,817 L 831,815 L 834,806 Z" fill="#6dc0ef" stroke="none"/>
<path d="M 633,591 L 633,733 L 632,751 L 630,751 L 630,741 L 629,749 L 632,755 L 631,756 L 633,751 Z" fill="#6dc0ef" stroke="none"/>
<path d="M 600,497 L 603,500 L 603,501 L 605,503 L 605,504 L 608,507 L 608,508 L 611,511 L 611,512 L 614,515 L 614,516 L 617,519 L 617,520 L 620,523 L 620,524 L 623,527 L 623,528 L 626,531 L 626,532 L 629,535 L 631,535 L 632,536 L 630,534 L 630,533 L 627,530 L 627,529 L 623,525 L 623,524 L 620,521 L 620,520 L 617,517 L 617,516 L 614,513 L 614,512 L 611,509 L 611,508 L 607,504 L 607,503 L 605,501 L 604,502 L 603,501 L 603,500 L 604,499 L 602,497 L 601,498 Z" fill="#6dc0ef" stroke="none"/>
<path d="M 705,490 L 768,490 L 767,490 L 766,489 L 767,488 L 770,488 L 707,488 L 710,488 L 711,489 L 710,490 Z" fill="#6dc0ef" stroke="none"/>
<path d="M 675,367 L 671,408 L 670,695 L 677,685 L 672,691 L 670,688 L 671,528 L 674,535 L 676,530 L 676,566 Z" fill="#6dc0ef" stroke="none"/>
<path d="M 813,366 L 774,404 L 773,455 L 760,467 L 710,467 L 710,469 L 703,469 L 761,469 L 776,454 L 776,405 Z" fill="#6dc0ef" stroke="none"/>
<path d="M 877,298 L 877,308 L 887,308 L 887,299 L 882,299 L 881,298 Z" fill="#6dc0ef" stroke="none"/>
<path d="M 813,297 L 802,297 L 801,299 L 801,309 L 807,312 L 807,332 L 806,334 L 759,379 L 746,379 L 745,380 L 744,379 L 744,393 L 746,394 L 760,393 L 759,381 L 809,333 L 809,312 L 811,310 L 815,310 L 815,299 Z" fill="#6dc0ef" stroke="none"/>
<path d="M 813,268 L 812,269 L 812,278 L 813,278 L 814,279 L 822,279 L 822,270 L 820,270 L 819,269 L 816,269 L 815,268 Z" fill="#6dc0ef" stroke="none"/>
<path d="M 731,268 L 731,282 L 746,282 L 746,268 Z" fill="#6dc0ef" stroke="none"/>
<path d="M 672,262 L 672,263 L 673,264 L 673,265 L 675,267 L 675,268 L 677,270 L 677,271 L 678,270 L 680,272 L 681,272 L 682,273 L 681,274 L 682,273 L 684,275 L 684,276 L 685,275 L 686,276 L 687,276 L 690,279 L 691,279 L 692,278 L 690,276 L 689,277 L 686,274 L 686,273 L 683,270 L 681,270 L 680,269 L 680,268 L 677,265 L 676,266 L 674,264 L 674,263 L 673,262 Z" fill="#6dc0ef" stroke="none"/>
<path d="M 849,257 L 849,264 L 855,264 L 856,265 L 856,258 L 854,258 L 853,257 Z" fill="#6dc0ef" stroke="none"/>
<path d="M 757,241 L 757,253 L 760,253 L 761,254 L 769,254 L 769,242 L 758,242 Z" fill="#6dc0ef" stroke="none"/>
<path d="M 514,618 L 520,624 L 521,623 L 523,625 L 522,627 L 527,632 L 528,631 L 530,633 L 530,635 L 531,635 L 532,637 L 533,637 L 534,639 L 552,657 L 553,657 L 565,668 L 565,667 L 560,662 L 559,662 L 524,627 L 524,626 L 518,620 L 517,621 Z" fill="#5b6f7d" stroke="none"/>
<path d="M 548,354 L 558,367 L 544,375 L 543,381 L 528,385 L 517,395 L 509,393 L 495,398 L 492,389 L 491,450 L 492,433 L 493,453 L 502,446 L 511,451 L 514,448 L 524,450 L 525,447 L 526,453 L 527,422 L 528,482 L 528,397 L 533,399 L 549,424 L 546,424 L 569,454 L 568,445 L 573,438 L 569,434 L 572,431 L 576,433 L 576,425 L 581,420 L 582,425 L 589,421 L 588,418 L 593,419 L 598,415 Z" fill="#5b6f7d" stroke="none"/>
<path d="M 634,310 L 635,403 L 637,402 L 637,404 L 650,392 L 651,394 L 654,394 L 655,397 L 659,397 L 656,400 L 660,398 L 661,399 L 659,402 L 662,404 L 661,406 L 662,404 L 663,408 L 664,406 L 666,406 L 663,375 L 665,365 L 664,340 L 666,329 L 666,309 L 663,309 L 660,312 L 664,314 L 662,316 L 660,315 L 660,317 L 658,317 L 658,315 L 655,318 L 649,315 L 644,315 L 640,318 L 640,324 L 638,325 L 637,323 L 638,325 L 635,327 Z" fill="#5b6f7d" stroke="none"/>
<path d="M 405,298 L 402,302 L 402,336 L 400,336 L 400,320 L 400,373 L 400,370 L 402,370 L 402,406 L 403,401 L 405,401 L 403,415 L 406,413 L 408,421 L 406,437 L 408,432 L 409,435 L 413,434 L 414,436 L 417,432 L 418,436 L 416,437 L 420,434 L 418,430 L 422,429 L 423,433 L 423,430 L 427,431 L 428,439 L 426,429 L 427,418 L 425,420 L 422,339 L 421,349 L 419,343 L 415,342 L 417,340 L 414,339 L 417,336 L 413,334 L 416,332 L 411,327 L 411,322 L 404,317 L 405,315 L 402,312 L 405,307 Z" fill="#5b6f7d" stroke="none"/>
<path d="M 688,245 L 690,247 L 689,248 L 687,248 L 686,249 L 685,248 L 688,251 L 687,252 L 686,252 L 687,255 L 686,256 L 685,256 L 684,255 L 683,256 L 684,255 L 685,256 L 685,257 L 684,258 L 686,260 L 684,262 L 685,261 L 686,262 L 686,263 L 685,264 L 685,266 L 684,267 L 685,268 L 684,269 L 683,269 L 676,263 L 680,267 L 681,267 L 687,273 L 688,273 L 694,279 L 693,278 L 695,276 L 695,274 L 696,273 L 696,269 L 697,268 L 697,255 L 698,254 L 699,255 L 698,254 L 697,255 L 693,251 L 693,250 L 694,249 L 695,250 L 694,249 L 693,250 Z" fill="#5b6f7d" stroke="none"/>
<path d="M 571,241 L 569,241 L 567,239 L 564,239 L 563,238 L 566,236 L 565,235 L 564,236 L 562,235 L 561,233 L 559,232 L 560,230 L 562,231 L 560,229 L 561,228 L 560,227 L 557,229 L 555,228 L 556,229 L 555,230 L 553,229 L 554,230 L 553,231 L 551,230 L 550,232 L 549,231 L 550,232 L 549,233 L 547,232 L 546,234 L 545,233 L 530,241 L 528,241 L 518,246 L 529,241 L 531,242 L 532,251 L 536,253 L 535,254 L 536,255 L 535,257 L 537,258 L 532,261 L 535,259 L 537,259 L 542,256 L 544,256 L 555,250 L 557,250 L 563,247 L 562,246 L 563,245 L 565,246 L 564,245 L 565,244 L 567,245 L 566,244 L 568,242 Z" fill="#5b6f7d" stroke="none"/>
<path d="M 764,925 L 845,925 L 846,924 L 855,924 L 782,924 L 781,925 Z" fill="#2e76ae" stroke="none"/>
<path d="M 393,924 L 398,924 L 399,925 L 489,925 L 478,925 L 477,924 Z" fill="#2e76ae" stroke="none"/>
<path d="M 1080,840 L 1080,879 L 1145,879 L 1145,871 L 1089,871 L 1088,870 L 1087,848 L 1088,847 L 1090,848 L 1088,847 L 1089,846 L 1140,846 L 1140,840 Z" fill="#2e76ae" stroke="none"/>
<path d="M 943,835 L 938,838 L 937,835 L 936,854 L 933,864 L 928,869 L 923,871 L 878,871 L 876,862 L 877,859 L 867,849 L 867,879 L 868,878 L 869,879 L 923,879 L 924,877 L 928,878 L 927,877 L 928,876 L 932,878 L 930,876 L 932,875 L 934,877 L 932,875 L 933,874 L 936,876 L 937,875 L 936,874 L 939,871 L 940,872 L 941,871 L 940,869 L 941,868 L 942,869 L 941,867 L 942,866 L 943,867 L 944,864 Z" fill="#2e76ae" stroke="none"/>
<path d="M 767,835 L 767,879 L 833,879 L 833,871 L 775,870 L 776,848 L 829,848 L 776,848 L 776,846 L 828,846 L 828,840 L 775,840 L 773,835 L 768,840 Z" fill="#2e76ae" stroke="none"/>
<path d="M 976,829 L 976,853 L 974,853 L 974,833 L 974,860 L 976,859 L 976,868 L 979,868 L 977,870 L 981,871 L 980,874 L 982,876 L 984,875 L 989,878 L 995,877 L 994,879 L 1032,879 L 1019,879 L 1019,877 L 1036,878 L 1041,877 L 1043,872 L 1045,872 L 1045,865 L 1047,866 L 1047,839 L 1046,851 L 1045,841 L 1018,841 L 1017,845 L 1016,843 L 1017,847 L 1038,848 L 1038,863 L 1036,868 L 1032,871 L 995,871 L 988,868 L 985,864 L 982,832 L 981,835 L 977,836 Z" fill="#2e76ae" stroke="none"/>
<path d="M 756,568 L 755,569 L 755,583 L 770,583 L 770,568 Z" fill="#2e76ae" stroke="none"/>
<path d="M 714,549 L 713,550 L 713,563 L 714,564 L 713,565 L 713,566 L 730,566 L 730,549 L 729,549 L 728,550 L 715,550 Z" fill="#2e76ae" stroke="none"/>
<path d="M 633,539 L 633,555 L 631,557 L 629,555 L 628,549 L 627,554 L 627,641 L 627,589 L 629,589 L 629,641 L 629,632 L 631,632 L 631,637 L 631,595 L 633,590 Z" fill="#2e76ae" stroke="none"/>
<path d="M 711,507 L 711,523 L 728,523 L 727,522 L 727,509 L 728,508 L 727,507 Z" fill="#2e76ae" stroke="none"/>
<path d="M 797,471 L 791,477 L 792,478 L 789,481 L 788,480 L 785,483 L 786,484 L 782,488 L 781,487 L 782,488 L 781,489 L 780,489 L 779,488 L 778,489 L 767,489 L 768,489 L 769,490 L 770,489 L 771,490 L 777,490 L 778,489 L 779,490 L 780,490 L 781,489 L 782,490 L 797,475 L 797,473 L 796,472 Z" fill="#2e76ae" stroke="none"/>
<path d="M 879,468 L 875,469 L 872,474 L 849,474 L 823,500 L 839,484 L 840,484 L 844,480 L 845,481 L 850,476 L 870,476 L 868,476 L 867,475 L 868,474 L 872,474 L 873,473 L 874,475 L 872,476 L 874,479 L 874,477 L 875,476 L 876,477 L 875,476 L 875,473 L 878,470 L 879,470 Z" fill="#2e76ae" stroke="none"/>
<path d="M 739,433 L 740,434 L 740,438 L 739,439 L 739,449 L 740,448 L 741,449 L 754,449 L 754,434 L 753,435 L 752,434 L 745,434 L 744,435 L 742,435 L 741,434 L 740,434 Z" fill="#2e76ae" stroke="none"/>
<path d="M 677,433 L 677,566 L 675,530 L 674,536 L 672,528 L 673,691 L 676,682 L 678,684 L 693,674 L 693,659 L 684,658 L 686,643 L 693,642 L 677,641 L 677,625 L 693,624 L 693,606 L 677,605 L 677,585 L 693,584 L 693,567 L 677,566 L 677,548 L 693,546 L 693,543 L 692,546 L 683,545 L 680,528 L 683,527 L 677,525 Z" fill="#2e76ae" stroke="none"/>
<path d="M 728,426 L 728,435 L 729,435 L 730,434 L 736,434 L 736,433 L 737,432 L 737,431 L 738,430 L 737,430 L 736,431 L 735,430 L 732,430 L 731,429 L 731,428 L 730,429 L 728,427 Z" fill="#2e76ae" stroke="none"/>
<path d="M 879,418 L 879,419 L 879,418 L 876,415 L 875,415 L 874,414 L 871,414 L 870,415 L 869,415 L 867,417 L 867,418 L 866,419 L 866,422 L 867,423 L 866,426 L 856,436 L 850,436 L 856,436 L 857,435 L 858,435 L 859,436 L 857,438 L 867,428 L 865,430 L 864,429 L 864,428 L 867,425 L 867,423 L 868,422 L 869,423 L 869,424 L 870,424 L 871,425 L 868,422 L 868,419 L 870,417 L 869,416 L 870,415 L 871,415 L 872,416 L 874,416 L 877,419 L 876,418 L 876,417 L 877,416 Z" fill="#2e76ae" stroke="none"/>
<path d="M 806,396 L 806,401 L 806,398 L 807,397 L 808,398 L 808,407 L 809,407 L 811,409 L 812,408 L 813,409 L 813,408 L 814,407 L 815,408 L 818,408 L 819,407 L 820,408 L 820,402 L 819,401 L 819,397 L 818,396 L 817,396 L 816,395 L 808,395 L 808,396 L 807,397 Z" fill="#2e76ae" stroke="none"/>
<path d="M 900,354 L 896,350 L 892,351 L 891,350 L 885,356 L 878,357 L 863,357 L 862,356 L 851,356 L 850,357 L 839,357 L 838,356 L 828,357 L 827,356 L 826,357 L 825,356 L 818,361 L 795,385 L 794,384 L 789,389 L 790,390 L 785,395 L 786,396 L 780,402 L 825,358 L 886,358 L 890,363 L 896,364 L 900,360 Z" fill="#2e76ae" stroke="none"/>
<path d="M 731,334 L 731,335 L 730,336 L 731,337 L 731,341 L 730,342 L 730,345 L 731,346 L 730,347 L 731,348 L 731,349 L 736,349 L 737,348 L 739,348 L 740,349 L 744,349 L 745,348 L 746,348 L 746,336 L 746,346 L 745,347 L 744,346 L 744,336 L 737,336 L 736,335 L 737,334 L 745,334 Z" fill="#2e76ae" stroke="none"/>
<path d="M 694,334 L 694,349 L 710,349 L 710,348 L 709,347 L 709,336 L 710,335 L 709,336 L 708,335 L 696,335 L 695,334 Z" fill="#2e76ae" stroke="none"/>
<path d="M 841,324 L 840,323 L 837,325 L 839,324 L 841,327 L 841,331 L 838,334 L 837,333 L 838,334 L 837,335 L 835,335 L 833,332 L 832,333 L 830,331 L 831,329 L 830,327 L 833,324 L 834,325 L 833,324 L 830,326 L 829,325 L 830,326 L 830,333 L 829,334 L 828,333 L 829,334 L 827,336 L 826,335 L 819,342 L 820,343 L 802,358 L 798,363 L 797,362 L 785,374 L 784,373 L 781,376 L 782,377 L 780,379 L 775,381 L 776,380 L 778,382 L 777,381 L 778,380 L 780,381 L 792,369 L 812,353 L 822,342 L 831,335 L 840,335 L 842,333 L 840,326 Z" fill="#2e76ae" stroke="none"/>
<path d="M 631,317 L 631,320 L 630,321 L 629,320 L 629,318 L 629,381 L 628,382 L 628,415 L 628,407 L 629,406 L 630,397 L 632,392 L 632,340 L 631,339 L 632,337 L 632,328 L 631,327 Z" fill="#2e76ae" stroke="none"/>
<path d="M 712,312 L 712,319 L 715,319 L 716,320 L 719,320 L 720,321 L 721,321 L 722,320 L 723,321 L 724,321 L 725,320 L 726,321 L 727,321 L 727,315 L 726,314 L 724,314 L 722,312 Z" fill="#2e76ae" stroke="none"/>
<path d="M 759,296 L 757,296 L 758,296 L 759,297 L 758,298 L 748,298 L 747,297 L 747,298 L 748,299 L 747,300 L 747,309 L 760,309 L 759,308 L 759,299 L 760,298 L 759,297 Z" fill="#2e76ae" stroke="none"/>
<path d="M 668,290 L 668,332 L 666,330 L 664,375 L 667,436 L 667,381 L 669,381 L 669,516 Z" fill="#2e76ae" stroke="none"/>
<path d="M 740,286 L 741,287 L 741,290 L 742,291 L 741,292 L 742,291 L 743,292 L 744,291 L 746,293 L 749,293 L 746,293 L 745,292 L 748,289 L 749,289 L 750,288 L 751,289 L 751,288 L 748,285 L 741,285 Z" fill="#2e76ae" stroke="none"/>
<path d="M 559,928 L 573,929 L 579,931 L 600,932 L 620,936 L 621,935 L 623,936 L 624,935 L 651,935 L 656,933 L 674,932 L 685,929 L 686,930 L 698,928 L 662,927 L 645,931 L 640,930 L 618,931 L 598,927 Z" fill="#10202e" stroke="none"/>
<path d="M 853,923 L 936,923 L 936,925 L 926,925 L 1010,924 Z" fill="#10202e" stroke="none"/>
<path d="M 256,924 L 263,925 L 331,925 L 326,925 L 325,924 L 326,923 L 397,923 Z" fill="#10202e" stroke="none"/>
<path d="M 562,920 L 582,921 L 562,922 L 604,921 L 604,919 L 643,918 L 654,919 L 655,920 L 652,921 L 694,922 L 681,922 L 681,920 L 693,920 L 680,920 L 675,918 L 645,914 L 613,914 L 599,917 L 587,917 L 580,920 Z" fill="#10202e" stroke="none"/>
<path d="M 655,718 L 654,719 L 653,718 L 652,718 L 650,715 L 649,715 L 647,717 L 646,717 L 645,716 L 645,715 L 646,714 L 645,715 L 644,714 L 643,714 L 644,715 L 643,716 L 642,716 L 641,715 L 642,716 L 640,718 L 639,718 L 639,719 L 640,719 L 641,720 L 641,721 L 640,722 L 640,725 L 638,727 L 636,727 L 635,728 L 635,739 L 636,740 L 642,740 L 643,739 L 644,740 L 643,739 L 643,738 L 644,737 L 645,738 L 644,737 L 645,736 L 646,733 L 647,732 L 648,733 L 647,732 L 647,731 L 648,730 L 647,731 L 645,729 L 645,728 L 646,727 L 648,727 L 649,728 L 650,727 L 651,728 L 650,727 L 650,726 L 651,725 L 652,726 L 651,725 L 653,722 L 654,723 L 653,722 L 653,721 L 654,720 L 655,721 L 654,720 L 654,719 Z" fill="#10202e" stroke="none"/>
<path d="M 723,654 L 723,663 L 724,664 L 723,663 L 723,659 L 724,658 L 725,659 L 725,662 L 726,663 L 732,663 L 733,662 L 733,654 Z" fill="#10202e" stroke="none"/>
<path d="M 753,627 L 753,636 L 752,637 L 753,638 L 758,638 L 759,637 L 761,637 L 762,638 L 763,637 L 762,636 L 762,627 L 759,627 L 758,628 L 755,628 L 754,627 Z" fill="#10202e" stroke="none"/>
<path d="M 729,613 L 729,614 L 728,615 L 728,619 L 727,620 L 727,622 L 726,623 L 726,624 L 734,624 L 734,618 L 733,617 L 732,618 L 731,618 L 730,619 L 729,619 L 728,618 L 729,617 L 728,616 L 729,615 Z" fill="#10202e" stroke="none"/>
<path d="M 785,602 L 785,612 L 786,613 L 787,613 L 788,612 L 794,612 L 795,613 L 796,612 L 796,605 L 795,604 L 796,603 L 795,602 Z" fill="#10202e" stroke="none"/>
<path d="M 730,596 L 730,602 L 729,603 L 729,605 L 729,603 L 730,602 L 730,601 L 731,600 L 732,601 L 732,603 L 731,604 L 731,606 L 730,607 L 730,610 L 744,610 L 745,609 L 746,609 L 746,596 L 732,596 L 732,597 L 731,598 L 730,597 Z" fill="#10202e" stroke="none"/>
<path d="M 720,573 L 720,576 L 723,576 L 724,577 L 724,578 L 723,579 L 724,580 L 724,581 L 725,582 L 725,583 L 730,583 L 730,575 L 729,575 L 728,574 L 728,573 L 727,572 L 723,572 L 722,573 Z" fill="#10202e" stroke="none"/>
<path d="M 818,569 L 819,569 L 820,570 L 819,571 L 818,571 L 818,579 L 827,579 L 827,570 L 820,570 L 819,569 Z" fill="#10202e" stroke="none"/>
<path d="M 694,548 L 695,583 L 693,585 L 681,585 L 693,586 L 687,587 L 688,599 L 692,603 L 686,605 L 694,605 L 694,624 L 690,625 L 693,626 L 690,629 L 690,637 L 692,636 L 693,639 L 687,640 L 694,641 L 694,659 L 700,660 L 706,657 L 701,652 L 708,644 L 708,641 L 712,641 L 712,639 L 722,639 L 722,625 L 721,632 L 720,627 L 711,627 L 711,640 L 707,640 L 708,626 L 720,625 L 708,625 L 709,607 L 702,608 L 698,606 L 700,602 L 701,604 L 701,588 L 700,590 L 699,586 L 696,585 L 710,584 L 711,581 L 710,567 L 694,566 Z" fill="#10202e" stroke="none"/>
<path d="M 831,528 L 833,530 L 840,530 L 841,531 L 854,531 L 855,530 L 857,530 L 857,529 L 856,529 L 855,528 Z" fill="#10202e" stroke="none"/>
<path d="M 694,526 L 694,542 L 695,543 L 695,545 L 694,546 L 695,545 L 696,546 L 709,546 L 710,547 L 711,546 L 711,530 L 710,529 L 695,529 L 694,528 Z" fill="#10202e" stroke="none"/>
<path d="M 867,523 L 864,526 L 864,527 L 863,528 L 863,531 L 864,531 L 866,534 L 865,533 L 865,532 L 866,531 L 866,528 L 869,525 L 871,525 L 874,528 L 874,531 L 871,534 L 869,534 L 868,533 L 869,534 L 871,534 L 874,531 L 875,532 L 875,533 L 873,535 L 874,536 L 873,537 L 871,537 L 870,538 L 869,538 L 870,538 L 871,537 L 873,537 L 874,536 L 873,535 L 875,533 L 876,534 L 877,533 L 877,527 L 874,524 L 873,524 L 872,523 Z" fill="#10202e" stroke="none"/>
<path d="M 746,507 L 746,523 L 747,524 L 747,525 L 748,525 L 749,526 L 753,526 L 756,523 L 758,523 L 759,522 L 768,522 L 769,521 L 769,518 L 768,519 L 767,518 L 766,519 L 762,519 L 761,518 L 761,507 Z" fill="#10202e" stroke="none"/>
<path d="M 828,499 L 823,504 L 820,502 L 823,499 L 803,519 L 800,519 L 799,518 L 785,518 L 781,515 L 782,514 L 780,512 L 773,512 L 771,514 L 773,512 L 780,512 L 781,513 L 780,514 L 777,514 L 779,515 L 778,516 L 775,516 L 778,516 L 780,518 L 780,522 L 778,524 L 776,524 L 773,522 L 773,520 L 773,523 L 775,525 L 778,524 L 781,526 L 784,522 L 800,522 L 801,521 L 806,521 Z" fill="#10202e" stroke="none"/>
<path d="M 798,493 L 798,501 L 806,501 L 807,502 L 810,502 L 810,493 Z" fill="#10202e" stroke="none"/>
<path d="M 440,483 L 456,528 L 453,531 L 448,522 L 442,524 L 438,535 L 433,525 L 435,515 L 430,515 L 426,508 L 452,567 L 496,634 L 535,674 L 610,729 L 610,711 L 604,696 L 590,685 L 598,692 L 594,694 L 590,688 L 591,691 L 584,693 L 581,682 L 564,671 L 526,634 L 484,581 L 459,539 Z" fill="#10202e" stroke="none"/>
<path d="M 585,472 L 634,537 L 635,708 L 644,705 L 640,703 L 649,699 L 647,696 L 653,697 L 647,705 L 659,714 L 668,698 L 666,534 L 658,526 L 657,508 L 651,506 L 650,501 L 645,501 L 648,496 L 642,490 L 634,498 L 630,495 L 630,499 L 626,493 L 628,495 L 624,495 L 623,501 L 617,501 L 620,495 L 614,501 L 621,502 L 620,505 L 624,503 L 625,506 L 622,506 L 626,511 L 621,515 Z" fill="#10202e" stroke="none"/>
<path d="M 527,457 L 527,518 L 525,518 L 525,500 L 523,502 L 525,505 L 524,508 L 517,512 L 514,509 L 514,506 L 516,505 L 511,511 L 504,511 L 499,507 L 493,511 L 492,503 L 492,521 L 489,529 L 491,533 L 495,535 L 496,538 L 494,538 L 498,540 L 497,542 L 496,541 L 528,587 L 528,584 L 526,583 Z" fill="#10202e" stroke="none"/>
<path d="M 692,435 L 692,450 L 685,453 L 685,463 L 686,466 L 690,469 L 691,468 L 692,469 L 691,471 L 687,472 L 688,473 L 688,486 L 691,487 L 692,490 L 690,492 L 686,493 L 686,504 L 684,505 L 685,506 L 692,506 L 693,505 L 694,506 L 694,523 L 693,524 L 686,524 L 684,525 L 691,525 L 694,523 L 694,494 L 692,490 L 694,485 L 693,484 L 694,483 L 694,476 L 695,475 L 696,478 L 697,478 L 698,473 L 693,470 L 694,453 L 692,450 Z" fill="#10202e" stroke="none"/>
<path d="M 725,434 L 718,434 L 718,435 L 719,435 L 720,436 L 720,437 L 717,440 L 717,441 L 716,442 L 715,442 L 715,448 L 716,447 L 717,448 L 718,448 L 719,449 L 720,449 L 721,448 L 721,446 L 723,444 L 724,444 L 723,443 L 724,442 L 725,442 L 725,438 L 726,437 L 726,436 L 727,435 L 726,436 L 725,435 Z" fill="#10202e" stroke="none"/>
<path d="M 696,434 L 696,437 L 697,438 L 697,442 L 697,441 L 698,440 L 699,440 L 701,442 L 704,442 L 705,443 L 705,445 L 706,446 L 705,447 L 699,447 L 697,445 L 697,444 L 697,446 L 696,447 L 695,447 L 708,447 L 709,448 L 710,447 L 711,448 L 711,447 L 710,446 L 710,434 L 707,434 L 708,434 L 709,435 L 709,436 L 708,437 L 703,437 L 702,436 L 703,435 L 701,435 L 700,434 Z" fill="#10202e" stroke="none"/>
<path d="M 727,424 L 727,428 L 727,424 L 729,422 L 741,422 L 742,421 L 743,422 L 743,430 L 742,431 L 739,431 L 752,431 L 752,424 L 746,424 L 745,423 L 744,424 L 743,423 L 743,421 L 733,421 L 732,422 L 729,422 Z" fill="#10202e" stroke="none"/>
<path d="M 731,402 L 731,403 L 732,404 L 739,404 L 740,403 L 743,403 L 744,404 L 744,405 L 745,404 L 751,404 L 751,403 L 750,402 L 750,401 L 748,399 L 748,397 L 747,396 L 747,395 L 747,399 L 746,400 L 745,400 L 743,402 L 742,401 L 742,400 L 741,399 L 740,400 L 738,398 L 737,398 L 736,397 L 739,394 Z" fill="#10202e" stroke="none"/>
<path d="M 850,383 L 849,384 L 850,385 L 849,386 L 849,390 L 850,391 L 849,392 L 857,392 L 857,386 L 856,385 L 857,384 L 851,384 Z" fill="#10202e" stroke="none"/>
<path d="M 700,380 L 700,384 L 699,385 L 699,393 L 708,393 L 709,394 L 725,394 L 709,394 L 708,393 L 709,392 L 709,389 L 708,388 L 708,382 L 707,381 L 707,379 L 706,380 L 705,379 L 703,379 L 702,380 Z" fill="#10202e" stroke="none"/>
<path d="M 694,373 L 694,378 L 693,379 L 678,379 L 678,394 L 679,395 L 678,396 L 678,433 L 679,432 L 681,433 L 693,433 L 694,434 L 694,445 L 694,433 L 693,432 L 693,420 L 692,419 L 693,418 L 693,397 L 690,395 L 691,394 L 693,394 L 693,379 L 694,378 Z" fill="#10202e" stroke="none"/>
<path d="M 726,361 L 725,362 L 722,362 L 721,363 L 713,363 L 712,362 L 711,362 L 711,375 L 713,377 L 718,377 L 719,376 L 726,376 L 726,373 L 727,372 L 727,362 Z" fill="#10202e" stroke="none"/>
<path d="M 852,322 L 852,332 L 853,331 L 862,331 L 862,324 L 861,323 L 862,322 L 861,323 L 854,323 L 853,322 Z" fill="#10202e" stroke="none"/>
<path d="M 692,322 L 691,323 L 689,323 L 687,322 L 685,324 L 682,324 L 681,325 L 679,325 L 678,327 L 678,330 L 679,331 L 679,357 L 678,358 L 678,375 L 678,363 L 679,362 L 684,362 L 685,363 L 692,363 L 686,363 L 685,362 L 685,361 L 687,360 L 689,356 L 689,354 L 687,351 L 688,349 L 683,342 L 683,340 L 682,339 L 683,337 L 683,334 L 681,332 L 681,331 L 684,329 L 686,329 L 687,328 L 693,328 L 693,323 Z" fill="#10202e" stroke="none"/>
<path d="M 770,321 L 770,332 L 771,333 L 772,333 L 773,332 L 781,332 L 782,333 L 783,333 L 783,322 L 783,327 L 782,328 L 781,327 L 781,324 L 772,324 L 772,332 L 771,333 L 770,332 L 770,322 L 771,321 L 772,322 L 781,322 L 772,322 L 771,321 Z" fill="#10202e" stroke="none"/>
<path d="M 690,299 L 690,301 L 688,303 L 687,303 L 686,302 L 684,302 L 681,305 L 680,305 L 679,306 L 679,311 L 680,310 L 681,311 L 691,311 L 692,310 L 692,303 L 693,302 L 694,303 L 694,311 L 692,313 L 690,313 L 691,314 L 691,319 L 692,320 L 692,319 L 693,318 L 693,312 L 694,311 L 694,303 L 693,302 L 693,300 L 692,300 L 691,299 Z" fill="#10202e" stroke="none"/>
<path d="M 712,296 L 711,297 L 712,298 L 712,302 L 713,302 L 713,301 L 714,300 L 715,300 L 716,301 L 716,302 L 717,303 L 718,303 L 721,306 L 721,307 L 722,308 L 721,309 L 717,309 L 722,309 L 723,310 L 722,311 L 713,311 L 723,311 L 724,312 L 726,312 L 728,314 L 727,313 L 728,312 L 728,311 L 726,309 L 727,308 L 727,301 L 728,300 L 728,296 L 722,296 L 721,297 L 716,297 L 715,296 Z" fill="#10202e" stroke="none"/>
<path d="M 780,271 L 781,272 L 780,273 L 780,280 L 781,281 L 780,282 L 783,282 L 784,281 L 787,281 L 788,282 L 792,282 L 792,272 L 782,272 L 781,271 Z" fill="#10202e" stroke="none"/>
<path d="M 712,242 L 712,243 L 713,244 L 712,245 L 713,246 L 712,247 L 714,249 L 715,249 L 716,250 L 716,251 L 718,253 L 718,254 L 724,254 L 725,253 L 726,254 L 725,253 L 725,242 Z" fill="#10202e" stroke="none"/>
<path d="M 611,195 L 605,198 L 603,200 L 600,201 L 598,203 L 597,203 L 596,205 L 595,204 L 593,207 L 592,206 L 593,207 L 592,208 L 590,207 L 591,208 L 589,210 L 586,211 L 581,215 L 575,218 L 578,216 L 579,216 L 580,218 L 582,217 L 583,218 L 582,220 L 583,222 L 585,223 L 584,224 L 585,223 L 587,225 L 587,226 L 589,226 L 591,228 L 593,227 L 594,228 L 593,230 L 592,230 L 590,232 L 586,234 L 590,232 L 592,230 L 599,227 L 603,223 L 608,213 L 608,210 L 609,209 L 609,205 L 610,204 L 611,205 L 611,208 Z" fill="#10202e" stroke="none"/>
</svg>
"""

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
<title>Noctis Edge Report</title>
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
  .badge-kev{background:#d32f2f;color:#fff;border:1px solid #ff5252;animation:kev-pulse 2s ease-in-out infinite}
  @keyframes kev-pulse{0%,100%{box-shadow:0 0 0 0 rgba(211,47,47,.4)}50%{box-shadow:0 0 0 4px rgba(211,47,47,0)}}
  .ev{font-family:monospace;font-size:.82em;background:#0d1117;padding:8px;border-radius:4px;
      max-height:90px;overflow-y:auto;white-space:pre-wrap;word-break:break-all}
  .tag{background:#0f3460;color:#00d4ff;padding:1px 6px;border-radius:8px;font-size:.75em;
       margin:1px;display:inline-block}
  .ok{color:#2ed573}.pend{color:#ffa502}.probe-inc{color:#ff9800;font-weight:600}
  .conclusion{background:#16213e;border-left:4px solid #00d4ff;padding:15px 20px;
              border-radius:0 8px 8px 0;margin:20px 0}
  footer{margin-top:40px;color:#555;font-size:.85em;text-align:center}
  .report-hero{display:flex;align-items:stretch;gap:0;margin-bottom:30px;border-bottom:2px solid #00d4ff;padding-bottom:20px}
  .report-hero-left{flex:1;display:flex;flex-direction:column;justify-content:flex-start;padding-right:24px}
  .report-hero-left h1{color:#00d4ff;margin:0 0 6px 0;border:none;padding:0;font-size:2em}
  .report-hero-left .sub{color:#aaa;font-size:.95em;margin-bottom:18px}
  .report-hero-left .meta{color:#ccc;font-size:.92em;line-height:1.9}
  .report-hero-left .meta strong{color:#00d4ff}
  .report-hero-logo{flex-shrink:0;display:flex;align-items:stretch}
  @media print{
    body{background:#fff!important;color:#000!important;padding:12px}
    h1,h2{color:#000!important;border-color:#000!important}
    .box{background:#fff!important;border-color:#ccc!important;color:#000!important}
    .box .num,.critical,.high,.medium,.low,.info{color:#000!important}
    th{background:#ddd!important;color:#000!important}
    td{color:#000!important;border-color:#ccc!important}
    tr:hover{background:transparent!important}
    .ev,.conclusion{background:#f5f5f5!important;color:#000!important}
    .tag{background:#eee!important;color:#000!important;border:1px solid #ccc}
    .badge{border:1px solid #000!important;color:#000!important;background:#eee!important}
    footer{color:#000!important}
    details{display:block}
    .report-hero-logo div{border-color:#000!important;color:#000!important}
    .report-hero-logo span{color:#555!important}
    .report-hero-logo svg text{fill:#000!important}
    .report-hero-logo svg path,.report-hero-logo svg rect,.report-hero-logo svg polygon{fill:#ddd!important}
    .report-hero-logo svg circle{fill:#555!important}
    .handling-notice{background:#fffde7!important;border-color:#f9a825!important}
  }
</style>
</head>
<body>
<div class="handling-notice" style="background:#1a0a0a;border:1px solid #ff4757;border-radius:4px;padding:.5em 1.2em;margin-bottom:14px;font-size:.82em;display:flex;align-items:center;gap:.8em"><span style="color:#ff4757;font-weight:700;white-space:nowrap">&#9888; SECURITY SENSITIVE</span><span style="color:#ffcdd2">This document contains vulnerability details, CVE data, and exploitation evidence. Handle in accordance with your organisation&#39;s information security policy. Do not transmit over unencrypted channels, store on unclassified systems, or forward to personnel without a need-to-know.</span></div>
<div class="report-hero">
  <div class="report-hero-left">
    <h1>Noctis Edge Report</h1>
    <div class="sub">Security Through Exposure</div>
    <div class="meta">
      <strong>Target:</strong> {{ target }}{% if target_info and target_info.ip_address and target_info.ip_address != target %} ({{ target_info.ip_address }}){% endif %}<br>
      <strong>Generated:</strong> {{ generated_at }}<br>
      <strong>Profile:</strong> {{ profile }}
    </div>
  </div>
  <div class="report-hero-logo" style="align-self:center">
    {{ logo_svg | safe }}
  </div>
</div>

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
{% set _cc = confirmed_counts if confirmed_counts else {} %}
<div style="display:flex;gap:1em;flex-wrap:wrap;margin:-8px 0 14px 0;font-size:.83em;color:#888">
  <span title="Actively validated or strong-probe confirmed findings only">
    &#10003;&nbsp;<strong style="color:#ccc">Confirmed+Probable:</strong>
    {% if _cc.critical %}<span class="critical">{{ _cc.critical }}C</span> {% endif %}
    {% if _cc.high %}<span class="high">{{ _cc.high }}H</span> {% endif %}
    {% if _cc.medium %}<span class="medium">{{ _cc.medium }}M</span> {% endif %}
    {% if (_cc.low or 0) + (_cc.info or 0) > 0 %}<span class="low">{{ (_cc.low or 0) + (_cc.info or 0) }}L</span>{% endif %}
    &nbsp;<em style="color:#666">(total counts above include unverified findings)</em>
  </span>
</div>
{% if timed_out_tools %}
<div style="background:#2a1500;border:1px solid #ff6d00;border-radius:6px;padding:10px 16px;margin:0 0 14px 0;font-size:.88em">
  <strong style="color:#ff9800">&#9888; Scan Coverage Incomplete</strong>
  <div style="color:#ffe0b2;margin-top:.4em">{{ timed_out_tools|length }} tool run(s) timed out — results may be partial:
    {% for t in timed_out_tools %}<code style="background:#1a0a00;padding:.1em .4em;border-radius:3px;margin:.1em">{{ t.tool }}{% if t.args %} {{ t.args[0:40] }}{% endif %}</code> {% endfor %}
  </div>
</div>
{% endif %}
{% if not conclusion_llm_ok %}<div style="background:#1a1000;border:1px solid #ff6d00;border-radius:6px;padding:8px 14px;margin:0 0 10px 0;font-size:.85em"><strong style="color:#ff9800">&#9888; Executive Summary Incomplete</strong><span style="color:#ffe0b2;margin-left:.5em">The LLM timed out &mdash; the summary below is auto-generated from scan data and may be missing context.</span></div>{% endif %}<div class="conclusion">{% for para in conclusion.split('\n\n') %}{% if para.strip() %}<p style="margin:0 0 .75em 0">{{ para.strip() }}</p>{% endif %}{% endfor %}</div>
{% if audit_notes %}<details style="margin:.5em 0 1em 0;border:1px solid #263238;border-radius:5px;background:#0a1520"><summary style="cursor:pointer;color:#546e7a;font-size:.8em;padding:.45em .9em;user-select:none;list-style:none">{% if conclusion_revised %}<span style="color:#ffb74d">&#x270F; Report Audit &mdash; conclusion revised</span>{% else %}<span style="color:#4caf50">&#x2713; Report Audit &mdash; no changes required</span>{% endif %}</summary><div style="padding:.6em 1em .7em;font-size:.83em;color:#78909c;line-height:1.65;border-top:1px solid #263238">{{ audit_notes }}</div></details>{% endif %}

{% if compliance_summary %}
<h2>Compliance Impact</h2>
<p style="color:#aaa;font-size:.9em;margin-bottom:1em">The following compliance controls are implicated by findings and CVEs identified in this assessment.</p>
<div style="display:flex;flex-wrap:wrap;gap:.5em;margin-bottom:1.5em">
  {% for ctrl in compliance_summary %}
  <span style="background:#1a2a3a;border:1px solid #29b6f6;color:#29b6f6;padding:.45em 1em;border-radius:6px;font-size:.88em;font-weight:600">{{ ctrl }}</span>
  {% endfor %}
</div>
{% endif %}

{% set ot_services = services | selectattr('asset_type', 'eq', 'OT') | list %}
{% if ot_services %}
<div style="background:#3d1f00;border:2px solid #ff8f00;border-radius:8px;padding:14px 20px;margin:18px 0;display:flex;align-items:center;gap:14px">
  <span style="font-size:1.6em">&#9888;</span>
  <div>
    <strong style="color:#ffb300;font-size:1.05em">Industrial / OT Environment Detected</strong><br>
    <span style="color:#ffe082;font-size:.9em">{{ ot_services | length }} OT service(s) identified. Refer to IEC 62443 and NERC-CIP before performing active tests on operational technology assets.</span>
  </div>
</div>
{% endif %}

<h2>Services Discovered</h2>
<table>
  <tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product / Version</th><th>Type</th><th>Priority</th><th>CVEs</th></tr>
  {% for s in services %}
  <tr>
    <td>{{ s.port }}</td><td>{{ s.protocol }}</td><td>{{ s.name }}</td>
    <td>{{ s.product }} {{ s.version }}</td>
    <td>
      {% if s.asset_type == 'OT' %}
      <span style="background:#7c3700;color:#ffb300;padding:2px 8px;border-radius:10px;font-size:.75em;font-weight:bold;border:1px solid #ffb300" title="{{ s.ot_protocol }}{% if s.ot_standard %} — {{ s.ot_standard }}{% endif %}">OT</span>
      {% else %}
      <span style="color:#777;font-size:.85em">IT</span>
      {% endif %}
    </td>
    <td>{{ s.priority }}</td>
    <td>{% for c in s.cves %}<span class="badge badge-{{ c.severity|lower }}">{{ c.id }}</span> {% endfor %}</td>
  </tr>
  {% endfor %}
</table>

{% if nmap_discovery and nmap_discovery.nse_summary %}
<h2>Nmap NSE Scripts</h2>
<details style="margin-bottom:1em;border:1px solid #1e4a6e;border-radius:6px;background:#0d1b2a">
  <summary style="cursor:pointer;color:#29b6f6;font-size:.92em;font-weight:600;padding:.65em 1em;user-select:none;display:flex;align-items:center;gap:.6em">
    <span>&#9654;</span>
    <span>{{ nmap_discovery.nse_summary | length }} port(s) scanned &mdash; click to expand NSE script results</span>
  </summary>
  <div style="padding:0 .5em .5em">
  <table>
    <tr><th>Port</th><th>Scripts Executed</th></tr>
    {% for port, scripts in nmap_discovery.nse_summary.items() %}
    <tr><td>{{ port }}</td><td>{{ scripts|join(', ') }}</td></tr>
    {% endfor %}
  </table>
  </div>
</details>
{% endif %}

{% if remediation_llm_failed %}<div style="background:#1a1000;border:1px solid #ff6d00;border-radius:6px;padding:8px 14px;margin:0 0 10px 0;font-size:.85em"><strong style="color:#ff9800">&#9888; Remediation Advice Incomplete</strong><span style="color:#ffe0b2;margin-left:.5em">LLM timed out for {{ remediation_llm_failed }} finding(s) &mdash; static fallback advice is shown for those items.</span></div>{% endif %}
<h2>Security Findings ({{ findings|length }} total)</h2>
<div style="margin:.5em 0 1.2em;padding:.8em 1.1em;background:#0d1b2a;border:1px solid #1e3a5f;border-radius:6px;font-size:.86em;color:#b0bec5;line-height:1.65">
  <div style="display:flex;flex-wrap:wrap;gap:1.4em">
    <div>
      <strong style="color:#e0e0e0;display:block;margin-bottom:.3em">Severity</strong>
      <span style="color:#ff4757;font-weight:700">CRITICAL</span> — Immediate exploitation risk; direct path to RCE, full compromise, or data exfiltration.<br>
      <span style="color:#ff6b35;font-weight:700">HIGH</span> — Significant exposure; likely exploitable with moderate effort or public tooling.<br>
      <span style="color:#ffa502;font-weight:700">MEDIUM</span> — Exploitable under specific conditions; increases attacker foothold or information exposure.<br>
      <span style="color:#2ed573;font-weight:700">LOW</span> — Limited direct impact; useful for reconnaissance or chaining with other findings.<br>
      <span style="color:#70a1ff;font-weight:700">INFO</span> — No exploitable risk; recorded for compliance, hardening, or asset inventory purposes.
    </div>
    <div>
      <strong style="color:#e0e0e0;display:block;margin-bottom:.3em">Confidence</strong>
      <span style="color:#c62828;font-weight:700">CONFIRMED</span> — Active curl/probe re-verified the finding against the live service; high-fidelity result.<br>
      <span style="color:#bf360c;font-weight:700">PROBABLE</span> — Discovered by a reliable tool (confidence ≥ 60 %) but not independently re-verified; treat as likely real.<br>
      <span style="color:#37474f;font-weight:700;color:#cfd8dc">REVIEW</span> — Probe returned inconclusive results or the reporting tool has low confidence; manual inspection recommended before actioning.<br>
      <span style="color:#546e7a;font-weight:700">INFO</span> — Informational finding; no active verification attempted.
    </div>
  </div>
</div>
{% if findings %}
{% macro render_finding(f) %}
{%- set _esev = _eff_sev.get(f.finding_id, f.severity) %}
  <details style="margin-bottom:.8em;border:1px solid {% if _esev == 'critical' %}#ff4757{% elif _esev == 'high' %}#ff6b35{% elif _esev == 'medium' %}#ffa502{% elif _esev == 'low' %}#2ed573{% else %}#70a1ff{% endif %};border-radius:6px;background:#16213e">
    <summary style="padding:10px 14px;cursor:pointer;display:flex;flex-wrap:wrap;align-items:center;gap:8px;list-style:none">
      <span class="badge badge-{{ _esev }}">{{ _esev|upper }}</span>
      {%- if _esev != f.severity %}<span style="color:#666;font-size:.72em;white-space:nowrap" title="Scanner reported {{ f.severity|upper }} — downgraded due to evidence quality">scanner:&nbsp;{{ f.severity|upper }}</span>{%- endif %}
      {%- if f.finding_id in _confirmed_ids %}<span style="background:#b71c1c;color:#fff;padding:1px 6px;border-radius:8px;font-size:.72em;font-weight:700">&#10003; CONFIRMED</span>
      {%- elif f.finding_id in _probable_ids %}<span style="background:#bf360c;color:#fff;padding:1px 6px;border-radius:8px;font-size:.72em;font-weight:700">~ PROBABLE</span>
      {%- elif f.finding_id in _review_ids %}<span style="background:#37474f;color:#cfd8dc;padding:1px 6px;border-radius:8px;font-size:.72em;font-weight:700">&#9888; REVIEW</span>
      {%- else %}<span style="background:#1a2a3a;color:#79b8d4;padding:1px 6px;border-radius:8px;font-size:.72em">INFO</span>
      {%- endif %}
      <span style="font-weight:600;flex:1;min-width:180px">{{ f.title }}</span>
      <span style="color:#aaa;font-size:.82em" title="{{ f.tool }}">{{ _tool_labels.get(f.tool, f.tool) }}</span>
      <span style="color:#888;font-size:.82em">{{ f.service }}</span>
      <span style="color:#aaa;font-size:.82em">Risk:&nbsp;<strong>{{ "%.2f"|format(f.risk_score) }}</strong></span>
      <span class="{{ 'ok' if f.verified else ('probe-inc' if f.verification_status == 'probe_inconclusive' else 'pend') }}" style="font-size:.82em">{% if f.verification_status == 'probe_inconclusive' %}&#9888; probe inconclusive{% else %}{{ f.verification_status }}{% endif %}</span>
      {% if f.manual_review %}<span style="background:#ff9800;color:#000;padding:.2em .5em;border-radius:3px;font-size:.75em;font-weight:700;white-space:nowrap">&#9888; MANUAL REVIEW</span>{% endif %}
    </summary>
    <div style="padding:12px 16px;border-top:1px solid #0f3460">
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:.8em;margin-bottom:1em;font-size:.88em">
        <div><strong style="color:#00d4ff">Confidence</strong><br>{{ "%.0f%%"|format(f.confidence * 100) }} &mdash; {% if f.confidence >= 0.95 %}<span style="color:#2ed573">Validated</span>{% elif f.confidence >= 0.75 %}<span style="color:#69f0ae">Strong Fingerprint</span>{% elif f.confidence >= 0.40 %}<span style="color:#ffa502">Banner / Heuristic</span>{% else %}<span style="color:#90a4ae">Weak Inference</span>{% endif %}</div>
        {%- if f.detection_method %}
      {%- if f.detection_method == 'exploit_confirmed' %}
        {%- set _dm_label = '&#10003; Exploit Confirmed' %}{%- set _dm_tier = 'HIGH' %}{%- set _dm_col = '#2ed573' %}
      {%- elif f.detection_method == 'service_probe' %}
        {%- set _dm_label = '&#x26A1; Active Probe' %}{%- set _dm_tier = 'MEDIUM' %}{%- set _dm_col = '#ffb300' %}
      {%- elif f.detection_method == 'template_match' %}
        {%- set _dm_label = '&#x1F4CB; Template Match' %}{%- set _dm_tier = 'MEDIUM' %}{%- set _dm_col = '#ffa502' %}
      {%- elif f.detection_method == 'banner_analysis' %}
        {%- set _dm_label = '&#x1F50E; Banner Match' %}{%- set _dm_tier = 'LOW' %}{%- set _dm_col = '#78909c' %}
      {%- else %}
        {%- set _dm_label = '&#x1F50D; Heuristic' %}{%- set _dm_tier = 'LOW' %}{%- set _dm_col = '#546e7a' %}
      {%- endif %}
      <div>
        <strong style="color:#00d4ff">Detection Source</strong><br>
        <span style="color:{{ _dm_col }};font-weight:600">{{ _dm_label }}</span>
        <span style="background:#0d1b2a;border:1px solid {{ _dm_col }};color:{{ _dm_col }};padding:1px 6px;border-radius:8px;font-size:.78em;margin-left:.4em">{{ _dm_tier }}</span>
      </div>
      {%- endif %}
        {% if f.vuln_type %}<div><strong style="color:#00d4ff">Vuln Type</strong><br>{{ f.vuln_type }}</div>{% endif %}
        {% if f.cwe_id %}
        {%- set _cwe_info = cwe_db.get(f.cwe_id, {}) %}
        <div>
          <strong style="color:#00d4ff">CWE</strong><br>
          <a href="https://cwe.mitre.org/data/definitions/{{ f.cwe_id[4:] }}.html" target="_blank" rel="noopener noreferrer" style="color:#90caf9;text-decoration:none;font-family:monospace;font-size:.92em">{{ f.cwe_id }}</a>
          {% if _cwe_info.get('name') %}<span style="color:#b0bec5;font-size:.85em;margin-left:.35em">&mdash; {{ _cwe_info.name }}</span>{% endif %}
        </div>
        {% endif %}
        {% if f.tags %}<div><strong style="color:#00d4ff">Tags</strong><br>{% for t in f.tags %}<span class="tag">{{ t }}</span>{% endfor %}</div>{% endif %}
      </div>
      <div style="margin-bottom:.8em">
        <strong style="color:#00d4ff;display:block;margin-bottom:.3em">Evidence</strong>
        <div class="ev">{{ f.evidence[:400] }}</div>
      </div>
      {% if f.description %}
      <div style="margin-bottom:.8em;background:#1a0d00;border-left:3px solid #ff9800;border-radius:0 4px 4px 0;padding:.8em 1em">
        <strong style="color:#ff9800">&#9760; Security Risk &amp; Recommendation</strong>
        <div style="color:#ffe0b2;margin-top:.45em;white-space:pre-wrap;line-height:1.55">{{ f.description }}</div>
      </div>
      {% endif %}
      {% if f.verification_status == 'probe_inconclusive' %}
      <div style="margin-bottom:.8em;background:#1a1200;border-left:3px solid #ff9800;border-radius:0 4px 4px 0;padding:.7em 1em">
        <strong style="color:#ff9800">&#9888; Probe Inconclusive</strong>
        <div style="font-size:.85em;color:#ffe082;margin-top:.3em;line-height:1.5">
          {% if f.verifier_tool %}Probed with <code style="background:#0d1117;padding:.1em .4em;border-radius:3px">{{ f.verifier_tool }}</code> — no confirming evidence found.{% else %}Could not be confirmed by automated verification.{% endif %}
          Manual inspection recommended before treating as a confirmed finding.
        </div>
      </div>
      {% endif %}
      {% if f.http_response %}
      <details style="margin-bottom:.8em">
        <summary style="cursor:pointer;color:#90caf9;font-size:.88em">&#9654; Raw HTTP Response</summary>
        <div class="ev" style="margin-top:.4em">{{ f.http_response[:600] }}</div>
      </details>
      {% endif %}
      {% if f.cmd %}
      <div style="margin-bottom:.8em">
        <strong style="color:#00d4ff;display:block;margin-bottom:.3em">Command</strong>
        <code style="background:#0d1117;padding:.4em .7em;border-radius:4px;font-size:.78em;word-break:break-all;display:block;white-space:pre-wrap">{{ f.cmd }}</code>
      </div>
      {% endif %}
      {% if f.compliance_controls %}
      <div style="margin-bottom:.8em">
        <strong style="color:#29b6f6;display:block;margin-bottom:.3em">Compliance Controls</strong>
        <div style="display:flex;flex-wrap:wrap;gap:.4em">
          {% for ctrl in f.compliance_controls %}<span style="background:#0f3460;color:#29b6f6;padding:.3em .6em;border-radius:4px;font-size:.78em;border:1px solid #29b6f6">{{ ctrl }}</span>{% endfor %}
        </div>
      </div>
      {% endif %}
      {% if f.references %}
      <div>
        <strong style="color:#00d4ff;display:block;margin-bottom:.3em">References</strong>
        <ul style="margin:.3em 0;padding-left:1.2em;font-size:.85em">
          {% for ref in f.references %}<li style="margin:.2em 0"><a href="{{ ref | safe_url }}" target="_blank" rel="noopener noreferrer" style="color:#29b6f6;text-decoration:none">{{ ref | truncate(80) }}</a></li>{% endfor %}
        </ul>
      </div>
      {% endif %}
      {% if f.vuln_type %}
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:.8em;margin-top:.8em">
        <div style="background:#1a2a0a;border-left:3px solid #8bc34a;border-radius:0 4px 4px 0;padding:.8em">
          <strong style="color:#8bc34a;display:block;margin-bottom:.35em">&#x26A1; Short-term Workaround</strong>
          {% set _sw = f.llm_remediation_short | parse_json %}
          {% if _sw %}
          <ol style="margin:.25em 0 0 0;padding-left:1.25em;font-size:.87em;color:#dcedc8;line-height:1.65">{% for _s in _sw %}<li style="margin:.3em 0">{{ _s }}</li>{% endfor %}</ol>
          {% else %}
          <div style="font-size:.87em;color:#dcedc8;line-height:1.55">{{ rem_short_map.get(f.vuln_type, rem_short_map["Unknown"]) }}</div>
          {% endif %}
        </div>
        <div style="background:#0d2137;border-left:3px solid #29b6f6;border-radius:0 4px 4px 0;padding:.8em">
          <strong style="color:#29b6f6;display:block;margin-bottom:.35em">&#x1F527; Long-term Fix</strong>
          {% set _lf = f.llm_remediation_long | parse_json %}
          {% if _lf %}
          <ol style="margin:.25em 0 0 0;padding-left:1.25em;font-size:.87em;color:#b3e5fc;line-height:1.65">{% for _l in _lf %}<li style="margin:.3em 0">{{ _l }}</li>{% endfor %}</ol>
          {% else %}
          <div style="font-size:.87em;color:#b3e5fc;line-height:1.55">{{ rem_long_map.get(f.vuln_type, rem_long_map["Unknown"]) }}</div>
          {% endif %}
        </div>
      </div>
      {% endif %}
      {% if f.cmd %}
      <div style="margin-top:.8em">
        <strong style="color:#00d4ff;display:block;margin-bottom:.3em">&#x1F50E; Steps to Reproduce</strong>
        <code style="background:#0d1117;padding:.5em .8em;border-radius:4px;font-size:.78em;word-break:break-all;display:block;white-space:pre-wrap">{{ f.cmd }}</code>
        <div style="color:#546e7a;font-size:.76em;margin-top:.3em;font-style:italic">Exact command used during this scan. Re-run against the target to reproduce independently.</div>
      </div>
      {% endif %}
    </div>
  </details>
{% endmacro %}
{% if active_findings %}
<details open style="margin-bottom:1.2em;border:2px solid #c62828;border-radius:6px;background:#0d1b2a">
  <summary style="cursor:pointer;color:#ff5252;font-size:.92em;font-weight:600;padding:.65em 1em;user-select:none;display:flex;align-items:center;gap:.6em">
    <span>&#9654;</span>
    <span>&#128308; Active Vulnerabilities &mdash; {{ active_findings|length }} finding(s)
      {% if confirmed_findings %}&nbsp;<span style="background:#c62828;color:#fff;padding:1px 7px;border-radius:10px;font-size:.82em">{{ confirmed_findings|length }} confirmed</span>{% endif %}
      {% if probable_findings %}&nbsp;<span style="background:#bf360c;color:#fff;padding:1px 7px;border-radius:10px;font-size:.82em">{{ probable_findings|length }} probable</span>{% endif %}
      &nbsp;<span style="color:#78909c;font-size:.78em;font-weight:400">calibrated critical &amp; high severity</span>
    </span>
  </summary>
  <div style="padding:.5em">
  {% for f in active_findings %}{{ render_finding(f) }}{% endfor %}
  </div>
</details>
{% endif %}
{% if hardening_findings %}
<details style="margin-bottom:1.2em;border:1px solid #e65100;border-radius:6px;background:#0d1b2a">
  <summary style="cursor:pointer;color:#ffa502;font-size:.92em;font-weight:600;padding:.65em 1em;user-select:none;display:flex;align-items:center;gap:.6em">
    <span>&#9654;</span>
    <span>&#9888; Hardening Issues &mdash; {{ hardening_findings|length }} finding(s)
      &nbsp;<span style="color:#78909c;font-size:.78em;font-weight:400">medium &amp; low severity &mdash; configuration &amp; hardening items</span>
    </span>
  </summary>
  <div style="padding:.5em">
  {% for f in hardening_findings %}{{ render_finding(f) }}{% endfor %}
  </div>
</details>
{% endif %}
{% if info_sev_findings %}
<details style="margin-bottom:1.2em;border:1px solid #37474f;border-radius:6px;background:#0d1b2a">
  <summary style="cursor:pointer;color:#78909c;font-size:.92em;font-weight:600;padding:.65em 1em;user-select:none;display:flex;align-items:center;gap:.6em">
    <span>&#9654;</span>
    <span>&#8505; Informational &mdash; {{ info_sev_findings|length }} finding(s)</span>
  </summary>
  <div style="padding:.5em">
  {% for f in info_sev_findings %}{{ render_finding(f) }}{% endfor %}
  </div>
</details>
{% endif %}
{% else %}<p>No findings detected.</p>{% endif %}

{% if cve_llm_failed %}<div style="background:#1a1000;border:1px solid #ff6d00;border-radius:6px;padding:8px 14px;margin:0 0 10px 0;font-size:.85em"><strong style="color:#ff9800">&#9888; CVE Analysis Incomplete</strong><span style="color:#ffe0b2;margin-left:.5em">LLM timed out for {{ cve_llm_failed }} CVE section(s) &mdash; attacker perspective and/or remediation may be missing from affected cards.</span></div>{% endif %}
<h2>CVE Matches ({{ cve_matches|length }} total)</h2>
<div style="margin:.5em 0 1.2em;padding:.8em 1.1em;background:#0d1b2a;border:1px solid #1e3a5f;border-radius:6px;font-size:.86em;color:#b0bec5;line-height:1.65">
  <div style="display:flex;flex-wrap:wrap;gap:1.4em">
    <div>
      <strong style="color:#e0e0e0;display:block;margin-bottom:.3em">Severity</strong>
      <span style="color:#ff4757;font-weight:700">CRITICAL</span> &mdash; Immediate exploitation risk; direct path to RCE, full compromise, or data exfiltration.<br>
      <span style="color:#ff6b35;font-weight:700">HIGH</span> &mdash; Significant exposure; likely exploitable with moderate effort or public tooling.<br>
      <span style="color:#ffa502;font-weight:700">MEDIUM</span> &mdash; Exploitable under specific conditions; increases attacker foothold or information exposure.<br>
      <span style="color:#2ed573;font-weight:700">LOW</span> &mdash; Limited direct impact; useful for reconnaissance or chaining with other findings.<br>
      <span style="color:#70a1ff;font-weight:700">INFO</span> &mdash; No exploitable risk; recorded for compliance, hardening, or asset inventory purposes.
    </div>
    <div>
      <strong style="color:#e0e0e0;display:block;margin-bottom:.3em">Verification Status</strong>
      <span style="color:#ff5252;font-weight:700">&#128308; CONFIRMED EXPLOITABLE</span> &mdash; Active probing confirmed this CVE is exploitable on this host.<br>
      <span style="color:#66bb6a;font-weight:700">&#9989; NOT VULNERABLE</span> &mdash; Tested; host was not found to be affected. Severity reflects the general CVE risk class.<br>
      <span style="color:#ffca28;font-weight:700">&#9888; INCONCLUSIVE</span> &mdash; Probes ran but could not confirm or rule out exploitability; verify manually.<br>
      <span style="color:#90a4ae;font-weight:700">&#9680; UNVERIFIED</span> &mdash; Matched by version fingerprint only; not actively probed. May be a false positive.
    </div>
  </div>
</div>
{# Split cve_matches into active (not confirmed not-vulnerable) vs cleared #}
{% set _cve_active = [] %}
{% set _cve_cleared = [] %}
{% for c in cve_matches %}
  {% if c.cve_test_result and c.cve_test_result.overall_verdict == 'NOT_VULNERABLE' %}
    {% if _cve_cleared.append(c) %}{% endif %}
  {% else %}
    {% if _cve_active.append(c) %}{% endif %}
  {% endif %}
{% endfor %}

{# ── Section 1: Active CVE Matches ─────────────────────────────────────── #}
{% if _cve_active %}
<details open style="margin-bottom:1.2em;border:1px solid #1e4a6e;border-radius:6px;background:#0d1b2a">
  <summary style="cursor:pointer;color:#29b6f6;font-size:.92em;font-weight:600;padding:.65em 1em;user-select:none;display:flex;align-items:center;gap:.6em">
    <span>&#9654;</span>
    <span>&#128313; {{ _cve_active|length }} CVE match(es) &mdash; ranked by exploit probability</span>
  </summary>
  <div style="padding:.5em;margin-bottom:2em">
  {% for c in _cve_active | sort(attribute='epss_score', reverse=True) %}
  <details style="margin-bottom:1.5em;border:1px solid #333;border-radius:6px;padding:1em;background:#16213e">
    <summary style="cursor:pointer;font-weight:600;color:#00d4ff;font-size:1.05em;display:flex;align-items:center;flex-wrap:wrap;gap:.5em">
      <span style="flex:1;min-width:180px"><a href="https://nvd.nist.gov/vuln/detail/{{ c.cve_id }}" target="_blank" rel="noopener noreferrer" style="color:#00d4ff;text-decoration:none" title="View on NVD">{{ c.cve_id }}</a> — {{ c.vulnerability_type }} on {{ c.service }}{% if c.product and c.product != 'unknown' %} <span style="color:#78909c;font-size:.85em;font-weight:400">({{ c.product }}{% if c.version_affected and c.version_affected != 'unknown' %} {{ c.version_affected }}{% endif %})</span>{% endif %}</span>
      {% set _tv = c.cve_test_result.overall_verdict if c.cve_test_result else None %}
      <span class="badge badge-{{ c.severity|lower }}"{% if _tv == 'NOT_VULNERABLE' %} style="opacity:.4;text-decoration:line-through"{% endif %}>{{ c.severity|upper }}</span>
      {% if c.nvd_cvss_v3_score %}
      <span style="background:#0f3460;color:#00d4ff;padding:3px 10px;border-radius:4px;font-size:.85em;font-weight:700;border:1px solid #00d4ff;min-width:2.5em;text-align:center" title="NVD CVSS v3.1">v3.1&nbsp;{{ c.nvd_cvss_v3_score }}</span>
      {% elif c.cvss_score %}
      <span style="background:#0f3460;color:#00d4ff;padding:3px 10px;border-radius:4px;font-size:.9em;font-weight:700;border:1px solid #00d4ff;min-width:2.5em;text-align:center" title="CVSS Score">{{ c.cvss_score }}</span>
      {% endif %}
      {% if c.epss_score %}
      <span style="background:#7c4700;color:#ffb300;padding:3px 9px;border-radius:4px;font-size:.82em;font-weight:700;border:1px solid #ff8f00" title="EPSS: probability of exploitation in the wild">EPSS&nbsp;{{ "%.1f%%"|format(c.epss_score * 100) }}</span>
      {% endif %}
      {% if c.kev_listed %}
      <span class="badge badge-kev" title="CISA Known Exploited Vulnerability — federal agencies must patch">&#9888; MUST-PATCH (KEV)</span>
      {% endif %}
    </summary>
    
    <div style="margin-top:1em;padding-top:1em;border-top:1px solid #333">

      {# ── Verification Status Banner ────────────────────────────────────── #}
      {% set _tv = c.cve_test_result.overall_verdict if c.cve_test_result else None %}
      {% if _tv == 'CONFIRMED_VULNERABLE' %}
      <div style="background:#3d0000;border-left:4px solid #ff1744;border-radius:0 6px 6px 0;padding:.7em 1em;margin-bottom:1em;display:flex;align-items:center;gap:.7em">
        <span style="font-size:1.2em">&#128308;</span>
        <div><strong style="color:#ff5252;font-size:.92em">CONFIRMED EXPLOITABLE</strong><div style="color:#ef9a9a;font-size:.84em;margin-top:.2em">Active probing confirmed this CVE is exploitable on this host.</div></div>
      </div>
      {% elif _tv == 'NOT_VULNERABLE' %}
      <div style="background:#0a2a12;border-left:4px solid #43a047;border-radius:0 6px 6px 0;padding:.7em 1em;margin-bottom:1em;display:flex;align-items:center;gap:.7em">
        <span style="font-size:1.2em">&#9989;</span>
        <div><strong style="color:#66bb6a;font-size:.92em">TESTED: NOT VULNERABLE ON THIS HOST</strong><div style="color:#a5d6a7;font-size:.84em;margin-top:.2em">Active probing found no exploitability. The EPSS score and severity above reflect the general danger of this CVE class &mdash; this host was not confirmed affected.</div></div>
      </div>
      {% elif _tv == 'INCONCLUSIVE' %}
      <div style="background:#1c1a00;border-left:4px solid #f9a825;border-radius:0 6px 6px 0;padding:.7em 1em;margin-bottom:1em;display:flex;align-items:center;gap:.7em">
        <span style="font-size:1.2em">&#9888;</span>
        <div><strong style="color:#ffca28;font-size:.92em">TESTING INCONCLUSIVE</strong><div style="color:#ffe082;font-size:.84em;margin-top:.2em">Probes ran but could not confirm or rule out exploitability. Treat as potentially exposed and verify manually.</div></div>
      </div>
      {% else %}
      <div style="background:#111820;border-left:4px solid #546e7a;border-radius:0 6px 6px 0;padding:.7em 1em;margin-bottom:1em;display:flex;align-items:center;gap:.7em">
        <span style="font-size:1.2em">&#9680;</span>
        <div><strong style="color:#90a4ae;font-size:.92em">UNVERIFIED</strong><div style="color:#b0bec5;font-size:.84em;margin-top:.2em">Matched by version fingerprint only &mdash; not actively probed. May be a false positive. Re-scan with <code style="background:#0d1117;padding:.05em .3em;border-radius:3px">--cve-test</code> to verify.</div></div>
      </div>
      {% endif %}

      {# ── KEV Alert Banner ───────────────────────────────────────────────── #}
      {% if c.kev_listed %}
      <div style="background:#3d0000;border-left:4px solid #d32f2f;border-radius:0 6px 6px 0;padding:.7em 1em;margin-bottom:1em;display:flex;align-items:center;gap:.7em">
        <span style="color:#ef5350;font-size:1.2em">&#9888;</span>
        <div>
          <strong style="color:#ef5350">CISA Known Exploited Vulnerability (KEV)</strong>
          <div style="color:#ffcdd2;font-size:.85em;margin-top:.2em">This CVE is actively exploited in the wild. Federal agencies are required to remediate.{% if c.kev_due_date %} <strong>Due date: {{ c.kev_due_date }}</strong>{% endif %}</div>
        </div>
      </div>
      {% endif %}

      {# Immediate Remediation Path — prominent quick-win block at the top of the card #}
      {% if c.immediate_remediation or c.remediation_short %}
      <div style="background:#0d2010;border-left:4px solid #66bb6a;border-radius:0 6px 6px 0;padding:.8em 1em;margin-bottom:1em;display:flex;align-items:flex-start;gap:.7em">
        <span style="color:#66bb6a;font-size:1.1em;flex-shrink:0">&#10003;</span>
        <div style="width:100%">
          <strong style="color:#66bb6a;font-size:.88em">IMMEDIATE REMEDIATION PATH</strong>
          <div style="color:#c8e6c9;font-size:.9em;margin-top:.2em;line-height:1.7;white-space:pre-wrap">{{ c.immediate_remediation or c.remediation_short }}</div>
        </div>
      </div>
      {% endif %}

      <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:1.5em;margin-bottom:1.5em;font-size:.9em">
        <div>
          {% if c.nvd_cvss_v3_score %}
          <strong style="color:#00d4ff">CVSS v3.1 (NVD)</strong><br>
          <span style="font-size:1.3em;font-weight:700">{{ c.nvd_cvss_v3_score }}</span>
          {% if c.nvd_cvss_v3_severity %}<span style="color:#aaa;font-size:.85em;margin-left:.4em">({{ c.nvd_cvss_v3_severity }})</span>{% endif %}
          {% else %}
          <strong style="color:#00d4ff">CVSS Score</strong><br>
          <span style="font-size:1.3em;font-weight:700">{{ c.cvss_score }}</span>
          {% endif %}
        </div>
        <div>
          {% if c.nvd_cvss_v4_score %}
          <strong style="color:#00d4ff">CVSS v4.0 (NVD)</strong><br>
          <span style="font-size:1.3em;font-weight:700">{{ c.nvd_cvss_v4_score }}</span>
          {% else %}
          <strong style="color:#00d4ff">CVSS Vector</strong><br>
          <code style="background:#0d1117;padding:.3em .6em;border-radius:3px;font-size:.8em;word-break:break-all">{{ c.cvss_vector }}</code>
          {% endif %}
        </div>
        <div{% if c.cwe_name %} style="grid-column:1/-1"{% endif %}>
          <strong style="color:#00d4ff">CWE</strong><br>
          {% if c.cwe_id and c.cwe_id.startswith('CWE-') %}
          <a href="https://cwe.mitre.org/data/definitions/{{ c.cwe_id[4:] }}.html" target="_blank" rel="noopener noreferrer" style="color:#90caf9;text-decoration:none;font-family:monospace">{{ c.cwe_id }}</a>
          {% if c.cwe_name %}<span style="color:#b0bec5;margin-left:.5em;font-size:.92em">&mdash; {{ c.cwe_name }}</span>{% endif %}
          {% if c.cwe_abstraction %}<span style="background:#1a2a3a;color:#78909c;font-size:.78em;padding:.1em .45em;border-radius:3px;margin-left:.4em;font-family:monospace">{{ c.cwe_abstraction }}</span>{% endif %}
          {% else %}
          <span style="font-family:monospace">{{ c.cwe_id }}</span>
          {% endif %}
          {% if c.cwe_description or c.cwe_consequences or c.cwe_mitigation %}
          <details style="margin-top:.5em">
            <summary style="color:#78909c;font-size:.82em;cursor:pointer;user-select:none">&#9656; CWE detail (offline)</summary>
            <div style="background:#0d1117;border:1px solid #1e3a5f;border-radius:4px;padding:.75em 1em;margin-top:.4em;font-size:.87em;line-height:1.6;color:#b0bec5">
              {% if c.cwe_likelihood %}<div style="margin-bottom:.4em"><span style="color:#ffb300;font-weight:600">Likelihood of Exploit:</span> {{ c.cwe_likelihood }}</div>{% endif %}
              {% if c.cwe_description %}<div style="margin-bottom:.6em"><span style="color:#00d4ff;font-weight:600">Description:</span><br>{{ c.cwe_description }}</div>{% endif %}
              {% if c.cwe_consequences %}<div style="margin-bottom:.6em"><span style="color:#ef9a9a;font-weight:600">Common Consequences:</span><br>
                {% for conseq in c.cwe_consequences.split(' | ') %}<div style="padding-left:.8em;color:#e0e0e0">&bull; {{ conseq }}</div>{% endfor %}
              </div>{% endif %}
              {% if c.cwe_mitigation %}<div><span style="color:#a5d6a7;font-weight:600">Suggested Mitigation:</span><br>{{ c.cwe_mitigation }}</div>{% endif %}
            </div>
          </details>
          {% endif %}
        </div>
        <div>
          <strong style="color:#00d4ff">Exploit Maturity</strong><br>
          {{ c.exploit_maturity }}
        </div>
        {% if c.epss_score %}
        <div style="grid-column:1/-1;background:#2a1a00;border:1px solid #ff8f00;border-radius:6px;padding:.7em 1em">
          <strong style="color:#ffb300">&#128313; EPSS Exploit Probability</strong>
          <div style="display:flex;gap:2em;margin-top:.4em;font-size:.92em">
            <span><strong style="color:#ffe082">Probability:</strong> {{ "%.2f%%"|format(c.epss_score * 100) }}</span>
            <span><strong style="color:#ffe082">Percentile:</strong> {{ "%.0f"|format(c.epss_percentile * 100) }}th</span>
            <span style="color:#bbb;font-size:.85em">(Source: FIRST.org EPSS)</span>
          </div>
        </div>
        {% endif %}
      </div>

      <div style="background:#0f3460;border-radius:4px;padding:1em;margin-bottom:1em">
        <strong style="color:#00d4ff;display:block;margin-bottom:.5em">Exploitation Details</strong>
        <div style="font-size:.9em;line-height:1.8;color:#ccc">
          <div><span style="color:#00d4ff">Type:</span> {{ c.vulnerability_type }}</div>
          {% if c.product and c.product != 'unknown' %}<div><span style="color:#00d4ff">Detected Service:</span> <strong style="color:#e0e0e0">{{ c.product }}{% if c.version_affected and c.version_affected != 'unknown' %} {{ c.version_affected }}{% endif %}</strong> &mdash; <em style="color:#aaa;font-size:.9em">this version matches the affected range for {{ c.cve_id }}</em></div>{% endif %}
          <div><span style="color:#00d4ff">Remote:</span> {{ "Yes" if c.remote else "No" }}</div>
          <div><span style="color:#00d4ff">Authentication Required:</span> {{ "Yes" if c.requires_auth else "No" }}</div>
          <div><span style="color:#00d4ff">Affected Versions:</span> <code>{{ c.version_range }}</code></div>
          <div style="margin-top:.5em"><span style="color:#00d4ff">Safe Validation Method:</span> <br><em>{{ c.safe_validation_method }}</em></div>
          <div style="margin-top:.5em"><span style="color:#00d4ff">Proof of Impact:</span> <br><em>{{ c.proof_of_impact }}</em></div>
          {% if c.attacker_perspective %}
          <div style="margin-top:.9em;padding-top:.8em;border-top:1px solid #1e3a5f">
            <span style="color:#ffb300;font-weight:600;font-size:.88em">&#9888; Attacker Gain &amp; Lateral Movement Potential</span>
            <div style="color:#ffe082;font-size:.88em;margin-top:.4em;line-height:1.6;white-space:pre-wrap">{{ c.attacker_perspective }}</div>
            <div style="color:#5d4037;font-size:.76em;margin-top:.4em;font-style:italic">AI-generated threat narrative — review against current threat intelligence.</div>
          </div>
          {% endif %}
        </div>
      </div>

      <div style="background:#0a2a0a;border-left:3px solid #4caf50;border-radius:0 4px 4px 0;padding:1em;margin-bottom:1em">
        <strong style="color:#4caf50">Business Impact</strong>
        <div style="margin-top:.5em;font-size:.95em">{{ c.business_impact }}</div>
      </div>

      {% if c.effort %}
      <div style="display:flex;flex-wrap:wrap;align-items:center;gap:.7em;margin-bottom:.75em;font-size:.88em">
        <span style="color:#9e9e9e">Remediation Effort:</span>
        {% if c.effort == "Low" %}
        <span style="background:#0d2a0d;color:#a5d6a7;padding:.25em .9em;border-radius:12px;border:1px solid #388e3c;font-weight:600">&#x1F7E2; Low &mdash; Config Change</span>
        {% elif c.effort == "Medium" %}
        <span style="background:#2a2000;color:#ffe082;padding:.25em .9em;border-radius:12px;border:1px solid #f9a825;font-weight:600">&#x1F7E1; Medium &mdash; Patch Required</span>
        {% else %}
        <span style="background:#2a0d0d;color:#ef9a9a;padding:.25em .9em;border-radius:12px;border:1px solid #c62828;font-weight:600">&#x1F534; High &mdash; Upgrade / Redesign</span>
        {% endif %}
      </div>
      {% endif %}

      {% if c.compliance_controls %}
      <div style="background:#1a2a3a;border-left:3px solid #29b6f6;border-radius:0 4px 4px 0;padding:1em;margin-bottom:1em">
        <strong style="color:#29b6f6">Compliance &amp; Regulations</strong>
        <div style="display:flex;flex-wrap:wrap;gap:.5em;margin-top:.5em;font-size:.9em">
          {% for control in c.compliance_controls %}
          <span style="background:#0f3460;padding:.4em .8em;border-radius:4px;border:1px solid #29b6f6">{{ control }}</span>
          {% endfor %}
        </div>
        <div style="margin-top:.65em;font-size:.8em;color:#78909c;line-height:1.7;border-top:1px solid #1e3a5f;padding-top:.55em">
          {% for control in c.compliance_controls %}{% if compliance_reasoning.get(control) %}<div><strong style="color:#546e7a">{{ control }}:</strong> {{ compliance_reasoning.get(control) }}</div>{% endif %}{% endfor %}
        </div>
      </div>
      {% endif %}

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:.8em;margin-bottom:1em">
        <div style="background:#1a2a0a;border-left:3px solid #8bc34a;border-radius:0 4px 4px 0;padding:.9em">
          <strong style="color:#8bc34a;display:block;margin-bottom:.4em">&#x26A1; Short-term Workaround</strong>
          <div style="font-size:.9em;color:#dcedc8;line-height:1.6">{{ c.remediation_short }}</div>
        </div>
        <div style="background:#0d2137;border-left:3px solid #29b6f6;border-radius:0 4px 4px 0;padding:.9em">
          <strong style="color:#29b6f6;display:block;margin-bottom:.4em">&#x1F527; Long-term Fix</strong>
          <div style="font-size:.9em;color:#b3e5fc;line-height:1.6">{{ c.remediation_long }}</div>
        </div>
      </div>

      <details style="margin-bottom:1em">
        <summary style="cursor:pointer;color:#90caf9;font-size:.93em;font-weight:600">&#x1F50E; Steps to Reproduce</summary>
        <div style="margin-top:.6em">
          <p style="color:#aaa;font-size:.85em;margin:.3em 0 .6em 0">Replace <code style="background:#111;padding:.1em .35em;border-radius:3px">{target}</code> and <code style="background:#111;padding:.1em .35em;border-radius:3px">{port}</code> with the actual host and service port. Run in a controlled authorised environment only.</p>
          <code style="background:#0d1117;color:#a5d6a7;padding:.6em .9em;border-radius:4px;font-size:.82em;display:block;white-space:pre-wrap;word-break:break-all">{{ c.steps_to_reproduce }}</code>
          <div style="color:#546e7a;font-size:.78em;margin-top:.4em;font-style:italic">&#9888; These snippets verify existence of the vulnerability — do not use against systems you do not own or have explicit permission to test.</div>
        </div>
      </details>

      {% if c.references %}
      <div>
        <strong style="color:#00d4ff;display:block;margin-bottom:.5em">&#x1F4DA; References</strong>
        <ul style="margin:.5em 0;padding-left:1.5em;font-size:.9em">
          {% for ref in c.references %}
          <li style="margin:.3em 0"><a href="{{ ref | safe_url }}" target="_blank" rel="noopener noreferrer" style="color:#29b6f6;text-decoration:none">{{ ref | truncate(80) }}</a></li>
          {% endfor %}
        </ul>
      </div>
      {% endif %}

      {# ── Testing Evidence (MSF + active probe results) ─────────────────── #}
      {% set _tr = c.cve_test_result %}
      {% set _msf = c.msf_validation if c.get('msf_validation') and c.msf_validation.get('module') else None %}
      {% if _tr or _msf %}
      <details style="margin-top:1em">
        <summary style="cursor:pointer;color:#78909c;font-size:.9em;font-weight:600">&#x1F9EA; Testing Evidence {% if _tr %}&mdash; {{ _tr.overall_verdict }}{% endif %}</summary>
        <div style="margin-top:.6em">

        {% if _msf %}
        <div style="background:#1a1428;border-left:3px solid #7c4dff;border-radius:0 4px 4px 0;padding:.65em .9em;margin-bottom:.6em;font-size:.86em">
          <strong style="color:#b39ddb">&#9658; Metasploit Framework Check</strong>
          <div style="display:flex;gap:1em;align-items:center;margin-top:.4em;flex-wrap:wrap">
            <span style="font-family:monospace;color:#ce93d8;font-size:.88em">{{ _msf.module }}</span>
            {% if _msf.vulnerable is sameas true %}<span class="badge badge-critical" style="font-size:.75em">VULNERABLE</span>
            {% elif _msf.vulnerable is sameas false %}<span class="badge badge-low" style="font-size:.75em">NOT EXPLOITABLE</span>
            {% else %}<span class="badge badge-info" style="font-size:.75em">UNCONFIRMED</span>{% endif %}
          </div>
          {% if _msf.result %}<div style="color:#9e9e9e;font-size:.82em;margin-top:.35em">{{ _msf.result[:200] }}</div>{% endif %}
        </div>
        {% endif %}

        {% if _tr %}
        {% set _tv = _tr.overall_verdict %}
        {% if _tv == 'CONFIRMED_VULNERABLE' %}{% set _vbg="#3d0000" %}{% set _vborder="#ff1744" %}
        {% elif _tv == 'NOT_VULNERABLE' %}{% set _vbg="#0a2a12" %}{% set _vborder="#43a047" %}
        {% elif _tv == 'VULNERABLE' %}{% set _vbg="#3a1800" %}{% set _vborder="#ff9800" %}
        {% else %}{% set _vbg="#1c1c1c" %}{% set _vborder="#757575" %}{% endif %}
        <div style="border-left:3px solid {{ _vborder }};background:{{ _vbg }};border-radius:0 4px 4px 0;padding:.6em .9em;margin-bottom:.5em;font-size:.86em">
          <div style="display:flex;gap:.8em;align-items:center;flex-wrap:wrap">
            <strong style="color:#e0e0e0">Active Probe Results</strong>
            <span style="color:#aaa;font-size:.82em">{{ _tr.attempts_run }} attempts &mdash; V:{{ _tr.verdict_counts.VULNERABLE }} N:{{ _tr.verdict_counts.NOT_VULNERABLE }} I:{{ _tr.verdict_counts.INCONCLUSIVE }} &mdash; KB replayed: {{ _tr.kb_replayed }}</span>
          </div>
          {% if _tv == 'INCONCLUSIVE' and _tr.inconclusive_reason %}
          <div style="color:#ffe082;font-size:.84em;margin-top:.4em">{{ _tr.inconclusive_reason }}</div>
          {% endif %}
        </div>

        {% if _tr.verification_results %}
        <div style="background:#1a2a1a;border-left:3px solid {% if _tr.verified %}#4caf50{% else %}#ff9800{% endif %};padding:.5em .8em;margin-bottom:.5em;border-radius:0 4px 4px 0;font-size:.84em">
          <strong style="color:{% if _tr.verified %}#4caf50{% else %}#ff9800{% endif %}">{% if _tr.verified %}&#10003; False-Positive Check: CONFIRMED{% else %}&#9888; False-Positive Check: UNCONFIRMED{% endif %}</strong>
          <div style="margin-top:.3em">
          {% for v in _tr.verification_results %}
            <span style="margin-right:.8em">V{{ v.verifier_num }}: <em>{{ v.strategy[:60] }}</em> &rarr;
              {% if v.verdict == 'VULNERABLE' %}<span style="color:#ef9a9a">VULNERABLE</span>
              {% elif v.verdict == 'NOT_VULNERABLE' %}<span style="color:#a5d6a7">NOT_VULNERABLE</span>
              {% else %}<span style="color:#ffcc80">INCONCLUSIVE</span>{% endif %}
            </span>
          {% endfor %}
          </div>
        </div>
        {% endif %}

        {% for a in _tr.attempts %}
        <details style="margin:.3em 0;font-size:.85em">
          <summary style="cursor:pointer;color:#90caf9">
            [{{ "%02d"|format(a.attempt_num) }}]
            {% if a.get('source') == 'kb_replay' %}<span style="color:#ce93d8;font-size:.8em">[KB]</span>{% endif %}
            {% if a.verdict == 'VULNERABLE' %}<span style="color:#ef9a9a">&#9679;</span>
            {% elif a.verdict == 'NOT_VULNERABLE' %}<span style="color:#a5d6a7">&#9679;</span>
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

        {% if _tr.attacker_perspective %}
        <div style="background:#1a0a00;border-left:3px solid #ff6d00;padding:.6em .9em;margin-top:.5em;border-radius:0 4px 4px 0;font-size:.86em">
          <strong style="color:#ff9800">&#9760; Attacker Perspective</strong>
          <div style="color:#ffe0b2;margin-top:.35em;white-space:pre-wrap;line-height:1.55">{{ _tr.attacker_perspective }}</div>
        </div>
        {% endif %}
        {% if _tr.remediation %}
        <div style="background:#0d2137;border-left:3px solid #29b6f6;padding:.6em .9em;margin-top:.5em;border-radius:0 4px 4px 0;font-size:.86em">
          <strong style="color:#29b6f6">&#128295; Suggested Remediation</strong>
          <div style="color:#cfd8dc;margin-top:.35em;white-space:pre-wrap;line-height:1.55">{{ _tr.remediation }}</div>
        </div>
        {% endif %}
        {% endif %}

        </div>
      </details>
      {% endif %}

    </div>
  </details>
  {% endfor %}
  </div>
</details>
{% else %}<p>No active CVE matches.</p>{% endif %}

{# ── Section 2: Tested — NOT VULNERABLE ────────────────────────────────── #}
{% if _cve_cleared %}
<details style="margin-bottom:1.2em;border:1px solid #2e7d32;border-radius:6px;background:#0d1b2a">
  <summary style="cursor:pointer;color:#66bb6a;font-size:.92em;font-weight:600;padding:.65em 1em;user-select:none;display:flex;align-items:center;gap:.6em">
    <span>&#9654;</span>
    <span>&#9989; {{ _cve_cleared|length }} CVE(s) tested &mdash; NOT VULNERABLE on this host</span>
  </summary>
  <div style="padding:.5em;margin-bottom:.5em">
    <p style="margin:.5em 1em .8em;color:#607d8b;font-size:.86em">These CVEs matched the detected service version but active probing confirmed this host is <strong style="color:#66bb6a">not affected</strong>. Shown for audit completeness. The CVSS/EPSS scores reflect the general danger class of the CVE, not the risk to this host.</p>
    {% for c in _cve_cleared | sort(attribute='epss_score', reverse=True) %}
    <details style="margin-bottom:.7em;border:1px solid #2e7d32;border-radius:5px;padding:.8em 1em;background:#0a1f0a">
      <summary style="cursor:pointer;font-weight:600;color:#66bb6a;font-size:.97em;display:flex;align-items:center;flex-wrap:wrap;gap:.5em">
        <span style="font-size:1.1em">&#9989;</span>
        <span style="flex:1;min-width:160px"><a href="https://nvd.nist.gov/vuln/detail/{{ c.cve_id }}" target="_blank" rel="noopener noreferrer" style="color:#66bb6a;text-decoration:none">{{ c.cve_id }}</a> &mdash; {{ c.vulnerability_type }} on {{ c.service }}</span>
        <span class="badge badge-{{ c.severity|lower }}" style="opacity:.4;text-decoration:line-through">{{ c.severity|upper }}</span>
        {% if c.nvd_cvss_v3_score %}<span style="background:#0f3460;color:#90a4ae;padding:2px 8px;border-radius:4px;font-size:.82em;border:1px solid #37474f">v3.1&nbsp;{{ c.nvd_cvss_v3_score }}</span>{% endif %}
        {% if c.epss_score %}<span style="background:#1a1a1a;color:#78909c;padding:2px 8px;border-radius:4px;font-size:.8em;border:1px solid #37474f">EPSS {{ "%.1f%%"|format(c.epss_score * 100) }}</span>{% endif %}
        {% if c.kev_listed %}<span class="badge badge-kev" style="opacity:.5">&#9888; KEV</span>{% endif %}
      </summary>
      <div style="margin-top:.8em;padding-top:.8em;border-top:1px solid #2e7d32;font-size:.9em">
        <div style="background:#0a2a12;border-left:4px solid #43a047;border-radius:0 6px 6px 0;padding:.7em 1em;margin-bottom:.8em;display:flex;align-items:center;gap:.7em">
          <span style="font-size:1.1em">&#9989;</span>
          <div><strong style="color:#66bb6a;font-size:.9em">TESTED: NOT VULNERABLE ON THIS HOST</strong>
          <div style="color:#a5d6a7;font-size:.83em;margin-top:.2em">Active probing found no exploitability. The CVSS score and EPSS probability above reflect the general danger of this CVE class &mdash; this host was not confirmed affected.</div></div>
        </div>
        {% if c.product and c.product != 'unknown' %}
        <div style="color:#78909c;font-size:.88em;margin-bottom:.5em">Detected: <strong style="color:#90a4ae">{{ c.product }}{% if c.version_affected and c.version_affected != 'unknown' %} {{ c.version_affected }}{% endif %}</strong></div>
        {% endif %}
        {# Show testing evidence accordion #}
        {% set _tr = c.cve_test_result %}
        {% if _tr and _tr.attempts %}
        <details style="margin-top:.4em">
          <summary style="cursor:pointer;color:#546e7a;font-size:.87em">&#x1F9EA; Testing Evidence &mdash; {{ _tr.attempts_run }} attempt(s)</summary>
          <div style="margin-top:.5em">
          {% for a in _tr.attempts %}
          <details style="margin:.3em 0;font-size:.84em">
            <summary style="cursor:pointer;color:#90caf9">[{{ "%02d"|format(a.attempt_num) }}] <span style="color:#a5d6a7">&#9679;</span> {{ a.verdict }} &mdash; {{ a.strategy[:80] }}</summary>
            <pre style="background:#1a1a1a;color:#ccc;padding:.6em;border-radius:4px;overflow-x:auto;white-space:pre-wrap;font-size:.8em">{{ a.output }}</pre>
          </details>
          {% endfor %}
          </div>
        </details>
        {% endif %}
      </div>
    </details>
    {% endfor %}
  </div>
</details>
{% endif %}

{% if suppressed_cve_matches %}
{# ── Section 3: Suppressed CVEs ─────────────────────────────────────────── #}
<details style="margin-bottom:1.2em;border:1px solid #37474f;border-radius:6px;background:#0d1b2a">
  <summary style="cursor:pointer;color:#78909c;font-size:.92em;font-weight:600;padding:.65em 1em;user-select:none;display:flex;align-items:center;gap:.6em">
    <span>&#9654;</span>
    <span>&#x2716; {{ suppressed_cve_matches|length }} CVE(s) suppressed &mdash; detected version &ge; fixed version (false positive reduction)</span>
  </summary>
  <div style="padding:.5em;color:#90a4ae;font-size:.88em">
    <p style="margin:.5em 1em;color:#607d8b">These CVEs were matched by service/version correlation but the detected version appears to be patched based on the CVE summary. They are shown here for audit completeness.</p>
    {% for c in suppressed_cve_matches %}
    <div style="margin-bottom:.7em;border:1px solid #37474f;border-radius:5px;padding:.7em 1em;background:#121e27">
      <div style="display:flex;flex-wrap:wrap;align-items:center;gap:.5em;margin-bottom:.3em">
        <a href="https://nvd.nist.gov/vuln/detail/{{ c.cve_id }}" target="_blank" rel="noopener noreferrer" style="color:#546e7a;text-decoration:none;font-weight:700;font-family:monospace">{{ c.cve_id }}</a>
        <span class="badge badge-{{ c.severity|lower }}" style="opacity:.5;text-decoration:line-through">{{ c.severity|upper }}</span>
        {% if c.epss_score %}<span style="background:#1a1a1a;color:#78909c;padding:2px 7px;border-radius:4px;font-size:.8em;border:1px solid #37474f">EPSS {{ "%.1f%%"|format(c.epss_score * 100) }}</span>{% endif %}
        <span style="color:#607d8b;font-size:.85em">&mdash; {{ c.service }}</span>
      </div>
      {% if c.suppression_reason %}<div style="color:#546e7a;font-size:.82em;font-style:italic">&#x2714; {{ c.suppression_reason }}</div>{% endif %}
    </div>
    {% endfor %}
  </div>
</details>
{% endif %}

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

_TOOL_LABELS = {
    "nikto":     "Web Scanner",
    "nikto_cgi": "CGI Scanner",
    "nmap":      "Network Scanner",
    "nuclei":    "Vulnerability Scanner",
    "ffuf":      "Directory Fuzzer",
    "curl":      "HTTP Probe",
    "dns_enum":  "DNS Enumerator",
    "hydra":     "Auth Tester",
    "rdpscan":   "RDP Scanner",
    "msf":       "Exploit Framework",
}


def generate_html_report(report_data):
    # Back-fill inconclusive_reason for reports generated before this field existed
    cve_results = report_data.get("cve_test_results", [])
    for r in cve_results:
        if r.get("overall_verdict") == "INCONCLUSIVE" and not r.get("inconclusive_reason"):
            r["inconclusive_reason"] = _derive_inconclusive_reason(r, r.get("attempts", []))

    # Merge CVE test results into each CVE match record so cards can render
    # testing evidence inline (verdict banner + attempt accordion).
    _test_lookup = {r["cve_id"]: r for r in cve_results}
    for match in report_data.get("cve_matches", []):
        result = _test_lookup.get(match.get("cve_id"))
        if result:
            match["cve_test_result"] = result
        elif "cve_test_result" not in match:
            match["cve_test_result"] = None

    _eff_map = report_data.get("effective_severity_map", {})
    _all_f   = report_data.get("findings", [])
    _active_findings    = [f for f in _all_f
                           if _eff_map.get(f["finding_id"], f.get("severity", "info")).lower()
                           in ("critical", "high")]
    _hardening_findings = [f for f in _all_f
                           if _eff_map.get(f["finding_id"], f.get("severity", "info")).lower()
                           in ("medium", "low")]
    _info_sev_findings  = [f for f in _all_f
                           if _eff_map.get(f["finding_id"], f.get("severity", "info")).lower()
                           not in ("critical", "high", "medium", "low")]

    data = dict(
        report_data,
        rem_short_map=_REMEDIATION_SHORT_TERM,
        rem_long_map=_REMEDIATION_LONG_TERM,
        steps_map=_STEPS_TO_REPRODUCE,
        compliance_reasoning=_COMPLIANCE_REASONING,
        remediation_effort=_REMEDIATION_EFFORT,
        time_to_fix_map=_REMEDIATION_TIME_ESTIMATE,
        cwe_db=_load_cwe_db(),
        # Calibrated severity map: finding_id → effective severity string
        # Falls back to the raw Finding.severity when id not present (e.g. re-rendered old reports)
        _eff_sev=_eff_map,
        logo_svg=_LOGO_SVG,
        _tool_labels=_TOOL_LABELS,
        _confirmed_ids=[f["finding_id"] for f in report_data.get("confirmed_findings", [])],
        _probable_ids=[f["finding_id"] for f in report_data.get("probable_findings", [])],
        _review_ids=[f["finding_id"] for f in report_data.get("review_needed", [])],
        active_findings=_active_findings,
        hardening_findings=_hardening_findings,
        info_sev_findings=_info_sev_findings,
    )
    _env = _JinjaEnv(autoescape=True)
    _env.filters['safe_url']   = lambda u: u if isinstance(u, str) and u.startswith(('https://', 'http://')) else '#'
    _env.filters['parse_json'] = lambda s: json.loads(s) if (s and s.strip().startswith('[')) else None
    return _env.from_string(HTML_TEMPLATE).render(**data)


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

    # REPORT_MODEL (qwen3:4b) is not called until _enrich_finding_remediation,
    # which runs after severity calibration.  By the time the executive summary
    # is generated (deferred to after remediations below), the model is already
    # warm — no explicit pre-load thread is needed.
    all_findings = deduplicate_findings(all_findings)
    # Build per-finding EPSS lookup: match CVE IDs from template_id or title
    # against the offline EPSS database so the composite risk score can incorporate
    # real exploit-probability data rather than relying on severity alone.
    _epss_db = _load_epss_db()
    _cve_re  = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
    for f in all_findings:
        _cve_hits = _cve_re.findall((f.template_id or "") + " " + (f.title or ""))
        _epss_val = 0.0
        for _cid in _cve_hits:
            _entry = _epss_db.get(_cid.upper())
            if _entry:
                _epss_val = max(_epss_val, _entry[0])
                break
        f.risk_score = calculate_risk_score(f, epss_score=_epss_val)

    # ── Calibrated severity (report-layer only — Finding.severity unchanged) ─
    # Step 1: deterministic rules — clear-cut cases resolved immediately
    _rules_map: dict = {}
    _ambiguous: list = []
    for f in all_findings:
        result = _effective_severity_rules(f)
        if result is None:
            _ambiguous.append(f)
        else:
            _rules_map[f.finding_id] = result
    # Step 2: batch LLM re-rating for ambiguous findings (structured JSON, no prose)
    _llm_map: dict = {}
    if _ambiguous:
        _sp2 = _Spinner(f"[ LLM ]  Calibrating severity for {len(_ambiguous)} ambiguous finding(s) ...").start()
        _t_cal = time.monotonic()
        try:
            _llm_map = _llm_recalibrate_severities(_ambiguous)
        finally:
            _sp2.stop(f" done ({_fmt_dur(time.monotonic() - _t_cal)})")
    # Merge: LLM result takes precedence for ambiguous findings
    _eff_sev_map: dict = {**_rules_map, **_llm_map}
    # Ensure every finding has an entry (should not happen, but safe fallback)
    for f in all_findings:
        if f.finding_id not in _eff_sev_map:
            _eff_sev_map[f.finding_id] = _cap_severity(f.severity, "medium")

    _SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_findings.sort(
        key=lambda f: (_SEV_ORDER.get(_eff_sev_map.get(f.finding_id, f.severity).lower(), 5), -f.risk_score)
    )

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        _esev = _eff_sev_map.get(f.finding_id, f.severity).lower()
        counts[_esev] = counts.get(_esev, 0) + 1

    # Partition findings into trust tiers for the report
    confirmed_findings    = [f for f in all_findings if f.verification_status == "confirmed"]
    review_needed         = [f for f in all_findings
                             if f.verification_status == "probe_inconclusive"
                             or getattr(f, "manual_review", False)]
    probable_findings     = [f for f in all_findings
                             if f.verification_status == "discovered"
                             and f not in review_needed
                             and f.confidence >= 0.60]
    informational_findings = [f for f in all_findings
                               if f not in confirmed_findings
                               and f not in probable_findings
                               and f not in review_needed]

    # Counts used for executive summary grid (all findings, for full picture)
    # Separate confirmed_counts drives the anchor sentence accuracy
    confirmed_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in confirmed_findings + probable_findings:
        _esev = _eff_sev_map.get(f.finding_id, f.severity).lower()
        confirmed_counts[_esev] = confirmed_counts.get(_esev, 0) + 1

    # Timed-out tools for coverage section
    timed_out_scan_records = [
        r for r in scan_records
        if r.get("timed_out") or "Command timed out" in (r.get("output", "") or "")
    ]

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

    # ── Deterministic anchor sentence ────────────────────────────────────────
    # Build a factually accurate first sentence from the real counts so the
    # LLM cannot hallucinate a risk level that contradicts the data.
    _c, _h, _m, _l = (counts.get(k, 0) for k in ("critical", "high", "medium", "low"))
    _total = _c + _h + _m + _l
    if _c > 0:
        _posture = "critical"
    elif _h > 0:
        _posture = "high"
    elif _m > 0:
        _posture = "medium"
    elif _l > 0:
        _posture = "low"
    else:
        _posture = "minimal"

    _finding_parts = []
    if _c: _finding_parts.append(f"{_c} critical")
    if _h: _finding_parts.append(f"{_h} high")
    if _m: _finding_parts.append(f"{_m} medium")
    if _l: _finding_parts.append(f"{_l} low")
    _finding_str = (", ".join(_finding_parts) + f" (total {_total})") if _finding_parts else "no exploitable"

    _anchor = (
        f"The assessment of {target} identified {_finding_str} severity findings, "
        f"indicating a {_posture}-risk security posture that requires immediate attention."
        if _posture not in ("minimal",) else
        f"The assessment of {target} identified no exploitable findings, indicating a low-risk security posture."
    )

    # Executive summary is generated AFTER _enrich_finding_remediation so that
    # REPORT_MODEL (qwen3:4b) is already warm — the remediation pass loads the
    # model first, eliminating the cold-load timeout that plagued this call.
    conclusion = _anchor          # deterministic fallback; overwritten below
    conclusion_llm_ok = False     # updated after model is warm

    # ── Per-finding LLM remediation ─────────────────────────────────────────
    # Pre-enrichment inference pass: use the static keyword map to fill in vuln_type
    # for any finding that still has an empty or Unknown vuln_type (covers nuclei,
    # ffuf, ssh-audit, nmap-service parsers that don't set it at parse time).
    for _f in all_findings:
        if not _f.vuln_type or _f.vuln_type == "Unknown":
            _inferred = _infer_vuln_type(_f.title + " " + (_f.description or ""))
            if _inferred and _inferred != "Unknown":
                _f.vuln_type = _inferred
            elif not _f.vuln_type:
                _f.vuln_type = "Misconfiguration"
    # Generate rich LLM remediation for all active (critical/high) and hardening
    # (medium/low) findings — informational findings use the static map only.
    _rem_findings = [f for f in all_findings if f.severity in ("critical", "high", "medium", "low")]
    if _rem_findings:
        print(f"\n[+] Generating LLM remediation advice for {len(_rem_findings)} finding(s) (active + hardening) ...")
        import concurrent.futures
        # max_workers=1 — Ollama on CPU serialises requests internally, so concurrent
        # callers don't run in parallel: they queue up and each burns through its
        # OLLAMA_TIMEOUT budget *while waiting*, causing nearly all to time out.
        # Sequential execution gives every call its full 360 s of actual inference time.
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as _pool:
            list(_pool.map(_enrich_finding_remediation, _rem_findings))
    _rem_failed = sum(1 for f in _rem_findings if not f.llm_remediation_short)

    # ── Executive summary (REPORT_MODEL now warm after remediation pass) ────
    # qwen3:4b is already loaded in Ollama's model cache after the remediation
    # ThreadPoolExecutor above — this call will not incur a cold-load delay.
    _t0 = time.monotonic()
    _sp = _Spinner("[ LLM ]  Writing executive summary ...").start()
    try:
        for attempt in range(MAX_LLM_RETRIES):
            try:
                resp = requests.post(
                    OLLAMA_URL,
                    json={"model": REPORT_MODEL, "stream": False,
                          "keep_alive": _OLLAMA_KEEP_ALIVE,
                          "options":    {"num_ctx": 2048, "temperature": 0.3, "num_predict": 1000},
                          "prompt": (
                              "/no_think\n"
                              "You are a professional penetration tester writing an executive summary "
                              "for a client-facing security assessment report. "
                              "Write exactly 3 paragraphs of professional prose in plain text. "
                              "No bullet points, no headings, no markdown, no numbered lists. "
                              "Each paragraph must be 2-4 sentences. Use plain business language \u2014 "
                              "avoid marketing terms, acronym soup, and vendor jargon. "
                              "Paragraph 1: Describe the scope of the assessment and the finding "
                              "categories \u2014 what was tested, what services were discovered, the "
                              "main types of weakness identified (unpatched software, configuration "
                              "problems, exposed services, weak authentication), and what the "
                              "spread of severities says about the overall posture. "
                              "Paragraph 2: Identify the 2-3 most serious issues by name and explain "
                              "in plain terms what an attacker could realistically do if they "
                              "exploited them and what the business consequence would be. Focus on "
                              "impact, not technique. "
                              "Paragraph 3: Summarise remediation urgency \u2014 what needs to be "
                              "addressed within days versus weeks, and whether any findings represent "
                              "systemic weaknesses that point to a broader process or policy gap. "
                              "Do NOT repeat the opening sentence verbatim. "
                              "Do not add disclaimers, questions, or sign-offs. "
                              f"Opening sentence (incorporate naturally, do not repeat verbatim): {_anchor} "
                              f"Assessment data: {json.dumps(mini_summary, separators=(',', ':'))}"
                          )},
                    timeout=OLLAMA_TIMEOUT,
                )
                payload = resp.json()
                if "response" in payload:
                    raw = payload["response"].strip()
                    # Strip closed and unclosed <think> blocks — qwen3 can leak reasoning
                    # even with /no_think; unclosed = output truncated mid-think.
                    raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
                    raw = re.sub(r"<think>.*", "", raw, flags=re.DOTALL).strip()
                    clean_lines = []
                    for line in raw.splitlines():
                        stripped = line.strip()
                        if not stripped:
                            if clean_lines:
                                clean_lines.append("")
                            continue
                        lower = stripped.lower()
                        if lower.startswith(("**", "##", "# ", "note:", "follow", "question")):
                            break
                        if lower.startswith("the assessment of") and not clean_lines:
                            continue
                        clean_lines.append(stripped)
                    continuation = "\n".join(clean_lines).strip() if clean_lines else ""
                    if continuation:
                        conclusion = f"{_anchor}\n\n{continuation}"
                        conclusion_llm_ok = True
                    break
            except Exception as e:
                print(f"[!] Conclusion LLM error (attempt {attempt + 1}/{MAX_LLM_RETRIES}): {e}")
                if attempt < MAX_LLM_RETRIES - 1:
                    time.sleep(2)
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

    # Aggregate unique compliance controls from findings and CVE matches
    compliance_summary = list(dict.fromkeys(
        ctrl
        for f in all_findings
        for ctrl in (f.compliance_controls if hasattr(f, "compliance_controls") else [])
    ))
    for c in cve_matches:
        for ctrl in c.get("compliance_controls", []):
            if ctrl not in compliance_summary:
                compliance_summary.append(ctrl)

    # Build suppressed CVE list across all services for the report
    suppressed_cve_matches = []
    for s in services:
        for c in s.get("suppressed_cves", []):
            enriched = enrich_cve(c, s)
            enriched["service"]             = f"{s['port']}/{s.get('name', '')}"
            enriched["suppression_reason"]  = c.get("_suppression_reason", "")
            suppressed_cve_matches.append(enriched)

    return {
        "target":        target,
        "profile":       profile,
        "generated_at":  generated_at,
        "counts":        counts,
        "confirmed_counts": confirmed_counts,
        "services":      services,
        "findings":      [dataclasses.asdict(f) for f in all_findings],
        "confirmed_findings":     [dataclasses.asdict(f) for f in confirmed_findings],
        "probable_findings":      [dataclasses.asdict(f) for f in probable_findings],
        "informational_findings": [dataclasses.asdict(f) for f in informational_findings],
        "review_needed":          [dataclasses.asdict(f) for f in review_needed],
        "cve_matches":   cve_matches,
        "suppressed_cve_matches": suppressed_cve_matches,
        "tools_run":     tools_run,
        "execution_log": execution_log,
        "conclusion":           conclusion,
        "conclusion_llm_ok":    conclusion_llm_ok,
        "conclusion_audited":   False,
        "conclusion_revised":   False,
        "audit_notes":          "",
        "remediation_llm_failed": _rem_failed,
        "cve_llm_failed":       0,
        "cve_test_results": [],
        "msf_validation": [],
        "target_info":   target_info.to_dict() if target_info else {},
        "compliance_summary": compliance_summary,
        "timed_out_tools": [
            {"tool": r.get("tool", ""), "args": str(r.get("args", "") or "")}
            for r in timed_out_scan_records
        ],
        "effective_severity_map": _eff_sev_map,
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
    """Write the CVE knowledge base to disk.

    Attempts an atomic rename first; falls back to shutil.copy2 when running
    inside Docker where the file is a bind-mounted inode (a separate mount
    point) and rename(2) would fail with EXDEV.
    """
    tmp = CVE_KB_PATH + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(kb, fh, indent=2, default=str)
        try:
            os.replace(tmp, CVE_KB_PATH)
        except OSError:
            # Docker file bind-mounts are separate mount points; rename(2)
            # across a mount boundary fails with EXDEV.  copy2 opens the
            # existing inode for writing, preserving the bind-mount link.
            shutil.copy2(tmp, CVE_KB_PATH)
            os.unlink(tmp)
    except Exception as e:
        print(f"[!] CVE KB save error: {e}")


def _load_nuclei_kb() -> dict:
    """Load the persistent Nuclei template knowledge base, returning {} on missing or corrupt file."""
    if not os.path.exists(NUCLEI_KB_PATH):
        return {}
    try:
        with open(NUCLEI_KB_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as e:
        print(f"[!] Nuclei KB load error ({e}) — starting with empty template KB.")
        return {}


def _save_nuclei_kb(nkb: dict):
    """Write the Nuclei template knowledge base to disk (atomic-with-EXDEV-fallback)."""
    tmp = NUCLEI_KB_PATH + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(nkb, fh, indent=2, default=str)
        try:
            os.replace(tmp, NUCLEI_KB_PATH)
        except OSError:
            shutil.copy2(tmp, NUCLEI_KB_PATH)
            os.unlink(tmp)
    except Exception as e:
        print(f"[!] Nuclei KB save error: {e}")


def _upsert_nuclei_template(nkb: dict, template_id: str, cve_id: str, template: dict,
                             verdict: str, output_sample: str):
    """Insert or update a Nuclei template entry in the template KB.

    template dict must contain: yaml_content, probe_type, protocol, confidence.
    verdict: 'VULNERABLE' | 'NOT_VULNERABLE' | 'INCONCLUSIVE'
    """
    now = datetime.now(timezone.utc).isoformat()
    if template_id not in nkb:
        nkb[template_id] = {
            "template_id":              template_id,
            "cve_ids":                  [cve_id],
            "probe_type":               template.get("probe_type", "unknown"),
            "protocol":                 template.get("protocol", "http"),
            "confidence_weight":        template.get("confidence", 0.7),
            "negative_matchers_present": template.get("negative_matchers_present", False),
            "matchers_summary":         template.get("matchers_summary", ""),
            "yaml_content":             template.get("yaml_content", ""),
            "runs":                     0,
            "verdict_counts":           {"VULNERABLE": 0, "NOT_VULNERABLE": 0, "INCONCLUSIVE": 0},
            "output_samples":           [],
            "created_at":               now,
            "last_tested":              now,
        }
    entry = nkb[template_id]
    if cve_id not in entry.get("cve_ids", []):
        entry["cve_ids"].append(cve_id)
    entry["runs"] = entry.get("runs", 0) + 1
    vc = entry.setdefault("verdict_counts", {"VULNERABLE": 0, "NOT_VULNERABLE": 0, "INCONCLUSIVE": 0})
    vc[verdict] = vc.get(verdict, 0) + 1
    entry["last_tested"] = now
    if output_sample and len(entry.get("output_samples", [])) < 3:
        entry.setdefault("output_samples", []).append(output_sample[:300])


# ---------------------------------------------------------------------------
# TOOL KNOWLEDGE BASE — persistent performance tracking per tool per service
# ---------------------------------------------------------------------------

# Canonical service key map — nmap service names → normalised protocol labels used in KB
_SVC_KEY_MAP: dict = {
    "http":          "http",
    "ssl/http":      "https",
    "https":         "https",
    "http-alt":      "http",
    "http-proxy":    "http",
    "ipp":           "http",   # CUPS IPP is HTTP-based
    "ssh":           "ssh",
    "rdp":           "rdp",
    "microsoft-rdp": "rdp",
    "ms-wbt-server": "rdp",
    "mysql":         "mysql",
    "ms-sql-s":      "mssql",
    "mssql":         "mssql",
    "dns":           "dns",
    "domain":        "dns",
    "ftp":           "ftp",
    "smtp":          "smtp",
    "smb":           "smb",
    "microsoft-ds":  "smb",
    "netbios-ssn":   "smb",
}

# Hard-coded tool→service for tools that are always tied to one service type
_TOOL_SVC_DIRECT: dict = {
    "ssh_enum":   "ssh",
    "rdp_enum":   "rdp",
    "mysql_enum": "mysql",
    "mssql_enum": "mssql",
    "dns_enum":   "dns",
}

# Last-resort fallback when port lookup fails
_TOOL_SVC_FALLBACK: dict = {
    "nikto":     "http",
    "nikto_cgi": "http",
    "ffuf":      "http",
    "nuclei":    "http",
    "curl":      "http",
    "nmap":      "host",
    "nxc":       "smb",
}

# nmap product string → short canonical product label.
# Longest matching prefix wins (sort by length descending at build time).
_PRODUCT_LABEL_MAP: dict = {
    # HTTP servers
    "apache":                  "apache",
    "nginx":                   "nginx",
    "microsoft-iis":           "iis",
    "microsoft iis":           "iis",
    "lighttpd":                "lighttpd",
    "cherokee":                "cherokee",
    "caddy":                   "caddy",
    "traefik":                 "traefik",
    "tomcat":                  "tomcat",
    "jetty":                   "jetty",
    "gunicorn":                "gunicorn",
    "uvicorn":                 "uvicorn",
    "uwsgi":                   "uwsgi",
    "werkzeug":                "werkzeug",
    "node.js":                 "nodejs",
    "node":                    "nodejs",
    "express":                 "express",
    "flask":                   "flask",
    "django":                  "django",
    "ollama":                  "ollama",
    "grafana":                 "grafana",
    "kibana":                  "kibana",
    "elasticsearch":           "elasticsearch",
    "jenkins":                 "jenkins",
    "jira":                    "jira",
    "confluence":              "confluence",
    "sonarqube":               "sonarqube",
    "gitea":                   "gitea",
    "gitlab":                  "gitlab",
    "harbor":                  "harbor",
    "keycloak":                "keycloak",
    "roundcube":               "roundcube",
    # SSH
    "openssh":                 "openssh",
    "dropbear":                "dropbear",
    "bitvise":                 "bitvise-ssh",
    # RDP / VNC
    "microsoft terminal":      "windows-rdp",
    "microsoft windows rdp":   "windows-rdp",
    "xrdp":                    "xrdp",
    "realvnc":                 "realvnc",
    "tigervnc":                "tigervnc",
    "tightvnc":                "tightvnc",
    "vnc":                     "vnc",
    # Databases
    "mysql":                   "mysql",
    "mariadb":                 "mariadb",
    "postgresql":              "postgresql",
    "microsoft sql server":    "mssql",
    "microsoft sql":           "mssql",
    "redis":                   "redis",
    "mongodb":                 "mongodb",
    "couchdb":                 "couchdb",
    "cassandra":               "cassandra",
    "influxdb":                "influxdb",
    # FTP
    "vsftpd":                  "vsftpd",
    "proftpd":                 "proftpd",
    "filezilla":               "filezilla-ftp",
    "pure-ftpd":               "pure-ftpd",
    # SMTP
    "postfix":                 "postfix",
    "exim":                    "exim",
    "sendmail":                "sendmail",
    "microsoft exchange":      "exchange",
    "microsoft esmtp":         "exchange",
    "hmail":                   "hmail",
    "dovecot":                 "dovecot",
    # SMB / AD
    "samba":                   "samba",
    "microsoft windows smb":   "windows-smb",
    "microsoft smb":           "windows-smb",
    # DNS
    "bind":                    "bind",
    "dnsmasq":                 "dnsmasq",
    "microsoft dns":           "windows-dns",
    "powerdns":                "powerdns",
    # Printing
    "cups":                    "cups",
    # SNMP
    "net-snmp":                "net-snmp",
    "snmpd":                   "snmpd",
    # Other
    "openssl":                 "",    # Not a product; will fall back to service label
    "telnetd":                 "telnetd",
}
# Pre-sort by key length descending so longest prefix wins
_PRODUCT_LABEL_MAP = dict(
    sorted(_PRODUCT_LABEL_MAP.items(), key=lambda kv: -len(kv[0]))
)


def _normalize_product(product: str) -> str:
    """Normalize an nmap product string to a short lowercase identifier.

    Returns an empty string when the product is unknown or uninformative,
    in which case the caller should fall back to the bare service label.
    """
    if not product:
        return ""
    p = product.lower().strip()
    # Strip trailing noise: version numbers, parenthetical OS qualifiers
    p = re.sub(r'\s*\([^)]*\)\s*$', '', p)   # e.g. "(Ubuntu)"
    p = re.sub(r'[\s/]\d[\d.]*.*$', '', p)    # e.g. " 2.4.51"
    p = p.strip()
    for prefix, label in _PRODUCT_LABEL_MAP.items():
        if p.startswith(prefix):
            return label
    # Generic normalisation: lower, collapse whitespace → hyphens, cap length
    p = re.sub(r'\s+', '-', p)
    return p[:24] if p else ""


def _svc_key(tool: str, args, services: list) -> str:
    """Derive a product-qualified service key from action context.

    Format: "<product>/<protocol>" when the server software is known
    (e.g. "nginx/http", "openssh/ssh", "mssql/mssql"), otherwise just the
    protocol label (e.g. "http", "ssh").  Port numbers are intentionally
    excluded — the KB tracks *what works against which infrastructure*, not
    against which port number a service happened to run on during one scan.
    """
    if tool in _TOOL_SVC_DIRECT:
        return _TOOL_SVC_DIRECT[tool]

    # Try to match port from URL/host args to a discovered service
    url = ""
    if isinstance(args, dict):
        url = args.get("url", "") or args.get("host", "")
    elif isinstance(args, str):
        url = args

    port_m = re.search(r":(\d+)", str(url))
    if port_m and services:
        port = port_m.group(1)
        for svc in services:
            if str(svc.get("port", "")) == port:
                raw        = svc.get("name", "").lower()
                protocol   = _SVC_KEY_MAP.get(raw, raw.split("/")[-1] or "unknown")
                product    = _normalize_product(svc.get("product", ""))
                if product:
                    return f"{product}/{protocol}"
                return protocol

    # No port match — fall back to tool's default service type
    return _TOOL_SVC_FALLBACK.get(tool, "unknown")


_PORT_KEY_RE = re.compile(r'^\d+/(.+)$')


def _migrate_tool_kb_v1(kb: dict) -> dict:
    """Migrate v1 port-keyed entries (e.g. '5000/http') to bare service labels ('http').

    Entries with the same post-migration key are merged by summing counters and
    recalculating derived rates.  The migrated KB is written back to disk immediately.
    """
    changed = False
    for tool, svcs in list(kb.items()):
        if tool.startswith("_") or not isinstance(svcs, dict):
            continue
        merged: dict = {}
        for key, stats in svcs.items():
            m = _PORT_KEY_RE.match(key)
            new_key = m.group(1) if m else key
            if new_key not in merged:
                merged[new_key] = dict(stats)
            else:
                # Merge: sum counters, recalculate rates
                slot = merged[new_key]
                slot["runs"]             = slot.get("runs", 0)             + stats.get("runs", 0)
                slot["findings_yielded"] = slot.get("findings_yielded", 0) + stats.get("findings_yielded", 0)
                slot["total_findings"]   = slot.get("total_findings", 0)   + stats.get("total_findings", 0)
                slot["broken_count"]     = slot.get("broken_count", 0)     + stats.get("broken_count", 0)
                slot["timed_out_count"]  = slot.get("timed_out_count", 0)  + stats.get("timed_out_count", 0)
                runs = slot["runs"]
                slot["success_rate"]         = round(slot["findings_yielded"] / runs, 3) if runs else 0.0
                slot["avg_findings_per_run"] = round(slot["total_findings"]   / runs, 2) if runs else 0.0
                # Keep the most recent last_run
                if stats.get("last_run", "") > slot.get("last_run", ""):
                    slot["last_run"] = stats["last_run"]
            if new_key != key:
                changed = True
        kb[tool] = merged
    if changed:
        kb.setdefault("_meta", {})["version"] = 2
        print("[*] Tool KB migrated from v1 (port-keyed) to v2 (product/service-keyed)")
    return kb


def _load_tool_manifest() -> dict:
    """Lazy-load tool_manifest.json.  Returns {} if the file is absent.

    The manifest is a subscriber artifact delivered via update.sh step 11.
    Free users will see a one-time advisory at scan start; the scanner
    degrades gracefully to rule-based defaults (curl catch-all).
    """
    global _TOOL_MANIFEST
    if _TOOL_MANIFEST is not None:
        return _TOOL_MANIFEST
    if not os.path.exists(TOOL_MANIFEST_PATH):
        _TOOL_MANIFEST = {}
        return _TOOL_MANIFEST
    try:
        with open(TOOL_MANIFEST_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        # Drop the _meta sentinel so callers only iterate real tool entries
        tool_count = sum(1 for k in data if not k.startswith("_"))
        _TOOL_MANIFEST = data
        print(f"[+] Tool manifest loaded \u2014 {tool_count} tool(s) ({TOOL_MANIFEST_PATH})")
    except Exception as e:
        print(f"[!] Tool manifest load error ({e}) \u2014 falling back to built-in service routing.")
        _TOOL_MANIFEST = {}
    return _TOOL_MANIFEST


def _validate_manifest_coverage(all_tool_names: list) -> None:
    """Warn about tools in all_tool_names that have no manifest entry.

    Called once at scan start after the manifest is loaded.  Helps operators
    identify gaps so they can run scripts/add_tool_manifest.py.
    """
    manifest = _load_tool_manifest()
    if not manifest:
        print(
            "[*] No tool_manifest.json found.  Service routing will use built-in rules.\n"
            "    To improve routing for unusual services, subscribe at:\n"
            "    https://noctisedge.lemonsqueezy.com  (KB_LICENSE_KEY in noctis.conf)\n"
            "    or generate a local manifest:  python3 scripts/build_tool_manifest.py"
        )
        return
    missing = [t for t in all_tool_names if t not in manifest]
    if missing:
        print(f"[*] Manifest missing entries for: {', '.join(missing)} "
              f"\u2014 run scripts/add_tool_manifest.py to add them.")


def _load_tool_kb() -> dict:
    """Load the persistent tool knowledge base, returning seed dict on missing/corrupt file.

    Automatically migrates v1 port-keyed entries (e.g. '5000/http') to the v2
    product/service scheme (e.g. 'nginx/http' or bare 'http') on first load.
    """
    if not os.path.exists(TOOL_KB_PATH):
        return {"_meta": {"version": 2}}
    try:
        with open(TOOL_KB_PATH, "r", encoding="utf-8") as fh:
            kb = json.load(fh)
    except Exception as e:
        print(f"[!] Tool KB load error ({e}) — starting with empty KB.")
        return {"_meta": {"version": 2}}
    # Migrate v1 → v2 if needed
    if kb.get("_meta", {}).get("version", 1) < 2:
        kb = _migrate_tool_kb_v1(kb)
        _save_tool_kb(kb)
    return kb


def _save_tool_kb(kb: dict):
    """Write the tool knowledge base to disk.

    Attempts an atomic rename first; falls back to shutil.copy2 when running
    inside Docker where the file is a bind-mounted inode (a separate mount
    point) and rename(2) would fail with EXDEV.
    """
    tmp = TOOL_KB_PATH + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(kb, fh, indent=2, default=str)
        try:
            os.replace(tmp, TOOL_KB_PATH)
        except OSError:
            # Docker file bind-mounts are separate mount points; rename(2)
            # across a mount boundary fails with EXDEV.  copy2 opens the
            # existing inode for writing, preserving the bind-mount link.
            shutil.copy2(tmp, TOOL_KB_PATH)
            os.unlink(tmp)
    except Exception as e:
        print(f"[!] Tool KB save error: {e}")


def _record_tool_outcome(tool_kb: dict, tool: str, svc_key: str,
                          findings_count: int, broken: bool, timed_out: bool):
    """Update in-memory tool KB with the outcome of a single tool run."""
    tool_entry = tool_kb.setdefault(tool, {})
    slot = tool_entry.setdefault(svc_key, {
        "runs":                0,
        "findings_yielded":    0,
        "total_findings":      0,
        "success_rate":        0.0,
        "avg_findings_per_run": 0.0,
        "broken_count":        0,
        "timed_out_count":     0,
        "last_run":            "",
    })
    slot["runs"]           += 1
    slot["total_findings"] += max(0, findings_count)
    if findings_count > 0:
        slot["findings_yielded"] += 1
    if broken:
        slot["broken_count"]     += 1
    if timed_out and not broken:
        slot["timed_out_count"]  += 1
    slot["success_rate"]         = round(slot["findings_yielded"] / slot["runs"], 3)
    slot["avg_findings_per_run"] = round(slot["total_findings"]   / slot["runs"], 2)
    slot["last_run"] = datetime.now(timezone.utc).isoformat()


def _tool_kb_summary(tool_kb: dict) -> str:
    """Return a compact text block of tool success rates for LLM prompt injection.

    Two sections:
      1. Per-tool breakdown (success rate per port/service it has been run against)
      2. Best-tool-per-service ranking (what to use when a given port is seen open)
    """
    # Build: { svc_key → [(tool, stats), ...] } for the per-service ranking
    svc_tools: dict = {}
    tool_lines: list = []

    for tool in sorted(tool_kb.keys()):
        if tool.startswith("_"):
            continue
        svcs = tool_kb[tool]
        if not isinstance(svcs, dict):
            continue
        parts = []
        for svc, stats in sorted(svcs.items(), key=lambda x: -x[1].get("success_rate", 0)):
            runs = stats.get("runs", 0)
            if runs < 1:
                continue
            rate = stats.get("success_rate", 0.0)
            avg  = stats.get("avg_findings_per_run", 0.0)
            to   = stats.get("timed_out_count", 0)
            suffix = f",{to}to" if to else ""
            parts.append(f"{svc}:{rate:.0%}({runs}r,{avg:.1f}f{suffix})")
            # Accumulate for per-service rankings
            svc_tools.setdefault(svc, []).append((tool, rate, avg, runs))
        if parts:
            tool_lines.append(f"  {tool:14} → {', '.join(parts)}")

    if not tool_lines:
        return ""

    # Per-service rankings: best tool first by success_rate then avg findings
    svc_lines: list = []
    for svc in sorted(svc_tools.keys()):
        ranked = sorted(svc_tools[svc], key=lambda x: (-x[1], -x[2]))
        entries = ", ".join(
            f"{t}:{r:.0%}({n}r)" for t, r, _, n in ranked
        )
        svc_lines.append(f"  {svc:16} → {entries}")

    blocks = ["TOOL KB — per-tool success rates (product/service, prior scans):"]
    blocks += tool_lines
    blocks += ["", "TOOL KB — best tools per service/infrastructure type:"]
    blocks += svc_lines
    return "\n".join(blocks)


# ===========================================================================
# SERVICE HEALTH CHECKS
# Parse NSE output already collected during nmap Phase 3 into structured
# Finding objects, covering low-hanging-fruit misconfigurations that a
# security tester would flag before any CVE lookup.
# ===========================================================================

def _hc_finding(svc: dict, target: str, title: str, severity: str,
                evidence: str, vuln_type: str = "Configuration Issue",
                cwe_id: str = "", tags: list | None = None) -> Finding:
    """Construct a health-check Finding with consistent defaults."""
    port    = svc.get("port", "?")
    svcname = svc.get("name", "unknown")
    product = svc.get("product", "")
    version = svc.get("version", "")
    label   = f"{product} {version}".strip() or svcname
    sev_score = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}
    score = sev_score.get(severity, 2.5)
    return Finding(
        finding_id          = make_finding_id("svc_health", f"{target}:{port}", title),
        tool                = "svc_health",
        target              = f"{target}:{port}",
        service             = svcname,
        severity            = severity,
        title               = title,
        evidence            = evidence,
        confidence          = 0.9,
        verified            = True,
        timestamp           = datetime.now(timezone.utc).isoformat(),
        tags                = (tags or []) + ["health_check", "config", svcname],
        cvss_score          = score,
        risk_score          = score,
        vuln_type           = vuln_type,
        cwe_id              = cwe_id,
        cmd                 = f"nmap NSE / svc_health probe on port {port}",
        description         = f"{label} on port {port}",
    )


def _hc_ssh(target: str, port: str, svc: dict) -> list:
    """Check SSH configuration from NSE output."""
    findings = []
    nse: dict = svc.get("nse_output", {})
    nse_sum: str = svc.get("nse_summary", "").lower()

    # --- Auth methods ---------------------------------------------------------
    auth_raw = nse.get("ssh-auth-methods", "") or ""
    if "password" in auth_raw.lower() or "keyboard-interactive" in auth_raw.lower():
        findings.append(_hc_finding(
            svc, target,
            title    = "SSH password authentication enabled",
            severity = "high",
            evidence = f"ssh-auth-methods: {auth_raw.strip()[:200]}",
            vuln_type= "Weak Authentication",
            cwe_id   = "CWE-521",
            tags     = ["ssh", "auth"],
        ))

    # --- Weak key-exchange algorithms -----------------------------------------
    algos_raw = nse.get("ssh2-enum-algos", "") or ""
    algos_low = algos_raw.lower()
    weak_kex  = [k for k in ("diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
                              "diffie-hellman-group-exchange-sha1")
                 if k in algos_low]
    if weak_kex:
        findings.append(_hc_finding(
            svc, target,
            title    = "SSH weak Diffie-Hellman key-exchange in use",
            severity = "medium",
            evidence = f"Weak kex detected: {', '.join(weak_kex)}",
            vuln_type= "Weak Cryptography",
            cwe_id   = "CWE-327",
            tags     = ["ssh", "crypto"],
        ))

    # --- CBC ciphers ----------------------------------------------------------
    weak_ciphers = [c for c in ("aes128-cbc", "aes192-cbc", "aes256-cbc",
                                 "3des-cbc", "blowfish-cbc", "cast128-cbc",
                                 "arcfour", "arcfour128", "arcfour256")
                    if c in algos_low]
    if weak_ciphers:
        findings.append(_hc_finding(
            svc, target,
            title    = "SSH weak cipher suite in use",
            severity = "medium",
            evidence = f"Weak ciphers: {', '.join(weak_ciphers[:4])}",
            vuln_type= "Weak Cryptography",
            cwe_id   = "CWE-327",
            tags     = ["ssh", "crypto"],
        ))

    # --- Weak MACs ------------------------------------------------------------
    weak_macs = [m for m in ("hmac-md5", "hmac-sha1-96", "hmac-md5-96",
                              "hmac-sha1")
                 if m in algos_low and "hmac-sha1-etm" not in algos_low]
    if weak_macs:
        findings.append(_hc_finding(
            svc, target,
            title    = "SSH weak MAC algorithm in use",
            severity = "low",
            evidence = f"Weak MACs: {', '.join(weak_macs[:4])}",
            vuln_type= "Weak Cryptography",
            cwe_id   = "CWE-327",
            tags     = ["ssh", "crypto"],
        ))

    # --- Weak host key --------------------------------------------------------
    hostkey_raw = (nse.get("ssh-hostkey", "") or "").lower()
    if "1024" in hostkey_raw and "rsa" in hostkey_raw:
        findings.append(_hc_finding(
            svc, target,
            title    = "SSH RSA host key is weak (< 2048 bits)",
            severity = "high",
            evidence = f"ssh-hostkey: {hostkey_raw.strip()[:200]}",
            vuln_type= "Weak Cryptography",
            cwe_id   = "CWE-326",
            tags     = ["ssh", "crypto"],
        ))

    return findings


def _hc_http(target: str, port: str, svc: dict) -> list:
    """Check HTTP/HTTPS service configuration from NSE output."""
    findings = []
    nse: dict = svc.get("nse_output", {})
    is_tls    = any(k in svc.get("name", "").lower() for k in ("ssl", "https"))

    # --- Dangerous HTTP methods -----------------------------------------------
    methods_raw = (nse.get("http-methods", "") or "").upper()
    for method, sev in [("PUT", "high"), ("DELETE", "high"), ("TRACE", "medium"), ("TRACK", "medium")]:
        if re.search(rf'\b{method}\b', methods_raw):
            findings.append(_hc_finding(
                svc, target,
                title    = f"HTTP {method} method enabled",
                severity = sev,
                evidence = f"http-methods: {methods_raw[:200]}",
                vuln_type= "Dangerous HTTP Method",
                cwe_id   = "CWE-650",
                tags     = ["http", "method"],
            ))

    # --- Basic auth over plain HTTP -------------------------------------------
    auth_raw = (nse.get("http-auth-finder", "") or "").lower()
    if "basic" in auth_raw and not is_tls:
        findings.append(_hc_finding(
            svc, target,
            title    = "HTTP Basic Auth over cleartext (credentials exposed)",
            severity = "high",
            evidence = f"http-auth-finder: {auth_raw.strip()[:200]}",
            vuln_type= "Cleartext Credentials",
            cwe_id   = "CWE-319",
            tags     = ["http", "auth"],
        ))

    # --- Security headers -----------------------------------------------------
    sec_raw = (nse.get("http-security-headers", "") or nse.get("http-headers", "") or "").lower()
    if sec_raw:
        header_checks = [
            ("strict-transport-security",  "Missing HSTS header",                "medium", "CWE-319"),
            ("x-frame-options",            "Missing X-Frame-Options header",      "medium", "CWE-1021"),
            ("content-security-policy",    "Missing Content-Security-Policy",     "medium", "CWE-693"),
            ("x-content-type-options",     "Missing X-Content-Type-Options",      "low",    "CWE-693"),
        ]
        for header, title, sev, cwe in header_checks:
            # Only flag HSTS on TLS services
            if header == "strict-transport-security" and not is_tls:
                continue
            if header not in sec_raw:
                findings.append(_hc_finding(
                    svc, target,
                    title    = title,
                    severity = sev,
                    evidence = "Header absent from NSE http-security-headers output",
                    vuln_type= "Missing Security Header",
                    cwe_id   = cwe,
                    tags     = ["http", "headers"],
                ))

    # --- TLS-specific: cipher suites and protocol versions --------------------
    ssl_raw = (nse.get("ssl-enum-ciphers", "") or "").lower()
    if ssl_raw:
        if "sslv2" in ssl_raw or "ssl 2" in ssl_raw:
            findings.append(_hc_finding(
                svc, target,
                title    = "SSLv2 enabled (critically deprecated)",
                severity = "critical",
                evidence = ssl_raw[:300],
                vuln_type= "Weak Cryptography",
                cwe_id   = "CWE-326",
                tags     = ["tls", "crypto"],
            ))
        elif "sslv3" in ssl_raw or "ssl 3" in ssl_raw:
            findings.append(_hc_finding(
                svc, target,
                title    = "SSLv3 enabled (POODLE risk)",
                severity = "high",
                evidence = ssl_raw[:300],
                vuln_type= "Weak Cryptography",
                cwe_id   = "CWE-326",
                tags     = ["tls", "crypto"],
            ))
        if "tlsv1.0" in ssl_raw or "tls 1.0" in ssl_raw:
            findings.append(_hc_finding(
                svc, target,
                title    = "TLS 1.0 enabled (deprecated)",
                severity = "medium",
                evidence = ssl_raw[:300],
                vuln_type= "Weak Cryptography",
                cwe_id   = "CWE-326",
                tags     = ["tls", "crypto"],
            ))
        elif "tlsv1.1" in ssl_raw or "tls 1.1" in ssl_raw:
            findings.append(_hc_finding(
                svc, target,
                title    = "TLS 1.1 enabled (deprecated)",
                severity = "medium",
                evidence = ssl_raw[:300],
                vuln_type= "Weak Cryptography",
                cwe_id   = "CWE-326",
                tags     = ["tls", "crypto"],
            ))
        weak_ciphers = []
        for bad in ("null", "_export_", "_rc4_", "_des_", "_3des_", "anon"):
            if bad in ssl_raw:
                weak_ciphers.append(bad.strip("_").upper())
        if weak_ciphers:
            findings.append(_hc_finding(
                svc, target,
                title    = f"Weak TLS cipher suite in use: {', '.join(set(weak_ciphers))}",
                severity = "high",
                evidence = ssl_raw[:300],
                vuln_type= "Weak Cryptography",
                cwe_id   = "CWE-326",
                tags     = ["tls", "crypto"],
            ))

    # --- TLS certificate issues -----------------------------------------------
    cert_raw = nse.get("ssl-cert", "") or ""
    if cert_raw:
        # Self-signed: subject == issuer
        sub_m  = re.search(r'Subject:(.+)', cert_raw, re.IGNORECASE)
        iss_m  = re.search(r'Issuer:(.+)',  cert_raw, re.IGNORECASE)
        if sub_m and iss_m and sub_m.group(1).strip() == iss_m.group(1).strip():
            findings.append(_hc_finding(
                svc, target,
                title    = "TLS certificate is self-signed",
                severity = "medium",
                evidence = cert_raw[:300],
                vuln_type= "Certificate Issue",
                cwe_id   = "CWE-295",
                tags     = ["tls", "cert"],
            ))
        # Expiry
        exp_m = re.search(r'Not valid after:\s*(.+)', cert_raw, re.IGNORECASE)
        if exp_m:
            try:
                from datetime import datetime as _dt
                exp_str = exp_m.group(1).strip()
                exp_dt  = _dt.strptime(exp_str[:19], "%Y-%m-%dT%H:%M:%S")
                days_left = (exp_dt - _dt.utcnow()).days
                if days_left < 0:
                    findings.append(_hc_finding(
                        svc, target,
                        title    = "TLS certificate has expired",
                        severity = "high",
                        evidence = f"Expired {-days_left} day(s) ago: {exp_str}",
                        vuln_type= "Certificate Issue",
                        cwe_id   = "CWE-298",
                        tags     = ["tls", "cert"],
                    ))
                elif days_left <= 7:
                    findings.append(_hc_finding(
                        svc, target,
                        title    = f"TLS certificate expires in {days_left} day(s)",
                        severity = "high",
                        evidence = f"Expiry: {exp_str}",
                        vuln_type= "Certificate Issue",
                        cwe_id   = "CWE-298",
                        tags     = ["tls", "cert"],
                    ))
                elif days_left <= 30:
                    findings.append(_hc_finding(
                        svc, target,
                        title    = f"TLS certificate expiring soon ({days_left} days)",
                        severity = "medium",
                        evidence = f"Expiry: {exp_str}",
                        vuln_type= "Certificate Issue",
                        cwe_id   = "CWE-298",
                        tags     = ["tls", "cert"],
                    ))
            except Exception:
                pass

    return findings


def _hc_ftp(target: str, port: str, svc: dict) -> list:
    """Check FTP configuration from NSE output."""
    findings = []
    nse: dict = svc.get("nse_output", {})

    # Cleartext protocol — always flag
    findings.append(_hc_finding(
        svc, target,
        title    = "FTP uses cleartext protocol — credentials unencrypted",
        severity = "medium",
        evidence = f"FTP service detected on port {port}. Use SFTP or FTPS instead.",
        vuln_type= "Cleartext Credentials",
        cwe_id   = "CWE-319",
        tags     = ["ftp"],
    ))

    # Anonymous login
    anon_raw = (nse.get("ftp-anon", "") or "").lower()
    if "anonymous" in anon_raw and "login allowed" in anon_raw:
        findings.append(_hc_finding(
            svc, target,
            title    = "FTP anonymous login accepted",
            severity = "high",
            evidence = nse.get("ftp-anon", "")[:300],
            vuln_type= "Weak Authentication",
            cwe_id   = "CWE-306",
            tags     = ["ftp", "auth"],
        ))

    # FTP bounce
    bounce_raw = (nse.get("ftp-bounce", "") or "").lower()
    if "bounce working" in bounce_raw or "server sent address" in bounce_raw:
        findings.append(_hc_finding(
            svc, target,
            title    = "FTP bounce attack possible",
            severity = "medium",
            evidence = nse.get("ftp-bounce", "")[:200],
            vuln_type= "FTP Bounce",
            cwe_id   = "CWE-441",
            tags     = ["ftp"],
        ))

    return findings


def _hc_smtp(target: str, port: str, svc: dict) -> list:
    """Check SMTP configuration from NSE output."""
    findings = []
    nse: dict = svc.get("nse_output", {})

    # Open relay
    relay_raw = (nse.get("smtp-open-relay", "") or "").lower()
    if "server is an open relay" in relay_raw or "open relay" in relay_raw:
        findings.append(_hc_finding(
            svc, target,
            title    = "SMTP open relay detected",
            severity = "critical",
            evidence = nse.get("smtp-open-relay", "")[:300],
            vuln_type= "Email Relay",
            cwe_id   = "CWE-183",
            tags     = ["smtp", "relay"],
        ))

    # VRFY / EXPN user enumeration
    cmds_raw = (nse.get("smtp-commands", "") or "").upper()
    if "VRFY" in cmds_raw:
        findings.append(_hc_finding(
            svc, target,
            title    = "SMTP VRFY command enabled (user enumeration risk)",
            severity = "medium",
            evidence = f"SMTP EHLO response includes: VRFY\n{cmds_raw[:200]}",
            vuln_type= "Information Disclosure",
            cwe_id   = "CWE-200",
            tags     = ["smtp", "enum"],
        ))
    if "EXPN" in cmds_raw:
        findings.append(_hc_finding(
            svc, target,
            title    = "SMTP EXPN command enabled (mailing list disclosure)",
            severity = "medium",
            evidence = f"SMTP EHLO response includes: EXPN\n{cmds_raw[:200]}",
            vuln_type= "Information Disclosure",
            cwe_id   = "CWE-200",
            tags     = ["smtp", "enum"],
        ))

    # No STARTTLS
    if cmds_raw and "STARTTLS" not in cmds_raw:
        findings.append(_hc_finding(
            svc, target,
            title    = "SMTP STARTTLS not advertised (credentials sent cleartext)",
            severity = "high",
            evidence = f"STARTTLS absent from EHLO commands: {cmds_raw[:200]}",
            vuln_type= "Cleartext Credentials",
            cwe_id   = "CWE-319",
            tags     = ["smtp", "tls"],
        ))

    # Users found
    enum_raw = (nse.get("smtp-enum-users", "") or "").strip()
    if enum_raw and len(enum_raw) > 10:
        findings.append(_hc_finding(
            svc, target,
            title    = "SMTP user enumeration confirmed",
            severity = "high",
            evidence = enum_raw[:300],
            vuln_type= "Information Disclosure",
            cwe_id   = "CWE-200",
            tags     = ["smtp", "enum"],
        ))

    return findings


def _hc_smb(target: str, port: str, svc: dict) -> list:
    """Check SMB configuration from NSE output."""
    findings = []
    nse: dict = svc.get("nse_output", {})

    # SMBv1
    sec_raw = (nse.get("smb-security-mode", "") or "").lower()
    smb2_raw = (nse.get("smb2-security-mode", "") or "").lower()

    if "smb1_enabled: true" in sec_raw or ("smb" in sec_raw and "message_signing" in sec_raw and "smb2" not in sec_raw):
        findings.append(_hc_finding(
            svc, target,
            title    = "SMBv1 protocol enabled (EternalBlue/WannaCry risk)",
            severity = "critical",
            evidence = nse.get("smb-security-mode", "")[:300],
            vuln_type= "Legacy Protocol",
            cwe_id   = "CWE-1188",
            tags     = ["smb"],
        ))

    # SMB signing
    if "message_signing: disabled" in sec_raw or "signing: disabled" in sec_raw:
        findings.append(_hc_finding(
            svc, target,
            title    = "SMB signing disabled (relay attack risk)",
            severity = "high",
            evidence = nse.get("smb-security-mode", "")[:300],
            vuln_type= "Weak Authentication",
            cwe_id   = "CWE-347",
            tags     = ["smb"],
        ))
    elif "signing: optional" in smb2_raw:
        findings.append(_hc_finding(
            svc, target,
            title    = "SMB2 signing not enforced",
            severity = "medium",
            evidence = nse.get("smb2-security-mode", "")[:200],
            vuln_type= "Weak Authentication",
            cwe_id   = "CWE-347",
            tags     = ["smb"],
        ))

    # Shares / null session
    shares_raw = (nse.get("smb-enum-shares", "") or "").lower()
    if "access: read/write" in shares_raw or "read/write" in shares_raw:
        # Check for admin shares
        for share in ("admin$", "c$", "d$"):
            if share in shares_raw:
                findings.append(_hc_finding(
                    svc, target,
                    title    = f"SMB admin share accessible ({share.upper()})",
                    severity = "critical",
                    evidence = nse.get("smb-enum-shares", "")[:300],
                    vuln_type= "Weak Access Control",
                    cwe_id   = "CWE-284",
                    tags     = ["smb", "shares"],
                ))
    if "anonymous" in shares_raw or "guest" in shares_raw:
        findings.append(_hc_finding(
            svc, target,
            title    = "SMB null/guest session access allowed",
            severity = "high",
            evidence = nse.get("smb-enum-shares", "")[:300],
            vuln_type= "Weak Authentication",
            cwe_id   = "CWE-306",
            tags     = ["smb", "auth"],
        ))

    return findings


def _hc_mysql(target: str, port: str, svc: dict) -> list:
    """Check MySQL configuration from NSE output."""
    findings = []
    nse: dict = svc.get("nse_output", {})

    empty_raw = (nse.get("mysql-empty-password", "") or "").lower()
    if "root account has empty password" in empty_raw or "empty password" in empty_raw:
        findings.append(_hc_finding(
            svc, target,
            title    = "MySQL root account has empty password",
            severity = "critical",
            evidence = nse.get("mysql-empty-password", "")[:300],
            vuln_type= "Weak Authentication",
            cwe_id   = "CWE-521",
            tags     = ["mysql", "auth"],
        ))

    enum_raw = (nse.get("mysql-enum", "") or nse.get("mysql-info", "") or "").strip()
    if enum_raw and len(enum_raw) > 20:
        findings.append(_hc_finding(
            svc, target,
            title    = "MySQL information exposed without authentication",
            severity = "high",
            evidence = enum_raw[:300],
            vuln_type= "Information Disclosure",
            cwe_id   = "CWE-200",
            tags     = ["mysql"],
        ))

    return findings


def _hc_mssql(target: str, port: str, svc: dict) -> list:
    """Check MSSQL configuration from NSE output."""
    findings = []
    nse: dict = svc.get("nse_output", {})

    empty_raw = (nse.get("ms-sql-empty-password", "") or "").lower()
    if "empty password" in empty_raw or "sa account" in empty_raw:
        findings.append(_hc_finding(
            svc, target,
            title    = "MSSQL SA account has empty password",
            severity = "critical",
            evidence = nse.get("ms-sql-empty-password", "")[:300],
            vuln_type= "Weak Authentication",
            cwe_id   = "CWE-521",
            tags     = ["mssql", "auth"],
        ))

    config_raw = (nse.get("ms-sql-config", "") or "").strip()
    if config_raw and len(config_raw) > 20:
        findings.append(_hc_finding(
            svc, target,
            title    = "MSSQL configuration exposed without authentication",
            severity = "high",
            evidence = config_raw[:300],
            vuln_type= "Information Disclosure",
            cwe_id   = "CWE-200",
            tags     = ["mssql"],
        ))

    return findings


def _hc_rdp(target: str, port: str, svc: dict) -> list:
    """Check RDP configuration from NSE output."""
    findings = []
    nse: dict = svc.get("nse_output", {})

    enc_raw = (nse.get("rdp-enum-encryption", "") or "").lower()
    if enc_raw:
        if "nla: not required" in enc_raw or "nla_not_required" in enc_raw or "credssp" not in enc_raw:
            findings.append(_hc_finding(
                svc, target,
                title    = "RDP Network Level Authentication (NLA) not required",
                severity = "high",
                evidence = nse.get("rdp-enum-encryption", "")[:300],
                vuln_type= "Weak Authentication",
                cwe_id   = "CWE-287",
                tags     = ["rdp", "auth"],
            ))
        if "encryption level: none" in enc_raw or "encryption_method_none" in enc_raw:
            findings.append(_hc_finding(
                svc, target,
                title    = "RDP encryption not enforced",
                severity = "high",
                evidence = nse.get("rdp-enum-encryption", "")[:300],
                vuln_type= "Cleartext Credentials",
                cwe_id   = "CWE-319",
                tags     = ["rdp", "crypto"],
            ))

    return findings


def _hc_vnc(target: str, port: str, svc: dict) -> list:
    """Check VNC configuration from NSE output."""
    findings = []
    nse: dict = svc.get("nse_output", {})

    vnc_raw = (nse.get("vnc-info", "") or "").lower()
    if "none" in vnc_raw and "auth" in vnc_raw:
        findings.append(_hc_finding(
            svc, target,
            title    = "VNC authentication disabled",
            severity = "critical",
            evidence = nse.get("vnc-info", "")[:300],
            vuln_type= "Weak Authentication",
            cwe_id   = "CWE-306",
            tags     = ["vnc", "auth"],
        ))
    elif "protocol version: 3.3" in vnc_raw:
        findings.append(_hc_finding(
            svc, target,
            title    = "Legacy VNC protocol version 3.3 in use",
            severity = "high",
            evidence = nse.get("vnc-info", "")[:300],
            vuln_type= "Legacy Protocol",
            cwe_id   = "CWE-1188",
            tags     = ["vnc"],
        ))

    return findings


def _hc_dns(target: str, port: str, svc: dict) -> list:
    """Check DNS configuration from NSE output."""
    findings = []
    nse: dict = svc.get("nse_output", {})

    zt_raw = (nse.get("dns-zone-transfer", "") or "").strip()
    if zt_raw and len(zt_raw) > 20 and "error" not in zt_raw.lower():
        findings.append(_hc_finding(
            svc, target,
            title    = "DNS zone transfer allowed (full record set exposed)",
            severity = "high",
            evidence = zt_raw[:300],
            vuln_type= "Information Disclosure",
            cwe_id   = "CWE-200",
            tags     = ["dns", "enum"],
        ))

    return findings


def _hc_ldap(target: str, port: str, svc: dict) -> list:
    """Check LDAP configuration from NSE output."""
    findings = []
    nse: dict = svc.get("nse_output", {})

    rootdse_raw = (nse.get("ldap-rootdse", "") or "").strip()
    if rootdse_raw and len(rootdse_raw) > 20:
        findings.append(_hc_finding(
            svc, target,
            title    = "Anonymous LDAP bind exposes directory information",
            severity = "medium",
            evidence = rootdse_raw[:300],
            vuln_type= "Information Disclosure",
            cwe_id   = "CWE-200",
            tags     = ["ldap", "auth"],
        ))

    return findings


def _hc_snmp(target: str, port: str, svc: dict) -> list:
    """Check SNMP configuration from NSE output."""
    findings = []
    nse: dict = svc.get("nse_output", {})

    brute_raw = (nse.get("snmp-brute", "") or "").lower()
    if "valid credentials" in brute_raw or "public" in brute_raw:
        findings.append(_hc_finding(
            svc, target,
            title    = "SNMP default community string 'public' accepted",
            severity = "high",
            evidence = nse.get("snmp-brute", "")[:300],
            vuln_type= "Weak Authentication",
            cwe_id   = "CWE-521",
            tags     = ["snmp", "auth"],
        ))

    info_raw = (nse.get("snmp-sysdescr", "") or nse.get("snmp-info", "") or "").strip()
    if info_raw and len(info_raw) > 10:
        findings.append(_hc_finding(
            svc, target,
            title    = "SNMP exposes system information without authentication",
            severity = "medium",
            evidence = info_raw[:300],
            vuln_type= "Information Disclosure",
            cwe_id   = "CWE-200",
            tags     = ["snmp"],
        ))

    return findings


def _hc_telnet(target: str, port: str, svc: dict) -> list:
    """Check Telnet — presence alone is a finding."""
    findings = []
    nse: dict = svc.get("nse_output", {})
    enc_raw = (nse.get("telnet-encryption", "") or "").lower()
    sev = "critical" if enc_raw and "encryption not" in enc_raw else "high"
    findings.append(_hc_finding(
        svc, target,
        title    = "Telnet service enabled (cleartext remote access)",
        severity = sev,
        evidence = f"Telnet detected on port {port}. Replace with SSH.",
        vuln_type= "Cleartext Credentials",
        cwe_id   = "CWE-319",
        tags     = ["telnet"],
    ))
    return findings


def _hc_email_plaintext(target: str, port: str, svc: dict) -> list:
    """Check POP3 / IMAP for STARTTLS."""
    findings = []
    nse: dict = svc.get("nse_output", {})
    svcname   = svc.get("name", "").lower()

    cap_key = "pop3-capabilities" if "pop3" in svcname else "imap-capabilities"
    caps_raw = (nse.get(cap_key, "") or "").upper()
    if caps_raw and "STLS" not in caps_raw and "STARTTLS" not in caps_raw:
        findings.append(_hc_finding(
            svc, target,
            title    = f"{svcname.upper()} STARTTLS not available (credentials sent cleartext)",
            severity = "high",
            evidence = f"{cap_key}: {caps_raw[:200]}",
            vuln_type= "Cleartext Credentials",
            cwe_id   = "CWE-319",
            tags     = [svcname, "tls"],
        ))
    if caps_raw and ("AUTH=PLAIN" in caps_raw or "AUTH=LOGIN" in caps_raw) and "STLS" not in caps_raw:
        findings.append(_hc_finding(
            svc, target,
            title    = f"{svcname.upper()} advertises plaintext auth without STARTTLS",
            severity = "high",
            evidence = f"{cap_key}: {caps_raw[:200]}",
            vuln_type= "Cleartext Credentials",
            cwe_id   = "CWE-319",
            tags     = [svcname, "auth"],
        ))
    return findings


# Service name fragment → check function (first match wins per service)
_HC_DISPATCH: list[tuple[str, object]] = [
    ("ssh",          _hc_ssh),
    ("ssl/http",     _hc_http),
    ("https",        _hc_http),
    ("http",         _hc_http),
    ("ftp",          _hc_ftp),
    ("telnet",       _hc_telnet),
    ("smtp",         _hc_smtp),
    ("submission",   _hc_smtp),
    ("smb",          _hc_smb),
    ("microsoft-ds", _hc_smb),
    ("netbios-ssn",  _hc_smb),
    ("mysql",        _hc_mysql),
    ("ms-sql",       _hc_mssql),
    ("mssql",        _hc_mssql),
    ("ms-wbt",       _hc_rdp),
    ("rdp",          _hc_rdp),
    ("vnc",          _hc_vnc),
    ("domain",       _hc_dns),
    ("ldap",         _hc_ldap),
    ("snmp",         _hc_snmp),
    ("pop3",         _hc_email_plaintext),
    ("imap",         _hc_email_plaintext),
]


def _hc_banner_disclosure(target: str, port: str, svc: dict) -> list[Finding]:
    """Universal check: version string exposed in nmap banner."""
    version = svc.get("version", "").strip()
    product = svc.get("product", "").strip()
    if not version or not product:
        return []
    return [_hc_finding(
        svc, target,
        title    = f"Service version exposed in banner: {product} {version}",
        severity = "info",
        evidence = f"nmap banner: {product} {version}",
        vuln_type= "Information Disclosure",
        cwe_id   = "CWE-200",
        tags     = ["banner", "info"],
    )]


def _run_service_health_checks(services: list, target: str) -> list[Finding]:
    """
    Run deterministic, read-only health checks on every discovered service.
    Parses NSE output already collected by nmap Phase 3 — no extra connections.
    Returns a list of Finding objects to be merged into all_findings.
    """
    results: list[Finding] = []
    for svc in services:
        name = svc.get("name", "").lower()
        port = svc.get("port", "?")
        dispatched = False
        for fragment, fn in _HC_DISPATCH:
            if fragment in name:
                try:
                    results.extend(fn(target, port, svc))
                except Exception as exc:
                    print(f"  [hc] {fragment} check error on port {port}: {exc}")
                dispatched = True
                break
        # Universal banner check always runs regardless of dispatch
        try:
            results.extend(_hc_banner_disclosure(target, port, svc))
        except Exception:
            pass
    return results


def _run_script(script: str, language: str, cwd: str, timeout: int = 30) -> dict:
    """Write script to a temp file, execute it, return result dict."""
    import uuid
    ext  = ".py" if language == "python" else ".sh"
    path = os.path.join(cwd, f"_tmp_{uuid.uuid4().hex}{ext}")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(script)
        os.chmod(path, 0o700)
        runner = [sys.executable, path] if language == "python" else ["bash", path]
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


def _sanitise_script(obj: dict) -> dict | None:
    """Post-process a parsed {language, strategy, script} dict.

    Fixes the most common LLM output defect: bare (unescaped) newlines/carriage-returns
    inside string or byte literals, which produce a SyntaxError at runtime.
    For Python scripts a compile() check is run after fixing; if it still fails the
    result is discarded (None) so the caller can retry the LLM.
    Bash scripts pass through unchanged.
    """
    script   = obj.get("script", "")
    language = obj.get("language", "python")

    if language == "python":
        # Walk the source character-by-character, tracking whether we are inside
        # a string literal.  Any bare newline or carriage-return found inside a
        # literal is replaced with its two-character escape sequence.
        def _fix_literal_newlines(src: str) -> str:
            result: list[str] = []
            in_str = False
            str_ch = ""
            i = 0
            while i < len(src):
                ch = src[i]
                if not in_str:
                    if ch in ('"', "'"):
                        in_str = True
                        str_ch = ch
                    result.append(ch)
                else:
                    if ch == "\\":          # escape sequence — keep both chars verbatim
                        result.append(ch)
                        i += 1
                        if i < len(src):
                            result.append(src[i])
                    elif ch == str_ch:      # closing quote
                        in_str = False
                        result.append(ch)
                    elif ch == "\n":        # bare newline INSIDE a literal
                        result.append("\\n")
                    elif ch == "\r":        # bare carriage-return INSIDE a literal
                        result.append("\\r")
                    else:
                        result.append(ch)
                i += 1
            return "".join(result)

        fixed = _fix_literal_newlines(script)
        if fixed != script:
            print(f"\n  [Script] Sanitiser fixed bare newline(s) in string literal(s)")
        script = fixed

        try:
            compile(script, "<llm_script>", "exec")
        except SyntaxError as exc:
            print(f"\n  [Script] SyntaxError in LLM output ({exc}) — discarding attempt")
            return None

    result_obj = dict(obj)
    result_obj["script"] = script
    return result_obj


def _parse_llm_script_response(raw: str) -> dict | None:
    """Parse an LLM response that should be a JSON object with language/strategy/script keys.

    The 3b model often outputs unescaped newlines inside JSON string values which makes
    json.loads() fail. This function tries several progressively looser strategies:
      1. Standard json.loads (handles well-formed JSON)
      2. Strip markdown fences then json.loads
      3. Regex extraction of language/strategy/script fields directly from the raw text
    All successfully parsed objects pass through _sanitise_script() before being returned.
    Returns {language, strategy, script} or None if all strategies fail.
    """
    def _valid(obj):
        return (
            isinstance(obj, dict)
            and obj.get("language") == "python"
            and isinstance(obj.get("strategy"), str)
            and isinstance(obj.get("script"), str)
            and len(obj["script"]) > 20
        )

    text = raw.strip()

    # Strategy 1: plain json.loads
    try:
        obj = json.loads(text)
        if _valid(obj):
            return _sanitise_script(obj)
    except Exception:
        pass

    # Strategy 2: strip markdown fences
    if text.startswith("```"):
        text = re.sub(r"^```[a-z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text.strip())
    try:
        obj = json.loads(text)
        if _valid(obj):
            return _sanitise_script(obj)
    except Exception:
        pass

    # Strategy 3: find the outermost {...} block and sanitise embedded newlines.
    # The model often writes: {"script": "line1\nline2"} with a literal newline
    # instead of the escaped \\n — we fix that by replacing bare newlines that
    # are INSIDE a JSON string value with \\n.
    m = re.search(r'\{.*\}', text, re.DOTALL)
    if m:
        candidate = m.group(0)
        # Replace literal newlines inside JSON strings: only inside quoted values.
        # Simple heuristic: replace \n that appears between two quotes with \\n.
        fixed = re.sub(r'(?<=[^\\])\n', r'\\n', candidate)
        try:
            obj = json.loads(fixed)
            if _valid(obj):
                # Unescape \\n back to real newlines in the script so it runs properly
                obj["script"] = obj["script"].replace("\\n", "\n")
                return _sanitise_script(obj)
        except Exception:
            pass

    # Strategy 4: regex field extraction — works when the model writes valid-looking
    # JSON but with unbalanced braces or extra text outside.
    lang_m     = re.search(r'"language"\s*:\s*"(python)"', text)
    strategy_m = re.search(r'"strategy"\s*:\s*"([^"]{5,})"', text)
    # Script may span multiple lines — grab everything between "script": " and the last "
    script_m   = re.search(r'"script"\s*:\s*"(.*)"', text, re.DOTALL)
    if lang_m and strategy_m and script_m:
        script = script_m.group(1).replace("\\n", "\n").replace('\\"', '"')
        if len(script) > 20:
            return _sanitise_script({
                "language": lang_m.group(1),
                "strategy": strategy_m.group(1),
                "script":   script,
            })

    # Strategy 5: the model output a bare Python/bash code block with no JSON.
    # Wrap it in a minimal dict so it can still be executed.
    code_m = re.search(r'```(?:python|bash)?\n(.*?)```', text, re.DOTALL)
    if not code_m:
        # Also try un-fenced code that starts with "import" or "#!/"
        code_m = re.search(r'((?:import|#!/)[^\n].*)', text, re.DOTALL)
    if code_m:
        script = code_m.group(1).strip()
        if len(script) > 20 and "VERDICT:" in script:
            return _sanitise_script({
                "language": "python",
                "strategy": "model-generated script (unwrapped)",
                "script":   script,
            })

    return None


# ---------------------------------------------------------------------------
# NUCLEI TEMPLATE GENERATION — LLM → YAML → nuclei execution engine
# ---------------------------------------------------------------------------

# Services that are suitable for Nuclei HTTP template generation
_NUCLEI_HTTP_SERVICES = frozenset({
    "http", "https", "http-alt", "https-alt", "http-proxy", "ssl/http", "ssl/https",
    "web", "ipp", "www", "8080", "8443", "8888",
})

# Matcher library injected into the generation prompt so the model
# composes known patterns rather than inventing fragile ones.
_NUCLEI_MATCHER_LIBRARY = """\
REUSABLE MATCHER PATTERNS (use these directly when applicable):
  # Exact file disclosure:
  matchers:
    - type: word
      words: ["root:x:"]          # /etc/passwd disclosure
  # Exact version extraction:
  extractors:
    - type: regex
      regex: ["Apache\\/([0-9\\.]+)"]
  # Negative matcher (reduces false positives):
  matchers-condition: and
  matchers:
    - type: word
      words: ["vulnerable-string"]
    - type: word
      negative: true
      words: ["patched", "disabled", "fixed"]
  # Status + word (safer than status alone):
  matchers-condition: and
  matchers:
    - type: status
      status: [200]
    - type: word
      part: body
      words: ["confidential-indicator"]
  # Common error indicators: "Java stack trace", "PHP Warning", "Spring Whitelabel", "IIS error"
  # Common auth bypass: "Welcome", "dashboard", "admin panel" (combine with negative: ["login"])
"""


def _is_nuclei_eligible(cve: dict) -> bool:
    """Return True if this CVE is suitable for Nuclei HTTP template generation."""
    service = (cve.get("service") or "").lower()
    port    = str(cve.get("port", ""))
    return (
        service in _NUCLEI_HTTP_SERVICES
        or port in ("80", "443", "8080", "8443", "8888", "8008")
        or "http" in service
        or "web" in service
    )


def _valid_nuclei(obj: dict) -> bool:
    """Validate a parsed Nuclei template generation response.

    Required fields: template_id (str), protocol (str), yaml_content (str ≥ 50 chars).
    The yaml_content must parse as YAML and contain an id, info.name, and at least
    one http/tcp/network block with a matchers section.
    """
    try:
        import yaml as _yaml  # only needed here; may not be installed
    except ImportError:
        _yaml = None

    if not isinstance(obj, dict):
        return False
    if not all(obj.get(k) for k in ("template_id", "protocol", "yaml_content")):
        return False
    if len(obj.get("yaml_content", "")) < 50:
        return False

    # YAML structural check (best-effort — skip if PyYAML not installed)
    if _yaml is not None:
        try:
            doc = _yaml.safe_load(obj["yaml_content"])
            if not isinstance(doc, dict):
                return False
            if not doc.get("id") or not doc.get("info", {}).get("name"):
                return False
            # Must have at least one protocol block with matchers
            has_matchers = False
            for key in ("http", "tcp", "network", "dns"):
                blocks = doc.get(key)
                if isinstance(blocks, list):
                    for blk in blocks:
                        if isinstance(blk, dict) and blk.get("matchers"):
                            has_matchers = True
                            break
            if not has_matchers:
                return False
        except Exception:
            return False

    return True


def _detect_negative_matchers(yaml_content: str) -> bool:
    """Return True if the template uses negative matchers (better FP control)."""
    return "negative: true" in yaml_content or "negative:true" in yaml_content


def _generate_nuclei_template(cve: dict, target: str, port: int,
                               msf_hint: dict | None = None) -> dict | None:
    """
    Ask the LLM to generate a Nuclei YAML template for this CVE.

    Returns a dict with keys:
      template_id, probe_type, protocol, confidence, negative_matchers_present,
      matchers_summary, yaml_content
    or None on failure/parse error.
    """
    cve_id   = cve.get("cve_id", "unknown")
    product  = cve.get("product", "")
    summary  = (cve.get("summary") or "")[:200]
    service  = cve.get("service", "http")

    # Derive a stable template ID from the CVE ID and a short hash
    import hashlib as _hl
    _tid_hash = _hl.sha256(f"{cve_id}{product}{summary}".encode()).hexdigest()[:8]
    suggested_id = f"noctis-{cve_id.lower().replace(':', '-')}-{_tid_hash}"

    base_url = f"http://{target}:{port}" if port not in (80, 443) else (
        f"https://{target}" if port == 443 else f"http://{target}"
    )

    msf_block = ""
    if msf_hint and msf_hint.get("module"):
        _msf_verdict = (
            "CONFIRMED VULNERABLE by MSF check" if msf_hint.get("vulnerable") is True
            else "UNCONFIRMED (MSF check ran but could not confirm)"
        )
        msf_block = (
            f"\nMSF MODULE HINT: Metasploit module '{msf_hint['module']}' exists for this CVE.\n"
            f"MSF CHECK RESULT: {_msf_verdict}\n"
            f"Use this as a structural hint only. Do NOT reference msfconsole in the template.\n"
        )

    prompt = f"""/no_think
Generate a safe Nuclei YAML template to test whether a target is affected by a CVE.
Reply with JSON only — no markdown, no code fences.

CVE: {cve_id}
Product: {product}
Service: {service} on {base_url}
Summary: {summary}
{msf_block}
### TEMPLATE RULES
- Protocol: http (use {{{{BaseURL}}}} — Nuclei substitutes the target automatically)
- id MUST be: {suggested_id}
- severity: one of info/low/medium/high/critical
- Use at least one matcher with specific, meaningful words — NOT generic terms like "200 OK"
- Use negative matchers where possible to eliminate false positives
- The probe MUST match the service and protocol type
- Only assert version-based VULNERABLE match if the CVE has a specific affected version range
- Timeout: 10 seconds maximum per request
- Do NOT include interactsh, OOB callbacks, or payloads that modify server state

{_NUCLEI_MATCHER_LIBRARY}

### VERSION MATCHING
Only match on version strings if the CVE's vulnerable range is explicitly known.
A matcher that triggers on product name alone (e.g. contains: 'Apache') without a version
comparison is a false-positive generator — matchers must be specific to the vulnerable version.
Do not assume: older == vulnerable. Use extractors + matchers together for version checks.

### CONFIDENCE SCORING
0.9-1.0 = exact file disclosure or confirmed vulnerable fingerprint
0.7-0.89 = exact vulnerable version string match
0.5-0.69 = strong protocol behaviour (specific error pattern, header, body keyword)
0.3-0.49 = weak fingerprint (generic banner, product name only)
0.0-0.29 = unreliable

### PROBE TYPES
version_banner | header_check | unauthenticated_get | error_pattern_match |
config_disclosure | api_version_check | protocol_fingerprint

Reply with ONLY this JSON:
{{"template_id": "{suggested_id}", "probe_type": "<type>", "protocol": "http", "confidence": 0.0, "matchers_summary": "<one sentence>", "yaml_content": "id: {suggested_id}\\ninfo:\\n  name: {cve_id} — {product[:40]}\\n  severity: medium\\n\\nhttp:\\n  - method: GET\\n    path:\\n      - \\"{{{{BaseURL}}}}/\\"\\n    matchers:\\n      - type: word\\n        words:\\n          - \\"indicator-of-vulnerability\\""}}"""

    _t0       = time.monotonic()
    _timed_out = False
    _sp = _Spinner(f"[ LLM ]  Generating Nuclei template for {cve_id} ...").start()
    try:
        for attempt in range(MAX_LLM_RETRIES):
            try:
                resp = requests.post(
                    OLLAMA_URL,
                    json={
                        "model":      CVE_SCRIPT_MODEL,
                        "prompt":     prompt,
                        "stream":     False,
                        "keep_alive": _OLLAMA_KEEP_ALIVE,
                        "options":    {"num_ctx": 2048, "temperature": 0.2},
                    },
                    timeout=OLLAMA_TIMEOUT,
                )
                payload = resp.json()
                raw = payload.get("response", "")

                # Parse the JSON wrapper from the LLM response
                obj = None
                for _text in (raw.strip(), re.sub(r"^```[a-z]*\n?", "", raw).rstrip("`")):
                    try:
                        obj = json.loads(_text)
                        break
                    except Exception:
                        pass
                if obj is None:
                    m = re.search(r'\{.*\}', raw, re.DOTALL)
                    if m:
                        try:
                            obj = json.loads(m.group(0))
                        except Exception:
                            pass

                if obj and _valid_nuclei(obj):
                    # Unescape the YAML content if the model encoded newlines
                    if isinstance(obj.get("yaml_content"), str):
                        obj["yaml_content"] = obj["yaml_content"].replace("\\n", "\n")
                    obj["negative_matchers_present"] = _detect_negative_matchers(
                        obj.get("yaml_content", "")
                    )
                    return obj

            except requests.exceptions.Timeout:
                _timed_out = True
                break
            except requests.exceptions.ConnectionError as exc:
                print(f"\n  [LLM] Ollama connection error: {exc}")
                break
            except Exception as exc:
                print(f"\n  [LLM] Unexpected error: {exc}")
    finally:
        _elapsed = _fmt_dur(time.monotonic() - _t0)
        if _timed_out:
            _sp.stop(f" TIMED OUT ({_elapsed})")
        else:
            _sp.stop(f" done ({_elapsed})")
    return None


async def _run_nuclei_template(yaml_content: str, target_url: str,
                                template_path: str, available_tools: dict,
                                timeout: int = 30) -> dict:
    """
    Write yaml_content to template_path and run nuclei against target_url.

    Returns {"verdict": str, "output": str, "matched": bool, "error": str}.
    verdict is one of VULNERABLE / NOT_VULNERABLE / INCONCLUSIVE.
    """
    try:
        with open(template_path, "w", encoding="utf-8") as fh:
            fh.write(yaml_content)
    except Exception as e:
        return {"verdict": "INCONCLUSIVE", "output": f"[WRITE ERROR: {e}]",
                "matched": False, "error": str(e)}

    nuclei_path = available_tools.get("nuclei", "nuclei")
    if not nuclei_path or not os.path.exists(nuclei_path):
        # Try bare binary name (may be on PATH)
        nuclei_path = "nuclei"

    cmd = [
        nuclei_path,
        "-t", template_path,
        "-u", target_url,
        "-j",
        "-silent",
        "-nc",
        "-timeout", "10",
        "-duc",
    ]
    try:
        raw = await run_command_async(cmd, timeout=timeout)
    except Exception as e:
        return {"verdict": "INCONCLUSIVE", "output": f"[EXEC ERROR: {e}]",
                "matched": False, "error": str(e)}

    # Any JSONL match line = template fired = VULNERABLE
    matched = False
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                if obj.get("matched-at") or obj.get("template-id"):
                    matched = True
                    break
            except Exception:
                pass

    # Distinguish "nuclei ran but no match" from "nuclei failed completely"
    if not raw.strip() or "[ERR]" in raw or "Error" in raw:
        if not raw.strip():
            # Empty output — nuclei ran and found nothing, OR nuclei failed
            verdict = "INCONCLUSIVE"
            error = "nuclei produced no output (check template validity or nuclei binary)"
        else:
            verdict = "INCONCLUSIVE"
            error = raw[:300]
    else:
        verdict = "VULNERABLE" if matched else "NOT_VULNERABLE"
        error = ""

    return {"verdict": verdict, "output": raw[:600], "matched": matched, "error": error}


def _generate_known_exploit_script(cve: dict, target: str, msf_hint: dict | None = None) -> dict | None:
    """
    Phase 0: Ask the LLM to implement the specific known safe test method described
    in the CVE data (safe_validation_method / proof_of_impact) rather than generating
    a creative approach. Returns {language, strategy, script} or None on failure.
    """
    method  = cve.get("safe_validation_method", "").strip()
    proof   = cve.get("proof_of_impact", "").strip()
    if not method and not proof:
        return None  # no known method — skip Phase 0

    guidance = f"Method: {method}" if method else ""
    if proof:
        guidance += (". " if guidance else "") + f"Proof: {proof}"

    if msf_hint and msf_hint.get("module"):
        _msf_verdict = (
            "CONFIRMED VULNERABLE by MSF check" if msf_hint.get("vulnerable") is True
            else "UNCONFIRMED (MSF check ran but could not confirm)"
        )
        msf_block = (
            f"\nMSF MODULE HINT: Metasploit module '{msf_hint['module']}' exists for this CVE.\n"
            f"MSF CHECK RESULT: {_msf_verdict}\n"
            f"MSF OUTPUT: {(msf_hint.get('result') or '')[:120]}\n"
            f"Use this as a mechanism hint only. Write an independent probe using requests/socket/curl. "
            f"Do NOT call msfconsole or metasploit.\n"
        )
    else:
        msf_block = ""

    prompt = f"""/no_think
Write a Python 3 script to verify whether a CVE affects the target. Reply with JSON only.

CVE: {cve.get('cve_id', '')} on {target}:{cve.get('service', '')}
Product: {cve.get('product', '')} — {cve.get('summary', '')[:150]}
{guidance}{msf_block}
{('Weakness class: ' + cve.get('cwe_id','') + (' — ' + cve.get('cwe_name','') if cve.get('cwe_name') else '')) if cve.get('cwe_id','').startswith('CWE-') else ''}
### LANGUAGE
Python 3 only. Use subprocess for system tools where needed.
- USE: requests, socket, ssl, subprocess, shutil, re, json, time, urllib.parse, Python standard library.
- SUBPROCESS ALLOWED: curl, wget, openssl, nc, dig, timeout.
- Before calling any subprocess tool: use shutil.which('tool') first; if None, print VERDICT: INCONCLUSIVE and exit.
- FORBIDDEN packages: beautifulsoup4, bs4, lxml, selenium, paramiko, pwntools, scapy.
- FORBIDDEN subprocess: bash, sh, perl, ruby, socat, nmap, metasploit, sqlmap.
- Never invoke Python, shell interpreters, or this program recursively.

### IMPLEMENTATION
- Keep implementations concise and deterministic. Avoid unnecessary logic.
- Handle all network and parsing failures gracefully. The script must never crash.
- Use single quotes (') for all strings to avoid breaking the JSON.
- Default timeout: 8 seconds. Maximum timeout: 15 seconds.
- For path traversal or header injection probes: use raw socket (socket library) to send the
  literal byte string — do NOT use requests or urllib, which normalise paths and cause 400 errors.
- The probe MUST match the target protocol and service type.
  Do not generate HTTP logic for non-HTTP services.
  Do not generate TLS logic unless TLS is present or implied by the service.

### VERSION MATCHING — CRITICAL RULES
There are exactly TWO valid paths to VERDICT: VULNERABLE:
1. VERSION CHECK: Extract a specific version string with regex and confirm it falls within
   the CVE stated vulnerable range. If no version string is parseable, output INCONCLUSIVE.
2. BEHAVIORAL CHECK: Directly observe the vulnerable behaviour described in the CVE
   (e.g. unauthenticated file read, specific error message, exploitable protocol response).

FORBIDDEN — product/service name presence alone MUST NEVER produce VERDICT: VULNERABLE:
    if 'OpenSSH' in banner: ...              # proves service exists, not that it is unpatched
    if 'Apache' in r.headers.get('Server','') ...  # same — product presence proves nothing
    if b'vsftpd' in data: ...               # same
    if '200 OK' in response: ...            # generic success is not vulnerability evidence

Path 1 template (version-based):
    m = re.search(r'ProductName[_/ ]([\d.]+)', banner)
    if not m: print('VERDICT: INCONCLUSIVE')        # no version found
    elif tuple(int(x) for x in m.group(1).split('.')) <= (MAX_VER,): print('VERDICT: VULNERABLE')
    else: print('VERDICT: NOT_VULNERABLE')

Path 2 template (behavioral):
    # Must check for the specific vulnerable behaviour, NOT just product existence
    if b'specific_error_or_disclosure' in data: print('VERDICT: VULNERABLE')
    elif b'not_accessible' in data: print('VERDICT: NOT_VULNERABLE')
    else: print('VERDICT: INCONCLUSIVE')

### CONFIDENCE SCORING
0.9-1.0 = direct disclosure or exact vulnerable fingerprint
0.7-0.89 = exact vulnerable version match
0.5-0.69 = strong protocol behaviour match
0.3-0.49 = weak fingerprint match
0.0-0.29 = unreliable or ambiguous evidence

### VERDICT
Script MUST print EXACTLY ONE of:
VERDICT: VULNERABLE
VERDICT: NOT_VULNERABLE
VERDICT: INCONCLUSIVE

Mark VULNERABLE only when: (a) a version string is extracted and confirmed within the CVE range,
  OR (b) the specific vulnerable behaviour is directly observed. Product/service name presence
  alone (e.g. 'OpenSSH' in banner, 'Apache' in Server header) is NEVER sufficient.
Mark INCONCLUSIVE when: CVE lacks technical detail, network fails, auth required, evidence is
  ambiguous, no version string found (for version-based probes), or behaviour is indeterminate.
Never rely on: generic HTTP 200 responses, page titles alone, unverified headers, or ambiguous errors.
Never use: example.com, localhost, 127.0.0.1, placeholder paths, TODO markers, or dummy values.

Reply with ONLY this JSON (no markdown, no code fences):
{{"language": "python", "probe_type": "<version_banner|header_check|unauthenticated_get|tcp_banner|error_pattern_match|timing_probe|config_disclosure|api_version_check|protocol_fingerprint>", "strategy": "<one sentence>", "confidence": 0.0, "script": "import requests\\ntry:\\n  r = requests.get('http://{target}/', timeout=5)\\n  if 'X-Version' in r.headers:\\n    print('VERDICT: VULNERABLE')\\n  else:\\n    print('VERDICT: NOT_VULNERABLE')\\nexcept Exception:\\n  print('VERDICT: INCONCLUSIVE')"}}"""

    _t0       = time.monotonic()
    _timed_out = False
    _parse_fail_raw = ""
    _sp = _Spinner(f"[ LLM ]  Generating known-exploit script for {cve.get('cve_id', 'CVE')} ...").start()
    try:
        for attempt in range(MAX_LLM_RETRIES):
            try:
                resp = requests.post(
                    OLLAMA_URL,
                    json={
                        "model":      SCRIPT_MODEL,
                        "prompt":     prompt,
                        "stream":     False,
                        "keep_alive": _OLLAMA_KEEP_ALIVE,
                        "options":    {"num_ctx": 2048, "temperature": 0},
                    },
                    timeout=OLLAMA_TIMEOUT,
                )
                payload = resp.json()
                raw = payload.get("response", "")
                obj = _parse_llm_script_response(raw)
                if obj:
                    return obj
                _parse_fail_raw = raw[:300]
            except requests.exceptions.Timeout:
                _timed_out = True
                break
            except requests.exceptions.ConnectionError as exc:
                print(f"\n  [LLM] Ollama connection error: {exc}")
                break
            except Exception as exc:
                print(f"\n  [LLM] Unexpected error: {exc}")
    finally:
        _elapsed = _fmt_dur(time.monotonic() - _t0)
        if _timed_out:
            _sp.stop(f" TIMED OUT ({_elapsed}) — try a faster model or raise OLLAMA_TIMEOUT")
        else:
            _sp.stop(f" done ({_elapsed})")
        if _parse_fail_raw:
            print(f"  [LLM] Parse failure — raw response (first 300 chars): {_parse_fail_raw!r}")
    return None


def _generate_cve_test_script(cve: dict, target: str, previous_attempts: list,
                               kb_entry: dict | None, iteration: int,
                               msf_hint: dict | None = None) -> dict | None:
    """
    Ask the LLM to generate a single safe test script for the given CVE.
    Returns {language, strategy, script} or None on failure.
    """
    prior_lines = []
    banned_strategies = []
    for i, a in enumerate(previous_attempts[-5:], 1):  # last 5 only to keep prompt short
        strategy = a['strategy']
        banned_strategies.append(strategy)
        line = f"  [{i}] {strategy} → {a['verdict']}"
        # Include a short output snippet so the LLM sees *why* it failed
        snippet = (a.get("output") or "").strip()
        if snippet:
            # First non-empty line of output, capped at 120 chars
            first_line = next((l for l in snippet.splitlines() if l.strip()), "")
            if first_line:
                line += f"\n      output: {first_line[:120]}"
        prior_lines.append(line)
    prior_block = "\n".join(prior_lines) if prior_lines else "  (none — this is attempt 1)"

    # Explicit ban clause: enumerate each failed strategy so a small model can't miss it
    if banned_strategies:
        _banned_list = "\n".join(f"  - {s}" for s in banned_strategies)
        _banned_clause = (
            f"\n### BANNED STRATEGIES (ALL FAILED — DO NOT REPEAT ANY OF THESE):\n{_banned_list}\n"
            f"You MUST use a completely different technique that is NOT in the banned list above.\n"
        )
    else:
        _banned_clause = ""

    kb_lines = []
    if kb_entry and kb_entry.get("scripts"):
        useful = [s for s in kb_entry["scripts"] if s.get("verdict") in ("VULNERABLE", "INCONCLUSIVE")]
        for s in useful[:2]:  # 2 max to stay short
            kb_lines.append(f"  Prior script ({s['verdict']}): {s['strategy']}")
    kb_block = ("\nKB techniques (adapt):\n" + "\n".join(kb_lines)) if kb_lines else ""

    if msf_hint and msf_hint.get("module"):
        _msf_verdict = (
            "CONFIRMED VULNERABLE by MSF check" if msf_hint.get("vulnerable") is True
            else "UNCONFIRMED (MSF check ran but could not confirm)"
        )
        msf_block = (
            f"\nMSF MODULE HINT: Metasploit module '{msf_hint['module']}' exists for this CVE.\n"
            f"MSF CHECK RESULT: {_msf_verdict}\n"
            f"MSF OUTPUT: {(msf_hint.get('result') or '')[:120]}\n"
            f"Use this as a mechanism hint only. Write an independent probe using requests/socket/curl. "
            f"Do NOT call msfconsole or metasploit.\n"
        )
    else:
        msf_block = ""

    prompt = f"""/no_think
Write a Python 3 script to verify whether a CVE affects the target using a FRESH strategy. Reply with JSON only.

CVE: {cve.get('cve_id', '')} on {target}:{cve.get('service', '')}
Product: {cve.get('product', '')} — {cve.get('summary', '')[:150]}
Safe method: {cve.get('safe_validation_method', '')}
{('Weakness class: ' + cve.get('cwe_id','') + (' — ' + cve.get('cwe_name','') if cve.get('cwe_name') else '')) if cve.get('cwe_id','').startswith('CWE-') else ''}
### ATTEMPTS SO FAR:
{prior_block}{kb_block}{msf_block}{_banned_clause}
### LANGUAGE
Python 3 only. Use subprocess for system tools where needed.
- USE: requests, socket, ssl, subprocess, shutil, re, json, time, urllib.parse, Python standard library.
- SUBPROCESS ALLOWED: curl, wget, openssl, nc, dig, timeout.
- Before calling any subprocess tool: use shutil.which('tool') first; if None, print VERDICT: INCONCLUSIVE and exit.
- FORBIDDEN packages: beautifulsoup4, bs4, lxml, selenium, paramiko, pwntools, scapy.
- FORBIDDEN subprocess: bash, sh, perl, ruby, socat, nmap, metasploit, sqlmap.
- Never invoke Python, shell interpreters, or this program recursively.

### IMPLEMENTATION
- Keep implementations concise and deterministic. Avoid unnecessary logic.
- Handle all network and parsing failures gracefully. The script must never crash.
- Use single quotes (') for all strings to avoid breaking the JSON.
- Default timeout: 8 seconds. Maximum timeout: 15 seconds.
- For path traversal or header injection probes: use raw socket (socket library) to send the
  literal byte string — do NOT use requests or urllib, which normalise paths and cause 400 errors.
- The probe MUST match the target protocol and service type.
  Do not generate HTTP logic for non-HTTP services.
  Do not generate TLS logic unless TLS is present or implied by the service.

### VERSION MATCHING — CRITICAL RULES
There are exactly TWO valid paths to VERDICT: VULNERABLE:
1. VERSION CHECK: Extract a specific version string with regex and confirm it falls within
   the CVE stated vulnerable range. If no version string is parseable, output INCONCLUSIVE.
2. BEHAVIORAL CHECK: Directly observe the vulnerable behaviour described in the CVE
   (e.g. unauthenticated file read, specific error message, exploitable protocol response).

FORBIDDEN — product/service name presence alone MUST NEVER produce VERDICT: VULNERABLE:
    if 'OpenSSH' in banner: ...              # proves service exists, not that it is unpatched
    if 'Apache' in r.headers.get('Server','') ...  # same — product presence proves nothing
    if b'vsftpd' in data: ...               # same
    if '200 OK' in response: ...            # generic success is not vulnerability evidence

Path 1 template (version-based):
    m = re.search(r'ProductName[_/ ]([\d.]+)', banner)
    if not m: print('VERDICT: INCONCLUSIVE')        # no version found
    elif tuple(int(x) for x in m.group(1).split('.')) <= (MAX_VER,): print('VERDICT: VULNERABLE')
    else: print('VERDICT: NOT_VULNERABLE')

Path 2 template (behavioral):
    # Must check for the specific vulnerable behaviour, NOT just product existence
    if b'specific_error_or_disclosure' in data: print('VERDICT: VULNERABLE')
    elif b'not_accessible' in data: print('VERDICT: NOT_VULNERABLE')
    else: print('VERDICT: INCONCLUSIVE')

### CONFIDENCE SCORING
0.9-1.0 = direct disclosure or exact vulnerable fingerprint
0.7-0.89 = exact vulnerable version match
0.5-0.69 = strong protocol behaviour match
0.3-0.49 = weak fingerprint match
0.0-0.29 = unreliable or ambiguous evidence

### VERDICT
Script MUST print EXACTLY ONE of:
VERDICT: VULNERABLE
VERDICT: NOT_VULNERABLE
VERDICT: INCONCLUSIVE

Mark VULNERABLE only when: (a) a version string is extracted and confirmed within the CVE range,
  OR (b) the specific vulnerable behaviour is directly observed. Product/service name presence
  alone (e.g. 'OpenSSH' in banner, 'Apache' in Server header) is NEVER sufficient.
Mark INCONCLUSIVE when: CVE lacks technical detail, network fails, auth required, evidence is
  ambiguous, no version string found (for version-based probes), or behaviour is indeterminate.
Never rely on: generic HTTP 200 responses, page titles alone, unverified headers, or ambiguous errors.
Never use: example.com, localhost, 127.0.0.1, placeholder paths, TODO markers, or dummy values.

Reply with ONLY this JSON (no markdown, no code fences):
{{"language": "python", "probe_type": "<version_banner|header_check|unauthenticated_get|tcp_banner|error_pattern_match|timing_probe|config_disclosure|api_version_check|protocol_fingerprint>", "strategy": "<one sentence NOT in banned list>", "confidence": 0.0, "script": "import socket\\ntry:\\n  s = socket.create_connection(('{target}', PORT), timeout=5)\\n  s.send(b'PROBE\\r\\n')\\n  data = s.recv(512)\\n  print('VERDICT: VULNERABLE' if b'SIGNATURE' in data else 'VERDICT: NOT_VULNERABLE')\\n  s.close()\\nexcept Exception:\\n  print('VERDICT: INCONCLUSIVE')"}}"""

    _t0        = time.monotonic()
    _timed_out  = False
    _parse_fail_raw = ""
    _sp = _Spinner(f"[ LLM ]  Generating test script for {cve.get('cve_id', 'CVE')} ...").start()
    try:
        for attempt in range(MAX_LLM_RETRIES):
            try:
                resp = requests.post(
                    OLLAMA_URL,
                    json={
                        "model":      CVE_SCRIPT_MODEL,
                        "prompt":     prompt,
                        "stream":     False,
                        "keep_alive": _OLLAMA_KEEP_ALIVE,
                        "options":    {"num_ctx": 2048, "temperature": 0.4},
                    },
                    timeout=OLLAMA_TIMEOUT,
                )
                payload = resp.json()
                raw = payload.get("response", "")
                obj = _parse_llm_script_response(raw)
                if obj:
                    return obj
                _parse_fail_raw = raw[:300]
            except requests.exceptions.Timeout:
                _timed_out = True
                break  # no point retrying a timeout — LLM is too slow right now
            except requests.exceptions.ConnectionError as exc:
                print(f"\n  [LLM] Ollama connection error: {exc}")
                break  # Ollama is down — no point retrying
            except Exception as exc:
                print(f"\n  [LLM] Unexpected error: {exc}")
    finally:
        _elapsed = _fmt_dur(time.monotonic() - _t0)
        if _timed_out:
            _sp.stop(f" TIMED OUT ({_elapsed}) — try a faster model or raise OLLAMA_TIMEOUT")
        else:
            _sp.stop(f" done ({_elapsed})")
        if _parse_fail_raw:
            print(f"  [LLM] Parse failure — raw response (first 300 chars): {_parse_fail_raw!r}")
    return None


def _generate_verification_script(cve: dict, target: str, triggering_attempt: dict) -> dict | None:
    """
    Generate a verification script that uses a DIFFERENT technique from the triggering attempt
    to confirm or deny a VULNERABLE result and reduce false positives.
    Returns {language, strategy, script} or None on failure.
    """
    _trig_strategy = triggering_attempt.get('strategy', '')
    _trig_script   = triggering_attempt.get('script', '')[:800]
    _trig_output   = triggering_attempt.get('output', '')[:400]

    prompt = f"""/no_think
Write a SECOND, INDEPENDENT Python 3 verification script to confirm or deny a prior VULNERABLE result. Reply with JSON only.

CVE: {cve.get('cve_id', '')} on {target}:{cve.get('service', '')}
Product: {cve.get('product', '')} — {cve.get('summary', '')[:150]}

### TRIGGERING RESULT — what you are verifying:
Strategy:  {_trig_strategy}
Evidence (script output that returned VULNERABLE):
{_trig_output}

### REFERENCE SCRIPT (the probe that found VULNERABLE):
{_trig_script}

### CONTRAST RULE — MANDATORY:
DO NOT REUSE: same endpoint, same URL path, same response field, same protocol primitive, or same code logic as the reference script above.
Study the reference script and evidence to understand WHAT was found, then validate the same vulnerability via a DIFFERENT observable indicator.
Examples of contrast: if the reference used HTTP GET → use a raw socket; if it matched a header → match a response body; if it read a version banner → confirm a behavioural symptom.

### LANGUAGE
Python 3 only. Use subprocess for system tools where needed.
- USE: requests, socket, ssl, subprocess, shutil, re, json, time, urllib.parse, Python standard library.
- SUBPROCESS ALLOWED: curl, wget, openssl, nc, dig, timeout.
- Before calling any subprocess tool: use shutil.which('tool') first; if None, print VERDICT: INCONCLUSIVE and exit.
- FORBIDDEN packages: beautifulsoup4, bs4, lxml, selenium, paramiko, pwntools, scapy.
- FORBIDDEN subprocess: bash, sh, perl, ruby, socat, nmap, metasploit, sqlmap.
- Never invoke Python, shell interpreters, or this program recursively.

### IMPLEMENTATION
- Keep implementations concise and deterministic. Avoid unnecessary logic.
- Handle all network and parsing failures gracefully. The script must never crash.
- Use single quotes (') for all strings to avoid breaking the JSON.
- Default timeout: 8 seconds. Maximum timeout: 15 seconds.
- For path traversal or header injection probes: use raw socket (socket library) to send the
  literal byte string — do NOT use requests or urllib, which normalise paths and cause 400 errors.
- The probe MUST match the target protocol and service type.
  Do not generate HTTP logic for non-HTTP services.
  Do not generate TLS logic unless TLS is present or implied by the service.

### VERSION MATCHING — CRITICAL RULES
There are exactly TWO valid paths to VERDICT: VULNERABLE:
1. VERSION CHECK: Extract a specific version string with regex and confirm it falls within
   the CVE stated vulnerable range. If no version string is parseable, output INCONCLUSIVE.
2. BEHAVIORAL CHECK: Directly observe the vulnerable behaviour described in the CVE
   (e.g. unauthenticated file read, specific error message, exploitable protocol response).

FORBIDDEN — product/service name presence alone MUST NEVER produce VERDICT: VULNERABLE:
    if 'OpenSSH' in banner: ...              # proves service exists, not that it is unpatched
    if 'Apache' in r.headers.get('Server','') ...  # same — product presence proves nothing
    if b'vsftpd' in data: ...               # same
    if '200 OK' in response: ...            # generic success is not vulnerability evidence

Path 1 template (version-based):
    m = re.search(r'ProductName[_/ ]([\d.]+)', banner)
    if not m: print('VERDICT: INCONCLUSIVE')        # no version found
    elif tuple(int(x) for x in m.group(1).split('.')) <= (MAX_VER,): print('VERDICT: VULNERABLE')
    else: print('VERDICT: NOT_VULNERABLE')

Path 2 template (behavioral):
    # Must check for the specific vulnerable behaviour, NOT just product existence
    if b'specific_error_or_disclosure' in data: print('VERDICT: VULNERABLE')
    elif b'not_accessible' in data: print('VERDICT: NOT_VULNERABLE')
    else: print('VERDICT: INCONCLUSIVE')

### CONFIDENCE SCORING
0.9-1.0 = direct disclosure or exact vulnerable fingerprint
0.7-0.89 = exact vulnerable version match
0.5-0.69 = strong protocol behaviour match
0.3-0.49 = weak fingerprint match
0.0-0.29 = unreliable or ambiguous evidence

### VERDICT
Script MUST print EXACTLY ONE of:
VERDICT: VULNERABLE
VERDICT: NOT_VULNERABLE
VERDICT: INCONCLUSIVE

Mark VULNERABLE only when this independent check confirms the original finding via: (a) a version
  string extracted and confirmed within the CVE range, OR (b) direct observation of the vulnerable
  behaviour. Product/service name presence alone is NEVER sufficient.
Mark NOT_VULNERABLE when this check disproves the original result.
Mark INCONCLUSIVE when evidence is ambiguous, the check cannot complete, no version string was
  found (for version-based probes), or the behavioural indicator was indeterminate.
Never rely on: generic HTTP 200 responses, page titles alone, unverified headers, or ambiguous errors.
Never use: example.com, localhost, 127.0.0.1, placeholder paths, TODO markers, or dummy values.

Reply with ONLY this JSON (no markdown, no code fences):
{{"language": "python", "probe_type": "<version_banner|header_check|unauthenticated_get|tcp_banner|error_pattern_match|timing_probe|config_disclosure|api_version_check|protocol_fingerprint>", "strategy": "<different strategy>", "confidence": 0.0, "script": "import socket,re\\ntry:\\n  s=socket.create_connection(('{target}',PORT),timeout=5)\\n  banner=s.recv(512).decode(errors='ignore')\\n  m=re.search(r'Product/([\\.\\d]+)',banner)\\n  if not m: print('VERDICT: INCONCLUSIVE')\\n  elif tuple(int(x) for x in m.group(1).split('.'))<=VULN_MAX: print('VERDICT: VULNERABLE')\\n  else: print('VERDICT: NOT_VULNERABLE')\\nexcept Exception: print('VERDICT: INCONCLUSIVE')"}}"""

    _t0        = time.monotonic()
    _timed_out  = False
    _parse_fail_raw = ""
    _sp = _Spinner("[ LLM ]  Generating verification script ...").start()
    try:
        for attempt in range(MAX_LLM_RETRIES):
            try:
                resp = requests.post(
                    OLLAMA_URL,
                    json={
                        "model":      CVE_SCRIPT_MODEL,
                        "prompt":     prompt,
                        "stream":     False,
                        "keep_alive": _OLLAMA_KEEP_ALIVE,
                        "options":    {"num_ctx": 2048, "temperature": 0.4},
                    },
                    timeout=OLLAMA_TIMEOUT,
                )
                payload = resp.json()
                raw = payload.get("response", "")
                obj = _parse_llm_script_response(raw)
                if obj:
                    return obj
                _parse_fail_raw = raw[:300]
            except requests.exceptions.Timeout:
                _timed_out = True
                break
            except requests.exceptions.ConnectionError as exc:
                print(f"\n  [LLM] Ollama connection error: {exc}")
                break  # Ollama is down — no point retrying
            except Exception as exc:
                print(f"\n  [LLM] Unexpected error: {exc}")
    finally:
        _elapsed = _fmt_dur(time.monotonic() - _t0)
        if _timed_out:
            _sp.stop(f" TIMED OUT ({_elapsed}) — try a faster model or raise OLLAMA_TIMEOUT")
        else:
            _sp.stop(f" done ({_elapsed})")
        if _parse_fail_raw:
            print(f"  [LLM] Parse failure — raw response (first 300 chars): {_parse_fail_raw!r}")
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


def _print_scan_eta(label: str, scan_start: datetime, frac_done: float) -> None:
    """Print a one-line phase status: current time, elapsed, and estimated completion."""
    now     = datetime.now()
    elapsed = (now - scan_start).total_seconds()
    if frac_done > 0.02:
        eta = scan_start + timedelta(seconds=elapsed / frac_done)
        eta_str = eta.strftime("%H:%M:%S")
    else:
        eta_str = "calculating…"
    print(f"[*] ── {label} | Time: {now.strftime('%H:%M:%S')} | Elapsed: {_fmt_dur(elapsed)} | Est. completion: {eta_str}")


def _script_score(s: dict) -> float:
    """
    Score a KB script for ranking. Higher = more historically useful.
    VULNERABLE results are weighted 3x (finding vulns is the goal).
    NOT_VULNERABLE results are weighted 1x (clear negative answer is still useful).
    INCONCLUSIVE results contribute 0 (broken or unreliable).
    community_confirmations (set by the build pipeline) adds a bonus proportional
    to the number of independent users who submitted the same script — a script
    confirmed by 10 users starts with a meaningful head-start over an untested one.
    Backward-compatible: fields absent in old KB entries default to safe values.
    """
    runs = s.get("runs", 1)
    v    = s.get("vulnerable_count",
                 1 if s.get("verdict") == "VULNERABLE" else 0)
    n    = s.get("not_vulnerable_count",
                 1 if s.get("verdict") == "NOT_VULNERABLE" else 0)
    base_score   = (v * 3 + n) / max(runs, 1)
    # Each additional community confirmation beyond the minimum-2 adds 0.5 bonus
    confirmations = s.get("community_confirmations", 0)
    community_bonus = max(0, confirmations - 2) * 0.5
    return base_score + community_bonus


def _select_kb_scripts(scripts: list) -> list:
    """
    Select a fair, tiered sample from a pool of KB scripts so that large
    knowledge bases don't exhaust the test budget on a single CVE.

    Tiers:
      Top  10 — highest-ranked scripts (most historically reliable)
      Mid   5 — random sample from the middle third (stable but not star performers)
      Low   5 — random sample from the bottom third (low-scorers worth re-validating)

    If the pool has <= 20 scripts the full pool is returned (sorted by score).
    """
    TOP_N      = 10
    MID_SAMPLE = 5
    LOW_SAMPLE = 5
    THRESHOLD  = TOP_N + MID_SAMPLE + LOW_SAMPLE  # 20

    scored = sorted(scripts, key=_script_score, reverse=True)
    if len(scored) <= THRESHOLD:
        return scored

    top       = scored[:TOP_N]
    remainder = scored[TOP_N:]
    third     = max(1, len(remainder) // 3)
    mid_pool  = remainder[:third]
    low_pool  = remainder[third:]

    mid = random.sample(mid_pool, min(MID_SAMPLE, len(mid_pool))) if mid_pool else []
    low = random.sample(low_pool, min(LOW_SAMPLE, len(low_pool))) if low_pool else []

    return top + mid + low


def _derive_inconclusive_reason(cve: dict, attempts: list) -> str:
    """Analyse attempt outputs to produce a human-readable explanation of why a
    CVE test returned INCONCLUSIVE rather than a definitive verdict.

    Checks the outputs in priority order so the most actionable explanation
    surfaces first.  Returns a single sentence suitable for display in the
    report.
    """
    if not attempts:
        return "No probe scripts were generated or executed for this CVE."

    all_outputs = " ".join(a.get("output", "") for a in attempts).lower()
    all_strategies = " ".join(a.get("strategy", "") for a in attempts).lower()

    # LLM generation failures
    llm_failures = sum(1 for a in attempts if "llm parse failure" in a.get("strategy", "").lower()
                       or "ollama unavailable" in a.get("strategy", "").lower())
    if llm_failures == len(attempts):
        return "All probe scripts failed to generate — Ollama was unavailable or returned unparseable JSON."
    if llm_failures > 0:
        return (f"{llm_failures} of {len(attempts)} scripts failed to generate (LLM parse failure); "
                "remaining probes ran but could not confirm the vulnerability.")

    # Timeout signals
    timed_out = sum(1 for a in attempts if
                    "[timed out]" in a.get("output", "").lower() or
                    "command timed out" in a.get("output", "").lower())
    if timed_out == len(attempts):
        return ("All probe scripts timed out (30s limit). "
                "The target service may be slow, filtered, or not responding on the probed port/protocol.")
    if timed_out > 0:
        return (f"{timed_out} of {len(attempts)} scripts timed out. "
                "The remaining scripts ran but returned INCONCLUSIVE — "
                "the target may be partially filtered.")

    # Connection-level errors
    if "connection refused" in all_outputs:
        return ("Probes received 'Connection refused' — the service is not accepting connections "
                "on the protocol the generated scripts targeted.")
    if "connection timed out" in all_outputs:
        return "Probes timed out at the network level — the port may be filtered or the host unreachable."
    if "name or service not known" in all_outputs or "nodename nor servname" in all_outputs:
        return "DNS resolution failed for the target — probes could not reach the host."

    # Script runtime errors
    error_count = sum(1 for a in attempts if "[error:" in a.get("output", "").lower())
    if error_count == len(attempts):
        return ("All scripts raised runtime errors during execution. "
                "The probes likely targeted a protocol not exposed on this port "
                "(e.g. HTTP probe against an RPC/SMB service).")
    if error_count > 0:
        return (f"{error_count} of {len(attempts)} scripts raised runtime errors. "
                "The LLM generated HTTP/network probes that do not match the actual service protocol.")

    # Version-banner-only strategies (common for old CVEs)
    banner_only = sum(1 for a in attempts if "version banner" in a.get("strategy", "").lower()
                      or "banner" in a.get("strategy", "").lower())
    if banner_only == len(attempts):
        vuln_type = cve.get("vulnerability_type", "")
        return (f"All {len(attempts)} probes used version-banner checks only — "
                f"insufficient to confirm or deny a {vuln_type or 'vulnerability'} "
                "without an exact version string in the service response.")

    # No VERDICT token found in output
    no_verdict = sum(1 for a in attempts
                     if "vulnerable" not in a.get("output", "").lower()
                     and "not_vulnerable" not in a.get("output", "").lower())
    if no_verdict == len(attempts):
        return ("Scripts ran but produced no VERDICT token — "
                "the target did not respond in a way the probes could interpret as vulnerable or safe.")

    # Generic HTTP probes against a non-HTTP service
    if ("http" in all_strategies or "requests.get" in all_outputs) and \
       cve.get("service", "") and "http" not in cve.get("service", "").lower():
        return ("The LLM generated HTTP probes for a non-HTTP service. "
                "The scripts could not determine vulnerability status because the port "
                "does not speak HTTP.")

    # Default — mixed inconclusive
    return ("The probe scripts ran but could not confirm or deny the vulnerability. "
            "This typically means the target does not expose a version string or "
            "detectable behaviour that distinguishes patched from unpatched versions. "
            "Manual verification is recommended.")


def _scrub_for_kb(text: str, target_host: str) -> str:
    """
    Remove user-specific data before persisting to the CVE knowledge base:
      - session temp-file paths from Python/shell tracebacks → bare filename
      - the actual target host/IP → 'TARGET_HOST' placeholder
    """
    if not text:
        return text
    # Strip absolute paths ending in a cve_tests temp file, keep only the filename
    text = re.sub(r'/[^ \t\r\n"\'\\]*/cve_tests/(_tmp_[a-f0-9]+\.[a-z]+)', r'\1', text)
    # Replace the scan target (IP or hostname) wherever it appears
    if target_host:
        text = text.replace(target_host, "TARGET_HOST")
    # Belt-and-braces: strip any remaining /home/* or /root/* absolute paths
    text = re.sub(r'/(?:home|root)/[^ \t\r\n"\'\\]+', '<path>', text)
    return text


async def run_cve_tests(cve_matches: list, target: str,
                        session_dir: str, kb: dict,
                        available_tools: dict | None = None,
                        nuclei_kb: dict | None = None) -> tuple[list, dict]:
    """
    For each CVE (sorted Critical → High → Medium → Low):
      0. Targeted attempt: implement the known safe_validation_method/proof_of_impact (if present).
      1a. Replay any Nuclei templates already in the nuclei KB (HTTP CVEs only).
      1b. Replay any scripts already in the knowledge base (proven techniques from prior runs).
      2a. Generate a Nuclei template (HTTP CVEs only, if nuclei available).
      2b. Generate CVE_FRESH_ATTEMPTS new LLM Python scripts with fresh creative approaches.
      3. On the first VULNERABLE result, run CVE_VERIFY_ATTEMPTS independent verifier scripts
         using a different technique to confirm and avoid false positives.
    Every CVE_BATCH_SIZE CVEs the user is prompted to continue (runaway guard).
    Returns (cve_test_results, updated_kb).
    """
    available_tools = available_tools or {}
    nuclei_kb = nuclei_kb if nuclei_kb is not None else _load_nuclei_kb()
    _nuclei_available = bool(available_tools.get("nuclei") or
                             os.path.exists(os.path.join(os.path.expanduser("~"), "go", "bin", "nuclei")))
    cve_tests_dir = os.path.join(session_dir, "cve_tests")
    os.makedirs(cve_tests_dir, exist_ok=True)

    # Sort by severity so highest-impact CVEs are tested first
    _sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    cve_matches = sorted(
        cve_matches,
        key=lambda c: _sev_rank.get(c.get("severity", "").upper(), 0),
        reverse=True,
    )

    cve_test_results = []
    total_cves    = len(cve_matches)
    scan_start    = time.monotonic()

    for cve_idx, cve in enumerate(cve_matches, 1):
        cve_start = time.monotonic()
        cve_id    = cve.get("cve_id", "UNKNOWN")
        kb_entry         = kb.get(cve_id)
        kb_scripts       = kb_entry["scripts"] if kb_entry else []
        kb_count         = len(kb_scripts)
        selected_scripts = _select_kb_scripts(kb_scripts)
        kb_selected      = len(selected_scripts)
        if kb_count == 0:
            kb_label = "new to KB"
        elif kb_selected < kb_count:
            kb_label = f"{kb_count} in KB (top-{kb_selected} selected by rank)"
        else:
            kb_label = f"{kb_count} prior script(s) in KB"

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
        kb_pending_vulnerable: list = []  # VULNERABLE scripts deferred until Phase 3 confirms

        # ------------------------------------------------------------------
        # Phase 0: Targeted known-exploit attempt (implements the documented
        #           safe_validation_method / proof_of_impact specifically)
        # ------------------------------------------------------------------

        # Extract MSF validation result for this CVE (populated by run_msf_validation,
        # which runs before _run_cve_test_phase).
        msf_hint: dict | None = cve.get("msf_validation") or None

        # Short-circuit: MSF already confirmed this CVE as vulnerable — no need to run
        # any LLM probes.  Record the result and move to the next CVE.
        if msf_hint and msf_hint.get("vulnerable") is True:
            print(f"  [MSF] {cve_id} — CONFIRMED VULNERABLE by MSF check, skipping LLM probe phase")
            attempts.append({
                "attempt_num": 1,
                "source":      "msf_confirmed",
                "strategy":    f"[MSF] {msf_hint.get('module', 'unknown module')} check confirmed vulnerable",
                "language":    "msf",
                "script":      "",
                "script_path": "",
                "output":      (msf_hint.get("result") or "")[:600],
                "verdict":     "VULNERABLE",
            })
            cve_test_results.append({
                "cve_id":               cve_id,
                "vulnerability_type":   cve.get("vulnerability_type", ""),
                "service":              cve.get("service", ""),
                "overall_verdict":      "CONFIRMED_VULNERABLE",
                "verdict_counts":       {"VULNERABLE": 1, "NOT_VULNERABLE": 0, "INCONCLUSIVE": 0},
                "attempts_run":         1,
                "kb_replayed":          0,
                "kb_pool_size":         kb_count,
                "verified":             True,
                "verification_results": [],
                "inconclusive_reason":  "",
                "attempts":             attempts,
            })
            _save_cve_kb(kb)
            continue

        has_method = bool(cve.get("safe_validation_method") or cve.get("proof_of_impact"))
        if has_method:
            print(f"  [P0] Attempting known test method ...")
            p0_gen = _generate_known_exploit_script(cve, target, msf_hint=msf_hint)
            if p0_gen:
                language = p0_gen["language"]
                strategy = p0_gen["strategy"]
                script   = p0_gen["script"]
                ext      = ".py" if language == "python" else ".sh"
                safe_cve = re.sub(r"[^a-zA-Z0-9_-]", "_", cve_id)
                script_path = os.path.join(cve_tests_dir, f"{safe_cve}_known_exploit{ext}")
                with open(script_path, "w", encoding="utf-8") as fh:
                    fh.write(script)
                sp = _Spinner("[P0] Running known-exploit script ...").start()
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
                    "attempt_num": 1,
                    "source":      "known_exploit",
                    "strategy":    f"[Known] {strategy}",
                    "language":    language,
                    "script":      script,
                    "script_path": script_path,
                    "output":      output[:600],
                    "verdict":     verdict,
                })
            else:
                print("  [P0] Known-exploit script generation failed — skipping.")

        # ------------------------------------------------------------------
        # Phase 1a: Replay Nuclei templates from KB (HTTP/web CVEs only)
        # ------------------------------------------------------------------
        _cve_nuclei_ids = kb_entry.get("nuclei_template_ids", []) if kb_entry else []
        if _cve_nuclei_ids and _is_nuclei_eligible(cve) and not vulnerable_found:
            _nuclei_port = int(cve.get("port", 80)) if str(cve.get("port", "")).isdigit() else 80
            _svc_raw    = (cve.get("service") or "http").lower()
            _nuclei_scheme = "https" if ("ssl" in _svc_raw or "https" in _svc_raw
                                         or _nuclei_port == 443) else "http"
            _nuclei_url = (f"{_nuclei_scheme}://{target}"
                           if _nuclei_port in (80, 443)
                           else f"{_nuclei_scheme}://{target}:{_nuclei_port}")
            print(f"  [Nuclei KB] Replaying {len(_cve_nuclei_ids)} template(s) against {_nuclei_url} ...")
            for _nid in _cve_nuclei_ids:
                _tmpl_entry = nuclei_kb.get(_nid)
                if not _tmpl_entry or not _tmpl_entry.get("yaml_content"):
                    continue
                _safe_cve  = re.sub(r"[^a-zA-Z0-9_-]", "_", cve_id)
                _tmpl_path = os.path.join(cve_tests_dir, f"{_safe_cve}_nuclei_kb_{_nid[-8:]}.yaml")
                _attempt_n = len(attempts) + 1
                _sp = _Spinner(f"[Nuclei KB] {_nid[-20:]} ...").start()
                _nr = await _run_nuclei_template(
                    _tmpl_entry["yaml_content"], _nuclei_url, _tmpl_path, available_tools
                )
                _nverdict = _nr["verdict"]
                _sp.stop(f" {_nverdict}")
                _upsert_nuclei_template(nuclei_kb, _nid, cve_id, _tmpl_entry, _nverdict,
                                        _nr["output"][:300])
                verdict_counts[_nverdict] = verdict_counts.get(_nverdict, 0) + 1
                if _nverdict == "VULNERABLE":
                    vulnerable_found = True
                attempts.append({
                    "attempt_num": _attempt_n,
                    "source":      "nuclei_kb_replay",
                    "strategy":    f"[Nuclei KB] {_tmpl_entry.get('matchers_summary', _nid)}",
                    "language":    "nuclei",
                    "script":      _tmpl_entry.get("yaml_content", "")[:200],
                    "script_path": _tmpl_path,
                    "output":      _nr["output"][:600],
                    "verdict":     _nverdict,
                })
                if vulnerable_found:
                    break

        # ------------------------------------------------------------------
        # Phase 1: Replay KB scripts — tiered selection by success score
        # ------------------------------------------------------------------
        if kb_scripts:
            if kb_selected < kb_count:
                print(f"  [KB] Pool: {kb_count} scripts — replaying {kb_selected} "
                      f"(top-10 by rank + 5 mid-tier + 5 low-tier sample) ...")
            else:
                print(f"  [KB] Replaying {kb_selected} known script(s) ...")
        for kb_idx, kb_script in enumerate(selected_scripts, 1):
            language   = kb_script.get("language", "python")
            strategy   = kb_script.get("strategy", "KB replay")
            script     = kb_script.get("script", "")
            if not script:
                continue
            # Substitute the TARGET_HOST placeholder with the current scan target
            script = script.replace("TARGET_HOST", target)
            ext        = ".py" if language == "python" else ".sh"
            safe_cve   = re.sub(r"[^a-zA-Z0-9_-]", "_", cve_id)
            script_path = os.path.join(cve_tests_dir, f"{safe_cve}_kb_{kb_idx:02d}{ext}")
            with open(script_path, "w", encoding="utf-8") as fh:
                fh.write(script)

            attempt_num = len(attempts) + 1
            sp = _Spinner(f"[KB {kb_idx:02d}/{kb_selected:02d}] Replaying ({language}) ...").start()
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

            # Update per-script run stats so future ranking improves over time
            kb_script["runs"] = kb_script.get("runs", 1) + 1
            if verdict == "VULNERABLE":
                kb_script["vulnerable_count"] = kb_script.get("vulnerable_count", 0) + 1
            elif verdict == "NOT_VULNERABLE":
                kb_script["not_vulnerable_count"] = kb_script.get("not_vulnerable_count", 0) + 1
            else:
                kb_script["inconclusive_count"] = kb_script.get("inconclusive_count", 0) + 1

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
            if vulnerable_found:
                break  # skip remaining KB scripts; proceed to Phase 3

        # ------------------------------------------------------------------
        # Phase 2a: Generate a Nuclei template (HTTP/web CVEs only)
        # ------------------------------------------------------------------
        _do_nuclei_gen = (
            not vulnerable_found
            and _nuclei_available
            and _is_nuclei_eligible(cve)
            and _ollama_is_up()
        )
        if _do_nuclei_gen:
            _gen_port   = int(cve.get("port", 80)) if str(cve.get("port", "")).isdigit() else 80
            _gen_svc    = (cve.get("service") or "http").lower()
            _gen_scheme = "https" if ("ssl" in _gen_svc or "https" in _gen_svc
                                      or _gen_port == 443) else "http"
            _gen_url    = (f"{_gen_scheme}://{target}"
                           if _gen_port in (80, 443)
                           else f"{_gen_scheme}://{target}:{_gen_port}")
            _gen_tmpl   = _generate_nuclei_template(cve, target, _gen_port)
            if _gen_tmpl and _valid_nuclei(_gen_tmpl):
                _gen_tid   = _gen_tmpl["template_id"]
                _safe_cve  = re.sub(r"[^a-zA-Z0-9_-]", "_", cve_id)
                _gen_path  = os.path.join(cve_tests_dir,
                                          f"{_safe_cve}_nuclei_gen_{_gen_tid[-8:]}.yaml")
                _attempt_n = len(attempts) + 1
                _sp = _Spinner(f"[Nuclei Gen] Running {_gen_tid[-20:]} ...").start()
                _nr = await _run_nuclei_template(
                    _gen_tmpl["yaml_content"], _gen_url, _gen_path, available_tools
                )
                _nverdict = _nr["verdict"]
                _sp.stop(f" {_nverdict}")
                _upsert_nuclei_template(nuclei_kb, _gen_tid, cve_id, _gen_tmpl, _nverdict,
                                        _nr["output"][:300])
                # Cross-reference template ID in CVE KB
                _kb_cve_entry = kb.setdefault(cve_id, {
                    "first_tested":  datetime.now(timezone.utc).isoformat(),
                    "last_tested":   datetime.now(timezone.utc).isoformat(),
                    "test_count":    0,
                    "best_verdict":  "INCONCLUSIVE",
                    "verdict_counts": {"VULNERABLE": 0, "NOT_VULNERABLE": 0, "INCONCLUSIVE": 0},
                    "scripts":       [],
                    "nuclei_template_ids": [],
                })
                if _gen_tid not in _kb_cve_entry.setdefault("nuclei_template_ids", []):
                    _kb_cve_entry["nuclei_template_ids"].append(_gen_tid)
                verdict_counts[_nverdict] = verdict_counts.get(_nverdict, 0) + 1
                if _nverdict == "VULNERABLE":
                    vulnerable_found = True
                attempts.append({
                    "attempt_num": _attempt_n,
                    "source":      "nuclei_generated",
                    "strategy":    f"[Nuclei] {_gen_tmpl.get('matchers_summary', _gen_tid)}",
                    "language":    "nuclei",
                    "script":      _gen_tmpl.get("yaml_content", "")[:200],
                    "script_path": _gen_path,
                    "output":      _nr["output"][:600],
                    "verdict":     _nverdict,
                })
                _save_nuclei_kb(nuclei_kb)
            else:
                print(f"  [Nuclei Gen] Template generation failed for {cve_id} — skipping.")

        # ------------------------------------------------------------------
        # Phase 2: Generate up to CVE_FRESH_ATTEMPTS new LLM scripts one at
        #   a time.  After each run, the full result (including output) is
        #   added to `attempts` before the next script is generated, so the
        #   LLM sees real feedback — what failed and why — and can adapt.
        # ------------------------------------------------------------------
        if vulnerable_found:
            print(f"  [Phase 2] VULNERABLE already found — skipping LLM script generation.")
        new_slots   = CVE_FRESH_ATTEMPTS if not vulnerable_found else 0
        done_new    = 0

        # Check Ollama once before generation to avoid burning all slots on
        # connection errors and to surface the real failure reason.
        _p2_ollama_up = _ollama_is_up() if new_slots > 0 else True
        if new_slots > 0 and not _p2_ollama_up:
            print(f"  [Phase 2] Ollama is not reachable — skipping LLM script generation.")

        for i in range(1, new_slots + 1):
            if not _p2_ollama_up:
                # Count the slot as exhausted but don't waste LLM calls
                done_new += 1
                continue

            attempt_num = len(attempts) + 1
            sp = _Spinner(f"[{i:02d}/{new_slots:02d}] Generating script ...").start()
            generated = _generate_cve_test_script(
                cve, target, attempts, kb_entry, attempt_num, msf_hint=msf_hint
            )
            sp.stop(" OK" if generated else " SKIPPED (parse failure)")

            if generated is None:
                done_new += 1
                continue

            language    = generated["language"]
            strategy    = generated["strategy"]
            script      = generated["script"]
            ext         = ".py" if language == "python" else ".sh"
            safe_cve    = re.sub(r"[^a-zA-Z0-9_-]", "_", cve_id)
            script_path = os.path.join(
                cve_tests_dir, f"{safe_cve}_attempt_{attempt_num:02d}{ext}"
            )
            with open(script_path, "w", encoding="utf-8") as fh:
                fh.write(script)

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
            sp2.stop(f" {verdict}")

            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
            if verdict == "VULNERABLE":
                vulnerable_found = True

            print(f"  [{attempt_num:02d}] {strategy[:80]} → {verdict}")
            rec = {
                "attempt_num": attempt_num, "source": "llm_generated",
                "strategy": strategy, "language": language, "script": script,
                "script_path": script_path, "output": output[:600],
                "verdict": verdict, "_gen": generated,
            }
            attempts.append(rec)
            done_new += 1

            # Write non-VULNERABLE results to KB immediately; defer VULNERABLE
            # until Phase 3 confirms (false-positive guard).
            gen = rec.pop("_gen", None)
            if gen is not None and script:
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
                vc = entry.setdefault("verdict_counts",
                                      {"VULNERABLE": 0, "NOT_VULNERABLE": 0, "INCONCLUSIVE": 0})

                if verdict == "VULNERABLE":
                    kb_pending_vulnerable.append({
                        "gen": gen, "script": script, "output": output,
                        "script_hash": script_hash, "strategy": strategy,
                        "language": language,
                    })
                else:
                    vc[verdict] = vc.get(verdict, 0) + 1
                    existing_hashes = {s["script_hash"] for s in entry["scripts"]}
                    if script_hash not in existing_hashes:
                        entry["scripts"].append({
                            "script_hash":          script_hash,
                            "strategy":             strategy,
                            "language":             language,
                            "script":               _scrub_for_kb(script, target),
                            "verdict":              verdict,
                            "runs":                 1,
                            "vulnerable_count":     0,
                            "not_vulnerable_count": 1 if verdict == "NOT_VULNERABLE" else 0,
                            "inconclusive_count":   1 if verdict == "INCONCLUSIVE" else 0,
                            "output_sample":        _scrub_for_kb(output[:400], target),
                            "target_context":       f"{cve.get('product', '')} {cve.get('service', '')}".strip(),
                            "tested_at":            datetime.now(timezone.utc).isoformat(),
                        })
                    _verdict_rank = {"VULNERABLE": 3, "INCONCLUSIVE": 2, "NOT_VULNERABLE": 1}
                    if _verdict_rank.get(verdict, 0) > _verdict_rank.get(entry["best_verdict"], 0):
                        entry["best_verdict"] = verdict

            if vulnerable_found:
                break  # found one — skip remaining slots and go to Phase 3

        # ------------------------------------------------------------------
        # Phase 2c: (removed — results are recorded inline above)
        # ------------------------------------------------------------------
        # Phase 3: False-positive verification — triggered by ANY VULNERABLE
        if vulnerable_found:
            triggering = next((a for a in attempts if a["verdict"] == "VULNERABLE"), None)
            print(f"\n  [VERIFY] VULNERABLE found — running {CVE_VERIFY_ATTEMPTS} independent verifier(s) ...")
            _p3_ollama_up = _ollama_is_up()
            if not _p3_ollama_up:
                print(f"  [VERIFY] Ollama is not reachable — skipping verification.")
            verify_confirmed = 0
            for v_i in range(1, CVE_VERIFY_ATTEMPTS + 1):
                if not _p3_ollama_up:
                    verification_results.append({
                        "verifier_num": v_i, "strategy": "Ollama unavailable",
                        "language": "", "script": "", "output": "", "verdict": "INCONCLUSIVE",
                    })
                    continue

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
        # Flush deferred VULNERABLE KB entries — now that we know whether
        # Phase 3 confirmed them, write the correct verdict into the KB.
        # Unconfirmed false positives are downgraded to INCONCLUSIVE so the
        # KB doesn't accumulate noise from bad concurrent guesses.
        # ------------------------------------------------------------------
        if kb_pending_vulnerable:
            kb_write_verdict = "VULNERABLE" if verified else "INCONCLUSIVE"
            if not verified and kb_pending_vulnerable:
                print(f"  [KB] Downgrading {len(kb_pending_vulnerable)} VULNERABLE "
                      f"pending entry/entries to INCONCLUSIVE (false-positive guard)")
            entry = kb.setdefault(cve_id, {
                "first_tested":   datetime.now(timezone.utc).isoformat(),
                "last_tested":    datetime.now(timezone.utc).isoformat(),
                "test_count":     0,
                "best_verdict":   "INCONCLUSIVE",
                "verdict_counts": {"VULNERABLE": 0, "NOT_VULNERABLE": 0, "INCONCLUSIVE": 0},
                "scripts":        [],
            })
            vc = entry.setdefault("verdict_counts", {"VULNERABLE": 0, "NOT_VULNERABLE": 0, "INCONCLUSIVE": 0})
            existing_hashes = {s["script_hash"] for s in entry["scripts"]}
            for pend in kb_pending_vulnerable:
                vc[kb_write_verdict] = vc.get(kb_write_verdict, 0) + 1
                if pend["script_hash"] not in existing_hashes:
                    entry["scripts"].append({
                        "script_hash":          pend["script_hash"],
                        "strategy":             pend["strategy"],
                        "language":             pend["language"],
                        "script":               _scrub_for_kb(pend["script"], target),
                        "verdict":              kb_write_verdict,
                        "runs":                 1,
                        "vulnerable_count":     1 if kb_write_verdict == "VULNERABLE" else 0,
                        "not_vulnerable_count": 0,
                        "inconclusive_count":   1 if kb_write_verdict == "INCONCLUSIVE" else 0,
                        "output_sample":        _scrub_for_kb(pend["output"][:400], target),
                        "target_context":       f"{cve.get('product', '')} {cve.get('service', '')}".strip(),
                        "tested_at":            datetime.now(timezone.utc).isoformat(),
                    })
                    existing_hashes.add(pend["script_hash"])
            _verdict_rank = {"VULNERABLE": 3, "INCONCLUSIVE": 2, "NOT_VULNERABLE": 1}
            if _verdict_rank.get(kb_write_verdict, 0) > _verdict_rank.get(entry["best_verdict"], 0):
                entry["best_verdict"] = kb_write_verdict

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
              f"I:{verdict_counts['INCONCLUSIVE']}, KB:{kb_selected}/{kb_count} replayed)  "
              f"[CVE time: {cve_elapsed}]")

        inconclusive_reason = (
            _derive_inconclusive_reason(cve, attempts) if overall == "INCONCLUSIVE" else ""
        )

        cve_test_results.append({
            "cve_id":               cve_id,
            "vulnerability_type":   cve.get("vulnerability_type", ""),
            "service":              cve.get("service", ""),
            "overall_verdict":      overall,
            "verdict_counts":       verdict_counts,
            "attempts_run":         len(attempts),
            "kb_replayed":          kb_selected,
            "kb_pool_size":         kb_count,
            "verified":             verified,
            "verification_results": verification_results,
            "inconclusive_reason":  inconclusive_reason,
            "attempts":             attempts,
        })

        # Persist KB progress after every CVE so partial results survive
        # container restarts or early operator stops.
        _save_cve_kb(kb)

        # ------------------------------------------------------------------
        # Batch continuation prompt (runaway guard)
        # ------------------------------------------------------------------
        if cve_idx < total_cves and cve_idx % CVE_BATCH_SIZE == 0:
            remaining = total_cves - cve_idx
            elapsed   = _fmt_dur(time.monotonic() - scan_start)
            print(f"\n{'=' * 52}")
            print(f"  CVE batch complete — {cve_idx}/{total_cves} tested  [{elapsed} elapsed]")
            print(f"  {remaining} CVE(s) remaining.")
            print(f"{'=' * 52}")
            if UNATTENDED:
                print("[*] UNATTENDED: continuing automatically.")
                cont = "y"
            else:
                try:
                    cont = input("  Continue testing remaining CVEs? [y/n]: ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    cont = "n"
            if cont not in ("y", "yes"):
                print(f"[CVE-TEST] Stopped by operator after {cve_idx} CVE(s).")
                break

    return cve_test_results, kb


# ---------------------------------------------------------------------------
# SERVICE HEALTH CHECK — LLM ENRICHMENT
# ---------------------------------------------------------------------------

def _enrich_hc_finding(f) -> None:
    """
    Ask the LLM for a 2-paragraph security narrative for a health-check finding.
    Populates f.description in-place.  Only called for medium/high/critical findings.
    """
    port = f.target.split(":")[-1] if ":" in f.target else f.target
    prompt = (
        f"You are a senior penetration tester summarising a misconfiguration finding for a client report.\n\n"
        f"Service:  {f.service} on port {port}\n"
        f"Finding:  {f.title}  ({f.severity.upper()})\n"
        f"Evidence: {(f.evidence or '')[:300]}\n\n"
        "Write two short paragraphs in plain text (no markdown, no bullet points, no headers):\n"
        "1. Security risk — how an attacker would discover and exploit this misconfiguration, "
        "what access or data they could gain, and the realistic business impact.\n"
        "2. Remediation — one specific immediate action (e.g. change a config setting, "
        "disable a service, enforce a policy) and one permanent architectural recommendation.\n\n"
        "Be specific to this finding. Keep each paragraph to 2-3 sentences. Plain text only."
    )
    _t0 = time.monotonic()
    _sp = _Spinner(f"[ LLM ]  Enriching health-check finding: {f.title[:50]} ...").start()
    try:
        resp = requests.post(
            OLLAMA_URL,
            json={
                "model":      REPORT_MODEL,
                "prompt":     prompt,
                "stream":     False,
                "keep_alive": _OLLAMA_KEEP_ALIVE,
                "options":    {"num_ctx": 1024, "temperature": 0.2},
            },
            timeout=OLLAMA_TIMEOUT,
        )
        text = resp.json().get("response", "").strip()
        if text:
            f.description = text
    except Exception as exc:
        # Non-fatal: finding is useful even without LLM description
        print(f"  [hc] LLM enrichment failed for '{f.title}': {exc}")
    finally:
        _sp.stop(f" done ({_fmt_dur(time.monotonic() - _t0)})")


def _enrich_finding_remediation(f) -> None:
    """
    Ask the LLM (REPORT_MODEL) for 3 concrete, technology-specific steps for both
    the immediate workaround and the permanent fix for a finding.  Populates
    f.llm_remediation_short and f.llm_remediation_long as JSON-encoded lists in-place.
    Applied to all active (critical/high) and hardening (medium/low) findings.
    Non-fatal — silently leaves fields empty on any failure (template falls back to
    the static _REMEDIATION_SHORT_TERM / _REMEDIATION_LONG_TERM maps).
    """
    prompt = (
        "/no_think\n"
        "You are a senior penetration tester writing remediation guidance for a client security report.\n\n"
        f"Finding:     {f.title}  ({f.severity.upper()})\n"
        f"Vuln type:   {f.vuln_type or 'Unknown'}\n"
        f"Service:     {f.service}\n"
        f"Evidence:    {(f.description or f.evidence or '')[:250]}\n\n"
        "Return JSON only — no markdown, no prose outside the object:\n"
        '{"short_steps": ["step 1", "step 2", "step 3"], "long_steps": ["step 1", "step 2", "step 3"]}\n\n'
        "short_steps = 3 immediate workaround actions an operator can complete TODAY without a full upgrade.\n"
        "  Rules: name the exact service, port, config file, or CLI command; use imperative verbs\n"
        "  (Disable, Block, Restrict, Set, Rotate); each step 1-2 sentences max.\n\n"
        "long_steps = 3 permanent remediation actions for the development/infrastructure backlog.\n"
        "  Rules: reference the specific component, version upgrade path, or architectural change;\n"
        "  each step 1-2 sentences max.\n\n"
        f"Technology context: {f.service}. Do NOT write 'apply vendor patch' or 'follow best practices'."
    )
    _sp = _Spinner(f"[ LLM ]  Generating remediation advice: {f.title[:55]} ...").start()
    _t0 = time.monotonic()
    try:
        for attempt in range(MAX_LLM_RETRIES):
            try:
                resp = requests.post(
                    OLLAMA_URL,
                    json={
                        "model":      REPORT_MODEL,
                        "prompt":     prompt,
                        "stream":     False,
                        "keep_alive": _OLLAMA_KEEP_ALIVE,
                        "options":    {"num_ctx": 2048, "temperature": 0.2, "num_predict": 350},
                    },
                    timeout=OLLAMA_TIMEOUT,
                )
                raw = resp.json().get("response", "").strip()
                raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
                raw = re.sub(r"<think>.*", "", raw, flags=re.DOTALL).strip()  # strip unclosed think blocks
                m = re.search(r"\{.*\}", raw, re.DOTALL)
                if m:
                    obj = json.loads(m.group(0))
                    short_steps = obj.get("short_steps", [])
                    long_steps  = obj.get("long_steps",  [])
                    if isinstance(short_steps, list) and short_steps:
                        f.llm_remediation_short = json.dumps(short_steps)
                    if isinstance(long_steps, list) and long_steps:
                        f.llm_remediation_long  = json.dumps(long_steps)
                if f.llm_remediation_short:
                    break  # populated — no need to retry
            except requests.exceptions.Timeout:
                if attempt < MAX_LLM_RETRIES - 1:
                    time.sleep(2)
            except Exception:
                break  # non-retriable error
    finally:
        _sp.stop(f" done ({_fmt_dur(time.monotonic() - _t0)})")


# ---------------------------------------------------------------------------
# CVE REMEDIATION SUGGESTIONS
# ---------------------------------------------------------------------------

def _generate_attacker_perspective(cve: dict) -> str:
    """
    Ask the LLM for a brief threat-actor narrative: how would an attacker exploit
    this CVE and what could they gain?  Returns plain text or empty on failure.
    """
    prompt = (
        "/no_think\n"
        "Output the answer directly. Do not include any reasoning or <think> tags.\n\n"
        f"You are a senior penetration tester writing the threat narrative section of a "
        f"client report.\n\n"
        f"CVE ID:        {cve.get('cve_id', 'Unknown')}\n"
        f"Description:   {cve.get('summary', '')[:400]}\n"
        f"Affected:      {cve.get('product', '')} {cve.get('version_range', '')}\n"
        f"Service:       {cve.get('service', '')}\n"
        f"Vuln type:     {cve.get('vulnerability_type', '')}\n\n"
        "In plain text (no markdown, no bullet symbols), write two short paragraphs:\n"
        "1. How a real attacker would discover and exploit this vulnerability \u2014 initial "
        "access method, tools or techniques likely used, and what level of skill is required.\n"
        "2. What an attacker could gain once exploitation succeeds \u2014 data exposed, "
        "credentials or tokens at risk, potential for lateral movement or privilege "
        "escalation, and the realistic business impact if this is left unpatched.\n\n"
        "Be specific to the vulnerability type. Keep each paragraph to 2-4 sentences. "
        "Plain text only. Begin your answer immediately."
    )
    _t0 = time.monotonic()
    _sp = _Spinner(f"[ LLM ]  Generating attacker perspective for {cve.get('cve_id', 'CVE')} ...").start()
    text = ""
    try:
        for attempt in range(MAX_LLM_RETRIES):
            try:
                resp = requests.post(
                    OLLAMA_URL,
                    json={
                        "model":      REPORT_MODEL,
                        "prompt":     prompt,
                        "stream":     False,
                        "keep_alive": _OLLAMA_KEEP_ALIVE,
                        # num_predict 500 — enough for 2×4-sentence paragraphs plus
                        # a small buffer for any stray <think> tokens before the strip.
                        "options":    {"num_ctx": 2048, "temperature": 0.2, "num_predict": 500},
                    },
                    timeout=OLLAMA_TIMEOUT,
                )
                raw = resp.json().get("response", "").strip()
                # Strip closed and unclosed <think> blocks
                raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
                raw = re.sub(r"<think>.*", "", raw, flags=re.DOTALL).strip()
                if raw:
                    text = raw
                    break
            except requests.exceptions.Timeout:
                if attempt < MAX_LLM_RETRIES - 1:
                    time.sleep(2)
            except Exception:
                break
        return text
    finally:
        _sp.stop(f" done ({_fmt_dur(time.monotonic() - _t0)})")


def _generate_immediate_remediation(cve: dict) -> str:
    """
    Ask the LLM for 3 numbered, CVE-specific steps an operator can take right now
    to reduce exposure — before a permanent patch is available.
    Returns plain text (numbered list), or a short fallback on failure.
    """
    prompt = (
        f"You are a security engineer writing the immediate-action section of a penetration test report.\n\n"
        f"CVE ID:        {cve.get('cve_id', 'Unknown')}\n"
        f"Description:   {cve.get('summary', '')[:400]}\n"
        f"Affected:      {cve.get('product', '')} {cve.get('version_range', '')}\n"
        f"Service:       {cve.get('service', '')}\n"
        f"Port:          {cve.get('port', '')}\n"
        f"Vuln type:     {cve.get('vulnerability_type', '')}\n\n"
        "List exactly 3 numbered steps an operator can take TODAY to reduce exposure for this specific CVE. "
        "Be concrete and specific — name the exact port, service name, config option, or credential type to act on. "
        "Do NOT write generic advice like 'apply the vendor patch' or 'follow best practices'. "
        "Focus on firewall rules, service isolation, config hardening, credential rotation, or access restriction "
        "that can be completed in under an hour without a full upgrade. "
        "Format: '1. <action>  2. <action>  3. <action>' — plain text only, no markdown, no bullet symbols."
    )
    _t0 = time.monotonic()
    _sp = _Spinner(f"[ LLM ]  Generating immediate remediation path for {cve.get('cve_id', 'CVE')} ...").start()
    try:
        resp = requests.post(
            OLLAMA_URL,
            json={
                "model":      SCRIPT_MODEL,
                "prompt":     prompt,
                "stream":     False,
                "keep_alive": _OLLAMA_KEEP_ALIVE,
                "options":    {"num_ctx": 1024, "temperature": 0.2},
            },
            timeout=OLLAMA_TIMEOUT,
        )
        payload = resp.json()
        text = payload.get("response", "").strip()
        return text if text else ""
    except Exception:
        return ""
    finally:
        _sp.stop(f" done ({_fmt_dur(time.monotonic() - _t0)})")


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
            json={
                "model":      SCRIPT_MODEL,
                "prompt":     prompt,
                "stream":     False,
                "keep_alive": _OLLAMA_KEEP_ALIVE,
                "options":    {"num_ctx": 1024, "temperature": 0},
            },
            timeout=OLLAMA_TIMEOUT,
        )
        payload = resp.json()
        text = payload.get("response", "").strip()
        return text if text else ""
    except Exception:
        return ""
    finally:
        _sp.stop(f" done ({_fmt_dur(time.monotonic() - _t0)})")


def _derive_evidence_type(result: dict) -> str:
    """Classify the strongest evidence basis found in a CVE test result.

    Active Probe  — a fresh (non-KB) script ran and observed the vulnerable behaviour
                    or a version string was extracted and confirmed in range.
    KB Replay     — the verdict came from a replayed known-good KB script.
    Banner Analysis — the service banner / version string was matched heuristically
                      without direct behavioural confirmation.
    """
    attempts = result.get("attempts", [])
    fresh_vulnerable = [
        a for a in attempts
        if a.get("verdict") == "VULNERABLE" and a.get("source") != "kb_replay"
    ]
    if fresh_vulnerable:
        for a in fresh_vulnerable:
            output = a.get("output", "").lower()
            if any(kw in output for kw in (
                "version:", "detected version", "extracted version",
                "version found", "banner:", "server version",
            )):
                return "Version Match"
        return "Active Probe"
    kb_vulnerable = [
        a for a in attempts
        if a.get("verdict") == "VULNERABLE" and a.get("source") == "kb_replay"
    ]
    if kb_vulnerable:
        return "KB Replay"
    return "Banner Analysis"


def generate_cve_attacker_perspectives(cve_matches: list) -> int:
    """
    Generate attacker_perspective narrative for all CRITICAL/HIGH/MEDIUM cve_matches
    that don't already have one.  Runs unconditionally (no --cve-test required) so
    the CVE Matches section of the report always has narrative context.

    Mutates each cve_match dict in place.  Returns the number of LLM failures.
    """
    _failed = 0
    perspective_severities = {"CRITICAL", "HIGH", "MEDIUM"}
    targets = [
        c for c in cve_matches
        if c.get("severity", "").upper() in perspective_severities
        and not c.get("attacker_perspective")
    ]
    if not targets:
        return 0
    print(f"\n[REMEDIATION] Generating attacker perspective for {len(targets)} CVE match(es) ...")
    for cve_rec in targets:
        cve_rec["attacker_perspective"] = _generate_attacker_perspective(cve_rec)
        if not cve_rec["attacker_perspective"]:
            _failed += 1
        print(f"  [+] Attacker perspective written for {cve_rec['cve_id']}")
    return _failed


def generate_cve_remediations(cve_test_results: list, cve_matches: list) -> int:
    """
    For each CVE test result that is VULNERABLE or CONFIRMED_VULNERABLE, look up the
    original CVE match record (for full metadata) and call _generate_remediation().
    Attaches a 'remediation' key to the result dict in-place.

    Additionally, generates attacker_perspective for all CRITICAL/HIGH/MEDIUM cve_matches
    that were not covered by active testing (e.g. because requires_auth=True caused them
    to be skipped).  These perspectives are written directly into the cve_match record.

    Returns the total number of LLM failures across all CVE LLM calls.
    """
    _cve_llm_failed = 0
    # Build a quick lookup from cve_id → original cve_match record
    cve_meta = {c["cve_id"]: c for c in cve_matches}

    # ── Phase 1: full remediation set for actively-tested vulnerable CVEs ────
    vulnerable_verdicts = {"CONFIRMED_VULNERABLE", "VULNERABLE"}
    targets = [r for r in cve_test_results if r.get("overall_verdict") in vulnerable_verdicts]
    if targets:
        print(f"\n[REMEDIATION] Generating LLM immediate remediation + attacker perspective + remediation for "
              f"{len(targets)} vulnerable CVE(s) ...")
        for result in targets:
            cve_id  = result["cve_id"]
            cve_rec = cve_meta.get(cve_id, {"cve_id": cve_id})
            result["immediate_remediation"] = _generate_immediate_remediation(cve_rec)
            result["attacker_perspective"]  = _generate_attacker_perspective(cve_rec)
            result["remediation"]           = _generate_remediation(cve_rec)
            result["evidence_type"]         = _derive_evidence_type(result)
            if not result["immediate_remediation"]: _cve_llm_failed += 1
            if not result["attacker_perspective"]:  _cve_llm_failed += 1
            if not result["remediation"]:           _cve_llm_failed += 1
            # Write-back to the cve_match record so the CVE Matches card can also render them
            if cve_id in cve_meta:
                cve_meta[cve_id]["immediate_remediation"] = result["immediate_remediation"]
                cve_meta[cve_id]["attacker_perspective"]  = result["attacker_perspective"]
            print(f"  [+] Immediate remediation + attacker perspective + remediation written for {cve_id}")

    # ── Phase 2: attacker perspective for any remaining untested CVEs ───────
    # Delegates to generate_cve_attacker_perspectives which is also called
    # outside this function when --cve-test is not enabled.
    _cve_llm_failed += generate_cve_attacker_perspectives(cve_matches)

    return _cve_llm_failed


def _audit_report(report: dict, _pass: int = 1) -> dict:
    """
    Proof-read the completed report by feeding a compact text digest back to
    REPORT_MODEL.  The model checks factual accuracy (counts, CVE verdicts),
    internal consistency, and professional tone, then returns brief audit notes.

    Notes-only contract: the audit produces a short assessment string for the
    report (visible in the HTML "Report Audit" collapsible).  It does NOT
    rewrite the conclusion — small report models (qwen3:1.7b) cannot reliably
    embed multi-paragraph prose inside a JSON string without breaking escapes.
    Non-fatal — returns report unchanged on any failure.
    """
    conclusion = report.get("conclusion", "")
    if not conclusion:
        return report

    counts      = report.get("counts", {})
    findings    = report.get("findings", [])
    cve_results = report.get("cve_test_results", [])
    cve_matches = report.get("cve_matches", [])

    # Compact finding digest — top 5 by risk_score
    top_findings = sorted(findings, key=lambda x: x.get("risk_score", 0), reverse=True)[:5]
    finding_lines = [
        f"  - [{_f.get('severity','?').upper()}] {_f.get('title','')[:80]}"
        for _f in top_findings
    ]

    # Compact CVE digest — top 5
    _result_lookup = {r["cve_id"]: r for r in cve_results}
    cve_lines = []
    for _cm in (cve_matches or [])[:5]:
        _cid     = _cm.get("cve_id", "")
        _verdict = _result_lookup.get(_cid, {}).get("overall_verdict", "UNVERIFIED")
        cve_lines.append(f"  - {_cid} ({_cm.get('severity','?').upper()}) verdict={_verdict}")

    digest = (
        f"EXECUTIVE SUMMARY:\n{conclusion}\n\n"
        f"FINDING COUNTS: critical={counts.get('critical',0)} high={counts.get('high',0)} "
        f"medium={counts.get('medium',0)} low={counts.get('low',0)}\n\n"
        "TOP FINDINGS:\n" + "\n".join(finding_lines or ["  (none)"]) + "\n\n"
        + ("CVE MATCHES:\n" + "\n".join(cve_lines) + "\n\n" if cve_lines else "")
    )

    prompt = (
        "/no_think\n"
        "Output the answer directly. Do not include any reasoning or <think> tags.\n\n"
        "You are a senior technical editor auditing the executive summary of a "
        "completed penetration test report before delivery.\n\n"
        "Check the executive summary against the data digest. Specifically verify:\n"
        "1. Do the finding counts mentioned in the summary match the actual counts?\n"
        "2. Are the most serious findings (top of digest) reflected appropriately?\n"
        "3. Are any CVE matches mentioned with accurate verdicts?\n"
        "4. Is the prose professional, complete (not truncated), and free of contradictions?\n\n"
        'Return ONLY a JSON object — no prose outside it, no markdown fences:\n'
        '{"needs_revision": true|false, "audit_notes": "<2-3 sentence assessment>"}\n\n'
        "audit_notes should briefly state what you checked and either confirm the summary "
        "is accurate or describe the specific issue found. Keep it concise and on a single line. "
        "Begin your answer immediately.\n\n"
        f"DATA DIGEST:\n{digest}"
    )

    _t0 = time.monotonic()
    _sp = _Spinner("[ LLM ]  Auditing report for coherence ...").start()
    try:
        resp = requests.post(
            OLLAMA_URL,
            json={
                "model":      REPORT_MODEL,
                "prompt":     prompt,
                "stream":     False,
                "keep_alive": _OLLAMA_KEEP_ALIVE,
                "options":    {"num_ctx": 3072, "temperature": 0.2, "num_predict": 800},
            },
            timeout=OLLAMA_TIMEOUT,
        )
        raw = resp.json().get("response", "").strip()
        # Strip closed and unclosed <think> blocks
        raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
        raw = re.sub(r"<think>.*", "", raw, flags=re.DOTALL).strip()
        _m = re.search(r"\{.*?\}", raw, re.DOTALL)
        if _m:
            try:
                obj   = json.loads(_m.group(0))
                notes = (obj.get("audit_notes", "") or "").strip()
                needs = bool(obj.get("needs_revision", False))
                report["conclusion_audited"] = True
                if notes:
                    report["audit_notes"]        = notes
                    report["conclusion_revised"] = needs  # flag only; no rewrite
            except json.JSONDecodeError:
                _m = None  # fall through to plain-text path
        if not _m and raw:
            # Plain-text fallback — qwen3:1.7b often returns notes without JSON braces.
            # Strip any leading "audit_notes:" / "Notes:" labels and keep first ~400 chars.
            txt = re.sub(r"^\s*(audit[_\s]?notes|notes)\s*[:\-]\s*", "", raw, flags=re.IGNORECASE).strip()
            txt = txt.strip('"\' \t\n')
            if txt:
                report["conclusion_audited"] = True
                report["audit_notes"]        = txt[:400]
    except Exception as e:
        print(f"[!] Report audit error: {e}")
    finally:
        _sp.stop(f" done ({_fmt_dur(time.monotonic() - _t0)})")

    return report


def _build_conclusion_with_cve(report: dict, target: str) -> tuple:
    """Rebuild the conclusion anchor after CVE test results are available.

    If confirmed/vulnerable CVEs exist the conclusion must reflect that —
    overwriting the earlier pre-CVE conclusion stored in the report.
    """
    counts = report.get("counts", {})
    _c, _h, _m, _l = (counts.get(k, 0) for k in ("critical", "high", "medium", "low"))
    _total = _c + _h + _m + _l

    cve_results = report.get("cve_test_results", [])
    confirmed = [r["cve_id"] for r in cve_results if r.get("overall_verdict") == "CONFIRMED_VULNERABLE"]
    vulnerable = [r["cve_id"] for r in cve_results if r.get("overall_verdict") == "VULNERABLE"]

    if _c > 0 or confirmed:
        _posture = "critical"
    elif _h > 0 or vulnerable:
        _posture = "high"
    elif _m > 0:
        _posture = "medium"
    elif _l > 0:
        _posture = "low"
    else:
        _posture = "minimal"

    _finding_parts = []
    if _c: _finding_parts.append(f"{_c} critical")
    if _h: _finding_parts.append(f"{_h} high")
    if _m: _finding_parts.append(f"{_m} medium")
    if _l: _finding_parts.append(f"{_l} low")

    cve_parts = []
    if confirmed:
        cve_parts.append(f"{len(confirmed)} CVE(s) confirmed by active probe testing: {', '.join(confirmed)}")
    if vulnerable:
        cve_parts.append(f"{len(vulnerable)} CVE(s) matched by version/banner analysis — manual verification recommended: {', '.join(vulnerable)}")

    if not _finding_parts:
        # No scanner findings — anchor entirely on CVE results (or clean bill)
        if cve_parts:
            anchor = (
                f"The assessment of {target} identified no scanner findings but CVE testing revealed "
                + "; ".join(cve_parts)
                + f", indicating a {_posture_from_cve(confirmed, vulnerable)}-risk exposure requiring immediate attention."
            )
        else:
            anchor = f"The assessment of {target} identified no exploitable findings, indicating a low-risk security posture."
    else:
        _finding_str = ", ".join(_finding_parts) + f" (total {_total})"
        anchor = (
            f"The assessment of {target} identified {_finding_str} severity findings, "
            f"indicating a {_posture}-risk security posture that requires immediate attention."
        )
        if cve_parts:
            anchor += " CVE testing identified " + "; ".join(cve_parts) + "."

    # Build a mini-summary for the LLM that includes CVE test verdicts
    _services_brief = [
        f"{s.get('port','')}/{s.get('name','')} {s.get('product','')} {s.get('version','')}".strip()
        for s in report.get("services", [])
    ]
    _top_findings = [
        f"{f.get('severity','').upper()}: {f.get('title','')}"
        for f in sorted(
            report.get("findings", []),
            key=lambda x: x.get("risk_score", 0), reverse=True
        )[:6]
    ]
    _mini = {
        "target":          target,
        "services":        _services_brief[:8],
        "finding_counts":  {"critical": _c, "high": _h, "medium": _m, "low": _l},
        "top_findings":    _top_findings,
        "cves_confirmed":  confirmed[:5],
        "cves_vulnerable": vulnerable[:5],
    }

    _llm_prose = ""
    try:
        _resp = requests.post(
            OLLAMA_URL,
            json={
                "model":      REPORT_MODEL,
                "stream":     False,
                "keep_alive": _OLLAMA_KEEP_ALIVE,
                "options":    {"num_ctx": 4096, "temperature": 0.3, "num_predict": 600},
                "prompt": (
                    "/no_think\n"
                    "You are a professional penetration tester writing an executive summary "
                    "for a client-facing security assessment report. "
                    "Write exactly 4 paragraphs of professional prose in plain text. "
                    "No bullet points, no headings, no markdown, no numbered lists. "
                    "Each paragraph must be 3-5 sentences. Use plain business language — "
                    "avoid marketing terms, acronym soup, and vendor jargon. "
                    "Paragraph 1: Describe the scope of the assessment — what was tested, "
                    "what services were discovered, and how many issues were identified overall. "
                    "Give the reader a clear sense of how exposed this device is without "
                    "overstating or understating the risk. "
                    "Paragraph 2: Walk through the finding categories — what types of weaknesses "
                    "were found (authentication issues, unpatched software, configuration "
                    "problems, exposed services), which services carry the most risk, and "
                    "what the spread of severity levels tells us about the security posture. "
                    "Paragraph 3: Identify the 2-3 most serious issues by name and explain in "
                    "plain terms what an attacker could realistically do if they exploited them "
                    "and what the business consequence would be. Focus on impact, not technique. "
                    "Paragraph 4: Summarise the remediation urgency — what needs to be addressed "
                    "within days versus weeks, and whether any findings represent systemic "
                    "weaknesses that point to a broader process or policy gap. "
                    "Do NOT repeat the opening sentence verbatim. "
                    "Do not add disclaimers, sign-offs, or follow-up questions. "
                    f"Opening sentence (incorporate naturally, do not repeat verbatim): {anchor} "
                    f"Assessment data: {json.dumps(_mini, separators=(',', ':'))}"
                ),
            },
            timeout=OLLAMA_TIMEOUT,
        )
        _raw = _resp.json().get("response", "").strip()
        _lines = []
        for _line in _raw.splitlines():
            _s = _line.strip()
            if not _s:
                if _lines:
                    _lines.append("")
                continue
            _lo = _s.lower()
            if _lo.startswith(("**", "##", "# ", "note:", "follow", "question")):
                break
            if _lo.startswith("the assessment of") and not _lines:
                continue
            _lines.append(_s)
        _llm_prose = "\n".join(_lines).strip()
    except Exception:
        pass  # fall back to anchor-only

    if _llm_prose:
        return f"{anchor}\n\n{_llm_prose}", True
    return anchor, False


def _posture_from_cve(confirmed: list, vulnerable: list) -> str:
    """Return posture label driven purely by CVE verdicts (no scanner findings)."""
    if confirmed:
        return "critical"
    if vulnerable:
        return "high"
    return "low"


async def _run_cve_test_phase(report: dict, target: str, session_dir: str,
                              available_tools: dict | None = None) -> dict:
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
        if UNATTENDED:
            print("[*] UNATTENDED: auto-approving CVE testing.")
            answer = "y"
        else:
            try:
                answer = input("  Proceed with CVE testing? [y/n]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                answer = "n"
        if answer not in ("y", "yes"):
            print("[CVE-TEST] Denied by operator.")
            return report

    kb = _load_cve_kb()
    nuclei_kb = _load_nuclei_kb()
    _nuclei_kb_before = len(nuclei_kb)
    try:
        cve_test_results, updated_kb = await run_cve_tests(
            cve_matches, target, session_dir, kb,
            available_tools=available_tools,
            nuclei_kb=nuclei_kb,
        )
    finally:
        # Ensure KBs are persisted even if the scan is interrupted mid-loop.
        _save_cve_kb(kb)
        _save_nuclei_kb(nuclei_kb)
    print(f"[+] CVE knowledge base updated → {CVE_KB_PATH}")
    _nuclei_added = len(nuclei_kb) - _nuclei_kb_before
    if _nuclei_added > 0:
        print(f"[+] Nuclei template KB updated ({_nuclei_added} new template(s)) → {NUCLEI_KB_PATH}")
    else:
        print(f"[i] Nuclei template KB unchanged (no HTTP/web CVEs tested this run) → {NUCLEI_KB_PATH}")

    # Generate LLM remediation suggestions for each confirmed/vulnerable CVE
    report["cve_llm_failed"] = generate_cve_remediations(cve_test_results, cve_matches)

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
    global SAFE_MODE, AIRGAP_MODE, MSF_VALIDATE, CVE_TEST, UNATTENDED, SESSION_FILE
    scan_start = datetime.now()

    if len(sys.argv) < 2:
        print("Usage: python3 noctis.py <target> [profile ...] [--resume] [--session-dir <path>] [--aggressive] [--dns-enum] [--msf-validate] [--cve-test] [--unattended]")
        print("       Target formats: 192.168.0.1  |  hostname  |  host:port  |  host:80,443,8080")
        print("       python3 noctis.py --report <json_file>")
        print("Profiles (one or more):", ", ".join(PROFILES))
        sys.exit(1)

    target        = sys.argv[1]
    # Parse optional port pin: host:port or host:port1,port2,port3
    # The colon suffix is stripped from target so all downstream code (nmap,
    # session naming, tool dispatch) receives a clean hostname/IP.
    pinned_ports: str | None = None
    if ":" in target and not target.startswith("["):   # guard: not an IPv6 literal [::1]
        _host, _ports_str = target.rsplit(":", 1)
        _port_nums = [p.strip() for p in _ports_str.split(",")]
        if _port_nums and all(p.isdigit() and 1 <= int(p) <= 65535 for p in _port_nums):
            target       = _host
            pinned_ports = ",".join(_port_nums)
    profile_names: list = []
    resume        = False
    resume_session_dir: str | None = None

    _argv = sys.argv[2:]
    _i = 0
    while _i < len(_argv):
        arg = _argv[_i]
        if arg in PROFILES:
            profile_names.append(arg)
        elif arg == "--resume":
            resume = True
        elif arg == "--session-dir":
            if _i + 1 < len(_argv):
                _i += 1
                resume_session_dir = _argv[_i]
        elif arg == "--aggressive":
            SAFE_MODE = False
        elif arg == "--dns-enum":
            AIRGAP_MODE = False
        elif arg == "--msf-validate":
            MSF_VALIDATE = True
        elif arg == "--cve-test":
            CVE_TEST = True
        elif arg == "--unattended":
            UNATTENDED = True
        _i += 1

    # Ensure Ollama is running before we attempt any LLM calls
    if not ensure_ollama_running():
        print("[!] Cannot continue without a running Ollama instance. Exiting.")
        sys.exit(1)

    if not profile_names:
        profile_names = ["standard"]

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
        if resume_session_dir and os.path.isdir(resume_session_dir):
            # Resume a specific session chosen by the caller (e.g. via Web UI picker)
            session_dir  = os.path.realpath(resume_session_dir)
            session_id   = os.path.basename(session_dir)
            _sf = os.path.join(session_dir, "session.json")
            try:
                with open(_sf) as _fh:
                    resume_state = json.load(_fh)
            except Exception:
                resume_state = None
        else:
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
    print(f"  Noctis Edge — Security Through Exposure  {VERSION}")
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

    # Pre-initialize nxc so ~/.nxc/ config directory is created before any
    # parallel Phase-1 calls.  Without this, two concurrent nxc_smb actions
    # can both attempt first-time setup simultaneously and crash each other.
    if "nxc" in available_tools:
        try:
            subprocess.run(["nxc", "--version"], capture_output=True, timeout=10)
        except Exception:
            pass

    # Session resume
    if resume:
        if resume_state:
            print(f"[+] Resuming session for {resume_state.get('target', target)} "
                  f"(iteration {resume_state.get('iteration', '?')})")
        else:
            print("[!] No saved session found — starting fresh.")

    # ---------------------------------------------------------------------------
    # Nmap 5-Phase Discovery
    # ---------------------------------------------------------------------------
    print(f"\n{'=' * 52}")
    print("  Nmap Discovery — 5 Phases")
    print(f"{'=' * 52}")
    services, nmap_meta = run_nmap_discovery(target, pinned_ports=pinned_ports)
    _print_scan_eta("Nmap discovery done", scan_start, 0.12)

    if not services:
        print("[!] No open services found. Exiting.")
        sys.exit(0)

    services = rank_and_annotate_services(services)

    print("[+] Gathering target identity information ...")
    target_info = await gather_target_info(target, available_tools, airgap=AIRGAP_MODE)
    target_info.open_ports = len(services)
    # Merge OS data from Phase 4 into TargetInfo if gather_target_info didn't find one
    if not target_info.os_guess and nmap_meta.get("phase4_os", {}).get("name"):
        os4 = nmap_meta["phase4_os"]
        target_info.os_guess    = os4.get("name", "")
        target_info.os_accuracy = os4.get("accuracy", 0)

    # CVE lookup
    print("[+] Searching CVE database ...")
    for s in services:
        s["cves"], s["suppressed_cves"] = cves_for_service(s)
        if s["cves"]:
            label = s.get("product") or s.get("name", "?")
            print(f"    {s['port']}/{s['name']} ({label}): {len(s['cves'])} CVE(s)")
            for c in s["cves"]:
                print(f"      [{c['severity']:8}] {c['id']}: {c['summary'][:80]}...")
        else:
            print(f"    {s['port']}/{s['name']}: no CVEs matched")
        if s.get("suppressed_cves"):
            for c in s["suppressed_cves"]:
                print(f"      [SUPPRESSED] {c['id']}: {c.get('_suppression_reason', '')}")

    svc_summary = ", ".join(
        f"{s['port']}/{s['name']}(p{s['priority']})" for s in services
    )
    print(f"[+] Ranked services: {svc_summary}")

    # Build a compact NSE summary for the LLM context so it can make better
    # decisions about which additional tools/paths to pursue.
    nse_context_lines: list = []
    for svc in services:
        nse_sum = svc.get("nse_summary", "")
        if nse_sum:
            nse_context_lines.append(f"  port {svc['port']}/{svc.get('name', '?')}: {nse_sum[:300]}")

    context = {
        "target":       target,
        "services":     services,
        "history":      [],
        "findings":     [],
        "tool_kb_text": "",   # populated below after KB load
        "nse_context":  "\n".join(nse_context_lines) if nse_context_lines else "",
    }

    tool_kb = _load_tool_kb()
    kb_text = _tool_kb_summary(tool_kb)
    if kb_text:
        context["tool_kb_text"] = kb_text
        print(f"[+] Tool KB loaded — {sum(len(v) for k, v in tool_kb.items() if not k.startswith('_'))} service-slot(s) tracked")
    else:
        print("[+] Tool KB: no prior data — will start building from this scan")

    # Validate manifest coverage against the tool list and warn on gaps
    _validate_manifest_coverage([
        "curl", "nikto", "nikto_cgi", "nuclei", "ffuf",
        "ssh_enum", "rdp_enum", "dns_enum", "mysql_enum", "mssql_enum",
        "nxc_smb", "nxc_ldap",
    ])

    broken_tools: set = set()               # tools structurally broken (binary missing / permission denied)
    timed_out_tools: dict[str, set] = {}    # tool → set of svc_keys where it timed out with no findings
    nmap_phase_cmd = (
        f"nmap -Pn -T4 --open -p- --min-rate 2000 {target} | "
        f"-sV -sC -p <ports> | --script <nse> | -O"
    )
    scan_records = [{"tool": "nmap", "args": target, "cmd": nmap_phase_cmd, "status": "ok", "findings_count": 0}]
    all_findings = []
    used_actions: set = set()  # deduplicate tool+args combos

    # ---------------------------------------------------------------------------
    # Service Security Health Checks
    # Deterministic, read-only analysis of NSE output already collected above.
    # Runs before the LLM scan loop so findings are visible from the first report.
    # ---------------------------------------------------------------------------
    print(f"\n{'=' * 52}")
    print("  Service Security Health Checks")
    print(f"{'=' * 52}")
    hc_findings = _run_service_health_checks(services, target)
    if hc_findings:
        print(f"[+] {len(hc_findings)} health-check finding(s) generated")
        to_enrich = [f for f in hc_findings if f.severity in ("critical", "high", "medium")]
        if to_enrich:
            print(f"[+] Generating security narratives for {len(to_enrich)} finding(s) ...")
            for f in to_enrich:
                _enrich_hc_finding(f)
        all_findings.extend(hc_findings)
    else:
        print("[+] No misconfigurations detected by automated health checks")

    # ---------------------------------------------------------------------------
    # Phase 1 — Parallel initial scan (one tool per service, all concurrent)
    # ---------------------------------------------------------------------------
    if not (resume and resume_state):
        print(f"\n{'=' * 52}")
        print("  Phase 1 — Parallel Initial Scan")
        print(f"{'=' * 52}")
        initial_actions = query_llm_parallel(context, broken_tools, available_tools, used_actions, timed_out_tools)
        if initial_actions:
            print(f"[+] LLM planned {len(initial_actions)} parallel action(s):")
            for a in initial_actions:
                print(f"    {a['tool']:12} → {str(a.get('args', ''))[:70]}")
            wave_results, wave_records = await run_parallel_wave(
                initial_actions, available_tools, session_dir
            )
            for action, output, findings, broken in wave_results:
                tool = action["tool"]
                args = action.get("args", "")
                used_actions.add(f"{tool}:{str(args)}")
                timed_out_w = "Command timed out" in (output or "")
                _record_tool_outcome(
                    tool_kb, tool,
                    _svc_key(tool, args, services),
                    len(findings) if findings else 0,
                    broken, timed_out_w,
                )
                if broken:
                    broken_tools.add(tool)
                    print(f"[!] '{tool}' appears broken — disabling for this session.")
                elif timed_out_w and not findings and tool not in {"ffuf", "nikto"}:
                    _p1_ban_key = _svc_key(tool, args, services)
                    timed_out_tools.setdefault(tool, set()).add(_p1_ban_key)
                    print(f"[!] '{tool}' timed out with no findings on '{_p1_ban_key}' (Phase 1) — "
                          f"skipping this service type in later iterations.")
                else:
                    preview = output[:300].replace("\n", " | ")
                    print(f"\n[>] {tool}: {preview}")
                    if findings:
                        print(f"[+] {len(findings)} finding(s) from {tool}")
                        all_findings.extend(findings)
                        context["findings"] = [dataclasses.asdict(f) for f in all_findings[-5:]]
                context["history"].append({
                    "action":   action,
                    "result":   output[:300],
                    "findings": len(findings) if not broken else 0,
                })
            scan_records.extend(wave_records)
            phase1_count = sum(r.get("findings_count", 0) for r in wave_records)
            print(f"\n[+] Phase 1 complete — {len(wave_records)} tool(s) run, {phase1_count} finding(s)")
            _print_scan_eta("Phase 1 done", scan_start, 0.20)
            # Persist KB and refresh context so sequential loop gets updated rates
            _save_tool_kb(tool_kb)
            context["tool_kb_text"] = _tool_kb_summary(tool_kb)
        else:
            print("[!] Phase 1 returned no actions — proceeding to sequential loop.")

    loop_start = time.monotonic()

    # ---------------------------------------------------------------------------
    # Phase 2 — Service-batched concurrent deep probe loop
    # Services are grouped into batches of PROBE_BATCH_SIZE.  Within each batch
    # every service gets its own LLM query per round; all non-none actions run
    # concurrently via run_parallel_wave.  Services drop out when the LLM returns
    # 'none' or they exhaust MAX_ROUNDS_PER_SERVICE rounds.
    # ---------------------------------------------------------------------------
    def _chunks(lst, n):
        for k in range(0, len(lst), n):
            yield lst[k : k + n]

    total_batches = max(1, -(-len(services) // PROBE_BATCH_SIZE))  # ceiling div
    print(f"\n{'=' * 52}")
    print(f"  Phase 2 — Batched Service Probe Loop")
    print(f"  Services: {len(services)}  |  "
          f"Batch size: {PROBE_BATCH_SIZE}  |  "
          f"Batches: {total_batches}  |  "
          f"Max rounds/service: {MAX_ROUNDS_PER_SERVICE}")
    print(f"{'=' * 52}")

    for batch_idx, svc_batch in enumerate(_chunks(services, PROBE_BATCH_SIZE)):
        print(f"\n[+] Starting batch {batch_idx + 1}/{total_batches} "
              f"({len(svc_batch)} service(s)): "
              + "  Â·  ".join(
                  f"{s.get('port','?')}/{s.get('name','?')}" for s in svc_batch
              ))
        batch_findings = await run_service_probe_batch(
            services_batch  = svc_batch,
            target          = target,
            all_findings    = all_findings,
            used_actions    = used_actions,
            tool_kb         = tool_kb,
            available_tools = available_tools,
            session_dir     = session_dir,
            broken_tools    = broken_tools,
            timed_out_tools = timed_out_tools,
            scan_records    = scan_records,
            batch_idx       = batch_idx,
            total_batches   = total_batches,
        )
        # Persist KB after each batch so partial results survive interruptions
        _save_tool_kb(tool_kb)
        context["tool_kb_text"] = _tool_kb_summary(tool_kb)
        context["findings"] = [dataclasses.asdict(f) for f in all_findings[-5:]]
        print(f"[+] Batch {batch_idx + 1}/{total_batches} complete — "
              f"{len(batch_findings)} finding(s) this batch, "
              f"{len(all_findings)} total so far")

        # Early exit if all tools are broken
        active_tools = set(available_tools.keys()) - broken_tools
        if not active_tools:
            print("[!] All available tools disabled — stopping early.")
            break

    print(f"\n{'=' * 52}")
    print(f"[+] Phase 2 complete — {len(all_findings)} total finding(s) on {target}")
    print(f"[+] Total scan time: {_fmt_dur(time.monotonic() - loop_start)}")
    print(f"{'=' * 52}")
    _print_scan_eta("Iterations complete", scan_start, 0.70)

    report = generate_report(target, services, all_findings, scan_records, profile_name, target_info=target_info)
    # Attach nmap discovery metadata for report consumers and the HTML renderer
    report["nmap_discovery"] = {
        "open_ports":  nmap_meta.get("open_ports", []),
        "os_detected": nmap_meta.get("phase4_os", {}),
        "nse_summary": {
            port: list(scripts.keys())
            for port, scripts in nmap_meta.get("phase3_scripts", {}).items()
            if scripts
        },
    }

    # Save final session state (includes target_info)
    save_session({
        "target":         target,
        "profile":        profile_name,
        "findings_count": len(all_findings),
        "target_info":    target_info.to_dict(),
    })

    if MSF_VALIDATE:
        _print_scan_eta("MSF validation starting", scan_start, 0.70)
        report = await run_msf_validation(report, target, session_dir, available_tools)
        _print_scan_eta("MSF validation done", scan_start, 0.85 if CVE_TEST else 0.93)

    json_path = os.path.join(session_dir, f"report_{safe_tgt}.json")
    html_path = os.path.join(session_dir, f"report_{safe_tgt}.html")

    # Generate attacker_perspective for matched CVEs regardless of --cve-test —
    # the CVE Matches narrative is informational and should always populate when
    # CRITICAL/HIGH/MEDIUM CVEs are present.  Phase 1 (immediate remediation +
    # remediation steps) is still gated on --cve-test inside _run_cve_test_phase.
    report["cve_llm_failed"] = generate_cve_attacker_perspectives(report.get("cve_matches", []))

    if not CVE_TEST:
        # No CVE phase follows — audit now so the final files include any corrections
        report = _audit_report(report)

    # Save base report immediately so it survives an interrupted CVE test phase
    with open(json_path, "w") as fh:
        json.dump(report, fh, indent=2, default=str)
    print(f"[+] JSON report → {json_path}")

    html_content = generate_html_report(report)
    with open(html_path, "w") as fh:
        fh.write(html_content)
    print(f"[+] HTML report → {html_path}")
    _print_scan_eta("Base reports saved", scan_start, 0.88 if CVE_TEST else (0.94 if MSF_VALIDATE else 0.97))

    if CVE_TEST:
        _print_scan_eta("CVE testing starting", scan_start, 0.88)
        report = await _run_cve_test_phase(report, target, session_dir,
                                            available_tools=available_tools)
        # Regenerate conclusion now that CVE verdicts are known
        report["conclusion"], report["conclusion_llm_ok"] = _build_conclusion_with_cve(report, target)
        # Proof-read the completed report for coherence and accuracy before final save
        report = _audit_report(report)
        # Overwrite with updated report containing CVE test results
        with open(json_path, "w") as fh:
            json.dump(report, fh, indent=2, default=str)
        html_content = generate_html_report(report)
        with open(html_path, "w") as fh:
            fh.write(html_content)
        print(f"[+] Reports updated with CVE test results")
        _print_scan_eta("CVE testing done", scan_start, 0.97)

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
        _cve_verdicts = {
            r["cve_id"]: r.get("overall_verdict", "")
            for r in report.get("cve_test_results", [])
            if r.get("cve_id")
        }
        print(f"\n  CVE Matches: {len(cve_matches)}")
        for c in cve_matches[:5]:
            verdict = _cve_verdicts.get(c.get("cve_id", ""), "")
            label = verdict if verdict else c.get("severity", "?")
            print(f"    [{label:<14}] {c.get('cve_id','')} — {c.get('summary','')[:55]}")

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
    print(f"{'=' * 52}")


# ---------------------------------------------------------------------------
# REPORT-FROM-JSON
# ---------------------------------------------------------------------------

def _report_from_json(json_path: str):
    """Load an existing JSON report and regenerate the HTML output."""
    if not os.path.isfile(json_path):
        print(f"[-] File not found: {json_path}")
        sys.exit(1)

    print(f"[*] Loading report from: {json_path}")
    with open(json_path, encoding="utf-8") as fh:
        report = json.load(fh)

    # Back-fill LLM-generated fields from cve_test_results into cve_matches so the
    # CVE Matches cards render the attacker gain block and immediate remediation path
    # even when re-rendering from an older JSON that predates those fields.
    _test_lookup = {r["cve_id"]: r for r in report.get("cve_test_results", []) if r.get("cve_id")}
    for cm in report.get("cve_matches", []):
        _tr = _test_lookup.get(cm.get("cve_id", ""))
        if _tr:
            if "attacker_perspective" not in cm and _tr.get("attacker_perspective"):
                cm["attacker_perspective"] = _tr["attacker_perspective"]
            if "immediate_remediation" not in cm and _tr.get("immediate_remediation"):
                cm["immediate_remediation"] = _tr["immediate_remediation"]

    # Always rebuild the conclusion from live data so it reflects the fixed logic
    # (handles the case where scanner found 0 findings but CVEs are confirmed).
    _regen_target = report.get("target", "unknown")
    report["conclusion"], report["conclusion_llm_ok"] = _build_conclusion_with_cve(report, _regen_target)

    base      = os.path.splitext(os.path.abspath(json_path))[0]
    html_path = base + ".html"

    html_content = generate_html_report(report)
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html_content)
    print(f"[+] HTML report → {html_path}")

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
        _cve_verdicts = {
            r["cve_id"]: r.get("overall_verdict", "")
            for r in report.get("cve_test_results", [])
            if r.get("cve_id")
        }
        print(f"\n  CVE Matches: {len(cve_matches)}")
        for c in cve_matches[:5]:
            verdict = _cve_verdicts.get(c.get("cve_id", ""), "")
            label = verdict if verdict else c.get("severity", "?")
            print(f"    [{label:<14}] {c.get('cve_id', '')} — {c.get('summary', '')[:55]}")

    print(f"\n  Conclusion : {report.get('conclusion', '')}")
    print(f"\n  Reports:")
    print(f"    JSON : {json_path}")
    print(f"    HTML : {html_path}")
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
