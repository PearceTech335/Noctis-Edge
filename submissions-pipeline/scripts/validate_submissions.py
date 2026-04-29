#!/usr/bin/env python3
"""
Noctis-Edge-Submissions — Submission Security Validator

Usage:
  validate_submissions.py <file1.json> [file2.json ...]
  validate_submissions.py --all   (scan every *.json in the repo root)

For each submission file, runs two independent checks on every script:
  1. Static blocklist — instant, no API call
  2. GitHub Models LLM review — gpt-4o-mini (free via $GITHUB_TOKEN)

UNSAFE submissions are moved to quarantine/.
Exits 1 if any files were quarantined (triggers CI failure + issue creation).
Exits 0 if all files are clean.
"""

import glob
import json
import os
import re
import shutil
import sys
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# Static blocklist — first line of defence
# ---------------------------------------------------------------------------

BLOCKLIST = [
    # Destructive commands
    (r"rm\s+-[rf]",                          "Destructive file removal"),
    (r"dd\s+if=",                            "dd if= (disk wipe risk)"),
    (r"\bmkfs\b",                            "mkfs (filesystem formatting)"),
    (r"\bshred\s",                           "shred command"),
    (r":\(\)\{:\|:&\};:",                   "Fork bomb"),
    # Reverse shells
    (r"/dev/tcp/",                           "Reverse shell via /dev/tcp"),
    (r"bash\s+-i\s+>",                       "Reverse shell: bash -i >"),
    (r"nc\s+-e\s+/bin",                      "netcat reverse shell (-e)"),
    (r"ncat.*-e",                            "ncat reverse shell (-e)"),
    (r"mkfifo.*\bnc\b",                      "mkfifo + netcat pipe"),
    # Remote exec chains
    (r"curl\b.*\|\s*sh\b",                   "curl pipe to shell"),
    (r"curl\b.*\|\s*bash\b",                 "curl pipe to bash"),
    (r"wget\b.*\|\s*bash\b",                 "wget pipe to bash"),
    (r"wget\b.*\|\s*sh\b",                   "wget pipe to shell"),
    # Obfuscated eval
    (r"eval\s*\(\s*base64",                  "eval(base64 obfuscation)"),
    (r"exec\s*\(\s*base64",                  "exec(base64 obfuscation)"),
    (r"__import__\s*\(\s*['\"]os['\"].*\.system", "os.system via __import__"),
    # Sensitive local files
    (r"/etc/shadow",                         "Reads /etc/shadow"),
    (r"\.ssh/id_rsa",                        "Reads SSH private key"),
    (r"/proc/\d+/mem",                       "Reads /proc/PID/mem"),
    # Crypto miners
    (r"\bxmrig\b",                           "Crypto miner: xmrig"),
    (r"\bminerd\b",                          "Crypto miner: minerd"),
    (r"\bcpuminer\b",                        "Crypto miner: cpuminer"),
]

# ---------------------------------------------------------------------------
# LLM review via GitHub Models (gpt-4o-mini, free with GITHUB_TOKEN)
# ---------------------------------------------------------------------------

_GITHUB_MODELS_URL = "https://models.inference.ai.azure.com/chat/completions"
_LLM_MODEL = "gpt-4o-mini"

_SYSTEM_PROMPT = (
    "You are a security code reviewer for a penetration testing tool.\n"
    "Classify the script as SAFE or UNSAFE.\n\n"
    "SAFE: passive network probe against a REMOTE target — sends a request, reads a "
    "banner, checks for a vulnerability. Does NOT touch local files, spawn shells, "
    "exfiltrate local data, download and execute code, or cause local DoS.\n\n"
    "UNSAFE: writes/deletes local files, spawns a reverse or bind shell, exfiltrates "
    "local data, downloads and executes additional code, uses obfuscation (base64 eval), "
    "or causes local resource exhaustion.\n\n"
    'Respond ONLY with valid JSON: {"verdict": "SAFE" or "UNSAFE", "reason": "one sentence"}'
)


def _static_check(script: str) -> tuple[bool, str]:
    """Returns (is_safe, reason). False = UNSAFE."""
    for pattern, reason in BLOCKLIST:
        if re.search(pattern, script, re.IGNORECASE):
            return False, f"Static blocklist: {reason}"
    return True, ""


def _llm_check(script: str, github_token: str) -> tuple[bool, str]:
    """Returns (is_safe, reason). False = UNSAFE. On failure, quarantines conservatively."""
    payload = json.dumps({
        "model": _LLM_MODEL,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": f"Classify this script:\n\n```\n{script[:3000]}\n```"},
        ],
        "temperature": 0,
        "max_tokens": 150,
    }).encode()

    req = urllib.request.Request(
        _GITHUB_MODELS_URL,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {github_token}",
            "User-Agent": "Noctis-Edge-Validator/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read())
            content = body["choices"][0]["message"]["content"].strip()
            result = json.loads(content)
            verdict = result.get("verdict", "UNSAFE")
            reason = result.get("reason", "LLM review")
            return (verdict == "SAFE"), f"LLM review: {reason}"
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            # Token doesn't have GitHub Models API access — skip LLM, rely on static check
            return True, f"LLM unavailable (HTTP {exc.code}) — static check only"
        # Other HTTP errors (500, 429, etc.) — be conservative and quarantine
        return False, f"LLM check failed ({exc}) — quarantined for human review"
    except Exception as exc:
        # Network error or parse failure — be conservative and quarantine
        return False, f"LLM check failed ({exc}) — quarantined for human review"


def _validate_file(path: str, github_token: str) -> list[dict]:
    """Validate one submission file. Returns list of findings (empty = all safe)."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:
        return [{"cve": "INVALID", "reason": f"Could not parse JSON: {exc}", "excerpt": ""}]

    findings = []
    for cve_id, entry in data.items():
        if not re.match(r"^CVE-\d{4}-\d+$", cve_id):
            continue
        for script_obj in entry.get("scripts", []):
            script = script_obj.get("script", "")
            if not script:
                continue

            # Check 1: static blocklist
            safe, reason = _static_check(script)
            if not safe:
                findings.append({"cve": cve_id, "reason": reason, "excerpt": script[:200]})
                continue  # No LLM call needed for known-bad

            # Check 2: LLM review (only when we have a token)
            if github_token:
                safe, reason = _llm_check(script, github_token)
                if not safe:
                    findings.append({"cve": cve_id, "reason": reason, "excerpt": script[:200]})

    return findings


def _quarantine(path: str) -> str:
    """Move file to quarantine/ sub-directory. Returns new path."""
    repo_root = os.path.dirname(os.path.abspath(path))
    qdir = os.path.join(repo_root, "quarantine")
    os.makedirs(qdir, exist_ok=True)
    dest = os.path.join(qdir, os.path.basename(path))
    shutil.move(path, dest)
    return dest


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file.json> [...]  |  --all", file=sys.stderr)
        sys.exit(1)

    github_token = os.environ.get("GITHUB_TOKEN", "")
    if not github_token:
        print("[validator] WARNING: GITHUB_TOKEN not set — LLM review skipped, static check only")

    if sys.argv[1] == "--all":
        files = [f for f in glob.glob("*.json") if os.path.isfile(f)]
    else:
        files = [a for a in sys.argv[1:] if a.endswith(".json")]

    if not files:
        print("[validator] No JSON files to validate — done.")
        sys.exit(0)

    any_quarantined = False
    for path in sorted(files):
        if not os.path.isfile(path):
            print(f"[validator] Skipping {path} — not found")
            continue

        print(f"[validator] Checking {os.path.basename(path)} …", flush=True)
        findings = _validate_file(path, github_token)

        if findings:
            dest = _quarantine(path)
            any_quarantined = True
            for f in findings:
                excerpt = repr(f["excerpt"][:200])
                print(f"[validator] UNSAFE  {f['cve']} | {f['reason']} | {excerpt}")
            print(f"[validator] → Quarantined: {dest}")
        else:
            print(f"[validator] SAFE    {os.path.basename(path)}")

    if any_quarantined:
        print("\n[validator] One or more submissions were quarantined.")
        sys.exit(1)

    print("\n[validator] All submissions passed.")
    sys.exit(0)


if __name__ == "__main__":
    main()
