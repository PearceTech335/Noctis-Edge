#!/usr/bin/env python3
# Copyright (C) 2026 Pearce Technologies Pty Ltd
# SPDX-License-Identifier: AGPL-3.0-or-later
# <https://www.gnu.org/licenses/agpl-3.0.html>
"""
Noctis Edge — Nuclei Template Knowledge Base Submission Tool

Usage: submit_nuclei_kb.py <nuclei_kb_path> <user_id> [relay_url]

Submits the local Nuclei template knowledge base to the Noctis Edge community
relay.  Target IP addresses are stripped before submission so no target
infrastructure data leaves the host.

Exit codes: 0 = success or skipped, 1 = error
"""
import json
import re
import ssl
import sys
import urllib.request
import urllib.error

RELAY_URL = "https://noctis-kb-relay.pearcetechnologies1.workers.dev/submit-nuclei"

_RE_IPV4       = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_RE_LOCAL_PATH = re.compile(r'(?:/[\w.\-]+){3,}/(?:sessions|cve_tests)/[\w/._\-]+')


def _sanitize_nuclei_kb(nkb: dict) -> dict:
    """Return a deep copy with target IPs and local paths scrubbed from yaml_content
    and output_samples fields."""
    import copy
    nkb = copy.deepcopy(nkb)
    for entry in nkb.values():
        if not isinstance(entry, dict):
            continue
        if isinstance(entry.get("yaml_content"), str):
            entry["yaml_content"] = _RE_IPV4.sub("{{BaseURL}}", entry["yaml_content"])
        samples = entry.get("output_samples", [])
        if isinstance(samples, list):
            entry["output_samples"] = [
                _RE_IPV4.sub("<TARGET>", _RE_LOCAL_PATH.sub("<path>", s))
                if isinstance(s, str) else s
                for s in samples
            ]
    return nkb


def main() -> None:
    if len(sys.argv) not in (3, 4):
        print(f"Usage: {sys.argv[0]} <nuclei_kb_path> <user_id> [relay_url]", file=sys.stderr)
        sys.exit(1)

    kb_path   = sys.argv[1]
    user_id   = sys.argv[2]
    relay_url = sys.argv[3] if len(sys.argv) == 4 else RELAY_URL

    if "REPLACE_WITH" in relay_url:
        print("[submit_nuclei_kb] Relay URL not configured — skipping.")
        sys.exit(0)

    try:
        with open(kb_path, "r", encoding="utf-8") as fh:
            nkb_data = json.load(fh)
    except FileNotFoundError:
        print("[submit_nuclei_kb] No local Nuclei KB found — skipping submission.")
        sys.exit(0)
    except json.JSONDecodeError as exc:
        print(f"[submit_nuclei_kb] ERROR: Invalid JSON in {kb_path}: {exc}", file=sys.stderr)
        sys.exit(1)

    if not nkb_data:
        print("[submit_nuclei_kb] Local Nuclei KB is empty — skipping submission.")
        sys.exit(0)

    nkb_data = _sanitize_nuclei_kb(nkb_data)

    payload = json.dumps({"user_id": user_id, "nuclei_kb": nkb_data}).encode()
    req = urllib.request.Request(
        relay_url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent":   "Noctis-Edge/1.0",
        },
    )

    def _do_request(ctx: "ssl.SSLContext | None" = None) -> None:
        kwargs = {"timeout": 30}
        if ctx is not None:
            kwargs["context"] = ctx
        with urllib.request.urlopen(req, **kwargs) as resp:
            body = resp.read().decode()
            code = resp.getcode()
            if code == 200:
                print(f"[submit_nuclei_kb] Accepted: {body[:120]}")
            else:
                print(f"[submit_nuclei_kb] Unexpected HTTP {code}: {body[:120]}", file=sys.stderr)
                sys.exit(1)

    try:
        _do_request()
    except urllib.error.URLError as exc:
        if "CERTIFICATE_VERIFY_FAILED" in str(exc):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            _do_request(ctx)
        else:
            print(f"[submit_nuclei_kb] Network error: {exc}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
