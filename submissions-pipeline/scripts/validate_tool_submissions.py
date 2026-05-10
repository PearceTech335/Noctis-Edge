#!/usr/bin/env python3
# Copyright (C) 2026 Pearce Technologies Pty Ltd
# SPDX-License-Identifier: AGPL-3.0-or-later
# <https://www.gnu.org/licenses/agpl-3.0.html>
"""
Noctis-Edge-Tool-Submissions — Tool KB Submission Validator

Usage:
  validate_tool_submissions.py <file1.json> [file2.json ...]
  validate_tool_submissions.py --all   (scan every *.json in the repo root)

Validates tool performance KB submissions for structural integrity.
Unlike CVE KB validation, there are no code scripts to security-review —
tool KB entries are pure numeric performance statistics.

Validation checks per submission:
  1. Parses as valid JSON
  2. Top-level keys are valid tool names (lowercase alnum + _ / -)
  3. Each tool value is a dict of service-key → stats
  4. Stats contain expected numeric fields with sensible ranges

INVALID submissions are moved to quarantine/.
Exits 1 if any files were quarantined.
Exits 0 if all files are clean.
"""

import glob
import json
import os
import re
import shutil
import sys

# ---------------------------------------------------------------------------
# Validation rules
# ---------------------------------------------------------------------------

# Tool name: lowercase alphanumeric + underscores/hyphens, 1-50 chars
TOOL_NAME_RE = re.compile(r'^[a-z_][a-z0-9_-]{0,49}$')
# Service key: bare label (e.g. "http"), product/label (e.g. "nginx/http",
# "golang-net/http-server/http"), or the special value "unknown".
# Port numbers are intentionally absent — noctis.py tracks what works against
# which infrastructure type, not which port a service ran on in a single scan.
SVC_KEY_RE   = re.compile(r'^([a-z0-9][a-z0-9._\-/]{0,79}|unknown)$')

REQUIRED_STATS_FIELDS = {"runs", "findings_yielded", "total_findings", "success_rate",
                          "avg_findings_per_run", "broken_count", "timed_out_count"}

# Sanity bounds
MAX_RUNS         = 100_000
MAX_FINDINGS     = 10_000_000
MAX_TOOL_COUNT   = 100
MAX_SVC_COUNT    = 500   # per tool


def _validate_submission(path: str) -> tuple[bool, str]:
    """
    Validate a single submission file.
    Returns (is_valid, reason).  is_valid=False means quarantine.
    """
    # 1. Parse JSON
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        return False, f"Invalid JSON: {exc}"
    except OSError as exc:
        return False, f"Cannot read file: {exc}"

    if not isinstance(data, dict):
        return False, "Top-level value must be a JSON object"

    # 2. Check tool count
    tool_keys = [k for k in data if k != "_meta"]
    if len(tool_keys) > MAX_TOOL_COUNT:
        return False, f"Too many tool entries ({len(tool_keys)} > {MAX_TOOL_COUNT})"

    # 3. Validate each tool entry
    for tool_name, svc_map in data.items():
        if tool_name == "_meta":
            continue

        if not TOOL_NAME_RE.match(tool_name):
            return False, f"Invalid tool name '{tool_name}' — must be lowercase alnum/underscore/hyphen"

        if not isinstance(svc_map, dict):
            return False, f"Tool '{tool_name}': value must be a JSON object of service slots"

        if len(svc_map) > MAX_SVC_COUNT:
            return False, f"Tool '{tool_name}': too many service slots ({len(svc_map)} > {MAX_SVC_COUNT})"

        for svc_key, stats in svc_map.items():
            if not SVC_KEY_RE.match(svc_key):
                return False, f"Tool '{tool_name}': invalid service key '{svc_key}'"

            if not isinstance(stats, dict):
                return False, f"Tool '{tool_name}'/'{svc_key}': stats must be a JSON object"

            # Check required fields exist and are numeric
            for field in REQUIRED_STATS_FIELDS:
                if field not in stats:
                    return False, f"Tool '{tool_name}'/'{svc_key}': missing field '{field}'"
                val = stats[field]
                if not isinstance(val, (int, float)):
                    return False, f"Tool '{tool_name}'/'{svc_key}': field '{field}' must be numeric"
                if val != val:  # NaN check
                    return False, f"Tool '{tool_name}'/'{svc_key}': field '{field}' is NaN"

            # Sanity range checks
            runs = stats["runs"]
            if runs < 0:
                return False, f"Tool '{tool_name}'/'{svc_key}': runs cannot be negative"
            if runs > MAX_RUNS:
                return False, f"Tool '{tool_name}'/'{svc_key}': runs ({runs}) exceeds maximum"
            if stats["findings_yielded"] < 0 or stats["total_findings"] < 0:
                return False, f"Tool '{tool_name}'/'{svc_key}': findings counts cannot be negative"
            if stats["total_findings"] > MAX_FINDINGS:
                return False, f"Tool '{tool_name}'/'{svc_key}': total_findings exceeds maximum"
            success_rate = stats["success_rate"]
            if not (0.0 <= success_rate <= 1.0):
                return False, f"Tool '{tool_name}'/'{svc_key}': success_rate {success_rate} out of [0,1]"
            avg = stats["avg_findings_per_run"]
            if avg < 0:
                return False, f"Tool '{tool_name}'/'{svc_key}': avg_findings_per_run cannot be negative"

    return True, ""


def _quarantine(path: str, reason: str) -> None:
    os.makedirs("quarantine", exist_ok=True)
    dest = os.path.join("quarantine", os.path.basename(path))
    shutil.move(path, dest)
    print(f"[validator] QUARANTINED {path}: {reason}")


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file1.json> ... | --all", file=sys.stderr)
        sys.exit(1)

    if sys.argv[1] == "--all":
        paths = [
            f for f in glob.glob("*.json")
            if os.path.isfile(f) and f not in ("community_tool_kb.json",)
        ]
    else:
        paths = sys.argv[1:]

    if not paths:
        print("[validator] No submission files to validate.")
        sys.exit(0)

    quarantined = 0
    for path in paths:
        is_valid, reason = _validate_submission(path)
        if is_valid:
            print(f"[validator] OK   {path}")
        else:
            _quarantine(path, reason)
            quarantined += 1

    if quarantined:
        print(f"[validator] {quarantined} file(s) quarantined.")
        sys.exit(1)

    print(f"[validator] All {len(paths)} submission(s) passed validation.")
    sys.exit(0)


if __name__ == "__main__":
    main()
