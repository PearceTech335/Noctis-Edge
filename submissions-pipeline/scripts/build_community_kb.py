#!/usr/bin/env python3
# Copyright (C) 2026 Pearce Technologies Pty Ltd
# SPDX-License-Identifier: AGPL-3.0-or-later
# <https://www.gnu.org/licenses/agpl-3.0.html>
"""
Noctis-Edge-Submissions — Community KB Build Script

Usage: build_community_kb.py [output_path] [--trust-admin UUID]
  output_path defaults to community_kb.json
  --trust-admin UUID  treat this user's scripts as if confirmed by 2 submitters

Reads all *.json from the repo root (never quarantine/).
Quality filter:
  - script verdict must be VULNERABLE or NOT_VULNERABLE
  - same script_hash must appear in >= 2 independent submissions (different user_id)
    (admin UUID bypasses this requirement when --trust-admin is set)
Final safety gate: re-runs the full static blocklist before writing output.
Output: community_kb.json with a built_at ISO timestamp.
"""

import glob
import json
import os
import re
import sys
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Static blocklist — identical to validate_submissions.py (defence in depth)
# ---------------------------------------------------------------------------

BLOCKLIST = [
    (r"rm\s+-[rf]",                          "Destructive file removal"),
    (r"dd\s+if=",                            "dd if= (disk wipe risk)"),
    (r"\bmkfs\b",                            "mkfs (filesystem formatting)"),
    (r"\bshred\s",                           "shred command"),
    (r":\(\)\{:\|:&\};:",                   "Fork bomb"),
    (r"/dev/tcp/",                           "Reverse shell via /dev/tcp"),
    (r"bash\s+-i\s+>",                       "Reverse shell: bash -i >"),
    (r"nc\s+-e\s+/bin",                      "netcat reverse shell (-e)"),
    (r"ncat.*-e",                            "ncat reverse shell (-e)"),
    (r"mkfifo.*\bnc\b",                      "mkfifo + netcat pipe"),
    (r"curl\b.*\|\s*sh\b",                   "curl pipe to shell"),
    (r"curl\b.*\|\s*bash\b",                 "curl pipe to bash"),
    (r"wget\b.*\|\s*bash\b",                 "wget pipe to bash"),
    (r"wget\b.*\|\s*sh\b",                   "wget pipe to shell"),
    (r"eval\s*\(\s*base64",                  "eval(base64 obfuscation)"),
    (r"exec\s*\(\s*base64",                  "exec(base64 obfuscation)"),
    (r"__import__\s*\(\s*['\"]os['\"].*\.system", "os.system via __import__"),
    (r"/etc/shadow",                         "Reads /etc/shadow"),
    (r"\.ssh/id_rsa",                        "Reads SSH private key"),
    (r"/proc/\d+/mem",                       "Reads /proc/PID/mem"),
    (r"\bxmrig\b",                           "Crypto miner: xmrig"),
    (r"\bminerd\b",                          "Crypto miner: minerd"),
    (r"\bcpuminer\b",                        "Crypto miner: cpuminer"),
]


def _static_safe(script: str) -> bool:
    for pattern, _ in BLOCKLIST:
        if re.search(pattern, script, re.IGNORECASE):
            return False
    return True


# ---------------------------------------------------------------------------
# Build logic
# ---------------------------------------------------------------------------

def main() -> None:
    args = sys.argv[1:]
    trust_admin: str | None = None
    if "--trust-admin" in args:
        idx = args.index("--trust-admin")
        if idx + 1 < len(args):
            trust_admin = args.pop(idx + 1)
        args.pop(idx)
    output_path = args[0] if args else "community_kb.json"
    if trust_admin:
        print(f"[build_kb] Trust-admin mode: UUID {trust_admin} bypasses the ≥2 submitter threshold.")

    # Find all submission files — skip quarantine/ and the output file itself
    submission_files = [
        f for f in glob.glob("*.json")
        if os.path.isfile(f)
        and f != os.path.basename(output_path)
    ]

    print(f"[build_kb] Found {len(submission_files)} submission file(s) in repo root.")

    # -------------------------------------------------------------------------
    # Aggregate: { cve_id: { script_hash: { user_ids: set, script_obj: dict } } }
    # -------------------------------------------------------------------------
    aggregated: dict[str, dict[str, dict]] = {}
    files_ok = 0
    files_skipped = 0

    for path in sorted(submission_files):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as exc:
            print(f"[build_kb] Skipping {path}: {exc}")
            files_skipped += 1
            continue

        # User ID is the filename stem (UUID)
        user_id = os.path.splitext(os.path.basename(path))[0]
        files_ok += 1

        for cve_id, entry in data.items():
            if not re.match(r"^CVE-\d{4}-\d+$", cve_id):
                continue
            for script_obj in entry.get("scripts", []):
                verdict = script_obj.get("verdict", "")
                if verdict not in ("VULNERABLE", "NOT_VULNERABLE"):
                    continue
                script_hash = script_obj.get("script_hash", "")
                if not script_hash:
                    continue

                bucket = aggregated.setdefault(cve_id, {}).setdefault(script_hash, {
                    "user_ids": set(),
                    "script_obj": script_obj,
                })
                bucket["user_ids"].add(user_id)

    # -------------------------------------------------------------------------
    # Quality filter + final safety gate
    # -------------------------------------------------------------------------
    community_kb: dict[str, dict] = {}
    included = 0
    filtered_quality = 0
    filtered_safety = 0

    for cve_id, hashes in sorted(aggregated.items()):
        accepted: list[dict] = []
        for script_hash, info in hashes.items():
            # Must appear in >= 2 independent submissions (admin UUID counts as 2)
            effective_count = len(info["user_ids"])
            if trust_admin and trust_admin in info["user_ids"]:
                effective_count = max(effective_count, 2)
            if effective_count < 2:
                filtered_quality += 1
                continue

            # Final static safety gate (defence in depth)
            script_text = info["script_obj"].get("script", "")
            if not _static_safe(script_text):
                filtered_safety += 1
                print(f"[build_kb] SAFETY GATE blocked {cve_id}/{script_hash[:8]}…")
                continue

            script_entry = dict(info["script_obj"])
            script_entry["community_confirmations"] = len(info["user_ids"])
            accepted.append(script_entry)
            included += 1

        if accepted:
            community_kb[cve_id] = {"scripts": accepted}

    # -------------------------------------------------------------------------
    # Write output
    # -------------------------------------------------------------------------
    output = {
        "built_at": datetime.now(timezone.utc).isoformat(),
        "stats": {
            "files_processed": files_ok,
            "files_skipped": files_skipped,
            "cves_included": len(community_kb),
            "scripts_included": included,
            "filtered_quality": filtered_quality,
            "filtered_safety": filtered_safety,
        },
    }
    output.update(community_kb)

    tmp = output_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(output, fh, indent=2)
    os.replace(tmp, output_path)

    print(
        f"[build_kb] Built {output_path} — "
        f"{included} script(s) across {len(community_kb)} CVE(s) "
        f"(quality filtered: {filtered_quality}, safety blocked: {filtered_safety})"
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
