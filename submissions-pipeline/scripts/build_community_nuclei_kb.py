#!/usr/bin/env python3
# Copyright (C) 2026 Pearce Technologies Pty Ltd
# SPDX-License-Identifier: AGPL-3.0-or-later
# <https://www.gnu.org/licenses/agpl-3.0.html>
"""
Noctis-Edge-Nuclei-Submissions — Community Nuclei KB Build Script

Usage: build_community_nuclei_kb.py [output_path] [--trust-admin UUID]
  output_path defaults to community_nuclei_kb.json
  --trust-admin UUID  treat this user's templates as if confirmed by 2 submitters

Reads all *.json from the repo root.
Quality filter:
  - same template_id must appear in >= 2 independent submissions (different user_id)
    (admin UUID bypasses this requirement when --trust-admin is set)
  - template_id must match the allowed key pattern
Output: community_nuclei_kb.json with a built_at ISO timestamp.
"""

import glob
import json
import os
import re
import sys
from datetime import datetime, timezone

# Template ID pattern — must match worker.js NUCLEI_TMPL_KEY_RE
TMPL_KEY_RE = re.compile(r"^[a-z0-9_/-]{3,120}$")

# Basic YAML safety check — block templates that embed shell payloads
YAML_BLOCKLIST = [
    (r"rm\s+-[rf]",                   "Destructive file removal"),
    (r"/dev/tcp/",                    "Reverse shell via /dev/tcp"),
    (r"bash\s+-i\s+>",               "Reverse shell: bash -i >"),
    (r"nc\s+-e\s+/bin",              "netcat reverse shell (-e)"),
    (r"curl\b.*\|\s*(sh|bash)\b",    "curl pipe to shell"),
    (r"wget\b.*\|\s*(sh|bash)\b",    "wget pipe to shell"),
    (r"eval\s*\(\s*base64",          "eval(base64 obfuscation)"),
    (r"\bxmrig\b",                   "Crypto miner: xmrig"),
    (r"\bminerd\b",                  "Crypto miner: minerd"),
]


def _yaml_safe(yaml_content: str) -> bool:
    for pattern, _ in YAML_BLOCKLIST:
        if re.search(pattern, yaml_content, re.IGNORECASE):
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
    output_path = args[0] if args else "community_nuclei_kb.json"
    if trust_admin:
        print(f"[build_nuclei_kb] Trust-admin mode: UUID {trust_admin} bypasses the ≥2 submitter threshold.")

    submission_files = [
        f for f in glob.glob("*.json")
        if os.path.isfile(f)
        and f != os.path.basename(output_path)
    ]

    print(f"[build_nuclei_kb] Found {len(submission_files)} submission file(s) in repo root.")

    # -------------------------------------------------------------------------
    # Aggregate: { template_id: { user_ids: set, template_obj: dict } }
    # The last submission seen for a template_id wins for the template data.
    # -------------------------------------------------------------------------
    aggregated: dict[str, dict] = {}
    files_ok = 0
    files_skipped = 0

    for path in sorted(submission_files):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as exc:
            print(f"[build_nuclei_kb] Skipping {path}: {exc}")
            files_skipped += 1
            continue

        if not isinstance(data, dict):
            print(f"[build_nuclei_kb] Skipping {path}: not a JSON object")
            files_skipped += 1
            continue

        user_id = os.path.splitext(os.path.basename(path))[0]
        files_ok += 1

        for tmpl_id, tmpl_obj in data.items():
            if not TMPL_KEY_RE.match(tmpl_id):
                continue
            if not isinstance(tmpl_obj, dict):
                continue

            bucket = aggregated.setdefault(tmpl_id, {
                "user_ids":   set(),
                "tmpl_obj":   tmpl_obj,
            })
            bucket["user_ids"].add(user_id)
            # Update template data from latest submission
            bucket["tmpl_obj"] = tmpl_obj

    # -------------------------------------------------------------------------
    # Quality filter + YAML safety gate
    # -------------------------------------------------------------------------
    community_kb: dict[str, dict] = {}
    included = 0
    filtered_quality = 0
    filtered_safety = 0

    for tmpl_id in sorted(aggregated):
        info = aggregated[tmpl_id]

        effective_count = len(info["user_ids"])
        if trust_admin and trust_admin in info["user_ids"]:
            effective_count = max(effective_count, 2)
        if effective_count < 2:
            filtered_quality += 1
            continue

        yaml_content = info["tmpl_obj"].get("yaml_content", "")
        if yaml_content and not _yaml_safe(yaml_content):
            filtered_safety += 1
            print(f"[build_nuclei_kb] SAFETY GATE blocked {tmpl_id}")
            continue

        entry = dict(info["tmpl_obj"])
        entry["community_confirmations"] = len(info["user_ids"])
        community_kb[tmpl_id] = entry
        included += 1

    # -------------------------------------------------------------------------
    # Write output
    # -------------------------------------------------------------------------
    output = {
        "built_at": datetime.now(timezone.utc).isoformat(),
        "stats": {
            "files_processed": files_ok,
            "files_skipped": files_skipped,
            "templates_included": included,
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
        f"[build_nuclei_kb] Built {output_path} — "
        f"{included} template(s) "
        f"(quality filtered: {filtered_quality}, safety blocked: {filtered_safety})"
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
