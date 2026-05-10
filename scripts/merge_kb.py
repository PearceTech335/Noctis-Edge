#!/usr/bin/env python3
# Copyright (C) 2026 Pearce Technologies Pty Ltd
# SPDX-License-Identifier: AGPL-3.0-or-later
# <https://www.gnu.org/licenses/agpl-3.0.html>
"""
Noctis Edge — CVE Knowledge Base Merge Tool

Usage: merge_kb.py <community_kb.json> <local_kb.json>

Additively merges the community knowledge base into the local knowledge base.
  - If a CVE is not in the local KB: the entire entry is added.
  - If a CVE already exists: only scripts with a new script_hash are appended.

The local KB is written atomically (tmp file then os.replace).
Prints a one-line summary and exits 0.  Exits 1 on unrecoverable errors.
"""
import json
import os
import sys


def _load_json(path: str, label: str) -> dict:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        print(f"[merge_kb] ERROR: Invalid JSON in {label}: {exc}", file=sys.stderr)
        sys.exit(1)


def _save_json(path: str, data: dict) -> None:
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, path)
    except OSError as exc:
        print(f"[merge_kb] ERROR: Could not write {path}: {exc}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <community_kb.json> <local_kb.json>", file=sys.stderr)
        sys.exit(1)

    community_path = sys.argv[1]
    local_path = sys.argv[2]

    community_kb = _load_json(community_path, "community_kb.json")
    local_kb = _load_json(local_path, "local cve_knowledge_base.json")

    if not community_kb:
        print("[merge_kb] Community KB is empty — nothing to merge.")
        sys.exit(0)

    new_cves = 0
    new_scripts = 0

    for cve_id, community_entry in community_kb.items():
        if not cve_id.startswith("CVE-"):
            continue
        if cve_id not in local_kb:
            # Brand-new CVE — add the full entry
            local_kb[cve_id] = community_entry
            new_cves += 1
            new_scripts += len(community_entry.get("scripts", []))
        else:
            # CVE already known — merge scripts by hash to avoid duplicates
            local_entry = local_kb[cve_id]
            existing_hashes = {
                s["script_hash"]
                for s in local_entry.get("scripts", [])
                if s.get("script_hash")
            }
            for script in community_entry.get("scripts", []):
                h = script.get("script_hash")
                if h and h not in existing_hashes:
                    local_entry.setdefault("scripts", []).append(script)
                    existing_hashes.add(h)
                    new_scripts += 1

    _save_json(local_path, local_kb)
    print(f"[merge_kb] Merged: {new_cves} new CVE(s), {new_scripts} new script(s) added to local KB.")


if __name__ == "__main__":
    main()
