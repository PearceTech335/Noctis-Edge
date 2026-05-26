#!/usr/bin/env python3
# Copyright (C) 2026 Pearce Technologies Pty Ltd
# SPDX-License-Identifier: AGPL-3.0-or-later
# <https://www.gnu.org/licenses/agpl-3.0.html>
"""
Noctis Edge — Tool Knowledge Base Merge Tool

Usage: merge_tool_kb.py <community_tool_kb.json> <local_tool_kb.json>

Additively merges the community tool knowledge base into the local one.
  - If a tool/service-slot is not in the local KB: the entry is added.
  - If a tool/service-slot already exists locally: local data is kept
    (local measurements are more accurate for this machine's tool versions).
    - Exception: existing nmap_nse slots are merged with confidence-weighted
        community counts so script reliability can improve across installs.

The local KB is written atomically (tmp file then os.replace).
Prints a one-line summary and exits 0.  Exits 1 on unrecoverable errors.
"""
import json
import os
import sys
from typing import Any


_COUNT_KEYS = (
    "runs",
    "findings_yielded",
    "total_findings",
    "broken_count",
    "timed_out_count",
)


def _as_non_negative_int(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return max(0, value)
    if isinstance(value, float):
        return max(0, int(round(value)))
    return 0


def _scaled_count(value: Any, numer: int, denom: int) -> int:
    if denom <= 0 or numer <= 0:
        return 0
    base = _as_non_negative_int(value)
    if base <= 0:
        return 0
    return max(0, int(round(base * (numer / float(denom)))))


def _merge_nmap_nse_slot(local_stats: dict, community_stats: dict) -> bool:
    if not isinstance(local_stats, dict) or not isinstance(community_stats, dict):
        return False

    local_runs = _as_non_negative_int(local_stats.get("runs"))
    community_runs = _as_non_negative_int(community_stats.get("runs"))
    if community_runs <= 0:
        return False

    # Lower local confidence means a larger community contribution.
    imported_runs = _as_non_negative_int(round((20 / float(local_runs + 20)) * community_runs))
    imported_runs = min(max(imported_runs, 1), community_runs)

    changed = False
    for key in _COUNT_KEYS:
        increment = _scaled_count(community_stats.get(key), imported_runs, community_runs)
        if increment <= 0:
            continue
        local_stats[key] = _as_non_negative_int(local_stats.get(key)) + increment
        changed = True

    for key, value in community_stats.items():
        if not key.startswith("tax_"):
            continue
        increment = _scaled_count(value, imported_runs, community_runs)
        if increment <= 0:
            continue
        local_stats[key] = _as_non_negative_int(local_stats.get(key)) + increment
        changed = True

    total_runs = _as_non_negative_int(local_stats.get("runs"))
    if total_runs > 0:
        local_stats["success_rate"] = (
            _as_non_negative_int(local_stats.get("findings_yielded")) / float(total_runs)
        )
        local_stats["avg_findings_per_run"] = (
            _as_non_negative_int(local_stats.get("total_findings")) / float(total_runs)
        )

    local_last = local_stats.get("last_run")
    community_last = community_stats.get("last_run")
    if isinstance(community_last, str) and (not isinstance(local_last, str) or community_last > local_last):
        local_stats["last_run"] = community_last
        changed = True

    return changed


def _load_json(path: str, label: str) -> dict:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        print(f"[merge_tool_kb] ERROR: Invalid JSON in {label}: {exc}", file=sys.stderr)
        sys.exit(1)


def _save_json(path: str, data: dict) -> None:
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, path)
    except OSError as exc:
        print(f"[merge_tool_kb] ERROR: Could not write {path}: {exc}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <community_tool_kb.json> <local_tool_kb.json>",
              file=sys.stderr)
        sys.exit(1)

    community_path = sys.argv[1]
    local_path     = sys.argv[2]

    community_kb = _load_json(community_path, "community_tool_kb.json")
    local_kb     = _load_json(local_path, "local tool_knowledge_base.json")

    if not community_kb:
        print("[merge_tool_kb] Community tool KB is empty — nothing to merge.")
        sys.exit(0)

    new_tools = 0
    new_slots = 0
    blended_slots = 0

    for tool_name, svc_map in community_kb.items():
        if tool_name == "_meta":
            continue
        if not isinstance(svc_map, dict):
            continue

        if tool_name not in local_kb:
            # Tool not seen locally at all — add entire entry
            local_kb[tool_name] = svc_map
            new_tools += 1
            new_slots += len(svc_map)
        else:
            # Tool known locally — add only service slots not yet seen
            local_tool = local_kb[tool_name]
            for svc_key, stats in svc_map.items():
                if svc_key not in local_tool:
                    local_tool[svc_key] = stats
                    new_slots += 1
                    continue

                if tool_name == "nmap_nse":
                    if _merge_nmap_nse_slot(local_tool[svc_key], stats):
                        blended_slots += 1

    if new_tools == 0 and new_slots == 0 and blended_slots == 0:
        print("[merge_tool_kb] No new entries — local tool KB already up to date.")
        sys.exit(0)

    _save_json(local_path, local_kb)
    print(
        f"[merge_tool_kb] Merged {new_tools} new tool(s), "
        f"{new_slots} new service slot(s), "
        f"{blended_slots} confidence-weighted nmap_nse slot update(s) into local tool KB."
    )


if __name__ == "__main__":
    main()
