#!/usr/bin/env python3
"""
Noctis Edge — Tool Knowledge Base Merge Tool

Usage: merge_tool_kb.py <community_tool_kb.json> <local_tool_kb.json>

Additively merges the community tool knowledge base into the local one.
  - If a tool/service-slot is not in the local KB: the entry is added.
  - If a tool/service-slot already exists locally: local data is kept
    (local measurements are more accurate for this machine's tool versions).

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

    if new_tools == 0 and new_slots == 0:
        print("[merge_tool_kb] No new entries — local tool KB already up to date.")
        sys.exit(0)

    _save_json(local_path, local_kb)
    print(
        f"[merge_tool_kb] Merged {new_tools} new tool(s), "
        f"{new_slots} new service slot(s) into local tool KB."
    )


if __name__ == "__main__":
    main()
