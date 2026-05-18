#!/usr/bin/env python3
# Copyright (C) 2026 Pearce Technologies Pty Ltd
# SPDX-License-Identifier: AGPL-3.0-or-later
"""One-time migration: split monolithic cve_knowledge_base.json files into
sharded per-year/range JSON files inside CVE_KB/.

Sources merged (highest priority first):
  1. cve_knowledge_base.json           (root — human-verified, highest priority)
  2. improvements/Generate_CVE/cve_knowledge_base.json  (LLM-generated PENDING)
  3. improvements/cve_knowledge_base.json               (audited import, lowest)

Merge rule: if the same CVE-ID appears in multiple sources, the entry with
more scripts wins.  On a tie, the higher-priority source wins.

Output: CVE_KB/CVE-<year>-<start>.json  (SHARD_SIZE = 5 000)

Run once from the project root:
    python scripts/migrate_kb_to_shards.py [--dry-run]
"""
import argparse
import json
import os
import sys

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KB_OUT_DIR  = os.path.join(BASE_DIR, "CVE_KB")
SHARD_SIZE  = 5_000

SOURCES = [
    os.path.join(BASE_DIR, "cve_knowledge_base.json"),
    os.path.join(BASE_DIR, "improvements", "Generate_CVE", "cve_knowledge_base.json"),
    os.path.join(BASE_DIR, "improvements", "cve_knowledge_base.json"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _shard_path(cve_id: str) -> str:
    parts = cve_id.split("-")
    year  = parts[1] if len(parts) >= 2 else "unknown"
    seq   = int(parts[2]) if len(parts) >= 3 and parts[2].isdigit() else 0
    start = (seq // SHARD_SIZE) * SHARD_SIZE or 1
    return os.path.join(KB_OUT_DIR, f"CVE-{year}-{start}.json")


def _load(path: str) -> dict:
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        assert isinstance(data, dict), f"{path}: expected top-level JSON object"
        return data
    except Exception as exc:
        print(f"[WARN] Could not load {path}: {exc}", file=sys.stderr)
        return {}


def _merge_entry(existing: dict, incoming: dict) -> dict:
    """Return the better of two entries for the same CVE-ID.

    'Better' means more scripts.  On a tie, existing (higher priority) wins.
    Scripts are deduplicated by script_hash when merging.
    """
    ex_scripts = existing.get("scripts", [])
    in_scripts = incoming.get("scripts", [])

    if len(in_scripts) <= len(ex_scripts):
        # Existing already has at least as many scripts — still absorb any
        # unique hashes from the incoming entry.
        existing_hashes = {s["script_hash"] for s in ex_scripts}
        for s in in_scripts:
            if s["script_hash"] not in existing_hashes:
                ex_scripts.append(s)
                existing_hashes.add(s["script_hash"])
        return existing

    # Incoming has more scripts — start from incoming, absorb unique existing ones.
    incoming_hashes = {s["script_hash"] for s in in_scripts}
    for s in ex_scripts:
        if s["script_hash"] not in incoming_hashes:
            in_scripts.append(s)
            incoming_hashes.add(s["script_hash"])
    return incoming


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true",
                    help="Print what would be written without touching disk")
    args = ap.parse_args()

    # ── Load and merge all sources ──────────────────────────────────────────
    merged: dict = {}
    total_loaded = 0
    for src in SOURCES:
        data = _load(src)
        if not data:
            print(f"[skip] {src} — not found or empty")
            continue
        print(f"[load] {src}  ({len(data):,} entries)")
        total_loaded += len(data)
        for cve_id, entry in data.items():
            if cve_id in merged:
                merged[cve_id] = _merge_entry(merged[cve_id], entry)
            else:
                merged[cve_id] = entry

    print(f"\n[info] {len(merged):,} unique CVE entries after merge "
          f"(from {total_loaded:,} total across sources)")

    if not merged:
        print("[done] Nothing to migrate.")
        return 0

    # ── Shard into output dict ───────────────────────────────────────────────
    shards: dict[str, dict] = {}
    for cve_id, entry in merged.items():
        path = _shard_path(cve_id)
        shards.setdefault(path, {})[cve_id] = entry

    print(f"[info] {len(shards)} shard file(s) will be written to {KB_OUT_DIR}/\n")

    # ── Write shards ─────────────────────────────────────────────────────────
    if args.dry_run:
        for path, shard in sorted(shards.items()):
            print(f"  [DRY-RUN] {os.path.basename(path):40s}  {len(shard):>6,} entries")
        print("\n[dry-run] No files written.")
        return 0

    os.makedirs(KB_OUT_DIR, exist_ok=True)
    written = 0
    for path, shard in sorted(shards.items()):
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(shard, fh, indent=2, default=str)
            os.replace(tmp, path)
            print(f"  [write] {os.path.basename(path):40s}  {len(shard):>6,} entries")
            written += 1
        except Exception as exc:
            print(f"  [ERROR] {path}: {exc}", file=sys.stderr)
            if os.path.exists(tmp):
                os.unlink(tmp)

    print(f"\n[done] {written}/{len(shards)} shard(s) written to {KB_OUT_DIR}/")
    print(f"       Original files are unchanged — remove them manually once verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
