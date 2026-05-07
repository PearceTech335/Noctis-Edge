#!/usr/bin/env python3
"""
Noctis-Edge-Tool-Submissions — Community Tool KB Build Script

Usage: build_community_tool_kb.py [output_path] [--trust-admin UUID]
  output_path defaults to community_tool_kb.json
  --trust-admin UUID  treat this user's entries as if they meet the MIN_RUNS gate

Reads all *.json from the repo root (never quarantine/).
Aggregates tool performance statistics across all user submissions:
  - Sums runs, findings_yielded, total_findings, broken_count, timed_out_count
  - Recalculates success_rate and avg_findings_per_run from aggregated totals
  - Records submission_count (number of users who contributed each entry)

Quality gate: only includes entries with total_runs >= 3 across all users.
  (admin UUID bypasses this when --trust-admin is set)
Safety gate:  re-runs structural validation before writing output.
Output:       community_tool_kb.json with a built_at ISO timestamp.
"""

import glob
import json
import os
import re
import sys
from datetime import datetime, timezone

# Tool name and service key patterns (mirror validate_tool_submissions.py)
TOOL_NAME_RE = re.compile(r'^[a-z_][a-z0-9_-]{0,49}$')
SVC_KEY_RE   = re.compile(r'^([a-z0-9][a-z0-9._\-/]{0,79}|unknown)$')

MIN_RUNS_FOR_INCLUSION = 3   # entries with fewer combined runs are excluded


def _structural_ok(tool_name: str, svc_key: str, stats: dict) -> bool:
    """Quick structural check — defence in depth before writing output."""
    if not TOOL_NAME_RE.match(tool_name):
        return False
    if not SVC_KEY_RE.match(svc_key):
        return False
    for field in ("runs", "findings_yielded", "total_findings",
                  "success_rate", "avg_findings_per_run", "broken_count", "timed_out_count"):
        v = stats.get(field)
        if not isinstance(v, (int, float)) or v != v:  # NaN check
            return False
    return True


def main() -> None:
    args = sys.argv[1:]
    trust_admin: str | None = None
    if "--trust-admin" in args:
        idx = args.index("--trust-admin")
        if idx + 1 < len(args):
            trust_admin = args.pop(idx + 1)
        args.pop(idx)
    output_path = args[0] if args else "community_tool_kb.json"
    if trust_admin:
        print(f"[build_tool_kb] Trust-admin mode: UUID {trust_admin} bypasses the runs gate.")

    submission_files = [
        f for f in glob.glob("*.json")
        if os.path.isfile(f) and f != os.path.basename(output_path)
    ]

    print(f"[build_tool_kb] Found {len(submission_files)} submission file(s).")

    # -------------------------------------------------------------------------
    # Aggregate:
    #   { tool_name: { svc_key: { totals..., user_ids: set } } }
    # -------------------------------------------------------------------------
    aggregated: dict[str, dict[str, dict]] = {}
    files_ok = 0
    files_skipped = 0

    for path in sorted(submission_files):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as exc:
            print(f"[build_tool_kb] Skipping {path}: {exc}")
            files_skipped += 1
            continue

        user_id = os.path.splitext(os.path.basename(path))[0]
        files_ok += 1

        for tool_name, svc_map in data.items():
            if tool_name == "_meta":
                continue
            if not TOOL_NAME_RE.match(tool_name) or not isinstance(svc_map, dict):
                continue

            for svc_key, stats in svc_map.items():
                if not SVC_KEY_RE.match(svc_key) or not isinstance(stats, dict):
                    continue

                runs = stats.get("runs", 0)
                if not isinstance(runs, (int, float)) or runs <= 0:
                    continue

                agg_tool = aggregated.setdefault(tool_name, {})
                agg_slot = agg_tool.setdefault(svc_key, {
                    "runs":               0,
                    "findings_yielded":   0,
                    "total_findings":     0,
                    "broken_count":       0,
                    "timed_out_count":    0,
                    "submission_count":   0,
                    "_user_ids":          set(),
                })

                # Only count each user once per slot (take their latest submission)
                # We just add/overwrite — sorted() ensures consistent ordering
                if user_id in agg_slot["_user_ids"]:
                    # Already seen this user — subtract their previous contribution
                    # (Not tracked separately, so just accept the overwrite behaviour:
                    # because files are re-read each build, this naturally averages)
                    pass

                agg_slot["runs"]             += runs
                agg_slot["findings_yielded"] += max(0, stats.get("findings_yielded", 0))
                agg_slot["total_findings"]   += max(0, stats.get("total_findings", 0))
                agg_slot["broken_count"]     += max(0, stats.get("broken_count", 0))
                agg_slot["timed_out_count"]  += max(0, stats.get("timed_out_count", 0))
                agg_slot["_user_ids"].add(user_id)
                agg_slot["submission_count"]  = len(agg_slot["_user_ids"])

    print(f"[build_tool_kb] Processed {files_ok} file(s), skipped {files_skipped}.")

    # -------------------------------------------------------------------------
    # Build output — apply quality gate and compute derived fields
    # -------------------------------------------------------------------------
    output: dict[str, dict] = {}
    total_slots = 0
    excluded_slots = 0

    for tool_name, svc_map in sorted(aggregated.items()):
        tool_out: dict[str, dict] = {}
        for svc_key, agg in sorted(svc_map.items()):
            total_runs = agg["runs"]

            is_admin_slot = trust_admin is not None and trust_admin in agg["_user_ids"]
            if total_runs < MIN_RUNS_FOR_INCLUSION and not is_admin_slot:
                excluded_slots += 1
                continue

            # Recalculate derived rates from aggregated totals
            fy  = agg["findings_yielded"]
            tf  = agg["total_findings"]
            success_rate        = round(fy / total_runs, 4) if total_runs > 0 else 0.0
            avg_findings_per_run = round(tf / total_runs, 4) if total_runs > 0 else 0.0

            entry = {
                "runs":               total_runs,
                "findings_yielded":   fy,
                "total_findings":     tf,
                "success_rate":       success_rate,
                "avg_findings_per_run": avg_findings_per_run,
                "broken_count":       agg["broken_count"],
                "timed_out_count":    agg["timed_out_count"],
                "submission_count":   agg["submission_count"],
            }

            if _structural_ok(tool_name, svc_key, entry):
                tool_out[svc_key] = entry
                total_slots += 1

        if tool_out:
            output[tool_name] = tool_out

    output["_meta"] = {
        "built_at":        datetime.now(timezone.utc).isoformat(),
        "total_tools":     len(output) - 1,  # exclude _meta
        "total_slots":     total_slots,
        "excluded_slots":  excluded_slots,
        "min_runs_gate":   MIN_RUNS_FOR_INCLUSION,
    }

    # -------------------------------------------------------------------------
    # Write output
    # -------------------------------------------------------------------------
    tmp = output_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(output, fh, indent=2)
    os.replace(tmp, output_path)

    print(
        f"[build_tool_kb] Written {output_path}: "
        f"{len(output) - 1} tool(s), {total_slots} slot(s) "
        f"({excluded_slots} excluded by quality gate)."
    )


if __name__ == "__main__":
    main()
