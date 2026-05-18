#!/usr/bin/env python3
# Copyright (C) 2026 Pearce Technologies Pty Ltd
# SPDX-License-Identifier: AGPL-3.0-or-later
# <https://www.gnu.org/licenses/agpl-3.0.html>
"""
Noctis Edge — Community KB Pull Tool

Usage: pull_community_kb.py <relay_url> <license_key> <cvekb_dir>

Downloads all community KB shards from the Noctis relay and merges them
into the local CVE_KB/ directory.  Designed for pre-flight download before
airgapped deployments — run this while online so the full KB is present on
disk before you disconnect.

Steps:
  1. POST {license_key} to relay  →  manifest.json (tiny, lists all shards)
  2. For each shard, POST {license_key, shard}  →  shard JSON
  3. Merge each shard into local CVE_KB/<shard>.json, deduplicating by script_hash
  4. New CVEs and scripts are additive — existing verified entries are kept

Exit codes: 0 = success, 1 = error
"""
import json
import os
import pathlib
import re
import ssl
import sys
import urllib.error
import urllib.request

# Strict shard-name validation — mirrors the Worker's SHARD_NAME_RE
_SHARD_RE = re.compile(r"^CVE-\d{4}-\d+$")


def _post_json(relay_url: str, payload: dict, timeout: int = 60) -> dict:
    """POST JSON to relay, return parsed response.  Raises RuntimeError on failure."""
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        relay_url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent":   "Noctis-Edge/1.0",
        },
    )

    def _attempt(ctx=None):
        kwargs = {"timeout": timeout}
        if ctx is not None:
            kwargs["context"] = ctx
        with urllib.request.urlopen(req, **kwargs) as resp:
            return json.loads(resp.read())

    try:
        return _attempt()
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read())
            msg  = body.get("error") or body.get("message") or str(exc)
        except Exception:
            msg = str(exc)
        if exc.code == 403:
            raise RuntimeError(
                f"License key rejected (HTTP 403): {msg}\n"
                "Check your subscription at https://noctisedge.lemonsqueezy.com"
            )
        raise RuntimeError(f"HTTP {exc.code}: {msg}")
    except Exception as exc:
        if "CERTIFICATE_VERIFY_FAILED" in str(exc) or "certificate is not yet valid" in str(exc):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            try:
                return _attempt(ctx)
            except Exception as exc2:
                raise RuntimeError(f"Network error (SSL fallback): {exc2}") from exc2
        raise RuntimeError(f"Network error: {exc}") from exc


def _merge_shard(existing: dict, incoming: dict) -> tuple[int, int]:
    """Merge incoming shard data into existing dict in-place.

    Returns (new_cves, new_scripts) counts.
    Only CVE-prefixed keys are processed; metadata keys (built_at, stats) are ignored.
    """
    new_cves    = 0
    new_scripts = 0

    for cve_id, community_entry in incoming.items():
        if not cve_id.startswith("CVE-"):
            continue
        if not isinstance(community_entry, dict):
            continue

        if cve_id not in existing:
            existing[cve_id] = community_entry
            new_cves    += 1
            new_scripts += len(community_entry.get("scripts", []))
        else:
            # Merge scripts by hash — never duplicate
            local_entry = existing[cve_id]
            existing_hashes = {
                s["script_hash"]
                for s in local_entry.get("scripts", [])
                if isinstance(s, dict) and s.get("script_hash")
            }
            for script in community_entry.get("scripts", []):
                if not isinstance(script, dict):
                    continue
                h = script.get("script_hash")
                if h and h not in existing_hashes:
                    local_entry.setdefault("scripts", []).append(script)
                    existing_hashes.add(h)
                    new_scripts += 1

    return new_cves, new_scripts


def main() -> None:
    if len(sys.argv) != 4:
        print(
            f"Usage: {sys.argv[0]} <relay_url> <license_key> <cvekb_dir>",
            file=sys.stderr,
        )
        sys.exit(1)

    relay_url   = sys.argv[1]
    license_key = sys.argv[2]
    cvekb_dir   = pathlib.Path(sys.argv[3])
    cvekb_dir.mkdir(parents=True, exist_ok=True)

    community_kb_url = relay_url.rstrip("/").removesuffix("/submit") + "/community-kb"

    # ── Step 1: Fetch manifest ────────────────────────────────────────────────
    print("[pull_kb] Fetching community KB manifest ...")
    try:
        manifest = _post_json(community_kb_url, {"license_key": license_key})
    except RuntimeError as exc:
        print(f"[pull_kb] ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    shards = manifest.get("shards", [])
    if not shards:
        print("[pull_kb] Manifest returned no shards — community KB may not be built yet.")
        sys.exit(0)

    built_at = manifest.get("built_at", "unknown")
    print(f"[pull_kb] Manifest: {len(shards)} shard(s), built {built_at}")

    # ── Step 2 & 3: Download + merge each shard ───────────────────────────────
    total_cves    = 0
    total_scripts = 0
    errors        = 0

    for i, shard_info in enumerate(shards, 1):
        name = shard_info.get("name") if isinstance(shard_info, dict) else shard_info

        # Validate locally before sending to the wire
        if not isinstance(name, str) or not _SHARD_RE.match(name):
            print(f"[pull_kb] WARNING: Skipping invalid shard name in manifest: {name!r}")
            continue

        shard_path = cvekb_dir / f"{name}.json"
        print(f"[pull_kb] [{i}/{len(shards)}] Downloading {name} ...", end=" ", flush=True)

        try:
            shard_data = _post_json(
                community_kb_url, {"license_key": license_key, "shard": name}
            )
        except RuntimeError as exc:
            print(f"FAILED ({exc})")
            errors += 1
            continue

        # Load existing local shard (if any)
        local: dict = {}
        if shard_path.exists():
            try:
                with open(shard_path, "r", encoding="utf-8") as fh:
                    local = json.load(fh)
            except Exception:
                local = {}

        new_cves, new_scripts = _merge_shard(local, shard_data)

        # Write atomically
        tmp = str(shard_path) + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(local, fh, indent=2)
            os.replace(tmp, str(shard_path))
        except OSError as exc:
            # Docker bind-mount EXDEV fallback
            try:
                import shutil
                shutil.copy2(tmp, str(shard_path))
                os.remove(tmp)
            except Exception as exc2:
                print(f"FAILED (write error: {exc2})")
                errors += 1
                continue

        total_cves    += new_cves
        total_scripts += new_scripts
        print(f"OK (+{new_cves} CVEs, +{new_scripts} scripts)")

    # ── Summary ───────────────────────────────────────────────────────────────
    if errors:
        print(
            f"[pull_kb] Completed with {errors} error(s). "
            f"Added {total_cves} CVE(s) and {total_scripts} script(s).",
            file=sys.stderr,
        )
        sys.exit(1)
    else:
        print(
            f"[pull_kb] Done. Added {total_cves} CVE(s) and {total_scripts} script(s) "
            f"across {len(shards)} shard(s) → {cvekb_dir}/"
        )
        sys.exit(0)


if __name__ == "__main__":
    main()
