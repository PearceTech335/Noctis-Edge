#!/usr/bin/env python3
# Copyright (C) 2026 Pearce Technologies Pty Ltd
# SPDX-License-Identifier: AGPL-3.0-or-later
# <https://www.gnu.org/licenses/agpl-3.0.html>
"""Download NVD JSON 2.0 feeds and extract CVSS v3.1/v4.0 scores to a lean CSV.

NVD publishes per-year gzipped JSON feeds at:
  https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz

Each year file is accompanied by a .meta file that records the SHA256 and
lastModifiedDate, so we can skip years whose local copy is already current.

Output file: CVE/nvd-cvss.csv
Columns:     cve_id,cvss_v3_score,cvss_v3_vector,cvss_v3_severity,cvss_v4_score,cvss_v4_vector

Run via update.sh or standalone: python3 scripts/build_nvd_cvss.py
"""

import csv
import gzip
import io
import json
import os
import re
import sys
import urllib.request
from datetime import datetime

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT      = os.path.join(BASE_DIR, "CVE", "nvd-cvss.csv")
CACHE_DIR   = os.path.join(BASE_DIR, "CVE", ".nvd-cache")
FEED_BASE   = "https://nvd.nist.gov/feeds/json/cve/2.0"
START_YEAR  = 2002
CURRENT_YEAR = datetime.now().year


def _meta_url(year: int) -> str:
    return f"{FEED_BASE}/nvdcve-2.0-{year}.meta"


def _feed_url(year: int) -> str:
    return f"{FEED_BASE}/nvdcve-2.0-{year}.json.gz"


def _fetch(url: str, timeout: int = 180) -> bytes | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Noctis-Edge/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except Exception as e:
        print(f"  [NVD] Fetch error {url}: {e}")
        return None


def _cached_meta(year: int) -> str:
    path = os.path.join(CACHE_DIR, f"{year}.meta")
    if os.path.isfile(path):
        with open(path) as f:
            return f.read()
    return ""


def _write_cached_meta(year: int, content: str) -> None:
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(os.path.join(CACHE_DIR, f"{year}.meta"), "w") as f:
        f.write(content)


def _parse_meta_date(meta_content: str) -> str:
    """Extract lastModifiedDate from .meta file content."""
    for line in meta_content.splitlines():
        if line.startswith("lastModifiedDate:"):
            return line.split(":", 1)[1].strip()
    return ""


def _extract_cvss(entry: dict) -> dict:
    """Extract CVSS v3.1 and v4.0 data from an NVD JSON 2.0 entry."""
    metrics = entry.get("metrics", {})
    result = {
        "cve_id":          entry.get("id", ""),
        "cvss_v3_score":   "",
        "cvss_v3_vector":  "",
        "cvss_v3_severity": "",
        "cvss_v4_score":   "",
        "cvss_v4_vector":  "",
    }

    # CVSS v3.1 — prefer primary, fall back to secondary source
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            # Primary source preferred
            entries.sort(key=lambda x: 0 if x.get("type") == "Primary" else 1)
            m = entries[0].get("cvssData", {})
            result["cvss_v3_score"]    = str(m.get("baseScore", ""))
            result["cvss_v3_vector"]   = m.get("vectorString", "")
            result["cvss_v3_severity"] = m.get("baseSeverity", "")
            break

    # CVSS v4.0
    for entry_item in metrics.get("cvssMetricV40", []):
        m = entry_item.get("cvssData", {})
        result["cvss_v4_score"]  = str(m.get("baseScore", ""))
        result["cvss_v4_vector"] = m.get("vectorString", "")
        break

    return result


def _process_year(year: int) -> list[dict]:
    """Download (if stale) and parse the NVD feed for a given year."""
    print(f"  [NVD] Year {year} ...", end=" ", flush=True)

    # Check .meta for staleness
    meta_raw = _fetch(_meta_url(year), timeout=15)
    if meta_raw is None:
        print("meta fetch failed — skipping")
        return []
    meta_str  = meta_raw.decode("utf-8", errors="replace")
    remote_ts = _parse_meta_date(meta_str)
    local_ts  = _parse_meta_date(_cached_meta(year))

    if remote_ts and local_ts and remote_ts == local_ts:
        # Check if cached CSV rows exist
        cached_rows_path = os.path.join(CACHE_DIR, f"{year}.rows.json")
        if os.path.isfile(cached_rows_path):
            print("up-to-date (cached)")
            with open(cached_rows_path, encoding="utf-8") as f:
                return json.load(f)
        print("up-to-date (no cache row file) — re-downloading")

    # Download the full feed
    gz_data = _fetch(_feed_url(year), timeout=300)
    if gz_data is None:
        print("download failed — skipping")
        return []

    try:
        with gzip.open(io.BytesIO(gz_data)) as gz:
            feed = json.load(gz)
    except Exception as e:
        print(f"decompress/parse failed: {e} — skipping")
        return []

    cve_items = feed.get("vulnerabilities", [])
    rows = [_extract_cvss(item.get("cve", {})) for item in cve_items if item.get("cve")]
    rows = [r for r in rows if r["cve_id"]]

    # Cache for future incremental runs
    os.makedirs(CACHE_DIR, exist_ok=True)
    cached_rows_path = os.path.join(CACHE_DIR, f"{year}.rows.json")
    with open(cached_rows_path, "w", encoding="utf-8") as f:
        json.dump(rows, f)
    _write_cached_meta(year, meta_str)

    print(f"{len(rows):,} CVEs")
    return rows


def main() -> int:
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    os.makedirs(CACHE_DIR, exist_ok=True)

    print("[NVD] Building CVSS database from NVD JSON 2.0 feeds ...")
    all_rows: list[dict] = []
    for year in range(START_YEAR, CURRENT_YEAR + 1):
        all_rows.extend(_process_year(year))

    if not all_rows:
        print("[NVD] ERROR: No CVE data collected. Check internet connectivity.")
        return 1

    print(f"[NVD] Writing {len(all_rows):,} records → {OUTPUT}")
    tmp = OUTPUT + ".tmp"
    fieldnames = ["cve_id", "cvss_v3_score", "cvss_v3_vector", "cvss_v3_severity",
                  "cvss_v4_score", "cvss_v4_vector"]
    with open(tmp, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)
    os.replace(tmp, OUTPUT)

    print("[NVD] Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
