#!/usr/bin/env python3
"""Build the offline CVE summary database from NVD JSON 2.0 feeds.

Downloads per-year NVD feeds and extracts CVE IDs, severities, and English
descriptions into CVE/cve-offline/cve-summary.csv.

Format (3 columns, no header):
    CVE-XXXX-XXXXX,SEVERITY,"English description text"

Severities are taken from CVSS v3.1 baseSeverity where available, falling back
to v3.0 then v4.0, then "NONE" if no score data is present.

The same NVD cache written by build_nvd_cvss.py is reused, so running both
scripts does not double-download the feeds.

Run standalone: python3 scripts/build_cve_db.py
Run via docker-entrypoint.sh on first boot (no CVE CSV present).
"""

import csv
import gzip
import io
import json
import os
import sys
import urllib.request
from datetime import datetime

BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT       = os.path.join(BASE_DIR, "CVE", "cve-offline", "cve-summary.csv")
CACHE_DIR    = os.path.join(BASE_DIR, "CVE", ".nvd-cache")
FEED_BASE    = "https://nvd.nist.gov/feeds/json/cve/2.0"
START_YEAR   = 2002
CURRENT_YEAR = datetime.now().year


def _meta_url(year: int) -> str:
    return f"{FEED_BASE}/nvdcve-2.0-{year}.meta"


def _feed_url(year: int) -> str:
    return f"{FEED_BASE}/nvdcve-2.0-{year}.json.gz"


def _fetch(url: str, timeout: int = 300) -> bytes | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Noctis-Edge/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except Exception as e:
        print(f"  [CVE-DB] Fetch error {url}: {e}")
        return None


def _cached_meta(year: int) -> str:
    path = os.path.join(CACHE_DIR, f"{year}.meta")
    if os.path.isfile(path):
        with open(path) as f:
            return f.read()
    return ""


def _parse_meta_date(meta_content: str) -> str:
    for line in meta_content.splitlines():
        if line.startswith("lastModifiedDate:"):
            return line.split(":", 1)[1].strip()
    return ""


def _write_cached_meta(year: int, content: str) -> None:
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(os.path.join(CACHE_DIR, f"{year}.meta"), "w") as f:
        f.write(content)


def _extract_entry(cve: dict) -> dict | None:
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    # English description
    description = "No description available."
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            text = d.get("value", "").strip()
            if text:
                description = text
            break

    # Severity — prefer CVSS v3.1, v3.0, v4.0
    severity = "NONE"
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
        entries = metrics.get(key, [])
        if entries:
            entries.sort(key=lambda x: 0 if x.get("type") == "Primary" else 1)
            sev = entries[0].get("cvssData", {}).get("baseSeverity", "")
            if sev:
                severity = sev
                break

    return {"id": cve_id, "severity": severity, "summary": description}


def _process_year(year: int) -> list[dict]:
    print(f"  [CVE-DB] Year {year} ...", end=" ", flush=True)

    meta_raw = _fetch(_meta_url(year), timeout=15)
    if meta_raw is None:
        print("meta fetch failed — skipping")
        return []

    meta_str  = meta_raw.decode("utf-8", errors="replace")
    remote_ts = _parse_meta_date(meta_str)
    local_ts  = _parse_meta_date(_cached_meta(year))

    # Reuse cached row file if already up-to-date
    cached_rows_path = os.path.join(CACHE_DIR, f"{year}.cve-db.rows.json")
    if remote_ts and local_ts and remote_ts == local_ts and os.path.isfile(cached_rows_path):
        print("up-to-date (cached)")
        with open(cached_rows_path, encoding="utf-8") as f:
            return json.load(f)

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

    rows = []
    for item in feed.get("vulnerabilities", []):
        entry = _extract_entry(item.get("cve", {}))
        if entry:
            rows.append(entry)

    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(cached_rows_path, "w", encoding="utf-8") as f:
        json.dump(rows, f)
    _write_cached_meta(year, meta_str)

    print(f"{len(rows):,} CVEs")
    return rows


def main() -> int:
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)

    print("[CVE-DB] Building CVE summary database from NVD JSON 2.0 feeds ...")
    all_rows: list[dict] = []
    for year in range(START_YEAR, CURRENT_YEAR + 1):
        all_rows.extend(_process_year(year))

    if not all_rows:
        print("[CVE-DB] ERROR: No CVE data collected. Check internet connectivity.")
        return 1

    print(f"[CVE-DB] Writing {len(all_rows):,} records → {OUTPUT}")
    tmp = OUTPUT + ".tmp"
    with open(tmp, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_MINIMAL)
        for row in all_rows:
            writer.writerow([row["id"], row["severity"], row["summary"]])
    os.replace(tmp, OUTPUT)

    print("[CVE-DB] Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
