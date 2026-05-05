#!/usr/bin/env python3
"""Download the latest EPSS scores CSV and store it at CVE/epss-scores.csv.

The EPSS project (FIRST.org / Empirical Security) publishes a daily gzipped CSV
with probability and percentile scores for every CVE in the NVD.

Source URL format:
  https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz

Output file: CVE/epss-scores.csv
Columns:    cve,epss,percentile,date

Run via update.sh or standalone: python3 scripts/build_epss_db.py
"""

import csv
import gzip
import io
import os
import sys
import urllib.request
from datetime import date, timedelta

BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT     = os.path.join(BASE_DIR, "CVE", "epss-scores.csv")
BASE_URL   = "https://epss.empiricalsecurity.com/epss_scores-{date}.csv.gz"
MAX_DAYS_BACK = 3   # Try up to N days back if today's file isn't published yet.


def _url_for(day: date) -> str:
    return BASE_URL.format(date=day.isoformat())


def _download(day: date) -> bytes | None:
    url = _url_for(day)
    print(f"[EPSS] Fetching {url} ...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Noctis-Edge/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            return resp.read()
    except Exception as e:
        print(f"[EPSS] Failed: {e}")
        return None


def main() -> int:
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)

    raw: bytes | None = None
    used_day: date | None = None

    today = date.today()
    for offset in range(MAX_DAYS_BACK + 1):
        day = today - timedelta(days=offset)
        raw = _download(day)
        if raw is not None:
            used_day = day
            break

    if raw is None:
        print("[EPSS] ERROR: Could not download EPSS CSV. Offline mode — skipping.")
        return 1

    # Decompress
    try:
        with gzip.open(io.BytesIO(raw)) as gz:
            content = gz.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"[EPSS] Decompress failed: {e}")
        return 1

    # The file ships with a comment header line like:
    #   #model_version:v2023.03.01,score_date:2024-05-01T00:00:00+0000
    # followed by the actual CSV header:  cve,epss,percentile,date
    lines = content.splitlines()
    data_lines = [l for l in lines if not l.startswith("#")]

    # Parse & re-write to a clean CSV (add date column if missing)
    try:
        reader = csv.DictReader(data_lines)
        rows = list(reader)
    except Exception as e:
        print(f"[EPSS] CSV parse failed: {e}")
        return 1

    # Normalise: ensure date field exists
    for row in rows:
        if "date" not in row or not row["date"]:
            row["date"] = used_day.isoformat()

    print(f"[EPSS] Writing {len(rows):,} scores → {OUTPUT}")
    tmp = OUTPUT + ".tmp"
    with open(tmp, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["cve", "epss", "percentile", "date"])
        writer.writeheader()
        writer.writerows(rows)
    os.replace(tmp, OUTPUT)

    print(f"[EPSS] Done. Date: {used_day}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
