#!/usr/bin/env python3
"""Download the CISA Known Exploited Vulnerabilities (KEV) catalog and write
to CVE/kev-catalog.csv for offline use by noctis.py.

Usage:
    python scripts/build_kev_db.py
"""

import csv
import json
import os
import sys
import urllib.request
import urllib.error

KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "CVE")
OUT_FILE = os.path.join(OUT_DIR, "kev-catalog.csv")

FIELDNAMES = ["cve_id", "vendor", "product", "name", "date_added", "due_date", "action"]


def fetch_kev() -> list[dict]:
    print(f"[*] Downloading KEV catalog from {KEV_JSON_URL} …")
    req = urllib.request.Request(KEV_JSON_URL, headers={"User-Agent": "noctis-kev-builder/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        print(f"[!] Download failed: {exc}", file=sys.stderr)
        sys.exit(1)

    vulns = data.get("vulnerabilities", [])
    print(f"[*] {len(vulns)} entries received.")
    return vulns


def write_csv(vulns: list[dict], path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
        writer.writeheader()
        for v in vulns:
            writer.writerow(
                {
                    "cve_id": v.get("cveID", "").upper(),
                    "vendor": v.get("vendorProject", ""),
                    "product": v.get("product", ""),
                    "name": v.get("vulnerabilityName", ""),
                    "date_added": v.get("dateAdded", ""),
                    "due_date": v.get("dueDate", ""),
                    "action": v.get("requiredAction", ""),
                }
            )
    print(f"[+] Wrote {len(vulns)} rows to {path}")


def main() -> None:
    vulns = fetch_kev()
    write_csv(vulns, OUT_FILE)
    print("[+] Done. Run noctis.py to use updated KEV data.")


if __name__ == "__main__":
    main()
