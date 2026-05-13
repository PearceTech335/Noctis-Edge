#!/usr/bin/env python3
# Copyright (C) 2026 Pearce Technologies Pty Ltd
# SPDX-License-Identifier: AGPL-3.0-or-later
# <https://www.gnu.org/licenses/agpl-3.0.html>
"""Download and parse the MITRE CWE XML dictionary to an offline CSV.

MITRE publishes the complete CWE list as a single zipped XML file:
  https://cwe.mitre.org/data/xml/cwec_latest.xml.zip

Each <Weakness> entry is extracted with:
  - cwe_id       : e.g. "CWE-89"
  - name         : human-readable weakness name
  - abstraction  : Pillar / Class / Base / Variant / Compound
  - description  : first paragraph (≤500 chars)
  - likelihood   : None / Low / Medium / High / Very High
  - consequences : up to 3 scope:impact pairs, pipe-separated
  - mitigation   : first mitigation description (≤400 chars)

Output: CVE/cwe-data.csv
Run standalone:  python3 scripts/build_cwe_db.py
Called from:     docker-entrypoint.sh (on first container start)
                 update.sh step 5c
"""

import csv
import io
import os
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT   = os.path.join(BASE_DIR, "CVE", "cwe-data.csv")
CWE_URL  = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

FIELDNAMES = ["cwe_id", "name", "abstraction", "description",
              "likelihood", "consequences", "mitigation"]


def _strip_ns(tag: str) -> str:
    """Remove XML namespace prefix from a tag, e.g. '{http://...}Weakness' → 'Weakness'."""
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _inner_text(elem) -> str:
    """Recursively collect all text content from an element and its children."""
    parts = []
    if elem.text:
        parts.append(elem.text)
    for child in elem:
        parts.append(_inner_text(child))
        if child.tail:
            parts.append(child.tail)
    return "".join(parts)


def _clean(text: str, max_len: int = 500) -> str:
    """Collapse whitespace, strip XML fragments, truncate."""
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:max_len]


def _get_description(weakness) -> str:
    """Extract <Description> text (or <Extended_Description> fallback)."""
    for child in weakness:
        if _strip_ns(child.tag) == "Description":
            return _clean(_inner_text(child))
    for child in weakness:
        if _strip_ns(child.tag) == "Extended_Description":
            return _clean(_inner_text(child))
    return ""


def _get_likelihood(weakness) -> str:
    for child in weakness:
        if _strip_ns(child.tag) == "Likelihood_Of_Exploit":
            return _clean(_inner_text(child), max_len=20)
    return ""


def _get_consequences(weakness) -> str:
    """Return up to 3 'Scope: Impact' pairs, pipe-separated."""
    results = []
    for child in weakness:
        if _strip_ns(child.tag) != "Common_Consequences":
            continue
        for conseq in child:
            if _strip_ns(conseq.tag) != "Consequence":
                continue
            scope = impact = ""
            for field in conseq:
                tag = _strip_ns(field.tag)
                if tag == "Scope":
                    scope = _clean(_inner_text(field), 60)
                elif tag == "Impact":
                    impact = _clean(_inner_text(field), 80)
            if scope or impact:
                results.append(f"{scope}: {impact}".strip(": "))
            if len(results) >= 3:
                break
        break
    return " | ".join(results)


def _get_mitigation(weakness) -> str:
    """Return the first Potential_Mitigations description (≤400 chars)."""
    for child in weakness:
        if _strip_ns(child.tag) != "Potential_Mitigations":
            continue
        for mit in child:
            if _strip_ns(mit.tag) != "Mitigation":
                continue
            for field in mit:
                if _strip_ns(field.tag) == "Description":
                    return _clean(_inner_text(field), max_len=400)
        break
    return ""


def _download() -> bytes | None:
    print(f"[CWE-DB] Downloading {CWE_URL} ...")
    try:
        req = urllib.request.Request(CWE_URL, headers={"User-Agent": "Noctis-Edge/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = resp.read()
        print(f"[CWE-DB] Downloaded {len(data):,} bytes")
        return data
    except Exception as exc:
        print(f"[CWE-DB] Download failed: {exc}")
        return None


def _parse(xml_bytes: bytes) -> list[dict]:
    """Parse the CWE XML and return a list of weakness dicts."""
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        print(f"[CWE-DB] XML parse failed: {exc}")
        return []

    rows: list[dict] = []
    for container in root:
        if _strip_ns(container.tag) != "Weaknesses":
            continue
        for weakness in container:
            if _strip_ns(weakness.tag) != "Weakness":
                continue
            wid   = weakness.get("ID", "")
            name  = weakness.get("Name", "")
            abstr = weakness.get("Abstraction", "")
            if not wid:
                continue
            rows.append({
                "cwe_id":       f"CWE-{wid}",
                "name":         name,
                "abstraction":  abstr,
                "description":  _get_description(weakness),
                "likelihood":   _get_likelihood(weakness),
                "consequences": _get_consequences(weakness),
                "mitigation":   _get_mitigation(weakness),
            })

    return rows


def main() -> int:
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)

    raw = _download()
    if raw is None:
        return 1

    # Unzip and find the XML file
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            xml_name = next(
                (n for n in zf.namelist() if n.lower().endswith(".xml")), None
            )
            if not xml_name:
                print("[CWE-DB] No XML file found in ZIP archive")
                return 1
            xml_bytes = zf.read(xml_name)
            print(f"[CWE-DB] Parsing {xml_name} ({len(xml_bytes):,} bytes) ...")
    except Exception as exc:
        print(f"[CWE-DB] ZIP extraction failed: {exc}")
        return 1

    rows = _parse(xml_bytes)
    if not rows:
        print("[CWE-DB] ERROR: No CWE entries parsed")
        return 1

    print(f"[CWE-DB] Writing {len(rows):,} entries → {OUTPUT}")
    tmp = OUTPUT + ".tmp"
    with open(tmp, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        writer.writerows(rows)
    os.replace(tmp, OUTPUT)

    print("[CWE-DB] Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
