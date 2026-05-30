#!/usr/bin/env python3
"""Track GitHub repository traffic with no external dependencies.

History storage model:
- Reads prior history from the latest Actions artifact (private to repo collaborators).
- Fetches current traffic/release metrics from GitHub REST API.
- Upserts today's snapshot into JSON+CSV under traffic-history/.

This script is intended to run in GitHub Actions.
"""

from __future__ import annotations

import csv
import datetime as dt
import io
import json
import os
import pathlib
import urllib.error
import urllib.request
import zipfile
from typing import Any

ARTIFACT_NAME = os.getenv("TRAFFIC_ARTIFACT_NAME", "repo-traffic-history")
OUT_DIR = pathlib.Path("traffic-history")
OUT_JSON = OUT_DIR / "traffic_history.json"
OUT_CSV = OUT_DIR / "traffic_history.csv"
OUT_SUMMARY = OUT_DIR / "summary.md"


def _api_get(url: str, token: str) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "repo-traffic-tracker",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _latest_artifact_download_url(owner: str, repo: str, token: str, artifact_name: str) -> str | None:
    url = f"https://api.github.com/repos/{owner}/{repo}/actions/artifacts?name={artifact_name}&per_page=100"
    data = _api_get(url, token)
    artifacts = data.get("artifacts", [])
    if not artifacts:
        return None

    # Choose newest non-expired artifact by created_at.
    artifacts = [a for a in artifacts if not a.get("expired")]
    if not artifacts:
        return None
    artifacts.sort(key=lambda a: a.get("created_at", ""), reverse=True)
    return artifacts[0].get("archive_download_url")


def _download_artifact_zip(download_url: str, token: str) -> bytes:
    req = urllib.request.Request(
        download_url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "repo-traffic-tracker",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


def _load_previous_history(owner: str, repo: str, token: str) -> dict[str, Any]:
    try:
        download_url = _latest_artifact_download_url(owner, repo, token, ARTIFACT_NAME)
        if not download_url:
            return {}

        blob = _download_artifact_zip(download_url, token)
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            for name in zf.namelist():
                if name.endswith("traffic_history.json"):
                    with zf.open(name) as fh:
                        return json.load(fh)
    except Exception:
        # Start fresh if artifact lookup/download fails.
        return {}
    return {}


def _release_download_totals(owner: str, repo: str, token: str) -> tuple[int, dict[str, int]]:
    url = f"https://api.github.com/repos/{owner}/{repo}/releases?per_page=100"
    data = _api_get(url, token)
    total = 0
    by_tag: dict[str, int] = {}

    for rel in data if isinstance(data, list) else []:
        tag = str(rel.get("tag_name") or "untagged")
        dls = 0
        for asset in rel.get("assets", []) or []:
            dls += int(asset.get("download_count") or 0)
        total += dls
        by_tag[tag] = dls

    return total, by_tag


def _upsert_snapshot(history: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
    snapshots = history.setdefault("snapshots", [])
    by_date = {str(s.get("date")): s for s in snapshots if isinstance(s, dict)}
    by_date[snapshot["date"]] = snapshot

    ordered = [by_date[k] for k in sorted(by_date.keys())]
    history["snapshots"] = ordered
    history["updated_at"] = snapshot["collected_at_utc"]
    return history


def _write_outputs(history: dict[str, Any]) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    with OUT_JSON.open("w", encoding="utf-8") as fh:
        json.dump(history, fh, indent=2, sort_keys=True)

    fieldnames = [
        "date",
        "clones_count",
        "clones_uniques",
        "views_count",
        "views_uniques",
        "release_downloads_total",
        "release_downloads_delta",
    ]
    with OUT_CSV.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in history.get("snapshots", []):
            writer.writerow({k: row.get(k, "") for k in fieldnames})

    latest = history.get("snapshots", [])[-1] if history.get("snapshots") else {}
    summary_lines = [
        "## Repo Traffic Snapshot",
        "",
        f"- date: {latest.get('date', 'n/a')}",
        f"- clones: {latest.get('clones_count', 0)} (unique: {latest.get('clones_uniques', 0)})",
        f"- views: {latest.get('views_count', 0)} (unique: {latest.get('views_uniques', 0)})",
        f"- total release downloads: {latest.get('release_downloads_total', 0)}",
        f"- release download delta: {latest.get('release_downloads_delta', 0)}",
        f"- snapshots stored: {len(history.get('snapshots', []))}",
    ]
    OUT_SUMMARY.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")


def main() -> int:
    token = os.getenv("REPO_TRAFFIC_TOKEN", "").strip() or os.getenv("GITHUB_TOKEN", "").strip()
    repo_slug = os.getenv("GITHUB_REPOSITORY", "").strip()

    if not token:
        raise RuntimeError("REPO_TRAFFIC_TOKEN (or GITHUB_TOKEN) is required")
    if "/" not in repo_slug:
        raise RuntimeError("GITHUB_REPOSITORY must be in owner/repo format")

    owner, repo = repo_slug.split("/", 1)
    now = dt.datetime.now(dt.timezone.utc)
    day = now.date().isoformat()

    history = _load_previous_history(owner, repo, token)
    if not isinstance(history, dict):
        history = {}

    history.setdefault("repo", repo_slug)
    history.setdefault("schema_version", 1)

    clones = _api_get(f"https://api.github.com/repos/{owner}/{repo}/traffic/clones", token)
    views = _api_get(f"https://api.github.com/repos/{owner}/{repo}/traffic/views", token)
    rel_total, rel_by_tag = _release_download_totals(owner, repo, token)

    snapshots = history.get("snapshots", [])
    previous = snapshots[-1] if snapshots else {}
    prev_total = int(previous.get("release_downloads_total") or 0)

    snapshot = {
        "date": day,
        "collected_at_utc": now.replace(microsecond=0).isoformat(),
        "clones_count": int(clones.get("count") or 0),
        "clones_uniques": int(clones.get("uniques") or 0),
        "views_count": int(views.get("count") or 0),
        "views_uniques": int(views.get("uniques") or 0),
        "release_downloads_total": rel_total,
        "release_downloads_delta": max(0, rel_total - prev_total),
        "release_downloads_by_tag": rel_by_tag,
    }

    history = _upsert_snapshot(history, snapshot)
    _write_outputs(history)
    print(f"[traffic] updated snapshot for {day}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except urllib.error.HTTPError as exc:
        print(f"[traffic] GitHub API HTTP error: {exc.code} {exc.reason}")
        if exc.code == 403:
            print("[traffic] Hint: set repository secret REPO_TRAFFIC_TOKEN with a classic PAT that has repo scope.")
        raise
    except Exception as exc:
        print(f"[traffic] error: {exc}")
        raise
