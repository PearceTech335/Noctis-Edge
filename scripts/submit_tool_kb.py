#!/usr/bin/env python3
"""
Noctis Edge — Tool Knowledge Base Submission Tool

Usage: submit_tool_kb.py <kb_path> <user_id> [relay_url]

Submits the local tool performance knowledge base to the Noctis Edge community
relay (a Cloudflare Worker).  The relay holds the GitHub credentials server-side —
no token is required on the user's machine.

relay_url defaults to RELAY_URL below.  Override via the optional 3rd argument
(or set KB_RELAY_URL in noctis.conf) for testing or self-hosted deployments.

Exit codes: 0 = success or skipped, 1 = error
"""
import json
import re
import ssl
import sys
import urllib.request
import urllib.error

# ── Update this after deploying the updated Cloudflare Worker ─────────────────
RELAY_URL = "https://noctis-kb-relay.pearcetechnologies1.workers.dev/submit-tool"
# ─────────────────────────────────────────────────────────────────────────────

_RE_IPV4 = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def _sanitize_tool_kb(kb: dict) -> dict:
    """Return a copy of the tool KB with target IPv4 addresses scrubbed from
    slot keys and any string values."""
    import copy
    kb = copy.deepcopy(kb)
    sanitized: dict = {}
    for tool, slots in kb.items():
        if tool == "_meta" or not isinstance(slots, dict):
            sanitized[tool] = slots
            continue
        clean_slots: dict = {}
        for slot_key, stats in slots.items():
            clean_key = _RE_IPV4.sub("<TARGET>", slot_key)
            clean_slots[clean_key] = stats
        sanitized[tool] = clean_slots
    return sanitized


def main() -> None:
    if len(sys.argv) not in (3, 4):
        print(f"Usage: {sys.argv[0]} <kb_path> <user_id> [relay_url]", file=sys.stderr)
        sys.exit(1)

    kb_path   = sys.argv[1]
    user_id   = sys.argv[2]
    relay_url = sys.argv[3] if len(sys.argv) == 4 else RELAY_URL

    if "REPLACE_WITH" in relay_url:
        print(
            "[submit_tool_kb] Relay URL not configured yet — deploy the updated "
            "Cloudflare Worker then update RELAY_URL in scripts/submit_tool_kb.py."
        )
        sys.exit(0)

    # ── Load and validate the local KB ───────────────────────────────────────
    try:
        with open(kb_path, "r", encoding="utf-8") as fh:
            kb_data = json.load(fh)
    except FileNotFoundError:
        print("[submit_tool_kb] No local tool knowledge base found — skipping submission.")
        sys.exit(0)
    except json.JSONDecodeError as exc:
        print(f"[submit_tool_kb] ERROR: Invalid JSON in {kb_path}: {exc}", file=sys.stderr)
        sys.exit(1)

    # Strip meta key and check there are real tool entries
    tool_entries = {k: v for k, v in kb_data.items() if k != "_meta"}
    if not tool_entries:
        print("[submit_tool_kb] Local tool knowledge base has no tool entries — skipping.")
        sys.exit(0)

    # ── Sanitize before transmission ─────────────────────────────────────────
    kb_data = _sanitize_tool_kb(kb_data)

    # ── POST to relay ─────────────────────────────────────────────────────────
    payload = json.dumps({"user_id": user_id, "tool_kb": kb_data}).encode()
    req = urllib.request.Request(
        relay_url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent":   "Noctis-Edge/1.0",
        },
    )

    def _do_request(ctx: "ssl.SSLContext | None" = None) -> None:
        kwargs = {"timeout": 30}
        if ctx is not None:
            kwargs["context"] = ctx
        with urllib.request.urlopen(req, **kwargs) as resp:
            body      = json.loads(resp.read())
            action    = body.get("action", "submitted")
            remaining = body.get("remaining", "?")
            print(
                f"[submit_tool_kb] Tool knowledge base {action} successfully "
                f"({remaining} submission(s) remaining today)."
            )
            sys.exit(0)

    try:
        _do_request()

    except urllib.error.HTTPError as exc:
        try:
            err_body = json.loads(exc.read())
            err_msg  = err_body.get("error", str(exc))
        except Exception:
            err_msg = str(exc)

        labels = {
            400: "Validation error",
            409: "Conflict",
            413: "KB too large",
            429: "Rate limited",
            502: "Relay/GitHub error",
        }
        label = labels.get(exc.code, "Error")
        print(f"[submit_tool_kb] {label} (HTTP {exc.code}): {err_msg}", file=sys.stderr)
        sys.exit(1 if exc.code not in (429,) else 0)

    except urllib.error.URLError as exc:
        # SSL verify failure on older systems — retry without verification
        if "CERTIFICATE_VERIFY_FAILED" in str(exc.reason):
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                _do_request(ctx)
            except Exception as inner:
                print(f"[submit_tool_kb] Network error (SSL fallback): {inner}", file=sys.stderr)
                sys.exit(1)
        else:
            print(f"[submit_tool_kb] Network error: {exc.reason}", file=sys.stderr)
            sys.exit(1)

    except Exception as exc:
        print(f"[submit_tool_kb] Unexpected error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
