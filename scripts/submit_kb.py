#!/usr/bin/env python3
"""
Noctis Edge — CVE Knowledge Base Submission Tool

Usage: submit_kb.py <kb_path> <user_id> [relay_url]

Submits the local CVE knowledge base to the Noctis Edge community relay
(a Cloudflare Worker).  The relay holds the GitHub credentials server-side —
no token is required on the user's machine.

relay_url defaults to RELAY_URL below.  Override via the optional 3rd argument
(or set KB_RELAY_URL in noctis.conf) for testing or self-hosted deployments.

Exit codes: 0 = success or skipped, 1 = error
"""
import json
import ssl
import sys
import urllib.request
import urllib.error

# ── Update this after deploying the Cloudflare Worker ────────────────────────
# Run `wrangler deploy` in the cloudflare/ directory, then paste the URL here.
# Format: https://noctis-kb-relay.<your-subdomain>.workers.dev/submit
RELAY_URL = "https://noctis-kb-relay.pearcetechnologies1.workers.dev/submit"
# ─────────────────────────────────────────────────────────────────────────────


def main() -> None:
    if len(sys.argv) not in (3, 4):
        print(f"Usage: {sys.argv[0]} <kb_path> <user_id> [relay_url]", file=sys.stderr)
        sys.exit(1)

    kb_path   = sys.argv[1]
    user_id   = sys.argv[2]
    relay_url = sys.argv[3] if len(sys.argv) == 4 else RELAY_URL

    if "REPLACE_WITH" in relay_url:
        print(
            "[submit_kb] Relay URL not configured yet — deploy the Cloudflare Worker "
            "(cloudflare/wrangler.toml) then update RELAY_URL in scripts/submit_kb.py."
        )
        sys.exit(0)

    # ── Load and validate the local KB ───────────────────────────────────────
    try:
        with open(kb_path, "r", encoding="utf-8") as fh:
            kb_data = json.load(fh)
    except FileNotFoundError:
        print("[submit_kb] No local knowledge base found — skipping submission.")
        sys.exit(0)
    except json.JSONDecodeError as exc:
        print(f"[submit_kb] ERROR: Invalid JSON in {kb_path}: {exc}", file=sys.stderr)
        sys.exit(1)

    if not kb_data:
        print("[submit_kb] Local knowledge base is empty — skipping submission.")
        sys.exit(0)

    # ── POST to relay ─────────────────────────────────────────────────────────
    payload = json.dumps({"user_id": user_id, "kb": kb_data}).encode()
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
                f"[submit_kb] Knowledge base {action} successfully "
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
        label = labels.get(exc.code, f"HTTP {exc.code}")
        print(f"[submit_kb] {label}: {err_msg}", file=sys.stderr)
        sys.exit(1)

    except Exception as exc:
        # Retry without SSL verification if the cert is not yet valid (clock skew).
        if "CERTIFICATE_VERIFY_FAILED" in str(exc) or "certificate is not yet valid" in str(exc):
            print(
                "[submit_kb] Warning: SSL cert not yet valid — "
                "retrying without verification (local clock skew).",
                file=sys.stderr,
            )
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            try:
                _do_request(ctx)
            except Exception as exc2:
                print(f"[submit_kb] Network error: {exc2}", file=sys.stderr)
                sys.exit(1)
        print(f"[submit_kb] Network error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
