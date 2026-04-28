# Paid Tier — Community CVE KB: Implementation Plan

## Goal

When a subscriber runs `./update.sh`, the community CVE knowledge base downloads and merges
into their local `cve_knowledge_base.json` automatically — no GitHub account, no PAT, no
manual steps. Just a license key in `noctis.conf`.

---

## Repositories

| Repo | Visibility | Purpose |
|------|-----------|---------|
| [`PearceTech335/Noctis-Edge-Submissions`](https://github.com/PearceTech335/Noctis-Edge-Submissions) | Public | Raw `<uuid>.json` submissions from all users (free tier) |
| [`PearceTech335/Noctis-Edge-KB`](https://github.com/PearceTech335/Noctis-Edge-KB) | **Private** | Curated `community_kb.json` — paid subscribers only |

---

## User Experience (end state)

1. User discovers paid tier (README, Polar.sh page)
2. Subscribes on Polar.sh → license key appears on their Polar dashboard
3. User adds **one line** to `noctis.conf`:
   ```
   KB_LICENSE_KEY="NOCTIS-XXXX-XXXX-XXXX"
   ```
4. Runs `./update.sh` → community KB downloads and merges silently

That's it. No GitHub account. No PAT. Key auto-revokes on cancellation.

---

## Architecture Overview

```
[Polar.sh]  —  subscription + license key issuance
      │
      │  license key in POST body
      ▼
[Cloudflare Worker]  ←  existing worker, new route: POST /community-kb
  1. Validates Polar license key via Polar API
  2. Fetches community_kb.json from Noctis-Edge-KB via GitHub API (GITHUB_KB_TOKEN)
  3. Streams JSON back to subscriber
      ▲
      │  commit community_kb.json (cross-repo PAT: KB_PUSH_TOKEN)
[GitHub Actions on Noctis-Edge-Submissions]
      │  1. validate-submissions.yml  — security check on every push
      │  2. build-community-kb.yml   — merge + quality filter + commit to KB repo
      │
[Noctis-Edge-Submissions]  ←  raw <uuid>.json from all users (free tier)
      └── quarantine/                ←  flagged scripts moved here by validator
```

**No Cloudflare R2 required.** The private `Noctis-Edge-KB` repo is the single
source of truth for the curated KB.

---

## Secrets Summary

| Secret | Where stored | Purpose |
|--------|-------------|---------|
| `GITHUB_TOKEN` | Cloudflare Worker (existing) | Write submissions to `Noctis-Edge-Submissions` |
| `GITHUB_KB_TOKEN` | Cloudflare Worker **(new)** | Read `community_kb.json` from private `Noctis-Edge-KB` |
| `POLAR_ORG_ACCESS_TOKEN` | Cloudflare Worker **(new)** | Validate Polar license keys |
| `POLAR_ORGANIZATION_ID` | Cloudflare Worker **(new)** | Your Polar org UUID |
| `KB_PUSH_TOKEN` | GitHub Actions secret on `Noctis-Edge-Submissions` **(new)** | Cross-repo push to `Noctis-Edge-KB` |

---

## Phase 1 — Repository Setup (~5 min, manual)

> No code changes. One-time setup only.

**Step 1** — Confirm `Noctis-Edge-KB` is set to **private** on GitHub.

**Step 2** — Create a fine-grained PAT named `KB_PUSH_TOKEN`:
- Scope: `Contents: Read and write` on **both** `Noctis-Edge-Submissions` and `Noctis-Edge-KB`
- Store as a GitHub Actions secret on `Noctis-Edge-Submissions`: Settings → Secrets → `KB_PUSH_TOKEN`

**Step 3** — Create a fine-grained PAT named `GITHUB_KB_TOKEN`:
- Scope: `Contents: Read` on `Noctis-Edge-KB` only (read-only, least privilege)
- Store as a Cloudflare Worker secret: `wrangler secret put GITHUB_KB_TOKEN`

---

## Phase 2 — Submission Security Validation

> New files on `PearceTech335/Noctis-Edge-Submissions`:
> - `scripts/validate_submissions.py`
> - `.github/workflows/validate-submissions.yml`

This phase runs **before** the build pipeline. Its job is to catch malicious
scripts (e.g. `rm -rf /`, reverse shells) before they can ever reach the curated
KB that runs on subscribers' machines. Two independent checks run in sequence.

**Step 4** — Write `scripts/validate_submissions.py`

Accepts one or more `<uuid>.json` file paths as CLI arguments. For each file,
iterates every `scripts[].script` field across all CVE entries and runs:

**Check 1 — Static blocklist** (instant, no API call):

| Category | Patterns blocked |
|----------|-----------------|
| Destructive commands | `rm -rf`, `rm -f /`, `dd if=`, `mkfs`, `shred`, fork bomb `:(){:\|:&};:` |
| Reverse shells | `/dev/tcp/`, `bash -i >`, `nc -e /bin`, `ncat.*-e`, `mkfifo.*nc` |
| Remote exec chains | `curl.*\|.*sh`, `wget.*\|.*bash`, `curl.*\|.*bash` |
| Obfuscated eval | `eval(base64`, `exec(base64`, `__import__('os').system` |
| Sensitive local files | `/etc/shadow`, `\.ssh/id_rsa`, `/proc/[0-9]+/mem` |
| Crypto miners | `xmrig`, `minerd`, `cpuminer` |

**Check 2 — GitHub Models LLM review** (scripts that pass the static check):

- Endpoint: `https://models.inference.ai.azure.com/chat/completions`
- Model: `gpt-4o-mini`
- Auth: `Authorization: Bearer $GITHUB_TOKEN` — **free, no extra secrets needed**
- Prompt: classify whether the script is a passive network probe against a
  remote target (SAFE) or does anything harmful to the local machine — writes/
  deletes files, spawns reverse shells, exfiltrates local data, downloads and
  executes code, or causes DoS (UNSAFE)
- Response: `{"verdict": "SAFE"|"UNSAFE", "reason": "..."}`

Any UNSAFE result (from either check): move `<uuid>.json` to
`quarantine/<uuid>.json`, log the CVE ID + reason + first 200 chars of the
flagged script (truncated). Exit code 1 if any files were quarantined.

> Quarantine is a move, not a delete — you can reinstate false positives
> by moving the file back to the repo root manually before the next build.

**Step 5** — Write `.github/workflows/validate-submissions.yml`

Triggers: `push` to main branch of `Noctis-Edge-Submissions`

```
steps:
  1. Checkout with fetch-depth: 2
  2. Get changed files:
       git diff --name-only HEAD^ HEAD | grep -E '^[0-9a-f-]+\.json$'
  3. Run: python3 scripts/validate_submissions.py <changed_files>
  4. If exit 1 (quarantines occurred):
       gh issue create --title "Submission quarantined: <uuid>"
                       --body  "<CVE IDs> | <reason> | <redacted excerpt>"
  5. git add quarantine/ && git commit -m "quarantine: <uuid>" && git push
     (uses default ${{ secrets.GITHUB_TOKEN }} scoped to Noctis-Edge-Submissions)
```

Weekly full-repo scan also runs as part of the build cron (Step 7).

---

## Phase 3 — Curation Pipeline

> New files on `PearceTech335/Noctis-Edge-Submissions`:
> - `scripts/build_community_kb.py`
> - `.github/workflows/build-community-kb.yml`

**Step 6** — Write `scripts/build_community_kb.py`

1. Read all `*.json` from repo root — **never** descend into `quarantine/`
2. Merge using the same additive-by-`script_hash` logic as `scripts/merge_kb.py`
3. **Quality filter**: include only scripts where `verdict` is `VULNERABLE` or
   `NOT_VULNERABLE` **and** the same `script_hash` appears in ≥ 2 independent
   submissions (different `user_id` values) — prevents low-quality/INCONCLUSIVE
   noise from reaching paying subscribers
4. **Final static safety gate**: re-run the full blocklist from Step 4 on every
   script before writing it to output — defence in depth against anything that
   slipped through Phase 2
5. Output: `community_kb.json` with a `built_at` ISO timestamp at the top level

**Step 7** — Write `.github/workflows/build-community-kb.yml`

Triggers:
- On every push to `Noctis-Edge-Submissions` (new submissions)
- Weekly schedule (`cron: '0 3 * * 0'`) — also runs the full-repo validation scan

```
steps:
  1. Checkout Noctis-Edge-Submissions (uses default GITHUB_TOKEN)
  2. (Weekly cron only) Run validate_submissions.py on ALL *.json files
  3. Run python3 scripts/build_community_kb.py → community_kb.json
  4. git clone https://x-access-token:${{ secrets.KB_PUSH_TOKEN }}
                @github.com/PearceTech335/Noctis-Edge-KB.git
  5. cp community_kb.json Noctis-Edge-KB/community_kb.json
  6. cd Noctis-Edge-KB
     git config user.email "actions@github.com"
     git config user.name  "GitHub Actions"
     git add community_kb.json
     git diff --cached --quiet || git commit -m "rebuild: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
     git push
```

> Phases 2 and 3 can be built and deployed in parallel.

---

## Phase 4 — Cloudflare Worker: New Route

> Edit: `cloudflare/worker.js`
> No `wrangler.toml` changes needed — no R2 binding required

**Step 8** — Add `POST /community-kb` handler to `worker.js`

```
Logic:
  1. Parse body: { "license_key": "..." }
  2. POST https://api.polar.sh/v1/license-keys/validate
       Authorization: Bearer <POLAR_ORG_ACCESS_TOKEN>
       { "key": "<license_key>", "organization_id": "<POLAR_ORGANIZATION_ID>" }
  3. If response.status !== "granted":
       return 403 { "error": "invalid_key",
                    "message": "Subscribe at https://polar.sh/PearceTech335" }
  4. GET https://api.github.com/repos/PearceTech335/Noctis-Edge-KB/contents/community_kb.json
       Authorization: Bearer <GITHUB_KB_TOKEN>
       Accept: application/vnd.github.v3.raw
  5. Return the raw JSON with Content-Type: application/json
```

**Step 9** — Deploy

```bash
cd cloudflare
wrangler secret put GITHUB_KB_TOKEN
wrangler secret put POLAR_ORG_ACCESS_TOKEN
wrangler secret put POLAR_ORGANIZATION_ID
wrangler deploy
```

---

## Phase 5 — Client Changes

> Edit: `update.sh`, `setup.sh`
> Docs: `README.md`, `Readme/requirements.md`

**Step 10** — `update.sh`: replace the `PAID_TIER` / `KB_COMMUNITY_TOKEN` / git-clone block

```bash
if [[ -z "$KB_LICENSE_KEY" ]]; then
    info "Community KB pull skipped — set KB_LICENSE_KEY in noctis.conf to enable"
    info "Subscribe at: https://polar.sh/PearceTech335"
else
    info "Pulling community CVE knowledge base (license key found) ..."
    RELAY="https://noctis-kb-relay.pearcetechnologies1.workers.dev"
    HTTP_CODE=$(curl -sS -w "%{http_code}" -o /tmp/_noctis_community_kb.json \
        -X POST "$RELAY/community-kb" \
        -H "Content-Type: application/json" \
        -d "{\"license_key\":\"$KB_LICENSE_KEY\"}")
    if [[ "$HTTP_CODE" == "200" ]]; then
        MERGE_OUTPUT=$("$PYTHON" "$SCRIPT_DIR/scripts/merge_kb.py" \
            /tmp/_noctis_community_kb.json "$KB_LOCAL" 2>&1)
        ok "Community KB merged: $MERGE_OUTPUT"
    elif [[ "$HTTP_CODE" == "403" ]]; then
        err "License key rejected — check your subscription at https://polar.sh/PearceTech335"
    else
        err "Community KB download failed (HTTP $HTTP_CODE) — will retry on next update"
    fi
    rm -f /tmp/_noctis_community_kb.json
fi
```

**Step 11** — `noctis.conf` template

Remove `PAID_TIER` and `KB_COMMUNITY_TOKEN`. Replace with:

```bash
KB_LICENSE_KEY=""
# ↑ Paste your Polar.sh license key here to enable the community CVE KB download.
#   Subscribe at: https://polar.sh/PearceTech335
#   Your key is always visible on your Polar dashboard.
```

Non-empty key = paid tier active. No separate `PAID_TIER=true` flag needed.

**Step 12** — `setup.sh`

Update the `noctis.conf` generation block to write `KB_LICENSE_KEY=""` instead
of `PAID_TIER=false` and `KB_COMMUNITY_TOKEN=""`.

**Step 13** — Docs

Update `README.md` and `Readme/requirements.md`:
- Replace PAT/git-clone instructions with the single `KB_LICENSE_KEY` line
- Add link to Polar.sh subscription page

---

## Phase 6 — Polar.sh Setup (manual, no code)

> Can be done at any time, in parallel with all other phases.

**Step 14** — Create a product on https://polar.sh under `PearceTech335`

**Step 15** — Add a **License Key** benefit to the product

Recommended settings:
- `limit_activations`: 3 (allows 3 machines per subscriber)
- `limit_usage`: leave unlimited (key validated on each `update.sh` run, not consumed)
- `expires_at`: leave blank (valid as long as subscription is active)

**Step 16** — Get your credentials for the Worker

| Value | Where to find it |
|-------|-----------------|
| `POLAR_ORGANIZATION_ID` | Polar dashboard → Settings → Organisation → copy the UUID |
| `POLAR_ORG_ACCESS_TOKEN` | Polar dashboard → Settings → API → New token → scope: `license_keys:write` |

Store both as Cloudflare Secrets (Step 9 above).

---

## Verification Checklist

**Pipeline security:**
- [ ] Push a `<uuid>.json` containing `rm -rf /` in a script → confirm it moves to `quarantine/` and a GitHub Issue opens
- [ ] Push a `<uuid>.json` with `eval(base64.b64decode(...))` → confirm LLM catches it even though static check misses it
- [ ] Push a clean passive HTTP probe → confirm it passes both checks and reaches `community_kb.json` on `Noctis-Edge-KB`
- [ ] Manually move a false-positive from `quarantine/` back to repo root → confirm next build includes it

**End-to-end paid tier:**
- [ ] Subscribe a test account on Polar.sh → set `KB_LICENSE_KEY` in `noctis.conf` → run `./update.sh` → confirm community KB merges
- [ ] Revoke test subscription → run `./update.sh` → confirm 403, local KB unchanged
- [ ] Set garbage key → confirm graceful skip with clear message and Polar link
- [ ] Fresh install (no `KB_LICENSE_KEY`) → free tier still works, paid skip message is friendly

---

## What Changes vs. Current Stub

| | Current stub | New plan |
|--|--|--|
| Auth mechanism | GitHub fine-grained PAT | Polar.sh license key |
| User needs GitHub account | Yes | No |
| Key auto-revokes on cancellation | No (PAT stays valid) | Yes (Polar handles it) |
| KB delivery | `git clone` private repo | `curl POST` to Worker → GitHub API |
| Curated KB stored in | GitHub private repo (ad-hoc) | `Noctis-Edge-KB` (private, purpose-built) |
| Extra infrastructure | None | None (no R2, no new services) |
| Config fields | `KB_COMMUNITY_TOKEN` + `PAID_TIER=true` | `KB_LICENSE_KEY` only |
| Script safety check | None | Static blocklist + GitHub Models LLM review |
| Friction | High (PAT setup, GitHub account) | Minimal (paste one key) |