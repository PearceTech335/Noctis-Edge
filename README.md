# Noctis Edge

<p align="center">
  <img src="noctis_logo.png" alt="Noctis Edge Logo" width="400"/>
</p>

**Security Through Exposure**

Noctis Edge is a Python-based, AI-assisted vulnerability exposure and testing platform built around **local execution, data sovereignty, and operational security**.

Unlike cloud-dependent security platforms, **Noctis Edge runs entirely on your local machine**. All scanning, LLM-assisted analysis, CVE validation, and report generation happen on-device — no target data, credentials, or findings ever leave the host. It supports command-line execution via `noctis.py` and a browser-based Web UI via `noctis_web.py` (served locally at `http://127.0.0.1:5000`), without requiring external SaaS platforms, third-party APIs, or cloud processing.

This architecture makes Noctis Edge particularly suited for regulated environments, internal security teams, air-gapped networks, OT environments, and organizations where confidentiality and control are non-negotiable.

---

## Legal Disclaimer

Noctis-Edge is a defensive security and exposure validation platform intended exclusively for authorized security assessment, research, asset discovery, vulnerability validation, and compliance testing activities.

This software must only be used against systems, networks, applications, and infrastructure that you own or are explicitly authorized to test.

Unauthorized use of this software against third-party targets may violate local, state, federal, or international laws and regulations, including but not limited to unauthorized access, computer misuse, privacy, and cybersecurity legislation.

The authors, contributors, and distributors of Noctis-Edge:

- make no warranties regarding fitness for any purpose
- accept no liability for misuse, damage, downtime, data loss, or legal consequences resulting from use of this software
- do not endorse or support illegal, malicious, disruptive, or unethical activities

Users are solely responsible for:

- ensuring they have proper authorization before conducting any testing
- complying with all applicable laws, regulations, contracts, and organizational policies
- operating the software in a safe and responsible manner

Noctis-Edge is provided for lawful defensive security operations, security research, validation, monitoring, and educational purposes only.

By installing, configuring, or using this software, you agree that you are acting with proper authorization and assume full responsibility for your actions.

---

## What Gives Noctis the Edge

Most automated scanners report which CVEs *exist* on a system. **Noctis Edge tests whether they're actually exploitable** — and learns from every engagement it runs.

The `--cve-test` flag instructs the local LLM to generate safe, targeted probe scripts for each matched CVE. Scripts run on-device with a strict timeout and print a clear `VULNERABLE` / `NOT_VULNERABLE` / `INCONCLUSIVE` verdict. Results accumulate in `cve_knowledge_base.json` — on subsequent runs against the same CVE, proven scripts are replayed first, giving faster, higher-confidence results without any LLM call.

Running `./update.sh` submits your local CVE and Tooling knowledge bases to the community repository via Cloudflare relay — **no target data, credentials, or environment variables ever leave your machine**. Submissions are anonymised (CVE ID or service fingerprint only). Community-contributed scripts are vetted before inclusion. Pulling the aggregated community KB requires a [Noctis Edge Intelligence subscription](https://noctisedge.lemonsqueezy.com).

Alongside CVE probes, `tooling_knowledge_base.json` accumulates tool-performance data — which invocations produced real findings versus noise against specific service fingerprints. The LLM uses this history as context on each new engagement, progressively improving tool selection and script quality over time.

---

## System Requirements

| Component | Minimum |
|-----------|---------|
| **RAM** | 8 GB (16 GB recommended) |
| **Storage** | 15 GB free |
| **CPU** | 4 cores |
| **OS** | Kali / Parrot / Ubuntu / Debian-based |
| **Python** | 3.10+ |

**Storage breakdown (approximate):**

| Item | Size |
|------|------|
| Ollama — `gemma3:4b` (planning + prose) | ~3.3 GB |
| Ollama — `qwen2.5-coder:7b-instruct` (scripts) | ~4.4 GB |
| Nuclei templates | ~1.5 GB |
| CVE offline database | ~3–5 GB |
| SecLists wordlists | ~2 GB |
| Tool binaries + Python venv | ~1 GB |
| Scan session outputs | Variable |

> **RAM note:** Only one model is active at a time during the main scan loop. During `--cve-test`, both models may be warm simultaneously — peak concurrent RAM is ~7.7 GB. 16 GB RAM recommended; 32 GB optimal.

---

## Installation

Both paths provide identical functionality.

| | Docker | Native Linux |
|---|---|---|
| **OS** | Windows, macOS, Linux | Kali, Parrot, Ubuntu, Debian |
| **Setup time** | ~10 min (first build) | ~15 min |
| **Dependencies** | Docker Desktop only | apt + snap + Go + Ollama |
| **Isolation** | Full container isolation | System-level install |
| **Updates** | `docker compose build` + `pull` | `./update.sh` |

---

### Option A — Docker (Windows / macOS / Linux)

**Requirements:** [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows/macOS) or Docker Engine + Compose plugin (Linux).

```bash
git clone https://github.com/PearceTech335/Noctis-Edge.git
cd Noctis-Edge
```

**Linux / macOS:**
```bash
chmod +x docker-run.sh && ./docker-run.sh
```

**Windows (PowerShell):**
```powershell
.\docker-run.ps1
```

The launcher script handles everything automatically: pulls latest source, builds the Docker image (all tools + offline CVE database baked in), starts the Ollama sidecar and downloads the LLM models (~7.7 GB total — `gemma3:4b` ~3.3 GB + `qwen2.5-coder:7b-instruct` ~4.4 GB — one-time download, stored in a Docker volume), then starts the Web UI at **http://localhost:5000**.

**Useful Docker commands:**
```bash
docker compose run --rm noctis scan 192.168.0.1               # CLI scan
docker compose run --rm noctis scan 192.168.0.1 web --cve-test
docker compose down                                            # stop all containers
docker compose logs -f noctis                                  # live logs
docker compose build && docker compose up -d                   # rebuild after git pull
```

> **Network scanning note:** On Windows/macOS, Docker Desktop runs inside a VM — use `host.docker.internal` to scan the host machine instead of `127.0.0.1`.

> **GPU acceleration (optional):** Uncomment the `deploy.resources` block in `docker-compose.yml` to route Ollama inference through an NVIDIA GPU (`nvidia-container-toolkit` required on the host).

---

### Option B — Native Linux

> Full manual setup instructions: [Readme/requirements.md](Readme/requirements.md)

```bash
git clone --recurse-submodules https://github.com/PearceTech335/Noctis-Edge.git
cd Noctis-Edge
chmod +x setup.sh && ./setup.sh
```

`setup.sh` installs and configures (in order):

| Step | What gets installed |
|------|---------------------|
| Git submodules | `nikto/` (from [sullo/nikto](https://github.com/sullo/nikto)) |
| apt packages | `nmap`, `curl`, `ffuf`, `hydra`, `ssh-audit`, `dnsenum`, `dnsrecon`, `perl`, `golang-go`, `python3-tk`, and more |
| SecLists | Wordlists via `snap install seclists` |
| Nuclei | Go-based template scanner (`~/go/bin/nuclei`) |
| Ollama | Local LLM server + `gemma3:4b` + `qwen2.5-coder:7b-instruct` |
| Python venv | `.venv/` with `requests`, `jinja2`, `pycryptodome`, `flask`, `flask-sock` |
| CVE database | `CVE/cve-offline/` → `cve-summary.csv`; EPSS scores; NVD CVSS data |
| rdpscan | `rdpscan/` helper |
| Additional tools | `amass`, `metasploit-framework` |

After setup:
```bash
./noctis.py <target>   # Ollama starts automatically if not running
./noctis_web.py        # optional browser-based Web UI
```

---

## Quick Start

### Command Line

**Docker:**
```bash
docker compose run --rm noctis scan 192.168.0.1
docker compose run --rm noctis scan 192.168.0.1 web --cve-test
docker compose run --rm noctis scan 192.168.0.1 --aggressive --msf-validate --cve-test
docker compose run --rm noctis scan 192.168.0.1 --resume
```

**Native Linux:**
```bash
./noctis.py 192.168.0.1                                         # default web profile
./noctis.py 192.168.0.1 web external api                        # multiple profiles merged
./noctis.py 192.168.0.1 web --cve-test --dns-enum
./noctis.py 192.168.0.1 --aggressive --msf-validate --cve-test  # full aggressive run
./noctis.py 192.168.0.1 --resume                                # resume interrupted scan
```

![Command Line Usage](https://github.com/user-attachments/assets/5c27d403-60bb-4608-93ce-0332c1a5a2f4)

---

## Command-Line Flags

| Flag | Description |
|------|-------------|
| `<target>` | IP address or hostname to scan (required) |
| `[profile]` | Assessment profile (default: `web`). Multiple profiles merge their tool lists. |
| `--aggressive` | Disable safe mode — runs ffuf and hydra without approval prompts |
| `--dns-enum` | Enable DNS enumeration tools (amass, dnsenum, dnsrecon) — requires internet access |
| `--msf-validate` | Non-destructively validate each CVE match using Metasploit `check` |
| `--cve-test` | Generate and execute LLM-driven probe scripts for each matched CVE |
| `--unattended` | Auto-approve all interactive prompts (useful for scripted/automated runs) |
| `--resume` | Resume the most recent interrupted scan session for this target |

---

## Assessment Profiles

Pass one or more profile names after the target. Tools from all selected profiles are deduplicated and merged.

| Profile | Focus | Key Tools |
|---------|-------|-----------|
| `web` | Web Application Assessment | curl, nikto, nuclei, ffuf |
| `external` | External Perimeter Review | nmap, curl, nuclei, ffuf, dns_enum |
| `internal_ad` | Internal AD Assessment | nmap, nxc (SMB/LDAP) |
| `api` | API Assessment | curl, nuclei, ffuf |
| `cloud` | Cloud Exposure Review | curl, nuclei, dns_enum |
| `ot` | Industrial / OT Assessment | nmap (OT-aware — skips ffuf/hydra/nuclei by default) |

---

## How It Works

### 1. Startup Checks
- Starts `ollama serve` automatically if not running (waits up to 30 s)
- Pulls configured models if not present locally
- Validates all tool binaries and prints a status table

### 2. Five-Phase Nmap Discovery

| Phase | nmap flags | Output |
|-------|------------|--------|
| **1 — Host Discovery & Port List** | `-Pn -T4 --open -p- --min-rate 2000` | All open TCP ports |
| **2 — Service & Version Enumeration** | `-sV -sC -T4 -p <ports>` | Banners, version strings, product names |
| **3 — NSE Script Execution** | `--script <service-targeted NSE scripts>` | HTTP headers/methods, SSH algorithms, SMB shares, SSL ciphers, etc. |
| **4 — OS Detection** | `-O --osscan-guess` | OS fingerprint with confidence % |
| **5 — Normalise** | (in-process) | All phases merged into unified service list; NSE output and OS context attached per port |

Phase 3 uses a service-to-NSE-script map to select the most relevant scripts per service type — for example HTTP gets `http-title,http-headers,http-methods,http-auth-finder,http-robots.txt`; SSH gets `ssh-auth-methods,ssh2-enum-algos,ssh-hostkey`. The full NSE output is injected into every subsequent LLM planning prompt.

CVE lookups run against the normalised service list after Phase 5 completes.

### 3. LLM-Driven Scan — Phase 1 (Parallel)

1. The LLM analyzes all discovered services at once (with NSE context) and returns a JSON array of one initial tool per service — or a deterministic fast-path map is used for well-known service fingerprints (SMB, RDP, SSH, FTP, etc.), eliminating LLM calls entirely for common targets.
2. All actions in the wave run concurrently via `asyncio.gather()`, bounded by `MAX_PARALLEL_ACTIONS` (default 4).
3. Findings are enriched, verified, and auto-tagged before being passed into Phase 2 context.

### 4. LLM-Driven Scan — Phase 2 (Sequential Loop)

The loop deepens investigation, asking the LLM what to do next based on the target, discovered services, NSE results, all findings so far, tool run history, and disabled tools. The LLM responds with a single JSON action `{"tool": "<name>", "args": "<value>"}`. Noctis executes it, parses findings, and feeds results back into context.

Tools that time out with no findings are auto-disabled for the session. In `SAFE` mode (default), aggressive tools (ffuf, hydra) require operator approval before running.

### 5. Finding Verification & Enrichment

After each tool run, findings are:
- **Verified** — re-requesting a discovered path to confirm it is real rather than a false positive
- **Enriched** — `vuln_type` (e.g. RCE, SQLi, XSS), `cwe_id` (e.g. CWE-89), and `compliance_controls` (PCI-DSS, SOC2, ISO 27001, NIST CSF 2.0) inferred via internal mapping tables

### 6. Risk Scoring

```
risk_score = severity_weight × confidence × exposure × tool_confidence
```

| Factor | Values |
|--------|--------|
| `severity_weight` | critical=1.0, high=0.8, medium=0.5, low=0.2, info=0.05 |
| `confidence` | set by tool parser (e.g. curl=0.90, nikto=0.40) |
| `exposure` | 1.2 if internet-facing, 1.0 internal |
| `tool_confidence` | per-tool weighting from config |

### 7. Report Generation

Reports are saved to `sessions/<target>_<timestamp>/`:
- `report_<target>.json` — full machine-readable report
- `report_<target>.html` — styled HTML report with collapsible sections

Reports include: Executive Summary (severity counts), Compliance Impact (PCI-DSS / SOC2 / ISO 27001 / NIST CSF 2.0 control chips), Service Inventory with CVE badge links, Findings (severity, tool, risk score, verification status, CWE, evidence, raw HTTP response, command run), CVE Matches (CVSS v3.1/v4.0, EPSS exploit probability, attacker perspective, immediate remediation path), MSF/CVE test results, and LLM-generated conclusion.

### 8. Session Persistence

After each tool run the current state is saved to `sessions/<id>/session.json`. Use `--resume` to continue after an interruption.

---

## Optional Phases

### `--msf-validate`

After the main scan, for each matched CVE:
1. Searches Metasploit for a module matching the CVE ID
2. If found, runs `msfconsole -x "use <module>; set RHOSTS <target>; check; exit"` — MSF's non-destructive `check` command (no payload, no exploitation)
3. Result (`vulnerable`, `not vulnerable`, `unknown`, `no module`) is recorded in the report

Requires `msfconsole` on PATH. Requires operator approval in SAFE mode.

### `--cve-test`

After the main scan:
1. Shows an approval prompt listing the CVEs to be tested
2. For each CVE, asks the LLM to generate up to **5 independent probe scripts** (Python or Bash), each using a different technical strategy
3. Scripts are written to `sessions/<id>/cve_tests/` and executed with a 30-second timeout
4. Each script must print one of: `VERDICT: VULNERABLE`, `VERDICT: NOT_VULNERABLE`, `VERDICT: INCONCLUSIVE`
5. Results are tallied into an overall per-CVE verdict and written into the reports

**Verdicts:**
- `CONFIRMED_VULNERABLE` — multiple independent probes all returned VULNERABLE
- `VULNERABLE` — at least one probe returned VULNERABLE (not unanimously confirmed)
- `NOT_VULNERABLE` — majority NOT_VULNERABLE with no VULNERABLE result
- `INCONCLUSIVE` — probes ran but could not determine status (timeout, wrong protocol, banner-only, etc.)

**Knowledge Base:** Results are persisted in `cve_knowledge_base.json`. On future runs, previously successful scripts for the same CVE are replayed first, improving confidence without LLM generation. Running `./update.sh` submits this file to the community relay. Pulling the aggregated community KB requires a subscription token.

> **Note:** These are heuristic probes generated by a small local LLM, not actual exploits. A VULNERABLE verdict means the probe's logic triggered — treat it as a lead to investigate, not a confirmed exploitation.

---

## Output Structure

```
sessions/
└── localhost_20260424_102554/
    ├── session.json              ← live state (for --resume)
    ├── report_localhost.json     ← full JSON report
    ├── report_localhost.html     ← styled HTML report
    └── cve_tests/
        ├── CVE-2002-1367_attempt_01.py
        ├── CVE-2002-1367_attempt_02.sh
        └── ...

cve_knowledge_base.json           ← cross-engagement CVE test KB (project root)
                                     gitignored; submitted to community by ./update.sh
```

---

## Configuration

Top-of-file constants in `noctis.py` (all overridable via environment variables):

| Constant | Default | Env var | Description |
|----------|---------|---------|-------------|
| `MODEL` | `gemma3:4b` | `NOCTIS_OLLAMA_MODEL` | Planning, iteration decisions, structured JSON tool selection |
| `SCRIPT_MODEL` | `qwen2.5-coder:7b-instruct` | `NOCTIS_OLLAMA_SCRIPT_MODEL` | CVE exploit scripts, verification scripts |
| `CVE_SCRIPT_MODEL` | *(same as `SCRIPT_MODEL`)* | `NOCTIS_OLLAMA_CVE_SCRIPT_MODEL` | CVE probe generation — override with a larger model for better pivoting |
| `REPORT_MODEL` | `gemma3:4b` | `NOCTIS_OLLAMA_REPORT_MODEL` | Report conclusion, attacker perspective, remediation guidance |
| `OLLAMA_URL` | `http://localhost:11434/api/generate` | — | Ollama API endpoint |
| `MAX_ITERATIONS` | `10` | — | Minimum (floor) Phase 2 iteration count — applied when few services detected |
| `MAX_ITERATIONS_CAP` | `40` | — | Hard ceiling — dynamic budget and auto-extensions can never exceed this |
| `MAX_EXTEND_ONCE` | `20` | — | Extra iterations granted by operator approval once the hard ceiling is hit (interactive only) |
| `MAX_EXTENSION_BUDGET` | `8` | — | Total auto-granted extension iterations from uninvestigated findings (+2 per finding) |
| `MAX_PARALLEL_ACTIONS` | `4` | — | Max concurrent tools in the Phase 1 parallel wave |
| `MAX_LLM_RETRIES` | `3` | — | LLM call retries per iteration |
| `CVE_TEST_ATTEMPTS` | `5` | — | LLM script attempts per CVE in `--cve-test` |
| `SAFE_MODE` | `True` | — | Require approval for aggressive tools (override with `--aggressive`) |
| `UNATTENDED` | `False` | — | Auto-approve all prompts (override with `--unattended`) |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Five-phase discovery: full port scan → service/version enumeration → targeted NSE scripts → OS detection → normalisation |
| `curl` | HTTP probing |
| `nikto` | Web server vulnerability scanning (bundled in `nikto/`) |
| `nikto_cgi` | Web server vulnerability scanning with `-C all` — exhaustive CGI scan; auto-selected for all HTTP/HTTPS services in Phase 1 |
| `nuclei` | Template-based scanning |
| `ffuf` | Directory and web fuzzing (rate-limited, auto-calibrated; HTTP/HTTPS only) |
| `hydra` | Credential brute-forcing (aggressive mode only) |
| `ssh-audit` | SSH configuration auditing |
| `amass` | Subdomain enumeration (internet required) |
| `dnsenum` / `dnsrecon` | DNS enumeration (internet required) |
| `nxc` (NetExec) | SMB/LDAP enumeration for AD assessments |
| `msfconsole` | MSF validation (`--msf-validate`) |
| `rdpscan` | RDP enumeration |

> **Note:** `nikto/` is a git submodule pointing to [sullo/nikto](https://github.com/sullo/nikto). Clone with `--recurse-submodules` or run `git submodule update --init --recursive` after cloning.

Install notes: see [Readme/requirements.md](Readme/requirements.md).

---

## Ollama Setup

`setup.sh` installs Ollama and pulls both models automatically. `noctis.py` will also start `ollama serve` automatically and pull any missing model before the scan begins.

Manual install:
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull gemma3:4b                       # planning + report prose
ollama pull qwen2.5-coder:7b-instruct      # CVE probe + verification scripts
```

### Model Roles

| Model | Env var | Purpose |
|-------|---------|---------|
| `gemma3:4b` | `NOCTIS_OLLAMA_MODEL` | Tool selection, scan planning, structured JSON decisions |
| `qwen2.5-coder:7b-instruct` | `NOCTIS_OLLAMA_SCRIPT_MODEL` | CVE exploit and verification scripts |
| `qwen2.5-coder:7b-instruct` | `NOCTIS_OLLAMA_CVE_SCRIPT_MODEL` | CVE probe generation (override with a larger model for better strategy pivoting) |
| `gemma3:4b` | `NOCTIS_OLLAMA_REPORT_MODEL` | Report conclusion, attacker perspective, remediation guidance |

`gemma3:4b` is ~3.3 GB; `qwen2.5-coder:7b-instruct` is ~4.4 GB. During the main scan only one model is active at a time. During `--cve-test` both may be resident simultaneously — peak combined RAM ~7.7 GB. Inference is typically 20–90 s per call on CPU-only hardware after the initial warm load.

---

## Community Knowledge Base

`cve_knowledge_base.json` and `tool_knowledge_base.json` accumulate test results and tool-performance data at the project root. Each entry is identified only by CVE ID or service fingerprint — **no target-specific information is recorded**. Both files are gitignored and never committed.

Running `./update.sh` submits both files to the community relay via the Cloudflare Worker (`cloudflare/worker.js`). The worker source is included in this repository for full transparency. Your installation ID (generated once by `setup.sh`, stored in `noctis.conf`) is used only to rate-limit submissions (4 per day) and is never linked to personal data.

### Unlocking the Community Knowledge Base

Subscribers receive access to the aggregated community CVE and tool knowledge bases. Once you have subscribed at [noctisedge.lemonsqueezy.com](https://noctisedge.lemonsqueezy.com):

1. Open `noctis.conf` and add your license key:
   ```ini
   KB_LICENSE_KEY=XXXX-XXXX-XXXX-XXXX
   ```
2. Run `./update.sh` — the community KB is downloaded and additively merged into your local knowledge base.

---

## Application Maintenance

```bash
./update.sh
```

| Step | What happens |
|------|--------------|
| 1 | apt packages upgraded |
| 2 | SecLists (snap) refreshed |
| 3 | pip dependencies upgraded |
| 4 | Nuclei binary + templates updated |
| 5 | Ollama models pulled |
| 5a | EPSS offline database refreshed (daily exploit-probability scores, 330k+ CVEs) |
| 5b | NVD CVSS offline database updated (real CVSS v3.1/v4.0 from NVD JSON 2.0 feeds) |
| 6 | CVE offline database pulled + CSV rebuilt |
| 7 | Noctis Edge source updated (`git fetch` + `git reset --hard origin/master`); Docker image rebuilt if Docker is detected |
| 8 | Nikto submodule updated |
| 9–10 | CVE and Tool knowledge bases submitted to community relay; community KB pulled if `KB_LICENSE_KEY` is set |

> **Data safety:** `git reset --hard` only affects git-tracked files. All user data lives in gitignored paths (`sessions/`, `noctis.conf`, `cve_knowledge_base.json`, `tool_knowledge_base.json`) and is never touched by the update.

---

## Scripts

| Script | Purpose |
|--------|---------|
| `setup.sh` | One-shot setup for a fresh install. Generates a unique installation ID stored in `noctis.conf`. |
| `update.sh` | Refresh all components and submit local knowledge bases to the community relay. |
| `scripts/submit_kb.py` | POSTs the local CVE knowledge base to the Cloudflare relay. Called automatically by `update.sh`. |
| `scripts/merge_kb.py` | Additively merges an external CVE knowledge base JSON into the local one. |
| `scripts/submit_tool_kb.py` | POSTs the local tool performance knowledge base to the Cloudflare relay. Called automatically by `update.sh`. |
| `scripts/merge_tool_kb.py` | Additively merges an external tool knowledge base JSON into the local one. |

---

## Cloudflare Relay

The `cloudflare/` directory contains the Cloudflare Worker that relays KB submissions to the community repository.

| File | Purpose |
|------|---------|
| `cloudflare/worker.js` | Worker source — validates, rate-limits, and writes submissions to GitHub |
| `cloudflare/wrangler.toml` | Wrangler deployment config (KV bindings, route) |

| Route | Method | Purpose |
|-------|--------|---------|
| `/submit` | POST | CVE KB submission |
| `/community-kb` | POST | CVE community KB pull (license-gated) |
| `/submit-tool` | POST | Tool KB submission |
| `/community-tool-kb` | POST | Tool community KB pull (license-gated) |

The worker is already deployed at `https://noctis-kb-relay.pearcetechnologies1.workers.dev`. End users do not need to deploy anything.

---

## What Is NOT Committed to Git

| Path | Reason |
|------|--------|
| `sessions/` | Runtime scan output — local to each installation |
| `noctis.conf` | Per-user config (UUID, license key) |
| `cve_knowledge_base.json` | Machine-specific CVE test results |
| `tool_knowledge_base.json` | Machine-specific tool performance data |
| `cloudflare/.wrangler/` | Wrangler cache (contains Cloudflare account credentials) |
| `WordLists/rockyou.txt` | 139 MB — not needed for directory enumeration |
| `CVE/cve-offline/cve-summary.csv` | 57 MB — regenerated by `updatecsv.sh` |
| `CVE/cve-offline/` | Separate git repo |
| `CVE/.nvd-cache/` | NVD CVSS download cache — large intermediate `.json.gz` files |
| `rdpscan/` | Separate git repo |

---

## Version History

## What's New in v0.8.2

- **CVE verdict language precision:** Report conclusion no longer uses "confirmed exploitable" for version/banner-match CVEs. Language now distinguishes between "confirmed by active probe testing" (script ran and triggered the vulnerable behaviour) and "matched by version/banner analysis — manual verification recommended" (version string in range, but no live proof). Eliminates the risk of overclaiming to stakeholders.
- **Detection confidence badges on CVE test results:** Each CVE test result card now displays a colour-coded evidence type badge: `Active Probe` (teal — specific behaviour observed), `Version Match` (blue — version string confirmed in range), `KB Replay` (purple — replayed from prior knowledge base entry), `Banner Analysis` (grey — product/banner match only). Derived by `_derive_evidence_type()`.
- **Ease-of-Fix effort tags on CVE match cards:** Every CVE match now shows a `Low` / `Medium` / `High` effort pill (green/amber/red) between the business impact block and the compliance section, sourced from the new `_REMEDIATION_EFFORT` dict (18 vulnerability types). Helps operators prioritise patches they can ship quickly.
- **Compliance control reasoning:** Each compliance control chip (PCI-DSS, SOC2, ISO 27001, NIST CSF 2.0) in the CVE match section now expands with a one-sentence explanation of why the specific control applies to that vulnerability type. Sourced from the new `_COMPLIANCE_REASONING` dict (26 entries). No more bare control IDs without context.
- **Expanded executive summary:** Conclusion prompt now requests exactly 4 paragraphs of 3–5 sentences each in plain business language, with `top_findings` context (top 6 findings by risk score) injected into the LLM call. `num_ctx` raised from 2048 → 4096 for this call.
- **Remediation LLM speed improvement:** `_generate_immediate_remediation()` and `_generate_remediation()` switched from `REPORT_MODEL` to `SCRIPT_MODEL` (`qwen2.5-coder:7b-instruct`), which is significantly faster at structured output generation. Per-CVE remediation latency reduced.
- **Nuclei KB message accuracy:** Console output now correctly distinguishes `(N new template(s))` vs `unchanged (no HTTP/web CVEs tested this run)` instead of always printing a misleading "updated" message.
- **Nuclei HTTPS coverage expanded:** `_NUCLEI_HTTP_SERVICES` frozenset now includes `https-alt` and `ssl/https` in addition to the existing `https` and `ssl/http` entries, ensuring all common HTTPS service label variants trigger template generation.
- **ETA timing fix:** Phase checkpoint `frac_done` values are now strictly non-decreasing across the full scan pipeline. Previously "Base reports saved" used `frac_done=0.70` after MSF validation done at `0.85`, causing the estimated completion time to jump backwards mid-scan. All checkpoints now form a monotonically increasing sequence.
- **CVE verdict strictness hardened:** The CVE test LLM prompt now explicitly requires (a) a version string extracted and confirmed within the CVE range, OR (b) the specific vulnerable behaviour directly observed. Product/service name presence alone (e.g. `OpenSSH` in banner, `Apache` in Server header) is explicitly forbidden as a basis for `VULNERABLE`.
- **`docker-run.sh` macOS compatibility:** Replaced `df --output=avail /` (GNU coreutils only) with `df -k / | awk 'NR==2 {print $4}'` which works identically on macOS (BSD) and Linux.
- **Model alignment across all deployment files:** `setup.sh`, `update.sh`, `docker-run.sh`, and `docker-compose.yml` now all correctly reference `gemma3:4b` for planning and report prose, and `qwen2.5-coder:7b-instruct` for CVE scripts and verification scripts — matching the runtime defaults in `noctis.py`. Fresh installs and `./update.sh` runs now pull the correct models.

## What's New in v0.8.1

- **Semantic false-positive checking — `probe_inconclusive` verification status:** Low-confidence tool findings (nikto: 0.40, ffuf: 0.60) that cannot be automatically confirmed are no longer marked `verified` by the naive evidence-length heuristic. `verify_finding()` now applies a three-stage check: (1) if `matched_url` is present, curl is run against it and the response body is scanned for vuln-type-specific confirmation keywords (`_VULN_BODY_KEYWORDS`); (2) if no keywords match — or no usable curl response comes back — and the reporting tool has `TOOL_CONFIDENCE < 0.65`, the finding is marked `verification_status = "probe_inconclusive"` with `manual_review = True`; (3) high-confidence tool findings (nmap, ssh-audit, curl) with substantial evidence still auto-verify as before. Findings already marked `"confirmed"` by the tool itself (e.g. ssh-audit) are trusted immediately without re-running curl.
- **Vuln-type keyword validation (`_VULN_BODY_KEYWORDS`):** New constant dict mapping 11 vulnerability type strings to lists of HTTP response-body keywords that are meaningful confirmation signals. Types covered: Information Disclosure, XSS, SQL Injection, Directory Traversal, RCE, Open Redirect, SSRF, File Inclusion, Authentication Bypass, Misconfiguration, Weak SSL/TLS. Findings with an unknown or unlisted `vuln_type` fall back to the legacy heuristic (any response > 20 chars = verified) so no regression occurs for unclassified findings.
- **`verifier_tool` field on `Finding`:** New `str` field (default `""`) records which tool was dispatched in the verification attempt. Set to `"curl"` when curl is run and returns inconclusive results. Left empty when no tool was dispatched (low-confidence finding with no `matched_url`). Persisted to `session.json` and rendered in the report.
- **LLM re-probe guidance (Rule 9 + `needs_verification` context):** `query_llm()` now includes a `needs_verification` key in `ctx_summary` — a list of `{title, service, tool, vuln_type, evidence[:120]}` dicts for every finding currently at `probe_inconclusive` status. Rule 9 in the planning prompt instructs the model: *"If NEEDS_VERIFICATION findings appear in CURRENT FINDINGS, prioritise re-probing each with a different higher-confidence tool matched to its vuln_type and service (e.g. curl for HTTP header issues, nuclei for web vulns, ssh-audit for SSH) before exploring new areas."* This gives the LLM the information and the directive it needs to automatically dispatch a second, better-suited verifier tool in the next iteration.
- **Report — `probe_inconclusive` visual treatment:** Findings at `probe_inconclusive` status are rendered distinctly in the report: the verification badge uses the new `.probe-inc` CSS class (amber, bold: `#ff9800`) and displays `⚠ probe inconclusive` instead of the generic `discovered` label. An amber left-bordered callout box is inserted inside the expanded finding detail, stating which tool was used in the verification attempt and that manual inspection is recommended before treating the finding as confirmed. The orange `⚠ MANUAL REVIEW` badge is also set automatically. Confirmed findings remain green; unverified high-confidence findings remain amber `discovered`. No findings are demoted or hidden.

## What's New in v0.8.0

- **Per-service tool timeout tracking (replaces global tool ban):** Previously, if a tool timed out with no findings on one service (e.g. `dns_enum` on port 53), it was permanently added to `broken_tools` and banned for the entire scan — meaning it could never be tried on SSH, HTTP, or any other service later. The new mechanic tracks timeouts in `timed_out_tools: dict[str, set]` — a mapping from tool name to the set of service-type keys where it timed out. A tool is only skipped for the specific service type it failed on; it remains available for every other service type in the scan. The LLM planning prompt now includes a "TIMED OUT PER SERVICE" block listing which service types to avoid per tool, so the model can make informed routing decisions. `_fast_path_actions()` and `_untested_service_fallback()` both respect the per-service ban. Structural failures (binary missing, permission denied) still trigger the full session-wide `broken_tools` ban as before.
- **Iteration budget overhaul — formula now scales with services found:** Previously the base budget was `min(max(10, n_services), 40)` — one iteration per service — so 6 services gave only 10 iterations (floor). The new formula is `min(max(10, n_services × 5), 40)`: **5 iteration slots per service**, floored at 10, hard-capped at 40. For a typical 6-service web target this yields 30 iterations instead of 10, giving each port an initial probe plus 4 follow-ups without consuming the entire budget on a single noisy scanner. The budget log line now prints the full calculation: `services × 5 = N, floor: 10, cap: 40`.
- **Proactive finding-based extension mechanic replaces single-shot extension:** The old code granted one automatic extension equal to the raw count of uninvestigated findings, which could push `effective_max` far above `MAX_ITERATIONS_CAP`. The new mechanic fires at every budget exhaustion point (not just once): it counts findings with no follow-up tool run, grants `+2 iterations per uninvestigated finding`, and consumes from a pool of `MAX_EXTENSION_BUDGET = 8` total auto-granted iterations across the entire scan. The pool is bounded by remaining headroom to `MAX_ITERATIONS_CAP`. For 10 uninvestigated findings: `min(20, 8, headroom)` = **+8** iterations maximum from auto-extension.
- **All-tools-disabled early exit:** At the start of every iteration (after `i += 1`) the engine now checks whether every tool is in `broken_tools`. If true it prints a warning and stops immediately rather than spinning out the remaining budget producing empty iterations.
- **Operator-approved ceiling overage is now exact and one-shot:** When the hard ceiling (`MAX_ITERATIONS_CAP = 40`) is reached, the interactive prompt offers exactly `MAX_EXTEND_ONCE = 20` additional iterations (`effective_max = 40 + 20 = 60`). Previously the prompt added an unbounded `+= 20` that could be triggered repeatedly. The extension is now capped at exactly one overage. In `--unattended` mode the ceiling stops the scan immediately without prompting.
- **Bug fix — `NameError: _svc_list` crash at first LLM iteration:** `query_llm()` referenced `_svc_list` in the tool-reference block comprehension but never defined it. This caused every scan to crash silently at the start of iteration 1 after Phase 1 tools finished — session directories were created but all files (including `session.json`) were never written. Fixed by assigning `_svc_list = context.get("services", [])` immediately before the check. Also hardened the loop to use `.get()` instead of direct key access so missing `status` or `recommended_tools` fields on a service dict no longer raise `KeyError`.
- **Nmap Phase 2 failure resilience:** When Phase 2 (`-sV -sC --version-intensity 7`) returns no service data (timeout on high-latency targets, or `-sC` default scripts hanging), the scanner now automatically retries with a lighter scan (`-sV --version-intensity 5`, no `-sC`, 120 s timeout) before continuing. Any port that Phase 2 still cannot enrich is flagged `version_unknown: True` in the service record. These ports are: (1) logged as a warning with a list of affected ports so the operator is aware; (2) annotated in the LLM planning prompt as `[VERSION UNKNOWN — probe with curl or nmap]` so the model actively probes them rather than silently skipping; (3) tagged in the CVE lookup path so missing version data is treated as expected rather than an error. Previously Phase 2 failure produced zero enrichment with no warning, no CVE matches, and the LLM receiving bare port numbers with empty service names.
- **LLM tool-selection guidance now conditional and lean:** The TOOL REFERENCE block (manifest capability guide) is only injected into the LLM planning prompt when there are services with `status == NOT_YET_TESTED` or no `recommended_tools` entry. For well-explored targets where every service already has KB history, the block is omitted entirely — keeping prompts shorter and faster to process. Rule 5 in the LLM prompt was updated to reflect this: *"Prefer tools from each service's `recommended_tools` list — use higher KB success rate tools first. For NOT_YET_TESTED services, consult the TOOL REFERENCE block."*
- **LLM prompt hardened against stale service dicts:** service fields `status` and `recommended_tools` are now accessed via `.get()` throughout `query_llm()`, so partial service records (e.g. services that completed nmap Phase 2 but did not reach Phase 3 enrichment) no longer raise `KeyError` and silently abort the iteration.
- **Bug fix — Dockerfile EPSS step incorrectly fails the build:** `build_epss_db.py` was returning a non-zero exit code when the FIRST.org CDN returns HTTP 403 (rate-limiting). Although the `||` fallback catches the failure at the shell level, Docker's BuildKit was still recording exit code 1 and marking the build as failed. Fixed by appending `; true` to the fallback branch to guarantee the layer always exits 0.

## What's New in v0.7.8

- **Tool manifest system (`tool_manifest.json`):** New subscriber artifact that gives the LLM per-tool capability guidance, service routing keywords, and flag examples for every scanning tool. `_tools_for_service()` is now manifest-driven — service keywords are matched against nmap service names, with `curl` as the automatic catch-all for unrecognised ports. Delivered via `update.sh` step 11 (license-key gated). Build or extend locally with `scripts/build_tool_manifest.py` and `scripts/add_tool_manifest.py`. The manifest is gitignored and never submitted to the community pipeline.
- **LLM stuck-on-duplicate fix (`_untested_service_fallback()`):** A new rule-based function intercepts the first consecutive duplicate action before burning 90-second LLM retries. It scans the service list for the first port with no prior `used_actions` entry and returns the best tool for that port (from `recommended_tools` or curl). This eliminates the pattern where a multi-service scan (e.g. SSH + VNC + HTTP) kept looping `ssh_enum` because VNC and unknown services returned `[]` from `_tools_for_service()` and were silently excluded from Phase 1.
- **`_tools_for_service()` catch-all fixed:** Previously returned `[]` for unknown services, causing the Phase-1 parallel scan filter to silently skip VNC, Kerberos, NetAssistant, and any other unrecognised port. Now returns `["curl"]` as a safe fallback with a logged advisory message.
- **`_FAST_PATH` extended:** Added `curl` fast-path entries for `vnc`, `rfb`, `kerberos`, `netassistant`, and `apple-remote` services so Phase 1 immediately probes these ports rather than waiting for LLM guidance.
- **Nikto severity triage:** `parse_nikto_output()` previously assigned `severity="info"` to every finding regardless of content. A new `_NIKTO_SEVERITY_UPGRADES` table (~40 pattern rules) now upgrades findings to `critical`/`high`/`medium`/`low` based on content keywords (CVEs → high, HTTP TRACE/XST → high, directory listing → medium, security header absence → low, etc.). The cap on returned findings increased from 15 → 30.
- **`manual_review` flag on findings:** `Finding` dataclass gains a `manual_review: bool` field. Nikto sets it to `True` on any finding upgraded above `info`. HTML report cards for these findings display an orange **⚠ MANUAL REVIEW** badge in the finding summary line.
- **LLM prompt enriched with service coverage status:** `query_llm()` now passes each service as a structured dict including `recommended_tools` and `status: NOT_YET_TESTED / tested` — previously the LLM saw only bare port/service strings and could not tell which ports had been exercised. A TOOL REFERENCE block (from the manifest) is injected into the prompt when untested or no-recommendation services are present.
- **`num_ctx` 1024 → 2048 for planning calls:** `_OLLAMA_PLAN_OPTIONS` `num_ctx` increased to accommodate the richer prompt with the TOOL REFERENCE block (~300 extra tokens). RAM impact is minimal (~100 MB).
- **`update.sh` step 11 — tool manifest pull:** New update step downloads `tool_manifest.json` from the relay endpoint (`/tool-manifest`) for subscribers. Validates JSON before overwriting the local copy. Existing step count updated to 11/11.
- **Docker bind-mount for `tool_manifest.json`:** `docker-compose.yml` now bind-mounts `./tool_manifest.json:/app/tool_manifest.json`. If the file is absent on the host, Docker creates a directory; `docker-entrypoint.sh` detects and removes the directory without creating a `{}` placeholder, so the scanner starts cleanly with a logged advisory.
- **New public scripts:** `scripts/build_tool_manifest.py` (Ollama-powered full-manifest generation), `scripts/add_tool_manifest.py` (single-tool CLI helper), `scripts/submit_tool_manifest.py` (operator manifest push to relay).

## What's New in v0.7.7

- **Script model upgraded to `qwen2.5-coder:7b-instruct`:** `SCRIPT_MODEL` and `CVE_SCRIPT_MODEL` default changed from `qwen2.5-coder:3b-instruct` to `qwen2.5-coder:7b-instruct` for improved CVE probe and verification script quality. Peak concurrent RAM during `--cve-test` increases to ~7.7 GB; 16 GB recommended.
- **Nikto `libjson-perl` fix:** `libjson-perl` added to the Dockerfile `apt-get install` list. Previously missing, causing nikto to print `Required module not found: JSON` at startup, which matched `BROKEN_TOOL_SIGNALS` and disabled nikto for every session without explanation. A post-clone sanity check is now baked into the Dockerfile build so missing Perl modules fail the build immediately.
- **CVE database race condition fixed:** `docker-entrypoint.sh` now always builds `cve-summary.csv` synchronously if missing (previously built in background `&`, so the scan started before the CSV was ready, producing "no CVEs matched" on every port).
- **`_load_cve_db()` self-heal:** if `cve-summary.csv` is missing at runtime, `noctis.py` now attempts to rebuild it automatically via `build_cve_db.py`. If the build also fails, it hard-exits with a `[FATAL]` message and exact instructions instead of silently returning an empty DB.
- **Bug fix — CVE knowledge base never persisted in Docker:** `_save_cve_kb()` was only called once after all CVEs finished testing. Stopping the scan mid-run (container restart, web UI stop, Ctrl-C) discarded all in-memory KB data, leaving `cve_knowledge_base.json` permanently empty. Fixed with two layers: (1) `_save_cve_kb()` is now called after every individual CVE completes inside `run_cve_tests`, so progress is flushed incrementally; (2) `_run_cve_test_phase` now wraps the test loop in `try/finally`, guaranteeing a final flush even on unexpected exits or exceptions.

## What's New in v0.7.6

- **Two-model architecture:** `gemma3:4b` handles planning and report prose; `qwen2.5-coder:3b-instruct` handles CVE and tool scripts. Updated `setup.sh`, `update.sh`, `docker-run.sh`, `docker-compose.yml`.
- **`nikto_cgi` auto-selected for HTTP/HTTPS in fast-path:** placed before plain `nikto` so all web services receive the exhaustive CGI scan without any LLM request.
- **Bash permitted in CVE probe scripts:** all three CVE script generation prompts now offer Python 3 or bash; execution layer already supported bash — only the prompts were gating Python-only output.
- **Bug fix — `nxc_smb`/`nxc_ldap` silently blocked:** both tools were missing from `KNOWN_TOOLS` and `validate_action()`, so every SMB/LDAP action was dropped before execution. Fixed by adding both to `KNOWN_TOOLS` and adding the corresponding `validate_action()` branch.
- **Bug fix — `nxc_smb`/`nxc_ldap` missing dispatch handlers in `run_tool()`:** added `if tool == "nxc_smb"` and `if tool == "nxc_ldap"` branches with correct `nxc smb`/`nxc ldap` command strings.
- **Bug fix — `nxc` first-time-use race condition:** two parallel Phase 1 `nxc_smb` actions crashed when both tried to create `~/.nxc/` simultaneously. Fixed by running `nxc --version` at startup pre-flight to pre-create the directory.
- **Bug fix — `OLLAMA_TIMEOUT` increased 180 → 360 s:** after a long Phase 1 parallel wave, `gemma3:4b` could be evicted from RAM on 8 GB machines; 360 s provides a safe buffer for cold reloads (overridable via `NOCTIS_OLLAMA_TIMEOUT`).
- **Runtime & ETA status line at every major scan phase:** CLI and Web UI print current time, elapsed time, and estimated completion at nmap discovery, Phase 1, each iteration, MSF validation, report save, and CVE test boundaries.
- **HTML report — "Scan Findings" heading:** the Findings section heading was renamed from "Findings" to make clear these are tool-based scanner results, not NSE-specific output.
- **HTML report — CVE Matches sorted by EPSS:** CVEs now appear highest exploit probability first instead of by CVSS score.
- **Community KB pipeline fixes:** `SVC_KEY_RE` broadened to accept all valid service-fingerprint strings (was rejecting `http`, `werkzeug/http`, etc.); `timed_out_count` field name corrected (was `timeout_count` — caused zero tool KB slots ever published).
- **Bug fix — `update.sh` did not rebuild Docker image after source pull:** added Docker detection to `update.sh`; if Docker is present, the script now runs `docker compose build` + `docker compose up -d --no-deps` after the git reset.
- **Bug fix — Docker KB persistence:** `os.replace()` fails with `EXDEV` across Docker bind-mount boundaries, silently discarding all CVE/tool KB data on container restart. Fixed with `shutil.copy2()` + `os.unlink()` fallback; `docker-entrypoint.sh` now bootstraps missing KB files as `{}` at startup.

---

## What's New in v0.7.5

- **CVE test pipeline reverted to sequential execution:** `asyncio.gather` was removed; scripts now run in sequence so each new generation sees the previous attempt's output and verdict before the next script is created.
- **Stronger strategy-pivot enforcement:** each CVE test prompt now includes a `BANNED STRATEGIES` block listing every previous failed attempt's strategy; `temperature` raised 0 → 0.4; `num_ctx` raised 2048 → 4096.
- **Neutral example JSON in CVE script prompt:** the previous example showed `if 'version' in r.text`, anchoring small models to banner-check probes. Replaced with a socket-based skeleton that suggests no specific strategy.
- **`CVE_SCRIPT_MODEL` constant added:** new constant (env var `NOCTIS_OLLAMA_CVE_SCRIPT_MODEL`) lets operators dedicate a larger model to CVE probe generation without affecting planning or verification models.
- **Report conclusion rebuilt after `--cve-test`:** the conclusion is now regenerated deterministically once CVE testing finishes — `CONFIRMED_VULNERABLE` promotes posture to `critical`; `VULNERABLE` promotes to at least `high`.
- **Conclusion wording fix:** when scanner finds zero findings but CVEs are confirmed exploitable, the conclusion now leads with *"identified no scanner findings but CVE testing revealed N CVE(s) confirmed exploitable"* instead of producing a contradictory sentence.
- **`IMMEDIATE REMEDIATION PATH` green bar:** renamed from `THE FIX`; now shows LLM-generated 3-step actionable guidance specific to the CVE, product, and port — no generic "apply vendor patch" advice.
- **Attacker Gain & Lateral Movement Potential section:** new amber-bordered block inside every CVE match card with a confirmed or likely-vulnerable verdict, surfacing the LLM-generated `attacker_perspective` text without requiring the reader to scroll to test results.

---

## What's New in v0.7.4

- **CVE IDs hyperlinked to NVD:** every CVE ID in the report links directly to `https://nvd.nist.gov/vuln/detail/<CVE-ID>`.
- **Real CVSS v3.1/v4.0 from offline NVD database:** authoritative scores sourced from local NVD data instead of derived estimates; score header labelled `v3.1` or `v4.0`; both shown where available.
- **EPSS exploitation probability badge:** amber `EPSS X.X%` badge on every CVE card with exact probability and percentile rank (sourced from FIRST.org).
- **"The Fix" green one-liner:** prominent green `THE FIX` block at the top of every expanded CVE card showing the short-term tactical workaround before any technical detail.
- **CWE IDs hyperlinked to MITRE:** CWE identifiers link to `https://cwe.mitre.org/data/definitions/<N>.html`.
- **OT warning banner + Type column:** orange banner when OT/ICS services are detected; new `Type` column shows `OT` (orange badge) or `IT` with protocol tooltip.
- **EPSS offline database:** `build_epss_db.py` downloads daily FIRST.org EPSS scores (~330k CVEs) to `CVE/epss-scores.csv`; 3-day fallback for early-UTC runs.
- **NVD CVSS offline database:** `build_nvd_cvss.py` incrementally downloads NVD JSON 2.0 feeds (2002–current, ~348k CVEs) to `CVE/nvd-cvss.csv`; only changed years re-downloaded on update.
- **NIST CSF 2.0 compliance mappings:** all 17 vulnerability types now map to NIST CSF 2.0 functions and control identifiers; CSF 2.0 chips appear in the Compliance Impact section.
- **`ot` assessment profile:** classifies services using 15 OT/ICS protocol ports and 20 vendor/product keywords; OT services annotated with `asset_type`, `ot_protocol`, and `ot_standard` in session JSON.
- **Docker improvements:** EPSS scores pre-fetched at image build time; `CVE` bind mount added to `docker-compose.yml`; entrypoint checks EPSS staleness and missing NVD CVSS on startup.

---

## What's New in v0.7.3

- **Three-role model split:** dedicated `REPORT_MODEL` (default `qwen2.5:3b`) for report conclusion, attacker perspective, and remediation prose; `MODEL`/`SCRIPT_MODEL` remain `qwen2.5-coder:3b-instruct`. Override via `NOCTIS_OLLAMA_REPORT_MODEL`.
- **Deterministic conclusion anchor:** the first sentence of the conclusion is built from real finding counts, not asked of the LLM — eliminates hallucinations where the model described 15 high-severity findings as "few vulnerabilities".
- **Polar.sh → Lemon Squeezy migration:** license validation for the community KB subscription moved to Lemon Squeezy.

---

## What's New in v0.7.2

- **Collapsible report sections:** Findings and CVE Matches sections collapse to header-only by default with a styled expand control.
- **Attacker perspective narrative in CVE test cards:** LLM-generated threat context (attacker gain, lateral movement potential) added above remediation inside each CVE test result card.
- **CVE test scripts parallelised:** Phase 2 probe scripts run concurrently via `asyncio.gather`, cutting worst-case CVE test wall-clock time by ~60%.

---

## What's New in v0.7.1

- **Automatic Ollama startup + model pull:** `noctis.py` starts `ollama serve` automatically if not running (waits up to 30 s) and pulls the configured model if not present locally.
- **Line-buffered stdout when piped:** `sys.stdout.reconfigure(line_buffering=True)` at startup ensures every log line appears immediately under `tee` or pipe.
- **Single-model architecture:** `phi4-mini:3.8b` removed; `qwen2.5-coder:3b-instruct` handles all LLM tasks (planning, scripting, reports).
- **Deterministic fast-path tool selector:** `_FAST_PATH` table maps well-known service fingerprints (SMB, RDP, SSH, FTP, HTTP, MySQL, MSSQL, DNS, LDAP, VMware, etc.) to tools without any LLM call.
- **Model keep-alive:** `keep_alive="1h"` sent with every Ollama request and passed as `OLLAMA_KEEP_ALIVE` to `ollama serve` — eliminates cold-load penalty between scan phases.
- **Inference options tightened:** `num_ctx` capped at 1024; `temperature: 0`; `format: json` grammar-constrained decoding on all planning and CVE calls.
- **Model warm-start:** `_warmup_models()` fires a tiny prompt at each model during the nmap discovery phase so the first real LLM call is warm.
- **INCONCLUSIVE reason surfaced in reports:** HTML report shows an amber ⚠ "Why INCONCLUSIVE?" callout per CVE row; JSON gains `inconclusive_reason` field; existing session JSONs upgraded on `--report` re-render.

---

## What's New in v0.7.0

- **Five-phase nmap discovery pipeline:** replaces the single fast-port-scan with: (1) full port list (`-p-`), (2) service/version enumeration (`-sV -sC`), (3) targeted NSE scripts per service, (4) OS detection (`-O`), (5) normalisation and merge.
- **NSE results injected into LLM context:** full NSE output summary included in every planning prompt for both Phase 1 and the sequential loop.
- **Nmap NSE Script Results table in HTML report:** lists each port and the NSE scripts executed against it when Phase 3 produced output.
- **`nmap_discovery` key in JSON report:** captures `open_ports`, `os_detected`, and `nse_summary` (port → script IDs executed).

---

## What's New in v0.6.8

- **Docker Ollama health check:** replaced `curl` with a pure-bash TCP probe (`</dev/tcp/localhost/11434`) — the official Ollama image does not include `curl`.
- **Ollama `start_period` increased 20 s → 45 s:** gives the Ollama server process enough time to initialise before health checks begin.
- **Docker env vars corrected:** `docker-compose.yml` now uses `NOCTIS_OLLAMA_MODEL` and `NOCTIS_OLLAMA_SCRIPT_MODEL` (was `NOCTIS_REPORT_MODEL`, which `noctis.py` does not recognise).
- **Disk space pre-flight checks:** `docker-run.sh` requires 8 GB free; `docker-test.sh` requires 2 GB free — exits with a clear message instead of failing mid-build.
- **`exec -T` flag added** to all `docker compose exec` calls in `docker-run.sh` and `docker-test.sh` — required for non-interactive script/CI execution.
- **Dockerfile Go cache cleanup:** `rm -rf /root/go/pkg/mod /root/go/pkg/cache /root/.cache/go-build` after `go install` steps — removes ~1 GB of intermediate build cache from the final image.
- **`.dockerignore` expanded:** `CVE/cve/` (~200 MB raw NVD JSON) excluded from Docker build context.
- **`docker-test.sh` model variable rename:** `REPORT_MODEL` → `SCRIPT_MODEL`, mapped to `NOCTIS_OLLAMA_SCRIPT_MODEL`.

---

## What's New in v0.6.7

- **`ffuf` scoped to HTTP/HTTPS only:** removed from the IPP/CUPS service branch — IPP on port 631 returned no directory listings and wasted ~5 minutes per port.
- **Tiered KB script selection with per-script success ranking:** scripts track `runs`, `vulnerable_count`, `not_vulnerable_count`, `inconclusive_count`; `VULNERABLE` weighted 3×, `NOT_VULNERABLE` 1×, `INCONCLUSIVE` 0×. When a CVE has > 20 KB scripts: top-10 by rank + 5 random mid-tier + 5 random low-tier selected for each run.
- **Community confirmation bonus:** `+0.5` score per confirmation beyond the minimum-2 required for community KB inclusion — scripts validated by more users rank above untested local scripts.
- **Tool Knowledge Base community pipeline:** `submit_tool_kb.py`, `merge_tool_kb.py`, Cloudflare Worker routes `/submit-tool` + `/community-tool-kb`, and `update.sh` step 9/9 added.

---

## What's New in v0.6.6

- **Split-model architecture:** `qwen2.5-coder:3b-instruct` (code-specialist, ~2 GB) added for CVE script generation; `phi4-mini:3.8b` retained for planning, iteration decisions, report prose, and remediation guidance.
- **`SCRIPT_MODEL` constant added:** controls the script-generation model; overridable via `NOCTIS_OLLAMA_SCRIPT_MODEL` env var.
- **Three CVE script generation sites switched to `SCRIPT_MODEL`:** `_generate_known_exploit_script`, `_generate_cve_test_script`, `_generate_verification_script`.
- **Models run sequentially:** no concurrent model loading — no additional RAM overhead over single-model architecture.
- **Fixes false-positive CVE verdicts:** broken Python syntax in LLM-generated probe scripts (logic fall-through, missing imports, wrong protocol) caused false positives; `qwen2.5-coder` produces significantly fewer broken scripts.
- **`setup.sh` and `update.sh` pull both models automatically:** ~2 GB additional storage.

---

## What's New in v0.6.5

- **Single-model architecture:** `llama3.2:3b` removed; `phi4-mini:3.8b` handles all LLM tasks — tool planning, CVE script generation, report conclusion, and remediation guidance.
- **`REPORT_MODEL` / `NOCTIS_REPORT_MODEL` removed:** `MODEL` constant now used for all tasks, simplifying configuration.
- **phi4-mini v1 prompt improvements — `PYTHON RULES` block:** explicit Python syntax rules in all three CVE script prompts prevent broken-Python / non-stdlib import failures.
- **`FORBIDDEN` import list:** eliminates `bs4`/`lxml` failures caused by unavailable libraries.
- **Single-quote rule:** stops escaped double-quotes from breaking JSON output.
- **Concrete working script example in JSON reply format:** model adapts existing syntax rather than inventing new patterns.
- **`CONTRAST RULE — MANDATORY` in verification prompt:** enforces an independent technical approach for the verification script.
- **`ALREADY RUN` moved to top of iteration prompt:** exploits primacy bias to prevent the model from repeating failed tool invocations.
- **Numbered rules + general-tool fallback in iteration prompt:** provides a structured decision hierarchy.
- **Single `BLACKLIST` in parallel-scan prompt:** merges `used_actions` and `broken_tools` into one block.
- **Collapsible CVE test result cards in HTML report:** each CVE card collapses to header-only by default; click to expand attempts, verification, and remediation.

---

## What's New in v0.6.4

- **Scan engine switched to `phi4-mini:3.8b`:** 2.5 GB model with 128K context window and native function calling; ~60–90 s/call on CPU vs ~3–5 min for the previous 7b model.
- **4-strategy LLM response parser added:** handles the four common response formats from the model.
- **`nikto_cgi` tool added:** runs `nikto -C all` for exhaustive CGI directory scanning.
- **Port-qualified service keys and best-tool-per-service rankings:** service keys now include port number; tools ranked by expected finding quality per service type.
- **Fixed `ffuf -retries` flag and Phase 1 URL construction.**
- **`maxtime` exposed in ffuf descriptions.**
- **CVE test verdicts shown in console summary.**
- **Version displayed in CLI banner and Web UI.**
- **Dedicated short-term/long-term remediation and Steps to Reproduce sections added to HTML report.**

---

## Credits

| Tool / Library | Author / Org | Purpose |
|----------------|-------------|---------|
| [Nikto](https://github.com/sullo/nikto) | Chris Sullo | Web server vulnerability scanner (bundled as submodule) |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | ProjectDiscovery | Template-based vulnerability scanning |
| [nmap](https://nmap.org) | Gordon Lyon (Fyodor) | Network discovery and port scanning |
| [ffuf](https://github.com/ffuf/ffuf) | Joona Hoikkala | Fast web fuzzer |
| [Hydra](https://github.com/vanhauser-thc/thc-hydra) | van Hauser / THC | Login brute-force testing |
| [ssh-audit](https://github.com/jtesta/ssh-audit) | Joe Testa | SSH configuration auditing |
| [Amass](https://github.com/owasp-amass/amass) | OWASP | Network attack surface mapping |
| [Metasploit Framework](https://github.com/rapid7/metasploit-framework) | Rapid7 | Exploitation framework for MSF validation |
| [rdpscan](https://github.com/robertdavidgraham/rdpscan) | Robert David Graham | RDP vulnerability scanning |
| [Ollama](https://ollama.com) | Ollama, Inc. | Local LLM server |
| [trickest/cve](https://github.com/trickest/cve) | Trickest | CVE PoC reference database (submodule) |
| [trickest/cve-offline](https://github.com/trickest/cve-offline) | Trickest | Offline CVE CSV dataset |
| [SecLists](https://github.com/danielmiessler/SecLists) | Daniel Miessler | Security wordlists |
| [NetExec (nxc)](https://github.com/Pennyw0rth/NetExec) | Pennyw0rth | Network service execution and enumeration |
| [Flask](https://flask.palletsprojects.com) | Pallets | Web framework for the browser UI |
| [flask-sock](https://github.com/miguelgrinberg/flask-sock) | Miguel Grinberg | WebSocket support for Flask |
| [Requests](https://requests.readthedocs.io) | Kenneth Reitz | HTTP library |
| [Jinja2](https://jinja.palletsprojects.com) | Pallets | HTML report templating |
| [PyCryptodome](https://pycryptodome.readthedocs.io) | Legrandin | Cryptographic primitives |
