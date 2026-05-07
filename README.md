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
| Ollama — `qwen2.5-coder:3b-instruct` (scripts) | ~2.0 GB |
| Nuclei templates | ~1.5 GB |
| CVE offline database | ~3–5 GB |
| SecLists wordlists | ~2 GB |
| Tool binaries + Python venv | ~1 GB |
| Scan session outputs | Variable |

> **RAM note:** Only one model is active at a time during the main scan loop. During `--cve-test`, both models may be warm simultaneously — peak concurrent RAM is ~5.2 GB.

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

The launcher script handles everything automatically: pulls latest source, builds the Docker image (all tools + offline CVE database baked in), starts the Ollama sidecar and downloads the LLM models (~5.2 GB total, one-time, stored in a Docker volume), then starts the Web UI at **http://localhost:5000**.

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
| Ollama | Local LLM server + `gemma3:4b` + `qwen2.5-coder:3b-instruct` |
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
| `SCRIPT_MODEL` | `qwen2.5-coder:3b-instruct` | `NOCTIS_OLLAMA_SCRIPT_MODEL` | CVE exploit scripts, verification scripts |
| `CVE_SCRIPT_MODEL` | *(same as `SCRIPT_MODEL`)* | `NOCTIS_OLLAMA_CVE_SCRIPT_MODEL` | CVE probe generation — override with a larger model for better pivoting |
| `REPORT_MODEL` | `gemma3:4b` | `NOCTIS_OLLAMA_REPORT_MODEL` | Report conclusion, attacker perspective, remediation guidance |
| `OLLAMA_URL` | `http://localhost:11434/api/generate` | — | Ollama API endpoint |
| `MAX_ITERATIONS` | `10` | — | Max Phase 2 sequential loop iterations |
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
ollama pull qwen2.5-coder:3b-instruct      # CVE probe + verification scripts
```

### Model Roles

| Model | Env var | Purpose |
|-------|---------|---------|
| `gemma3:4b` | `NOCTIS_OLLAMA_MODEL` | Tool selection, scan planning, structured JSON decisions |
| `qwen2.5-coder:3b-instruct` | `NOCTIS_OLLAMA_SCRIPT_MODEL` | CVE exploit and verification scripts |
| `qwen2.5-coder:3b-instruct` | `NOCTIS_OLLAMA_CVE_SCRIPT_MODEL` | CVE probe generation (override with a larger model for better strategy pivoting) |
| `gemma3:4b` | `NOCTIS_OLLAMA_REPORT_MODEL` | Report conclusion, attacker perspective, remediation guidance |

`gemma3:4b` is ~3.3 GB; `qwen2.5-coder:3b-instruct` is ~2 GB. During the main scan only one model is active at a time. During `--cve-test` both may be resident simultaneously — peak combined RAM ~5.2 GB. Inference is typically 20–90 s per call on CPU-only hardware after the initial warm load.

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

| Version | Date | Summary |
|---------|------|---------|
| **v0.7.6** | May 2026 | Two-model architecture: `gemma3:4b` (planning + prose), `qwen2.5-coder:3b-instruct` (scripting); `nikto_cgi` auto-selected for all HTTP/HTTPS in fast-path; bash permitted in CVE probe scripts; nxc_smb/nxc_ldap fixes; OLLAMA_TIMEOUT 180→360 s; runtime & ETA status line at each scan phase; CVE Matches sorted by EPSS; submissions pipeline bug fixes |
| **v0.7.5** | May 2026 | CVE test pipeline reverted to sequential execution; stronger LLM strategy-pivot enforcement (BANNED STRATEGIES block, temperature 0→0.4, num_ctx 2048→4096); `CVE_SCRIPT_MODEL` constant; `IMMEDIATE REMEDIATION PATH` green bar with LLM-generated 3-step guidance; Attacker Gain & Lateral Movement section in CVE match cards |
| **v0.7.4** | May 2026 | CVE IDs hyperlinked to NVD; real CVSS v3.1/v4.0 from offline NVD DB; EPSS badge with exploit probability and percentile; CWE links to MITRE; OT warning banner + Type column; EPSS offline DB (330k+ CVEs); NVD CVSS offline DB (348k records); NIST CSF 2.0 compliance mappings; `ot` assessment profile |
| **v0.7.3** | May 2026 | Three-role model split with dedicated `REPORT_MODEL`; deterministic conclusion anchor from real finding counts; Polar.sh → Lemon Squeezy migration |
| **v0.7.2** | May 2026 | Collapsible report sections; attacker perspective narrative in CVE test cards; resume session picker in Web UI |
| **v0.7.1** | May 2026 | Automatic Ollama startup + model pull; deterministic fast-path tool selector; model keep-alive; INCONCLUSIVE reason surfaced in reports |
| **v0.7.0** | May 2026 | Five-phase nmap discovery pipeline; NSE script results injected into LLM planning context |
| **v0.6.7** | May 2026 | ffuf scoped to HTTP/HTTPS only; Tool KB community pipeline |
| **v0.6.6** | May 2026 | Split-model architecture: `qwen2.5-coder:3b-instruct` for CVE scripts |
| **v0.6.5** | May 2026 | Single-model architecture (`phi4-mini:3.8b`); phi4-mini v1 prompt improvements; collapsible CVE test result cards |
| **v0.6.4** | May 2026 | `phi4-mini:3.8b` scan engine; 4-strategy LLM response parser; `nikto_cgi` tool; port-qualified service keys |

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
