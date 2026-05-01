# Noctis Edge

<p align="center">
  <img src="noctis_logo.png" alt="Noctis Edge Logo" width="400"/>
</p>

**Security Through Exposure**

Noctis Edge is a Python-based, AI-assisted penetration testing platform built with a strong focus on **local execution, data sovereignty, and operational security**.

Unlike cloud-dependent security platforms, **Noctis Edge runs entirely on the local machine**. All scanning, analysis, LLM-assisted testing, CVE validation, reporting, and evidence generation are performed on-device, ensuring that **no target data, credentials, vulnerability findings, or client-sensitive information ever leaves the host system**.

The platform conducts automated, LLM-guided penetration testing against a target environment, collects and verifies findings, generates professional HTML reports, and can optionally validate CVEs using Metasploit modules or locally generated probe scripts.

It supports both command-line execution via `noctis.py` and a browser-based Web UI via `noctis_web.py`, served locally on `http://127.0.0.1:5000`, without requiring external SaaS platforms, third-party APIs, or cloud processing.

This architecture makes Noctis Edge particularly suited for regulated environments, internal security teams, air-gapped networks, operational technology (OT) environments, and organizations where confidentiality and control are non-negotiable.

---

## System Requirements

| Component | Minimum |
|-----------|---------|
| **RAM** | 8 GB |
| **Storage** | 15 GB free |
| **CPU** | 4 cores |
| **OS** | Kali / Parrot / Ubuntu / Debian-based |
| **Python** | 3.10+ |

**Storage breakdown** (approximate):

| Item | Size |
|------|------|
| Ollama model — `phi4-mini:3.8b` (planning + reports) | ~2.5 GB |
| Ollama model — `qwen2.5-coder:3b-instruct` (script generation) | ~2.0 GB |
| Nuclei templates | ~1.5 GB |
| CVE offline database (built by `setup.sh`) | ~3–5 GB |
| SecLists wordlists (snap) | ~2 GB |
| Tool binaries + Python venv | ~1 GB |
| Scan session outputs | Variable |

> **RAM note:** Split-model architecture — `phi4-mini:3.8b` (~3 GB) handles planning, iteration decisions, and report prose; `qwen2.5-coder:3b-instruct` (~2 GB) handles all CVE script generation. Models are called sequentially so only one is loaded at a time. 8 GB RAM is sufficient; 16 GB+ recommended.

---

## Installation

Two installation paths are available — choose whichever suits your environment. Both paths provide identical functionality.

| | Docker | Native Linux |
|---|---|---|
| **OS** | Windows, macOS, Linux | Kali, Parrot, Ubuntu, Debian |
| **Setup time** | ~10 min (first build) | ~15 min |
| **Dependencies** | Docker Desktop only | apt + snap + Go + Ollama |
| **Isolation** | Full container isolation | System-level install |
| **Updates** | `docker compose build` + `pull` | `./update.sh` |

---

### Option A — Docker (Windows / macOS / Linux)

**Requirements:** [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows or macOS) or Docker Engine + Compose plugin (Linux).

```bash
# 1. Clone the repo
git clone https://github.com/PearceTech335/Noctis-Edge.git
cd Noctis-Edge
```

**Linux / macOS:**
```bash
chmod +x docker-run.sh
./docker-run.sh
```

**Windows (PowerShell):**
```powershell
.\docker-run.ps1
```

The launcher script handles everything automatically:
1. Pulls the latest source (`git pull`)
2. Builds the Docker image — all scanning tools and the offline CVE database are baked in (~5–10 min first build; cached on subsequent runs)
3. Starts the Ollama sidecar and downloads the LLM model (~1.9 GB, one-time, stored in a Docker volume)
4. Starts the Noctis Edge Web UI

Open **http://localhost:5000** in your browser — no further configuration needed.

**Useful Docker commands:**
```bash
# Run a CLI scan (no web UI):
docker compose run --rm noctis scan 192.168.0.1
docker compose run --rm noctis scan 192.168.0.1 web --cve-test

# Stop all containers:
docker compose down

# View live logs:
docker compose logs -f noctis

# Rebuild after a git pull:
docker compose build && docker compose up -d
```

> **Network scanning note:** nmap inside Docker can reach targets on your local network. On Windows/macOS, Docker Desktop runs inside a VM — to scan the host machine itself use `host.docker.internal` instead of `127.0.0.1`.

> **GPU acceleration (optional):** Uncomment the `deploy.resources` block in `docker-compose.yml` to route Ollama inference through an NVIDIA GPU (requires `nvidia-container-toolkit` on the host).

---

### Option B — Native Linux Setup

> Full manual setup instructions: [Readme/requirements.md](Readme/requirements.md)

On a fresh Kali / Parrot / Debian-based machine, a single script handles everything:

```bash
git clone --recurse-submodules https://github.com/PearceTech335/Noctis-Edge.git
cd Noctis-Edge
chmod +x setup.sh
./setup.sh
```

`setup.sh` installs and configures (in order):

| Step | What gets installed |
|------|---------------------|
| Git submodules | `nikto/` — cloned from [sullo/nikto](https://github.com/sullo/nikto) |
| apt packages | `nmap`, `curl`, `ffuf`, `hydra`, `ssh-audit`, `dnsenum`, `dnsrecon`, `perl`, `golang-go`, `python3-tk`, and more |
| SecLists | Wordlists via `snap install seclists` |
| Nuclei | Go-based template scanner (`~/go/bin/nuclei`) |
| Ollama | Local LLM server + pulls `phi4-mini:3.8b` (planning/reports) and `qwen2.5-coder:3b-instruct` (script generation) |
| Python venv | `.venv/` with `requests`, `jinja2`, `pycryptodome`, `flask`, `flask-sock` |
| CVE database | Clones `CVE/cve-offline/` and builds `cve-summary.csv` |
| rdpscan | Clones `rdpscan/` helper |
| Additional tools | `amass`, `metasploit-framework` |

After setup completes:
```bash
./noctis.py <target>   # Ollama starts automatically if not already running
# Optional browser-based Web UI:
./noctis_web.py
```

Run `./update.sh` to keep all components current.

---

## Quick Start

### Command Line

**Docker:**
```bash
# Standard web scan:
docker compose run --rm noctis scan 192.168.0.1

# With profile and flags:
docker compose run --rm noctis scan 192.168.0.1 web --cve-test
docker compose run --rm noctis scan 192.168.0.1 web external --aggressive

# Full aggressive run:
docker compose run --rm noctis scan 192.168.0.1 --aggressive --msf-validate --cve-test

# Resume an interrupted scan:
docker compose run --rm noctis scan 192.168.0.1 --resume
```

**Native Linux:**
```bash
# Standard web scan:
./noctis.py 192.168.0.1

# Single profile:
./noctis.py 192.168.0.1 web

# Multiple profiles (tools from both are merged):
./noctis.py 192.168.0.1 web external

# Three profiles at once:
./noctis.py 192.168.0.1 web external api

# With CVE test scripts:
./noctis.py 192.168.0.1 web --cve-test

# Opt in to DNS enumeration (requires internet):
./noctis.py 192.168.0.1 --dns-enum

# Full aggressive run:
./noctis.py 192.168.0.1 --aggressive --msf-validate --cve-test

# Resume an interrupted scan:
./noctis.py 192.168.0.1 --resume
```

![Command Line Usage](https://github.com/user-attachments/assets/5c27d403-60bb-4608-93ce-0332c1a5a2f4)

### Web UI

A browser-based front-end is available for users who prefer to interact via a web browser. It features a VS Code dark colour scheme, profile and flag controls, and live terminal output streamed in real time via WebSocket.

**Docker:**
```bash
# Start the Web UI (runs in background, Web UI starts automatically):
./docker-run.sh          # Linux / macOS
.\docker-run.ps1         # Windows (PowerShell)

# Then open in your browser:
#   http://localhost:5000
```

> The `docker-run` script starts both Ollama and the Web UI automatically. Just wait for the terminal to settle and open your browser — no extra steps needed.

**Native Linux:**
```bash
./noctis_web.py
# Then open: http://127.0.0.1:5000

# Custom port:
./noctis_web.py --port 8080
```

The server binds to `127.0.0.1` only — it is not accessible from other machines on the network.

The Web UI provides:

- **Target** field with Enter-to-start support
- **Profiles** and **Flags** checkboxes
- Live colour-coded terminal output streamed via WebSocket (green `[+]`, amber `[!]`, red `[-]`, blue `[*]`)
- Spinner line updates for real-time progress
- **Prompt reply** bar with quick **Y** / **N** buttons for approval gates
- **Report** button to regenerate HTML from any existing JSON session file
- Logo watermark in the terminal area

![Noctis Edge Web UI](https://github.com/user-attachments/assets/0c3072c5-5198-4714-aa11-d6b2ee22096e)

![Noctis Edge Web UI - Running](https://github.com/user-attachments/assets/e8531796-0264-4733-a7c2-6ef7a88daa33)

| Feature | CLI | Web UI |
|---------|-----|--------|
| Profile selection | ✓ | ✓ |
| Flag checkboxes | ✓ | ✓ |
| Live terminal output | ✓ | ✓ (WebSocket) |
| y/n prompt replies | ✓ | ✓ |
| Regenerate report | ✓ | ✓ |

**Dependencies:** `flask` and `flask-sock` — installed automatically by `setup.sh` and kept up to date by `update.sh`.

---

## Command-Line Flags

| Flag | Description |
|------|-------------|
| `<target>` | IP address or hostname to scan (required) |
| `[profile]` | Assessment profile (default: `web`). See Profiles section below. |
| `--aggressive` | Disable safe mode — runs ffuf, hydra without asking for approval |
| `--dns-enum` | Enable DNS enumeration tools (amass, dnsenum, dnsrecon) — disabled by default, requires internet access |
| `--msf-validate` | After scan, use Metasploit `check` commands to non-destructively validate each CVE match |
| `--cve-test` | After scan, use the LLM to generate and execute safe probe scripts for each matched CVE |
| `--unattended` | Auto-approve all interactive prompts — no user input required (useful for scripted/automated runs) |
| `--resume` | Resume the most recent interrupted scan session for this target |

---

## Assessment Profiles

Pass one or more profile names after the target. Tools from all selected profiles are merged into a single deduplicated list for the scan.

| Profile | Focus | Key Tools |
|---------|-------|-----------|
| `web` | Web Application Assessment | curl, nikto, nuclei, ffuf |
| `external` | External Perimeter Review | nmap, curl, nuclei, ffuf, dns_enum |
| `internal_ad` | Internal AD Assessment | nmap, nxc (SMB/LDAP) |
| `api` | API Assessment | curl, nuclei, ffuf |
| `cloud` | Cloud Exposure Review | curl, nuclei, dns_enum |

---

## How It Works

### 1. Startup Checks
- Checks if Ollama is serving — starts `ollama serve` automatically if not
- Validates all tool binaries are present and prints a status table
- DNS enumeration tools (amass, dnsenum, dnsrecon) are disabled by default — pass `--dns-enum` to enable them
- Runs `nmap` against the target to discover open ports and services
- Searches the offline CVE database (`CVE/cve-offline/cve-summary.csv`) for matches on each service

### 2. LLM-Driven Scan — Phase 1 (Parallel)
Immediately after Nmap, Noctis Edge performs a **parallel initial scan wave**:

1. The LLM analyses all discovered services at once and returns a JSON array — one initial tool per service (e.g. `nikto` for HTTP, `ssh_enum` for SSH, `mysql_enum` for MySQL).
2. All actions in the wave run concurrently via `asyncio.gather()`, bounded by `MAX_PARALLEL_ACTIONS` (default 4) to avoid overwhelming the target.
3. Findings are enriched, verified, and auto-tagged before being passed into context for Phase 2.

### 3. LLM-Driven Scan — Phase 2 (Sequential loop)
The sequential loop continues deeper investigation, asking the LLM what to do next based on:
- Target, profile, and discovered services
- All findings collected in Phase 1 and so far in Phase 2
- History of tools already run
- List of disabled/broken tools

The LLM responds with a single JSON action `{"tool": "<name>", "args": "<value>"}`.
Noctis Edge executes the tool, parses structured findings from the output, and feeds results back into context for the next iteration.

Tools that time out with no findings or return error signals are auto-disabled for the session.
In `SAFE` mode (default), aggressive tools (ffuf, hydra) require operator approval before running.

### 4. Finding Verification & Enrichment
After each tool run (Phase 1 and Phase 2), findings go through:
- **Verification** — re-requesting a discovered path to confirm it is real rather than a false positive.
- **Metadata enrichment** — inferring `vuln_type` (e.g. RCE, SQLi, XSS), `cwe_id` (e.g. CWE-89), and applicable `compliance_controls` (PCI-DSS, SOC2, ISO 27001) using the existing internal mapping tables.

### 5. Risk Scoring
Each finding is scored using:
```
risk_score = severity_weight × confidence × exposure × tool_confidence
```
- **severity_weight**: critical=1.0, high=0.8, medium=0.5, low=0.2, info=0.05
- **confidence**: set by the tool parser (e.g. curl=0.90, nikto=0.40)
- **exposure**: 1.2 if internet-facing, 1.0 internal
- **tool_confidence**: per-tool weighting from the config

### 6. Report Generation
After the scan loop, reports are saved to `sessions/<target>_<timestamp>/`:
- `report_<target>.json` — full machine-readable report
- `report_<target>.html` — styled HTML report with collapsible sections

Reports include:
- **Executive Summary** — severity counts at a glance
- **Compliance Impact** — badge chips for all implicated PCI-DSS / SOC2 / ISO 27001 controls, aggregated across findings and CVE matches
- **Service Inventory** — discovered services with CVE badge links
- **Findings** — expandable card per finding showing: severity, title, tool, risk score, verification status, vuln type, CWE, evidence, raw HTTP response (collapsible), command run, compliance controls, and clickable reference links
- **CVE Matches** — detailed CVE cards with CVSS vector, exploit maturity, compliance controls, and remediation references
- **MSF / CVE test results** (if run) and **LLM-generated conclusion**

### 7. Session Persistence
After each tool run the current state is saved to `sessions/<id>/session.json`. Use `--resume` to pick up where you left off after an interruption.

---

## Optional Phases

### `--msf-validate`
After the main scan, for each CVE matched against a service:
1. Searches Metasploit for a module matching the CVE ID
2. If found, runs `msfconsole -x "use <module>; set RHOSTS <target>; check; exit"` — this uses MSF's safe `check` command (no payload, no exploitation)
3. Result (`vulnerable`, `not vulnerable`, `unknown`, `no module`) is recorded in the report

Requires `msfconsole` on PATH. Requires operator approval in SAFE mode.

### `--cve-test`
After the main scan (and after `--msf-validate` if both are set):
1. Shows an approval prompt listing the CVEs to be tested
2. For each CVE, asks the LLM to generate up to **5 independent test scripts** (Python or Bash)
3. Each script is written to `sessions/<id>/cve_tests/` and executed with a 30-second timeout
4. Scripts must print one of: `VERDICT: VULNERABLE`, `VERDICT: NOT_VULNERABLE`, `VERDICT: INCONCLUSIVE`
5. Results are tallied into an overall per-CVE verdict and written into the reports

**Knowledge Base**: Results are persisted in `cve_knowledge_base.json` in the project root. On future runs, previously successful scripts for the same CVE are passed back to the LLM as context, improving quality over time. Running `./update.sh` automatically submits this file to the community repository via the Cloudflare relay — no token or account required.

**Verdicts**:
- `VULNERABLE` — at least 1 script returned VULNERABLE
- `NOT_VULNERABLE` — majority of scripts returned NOT_VULNERABLE with no VULNERABLE result
- `INCONCLUSIVE` — scripts ran but could not determine vulnerability status

> Note: These are heuristic probes generated by a small local LLM, not actual exploits. A VULNERABLE verdict means the probe's logic triggered — treat it as a lead to investigate, not a confirmed exploitation.

---

## In Operation

During a `--cve-test` run, the terminal displays each CVE under test in sequence, showing the method attempted (known-exploit replay from the knowledge base, LLM-generated probe, or both), the individual script verdicts, and the final per-CVE result. The LLM generates executable Python or Bash scripts in real time — the strategy and full source are printed to the terminal before execution so the operator can audit exactly what is being run against the target.

| CVE test loop — KB replay and LLM script generation | LLM-generated probe script printed before execution |
|---|---|
| ![CVE test loop - KB replay](https://github.com/user-attachments/assets/fa832839-50bd-48fc-a598-5679e4e40792) | ![LLM-generated probe script](https://github.com/user-attachments/assets/3bdf1f6f-33c2-4514-be3a-dbfff592e9e3) |

| LLM script source output | HTML report — executive summary |
|---|---|
| ![LLM script source](https://github.com/user-attachments/assets/b8531a5e-4c5f-4992-9e78-56f486951ad1) | ![HTML report executive summary](https://github.com/user-attachments/assets/2f6d2ce6-77c3-4f21-87ce-7c3ac88d7527) |

| Per-attempt verdict breakdown — INCONCLUSIVE and NOT_VULNERABLE results | VULNERABLE detection with false-positive flagging and expanded script view |
|---|---|
| ![Per-attempt verdict breakdown](https://github.com/user-attachments/assets/76a25300-696e-45be-b9bd-52cf35599d47) | ![VULNERABLE detection with false-positive check](https://github.com/user-attachments/assets/70e831f8-6496-4f98-83ad-d08ce5bf5698) |

| CVE test results panel — remediation guidance |
|---|
| ![CVE test results with suggested remediation](https://github.com/user-attachments/assets/7b699ade-ddba-4dde-8134-0aa1746dde6f) |

Noctis Edge enforces thorough reporting and rigorous check verification at every stage of the CVE test cycle. Each attempt is individually labelled with a verdict — `VULNERABLE`, `NOT_VULNERABLE`, or `INCONCLUSIVE` — so operators can trace exactly which probe triggered a finding and which fell short. When a result is flagged as `VULNERABLE`, a false-positive check runs automatically, replaying two independent verification passes and surfacing a warning banner if both return `INCONCLUSIVE`, preventing unconfirmed detections from being reported as confirmed hits. The final CVE test results panel consolidates all attempt verdicts alongside AI-generated remediation guidance, covering immediate mitigations, permanent fixes, and step-by-step verification procedures — giving operators both the evidence trail and the actionable next steps needed to confidently triage and remediate every finding.

On completion, the HTML report is generated with an executive summary stating the overall security posture, followed by sections covering the service inventory, findings ranked by risk score, CVE matches, validation results, and the LLM-generated conclusion. 

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
                                     gitignored locally; submitted to community
                                     repo automatically by ./update.sh
```

---

## Configuration (top of `noctis.py`)

| Constant | Default | Description |
|----------|---------|-------------|
| `MODEL` | `phi4-mini:3.8b` | Planning, iteration decisions, report prose, CVE remediation (`NOCTIS_OLLAMA_MODEL` env var to override) |
| `SCRIPT_MODEL` | `qwen2.5-coder:3b-instruct` | CVE exploit scripts, test scripts, verification scripts (`NOCTIS_OLLAMA_SCRIPT_MODEL` env var to override) |
| `OLLAMA_URL` | `http://localhost:11434/api/generate` | Ollama API endpoint |
| `MAX_ITERATIONS` | `10` | Max Phase 2 sequential loop iterations |
| `MAX_PARALLEL_ACTIONS` | `4` | Max concurrent tools in the Phase 1 parallel wave |
| `MAX_LLM_RETRIES` | `3` | LLM call retries per iteration |
| `CVE_TEST_ATTEMPTS` | `5` | LLM script attempts per CVE in `--cve-test` |
| `SAFE_MODE` | `True` | Require approval for aggressive tools (override with `--aggressive`) |
| `UNATTENDED` | `False` | Auto-approve all prompts (override with `--unattended`) |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Port and service discovery |
| `curl` | HTTP probing |
| `nikto` | Web server vulnerability scanning (bundled in `nikto/`) |
| `nuclei` | Template-based scanning |
| `ffuf` | Directory and web fuzzing (rate-limited, auto-calibrated) |
| `hydra` | Credential brute-forcing (aggressive only) |
| `ssh-audit` | SSH configuration auditing |
| `amass` | Subdomain enumeration (internet required) |
| `dnsenum` / `dnsrecon` | DNS enumeration (internet required, installed by `setup.sh`) |
| `nxc` (NetExec) | SMB/LDAP enumeration for AD assessments |
| `msfconsole` | MSF validation (`--msf-validate`) |
| `rdpscan` | RDP enumeration |

Install notes: see [Readme/requirements.md](Readme/requirements.md).

> **Note:** `nikto/` is a git submodule pointing to [sullo/nikto](https://github.com/sullo/nikto).
> Clone with `--recurse-submodules` or run `git submodule update --init --recursive` after cloning.

---

## Ollama Setup

Noctis Edge requires Ollama. `setup.sh` installs it and pulls the model automatically.

`noctis.py` will **automatically start `ollama serve`** if it is not already running — no manual step needed.

Manual install (if not using `setup.sh`):

```bash
# Install Ollama:
curl -fsSL https://ollama.com/install.sh | sh

# Pull both models:
ollama pull phi4-mini:3.8b                 # planning, iteration decisions, report prose
ollama pull qwen2.5-coder:3b-instruct      # CVE exploit scripts, test scripts, verification scripts
```

Ollama will be started automatically by `noctis.py` on first use. The split-model architecture routes natural-language reasoning tasks to `phi4-mini:3.8b` (128K context, native function calling) and all Python script generation to `qwen2.5-coder:3b-instruct` (code-specialist training, stronger structured-output for exploit probes). Models are called sequentially — only one is loaded in RAM at a time. Inference is typically 30–90 seconds per LLM call on CPU-only hardware.

### Model

| Model | Environment variable | Purpose |
|-------|---------------------|---------|
| `phi4-mini:3.8b` | `NOCTIS_OLLAMA_MODEL` | Agentic tool decisions, scan planning, report conclusion, CVE remediation guidance |
| `qwen2.5-coder:3b-instruct` | `NOCTIS_OLLAMA_SCRIPT_MODEL` | CVE known-exploit scripts, CVE test scripts, verification scripts |

---

## Application Maintenance

Run `./update.sh` to keep all components current.

```bash
./update.sh
```

This updates (in order):

| Step | What happens |
|------|--------------|
| 1 | apt packages upgraded |
| 2 | SecLists (snap) refreshed |
| 3 | pip dependencies upgraded |
| 4 | Nuclei binary + templates updated |
| 5 | Ollama models pulled (`phi4-mini:3.8b` + `qwen2.5-coder:3b-instruct`) |
| 6 | CVE offline database pulled + CSV rebuilt |
| 7 | Noctis Edge — `git fetch` + `git reset --hard origin/master` (always gets latest, even with local changes) |
| 8 | Nikto submodule — `git pull` inside `nikto/` (initialises submodule if missing) |
| 9 | CVE Knowledge Base submitted to the community relay |
| 10 | Tool Knowledge Base submitted to the community relay (pull community KB if `KB_LICENSE_KEY` set) |

> **Note on step 7:** `update.sh` uses `git fetch` + `git reset --hard origin/master` rather than `git pull`. This means it will **always** succeed and always result in the exact latest version from GitHub, even if there are local modifications. Any uncommitted local changes to tracked files will be discarded — this is intentional for an update script.
>
> **Your data is safe.** `git reset --hard` only affects files that git tracks. All user-generated data lives in gitignored files and will never be deleted by the update:
>
> | File / Directory | What the update does |
> |------------------|----------------------|
> | `cve_knowledge_base.json` | ✅ gitignored — `git reset --hard` never touches it. Subscribed users receive community KB entries **additively merged** in step 9 (new entries added, nothing overwritten or deleted). |
> | `tool_knowledge_base.json` | ✅ gitignored — `git reset --hard` never touches it. Subscribed users receive community tool KB entries **additively merged** in step 10 (new entries added, nothing overwritten or deleted). |
> | `noctis.conf` | ✅ gitignored — your UUID and license key are always preserved. |
> | `sessions/` | ✅ gitignored — all scan reports and session files are always preserved. |
---

## CVE Knowledge Base

Noctis Edge accumulates CVE test results in `cve_knowledge_base.json` at the project root (created automatically on first `--cve-test` run). This file is machine-specific and anonymised — each entry is identified **only** by CVE ID; no target-specific information is recorded. This file is **not committed to the main git branch**.

Each time you run `./update.sh`, the knowledge base is automatically submitted to the community repository via a Cloudflare relay — no token or account required. Your installation ID (generated once by `./setup.sh` and stored in `noctis.conf`) is used only to rate-limit submissions (4 per day) and is never linked to personal data.

### How the relay works

The Cloudflare Worker (`cloudflare/worker.js`) acts as a server-side relay: it holds the GitHub credentials and writes the submitted JSON to the community repository on your behalf. The source code is included in this repository for full transparency — you can audit exactly what is done with your data.

### Unlocking the Community Knowledge Base

Subscribers receive access to the aggregated community CVE knowledge base — a curated collection of validated test scripts contributed by all Noctis Edge users. Once you have subscribed at [polar.sh/checkout](https://buy.polar.sh/polar_cl_rEP2IebC07PDSnIal0HF4kZSBJVecdZSmkREx3Emnin) and received your license key:

1. Open `noctis.conf` in your Noctis Edge install directory.
2. Set `PAID_TIER` to `true`:
   ```ini
   PAID_TIER=true
   ```
3. Paste your license key:
   ```ini
   KB_LICENSE_KEY=XXXX-XXXX-XXXX-XXXX
   ```
4. Run `./update.sh` — the community KB will be downloaded and merged into your local knowledge base automatically.

The community KB is pulled on every subsequent `./update.sh` run as long as `PAID_TIER=true` and a valid license key are present. No GitHub account or PAT is required — the Cloudflare relay handles authentication server-side.

---

## Scripts

| Script | Purpose |
|--------|---------|
| `setup.sh` | One-shot setup for a fresh install — run once after cloning. Also generates a unique installation ID stored in `noctis.conf`. |
| `update.sh` | Refresh of all components. On completion, automatically submits your local `cve_knowledge_base.json` and `tool_knowledge_base.json` to the community relay (no token required). |
| `scripts/submit_kb.py` | POSTs the local CVE knowledge base to the Cloudflare community relay. Called automatically by `update.sh`. |
| `scripts/merge_kb.py` | Additively merges an external CVE knowledge base JSON into the local one (no data is overwritten or removed). |
| `scripts/submit_tool_kb.py` | POSTs the local tool performance knowledge base to the Cloudflare community relay. Called automatically by `update.sh`. |
| `scripts/merge_tool_kb.py` | Additively merges an external tool knowledge base JSON into the local one (no data is overwritten or removed). |

---

## Cloudflare Relay

The `cloudflare/` directory contains the Cloudflare Worker that relays KB submissions to the community repository.

| File | Purpose |
|------|---------|
| `cloudflare/worker.js` | Worker source — validates, rate-limits, and writes submissions to GitHub |
| `cloudflare/wrangler.toml` | Wrangler deployment config (KV bindings, route) |
| `cloudflare/.gitignore` | Excludes `.wrangler/` cache (contains sensitive account credentials) |

The worker handles four routes:

| Route | Method | Purpose |
|-------|--------|---------|
| `/submit` | POST | CVE KB submission — writes to `Noctis-Edge-Submissions` repo |
| `/community-kb` | POST | CVE community KB pull — reads from `Noctis-Edge-KB` (Polar license check) |
| `/submit-tool` | POST | Tool KB submission — writes to `Noctis-Edge-Tool-Submissions` repo |
| `/community-tool-kb` | POST | Tool community KB pull — reads from `Noctis-Edge-Tool-KB` (Polar license check) |

The worker is already deployed at `https://noctis-kb-relay.pearcetechnologies1.workers.dev`. End users do not need to deploy anything — `update.sh` handles submission automatically.

---

## What Is NOT Committed to Git

The following are excluded from version control (see `.gitignore`):

| Path | Reason |
|------|--------|
| `sessions/` | Runtime scan output — local to each installation |
| `noctis.conf` | Per-user config (installation UUID, optional overrides) — never commit |
| `cloudflare/.wrangler/` | Wrangler cache containing Cloudflare account credentials |
| `WordLists/rockyou.txt` | 139 MB — not needed for directory enumeration |
| `CVE/cve-offline/cve-summary.csv` | 57 MB — regenerate with `updatecsv.sh` |
| `CVE/cve-offline/` | Separate git repo |
| `rdpscan/` | Separate git repo |

---

## Version History

## What's New in v0.6.7

**ffuf scoped to HTTP/HTTPS only** — ffuf is a directory fuzzer and is now dispatched only when the service is a genuine HTTP or HTTPS endpoint. Previously, `ipp` services (CUPS/printing on port 631) also triggered ffuf, which ran its full 300-second timeout budget against a printing protocol that returns no directory listings, inflating scan times by ~5 minutes per IPP port with zero findings.

- `_tools_for_service` split into two branches: `http/ssl` → `[curl, nikto, nuclei, ffuf]`; `ipp` → `[curl, nikto, nuclei]` (no ffuf)
- No other ffuf behaviour changed — it remains fully available for all web application targets
- No other tool removed from any service branch

**Tiered KB script selection with per-script success ranking** — as the community CVE Knowledge Base grows, a single CVE can accumulate hundreds of test scripts. Running every script on every scan would be impractical. Noctis now scores and ranks scripts based on their historical performance, then selects a fair tiered sample for each test run.

- Each KB script tracks `runs`, `vulnerable_count`, `not_vulnerable_count`, and `inconclusive_count` — updated every time the script is replayed
- `VULNERABLE` results are weighted **3×**, `NOT_VULNERABLE` **1×**, `INCONCLUSIVE` **0** — so scripts that reliably detect vulnerabilities rise to the top
- When a CVE has ≤ 20 KB scripts the full set is run (sorted by score); when the pool exceeds 20, exactly **20 scripts** are selected: **top-10 by rank** + **5 random mid-tier** + **5 random low-tier**
- The low-tier sample is intentional — previously low-scoring scripts are periodically re-validated against new targets and can climb the rankings over time
- The verdict line now shows `KB:20/150 replayed` so the full pool size is always visible
- Fully backward-compatible — existing KB entries without run stats fall back to their single recorded `verdict` field

**Tool Knowledge Base community pipeline** — mirrors the existing CVE KB pipeline with a parallel infrastructure for tool performance data:

- `scripts/submit_tool_kb.py` — submits `tool_knowledge_base.json` to the community relay via `/submit-tool`
- `scripts/merge_tool_kb.py` — additively merges community tool KB into the local file
- `cloudflare/worker.js` extended with `/submit-tool` and `/community-tool-kb` routes (same rate-limiting, same Polar license gate for pull)
- `update.sh` step 9/9 added — submits and pulls tool KB alongside the existing CVE KB step
- Submissions pipeline added to `Noctis-Edge-Tool-Submissions` GitHub repo (validate + build workflows)

---

## What's New in v0.6.6

**Split-model architecture** — CVE script generation now uses `qwen2.5-coder:3b-instruct` (code-specialist model) while planning, iteration decisions, report prose, and remediation guidance continue using `phi4-mini:3.8b`.

- `SCRIPT_MODEL` constant added — controls the script generation model (`NOCTIS_OLLAMA_SCRIPT_MODEL` env var to override)
- Three script generation call sites switched to `SCRIPT_MODEL`: `_generate_known_exploit_script`, `_generate_cve_test_script`, `_generate_verification_script`
- Models are called sequentially — only one loaded in RAM at a time, no memory overhead over single-model architecture
- Addresses false-positive CVE verdicts caused by broken Python syntax in LLM-generated probe scripts (logic fall-through, missing imports, wrong protocol)
- `setup.sh` and `update.sh` pull both models automatically
- Total additional storage: ~2.0 GB

---

## What's New in v0.6.5

**Single-model architecture** — `llama3.2:3b` has been removed. All LLM tasks (tool planning, CVE script generation, report conclusion, CVE remediation guidance) now run through `phi4-mini:3.8b`.

- Reduces storage requirements by ~2.0 GB
- Reduces RAM footprint by ~2 GB (no second model loaded for report generation)
- Simplifies setup: only one `ollama pull` required
- Removes `REPORT_MODEL` / `NOCTIS_REPORT_MODEL` constant and env var — `MODEL` is now used for everything
- `phi4-mini:3.8b` performs equivalently to `llama3.2:3b` on the two-sentence conclusion and remediation prose prompts, while being a stronger model overall

**Improved LLM prompts (phi4-mini v1)** — all five prompts rewritten for phi4-mini's behaviour:
- `### PYTHON RULES` block in all three CVE script prompts — prevents broken-Python / non-stdlib import failures
- `FORBIDDEN` import list — eliminates `bs4`/`lxml` failures
- Single-quote rule — stops escaped double-quotes breaking JSON output
- Concrete working script example in JSON reply format — model adapts rather than invents syntax
- `### CONTRAST RULE — MANDATORY` in verification prompt — enforces independent approach
- `ALREADY RUN` moved to top of iteration prompt (primacy bias)
- Numbered rules + rule #6 general-tool fallback in iteration prompt
- Single `BLACKLIST` in parallel-scan prompt merges `used_actions` + `broken_tools`

**Collapsible CVE test result cards** in HTML report — each CVE card collapses to header-only by default; click to expand attempts, verification, and remediation.

---

| Version | Date | Changes |
|---------|------|---------|
| **v0.6.7** | May 2026 | ffuf scoped to HTTP/HTTPS only (removed from IPP/CUPS service branch); Tool KB community pipeline added (`submit_tool_kb.py`, `merge_tool_kb.py`, Cloudflare routes `/submit-tool` + `/community-tool-kb`, `update.sh` step 9/9) |
| **v0.6.6** | May 2026 | Split-model architecture: `qwen2.5-coder:3b-instruct` added for CVE script generation; `phi4-mini:3.8b` retained for planning/reports; `SCRIPT_MODEL` constant + `NOCTIS_OLLAMA_SCRIPT_MODEL` env var |
| **v0.6.5** | May 2026 | Single-model architecture: removed `llama3.2:3b`, `phi4-mini:3.8b` now handles all LLM tasks; phi4-mini v1 prompt improvements (PYTHON RULES, CONTRAST RULE, BLACKLIST consolidation, primacy bias); collapsible CVE test result cards in HTML report |
| **v0.6.4** | May 2026 | Switched scan engine to `phi4-mini:3.8b` (2.5 GB, 128K ctx, native function calling — ~60–90s/call on CPU vs ~3–5 min for 7b); added 4-strategy LLM response parser; added `nikto_cgi` tool; port-qualified service keys and best-tool-per-service rankings; fixed `ffuf -retries` flag; fixed Phase 1 URL construction; exposed `maxtime` in ffuf descriptions; CVE test verdicts in console summary; version in CLI banner and Web UI; dedicated short-term/long-term remediation and Steps to Reproduce sections in HTML report |

---

## Credits

Noctis Edge builds on and bundles a number of excellent open-source projects:

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
| [Ollama](https://ollama.com) | Ollama, Inc. | Local LLM server for AI-guided analysis |
| [trickest/cve](https://github.com/trickest/cve) | Trickest | CVE PoC reference database (bundled as submodule) |
| [trickest/cve-offline](https://github.com/trickest/cve-offline) | Trickest | Offline CVE CSV dataset |
| [SecLists](https://github.com/danielmiessler/SecLists) | Daniel Miessler | Security wordlists |
| [NetExec (nxc)](https://github.com/Pennyw0rth/NetExec) | Pennyw0rth | Network service execution and enumeration |
| [Flask](https://flask.palletsprojects.com) | Pallets | Web framework for the browser UI |
| [flask-sock](https://github.com/miguelgrinberg/flask-sock) | Miguel Grinberg | WebSocket support for Flask |
| [Requests](https://requests.readthedocs.io) | Kenneth Reitz | HTTP library |
| [Jinja2](https://jinja.palletsprojects.com) | Pallets | HTML report templating |
| [PyCryptodome](https://pycryptodome.readthedocs.io) | Legrandin | Cryptographic primitives |
