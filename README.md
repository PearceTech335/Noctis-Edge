# Noctis Edge

**Security Through Exposure**

Noctis Edge is a Python-based AI-assisted penetration testing platform. It runs an automated, LLM-guided penetration test against a target, collects and verifies findings, generates HTML/PDF reports, and optionally validates CVEs using Metasploit or LLM-generated probe scripts. It can be run from the **command line** (`noctis.py`) or via the included **Tkinter GUI** (`noctis_gui.py`).

---

## System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **RAM** | 8 GB | 16 GB+ |
| **Storage** | 15 GB free | 30 GB+ free |
| **CPU** | 4 cores | 8 cores+ |
| **OS** | Kali / Parrot / Ubuntu / Debian-based | Kali Linux (latest) |
| **Python** | 3.10+ | 3.13 |

**Storage breakdown** (approximate):

| Item | Size |
|------|------|
| Ollama LLM model (`Qwen2.5-7B-Instruct Q4`) | ~4.7 GB |
| Nuclei templates | ~1.5 GB |
| CVE offline database (built by `setup.sh`) | ~3–5 GB |
| SecLists wordlists (snap) | ~2 GB |
| Tool binaries + Python venv | ~1 GB |
| Scan session outputs | Variable |

> **RAM note:** The Qwen2.5-7B Q4 model requires ~5–6 GB of RAM to load. On machines with less than 8 GB total, the system may swap heavily during inference, significantly slowing LLM response times (expect 3–10 min per call on CPU-only with 8 GB). 16 GB+ is strongly recommended for comfortable use.

---

## Initial Setup (new install)

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
| apt packages | `nmap`, `curl`, `gobuster`, `ffuf`, `hydra`, `ssh-audit`, `dnsenum`, `dnsrecon`, `perl`, `golang-go`, `python3-tk`, and more |
| SecLists | Wordlists via `snap install seclists` |
| Nuclei | Go-based template scanner (`~/go/bin/nuclei`) |
| Ollama | Local LLM server + pulls `hf.co/RCorvalan/Qwen2.5-7B-Instruct-1M-Q4_K_M-GGUF` |
| Python venv | `.venv/` with `requests`, `jinja2`, `pycryptodome`, `weasyprint`, `pdfkit` |
| CVE database | Clones `CVE/cve-offline/` and builds `cve-summary.csv` |
| rdpscan | Clones `rdpscan/` helper |
| Additional tools | `amass`, `metasploit-framework` |

You can skip extra/heavy steps with env flags:
```bash
NO_MSF=1 ./setup.sh          # skip Metasploit
NO_OPTIONAL=1 ./setup.sh     # skip amass + Metasploit
```

After setup completes:
```bash
python3 noctis.py <target>   # Ollama starts automatically if not already running
# Optional GUI:
python3 noctis_gui.py
```

Run `./update.sh` monthly to keep all components current.

---

## Quick Start

### Command Line

```bash
# Standard web scan:
python3 noctis.py 192.168.0.1

# Single profile:
python3 noctis.py 192.168.0.1 web

# Multiple profiles (tools from both are merged):
python3 noctis.py 192.168.0.1 web external

# Three profiles at once:
python3 noctis.py 192.168.0.1 web external api

# With CVE test scripts:
python3 noctis.py 192.168.0.1 web --cve-test

# No internet access:
python3 noctis.py 192.168.0.1 --airgap

# Full aggressive run:
python3 noctis.py 192.168.0.1 --aggressive --msf-validate --cve-test

# Resume an interrupted scan:
python3 noctis.py 192.168.0.1 --resume
```

### GUI

A Tkinter-based graphical front-end is included for users who prefer not to use the terminal:

```bash
source .venv/bin/activate
python3 noctis_gui.py
```

The GUI provides:

- **Target** field
- **Profiles** checkboxes — select one or more (`web`, `external`, `internal_ad`, `api`, `cloud`); tools from all selected profiles are merged at scan time
- Checkboxes for all scan flags (`--aggressive`, `--airgap`, `--msf-validate`, `--cve-test`, `--resume`)
- Live colour-coded terminal output (findings highlighted in green/amber/red)
- **Prompt reply** input bar with quick **Y** / **N** buttons for approval gates
- Stop button to terminate a running scan at any time

The GUI launches `noctis.py` as a subprocess — all behaviour, output, and session files are identical to the command-line version.

---

## Command-Line Flags

| Flag | Description |
|------|-------------|
| `<target>` | IP address or hostname to scan (required) |
| `[profile]` | Assessment profile (default: `web`). See Profiles section below. |
| `--aggressive` | Disable safe mode — runs gobuster, ffuf, hydra without asking for approval |
| `--airgap` | Disable all internet-dependent tools (amass, dnsenum, dnsrecon). Auto-detected if no internet found. |
| `--msf-validate` | After scan, use Metasploit `check` commands to non-destructively validate each CVE match |
| `--cve-test` | After scan, use the LLM to generate and execute safe probe scripts for each matched CVE |
| `--resume` | Resume the most recent interrupted scan session for this target |

---

## Assessment Profiles

Pass one or more profile names after the target. Tools from all selected profiles are merged into a single deduplicated list for the scan.

| Profile | Focus | Key Tools |
|---------|-------|-----------|
| `web` | Web Application Assessment | curl, nikto, nuclei, gobuster, ffuf |
| `external` | External Perimeter Review | nmap, curl, nuclei, gobuster, dns_enum |
| `internal_ad` | Internal AD Assessment | nmap, nxc (SMB/LDAP) |
| `api` | API Assessment | curl, nuclei, ffuf |
| `cloud` | Cloud Exposure Review | curl, nuclei, dns_enum |

---

## How It Works

### 1. Startup Checks
- Checks if Ollama is serving — starts `ollama serve` automatically if not
- Validates all tool binaries are present and prints a status table
- Checks internet connectivity — automatically enables `--airgap` if offline
- Runs `nmap` against the target to discover open ports and services
- Searches the offline CVE database (`CVE/cve-offline/cve-summary.csv`) for matches on each service

### 2. LLM-Driven Scan Loop (up to 10 iterations)
The core loop asks the local Ollama LLM what to do next based on:
- Target, profile, and discovered services
- All findings collected so far
- History of tools already run
- List of disabled/broken tools

The LLM responds with a single JSON action `{"tool": "<name>", "args": "<value>"}`.
Noctis Edge executes the tool, parses structured findings from the output, and feeds results back into context for the next iteration.

Tools that time out with no findings or return error signals are auto-disabled for the session.
In `SAFE` mode (default), aggressive tools (gobuster, ffuf, hydra) require operator approval before running.

### 3. Finding Verification
After each tool run, findings go through a verification pass that attempts to confirm they are real (e.g. re-requesting a discovered path to confirm it exists) rather than false positives.

### 4. Risk Scoring
Each finding is scored using:
```
risk_score = severity_weight × confidence × exposure × tool_confidence
```
- **severity_weight**: critical=1.0, high=0.8, medium=0.5, low=0.2, info=0.05
- **confidence**: set by the tool parser (e.g. curl=0.90, nikto=0.40)
- **exposure**: 1.2 if internet-facing, 1.0 internal
- **tool_confidence**: per-tool weighting from the config

### 5. Report Generation
After the scan loop, reports are saved to `sessions/<target>_<timestamp>/`:
- `report_<target>.json` — full machine-readable report
- `report_<target>.html` — styled HTML report with collapsible sections
- `report_<target>.pdf` — PDF version (requires `weasyprint` or equivalent)

Reports include: executive summary, service inventory, findings table (severity-sorted), CVE matches, MSF validation results (if run), CVE test results (if run), and LLM-generated conclusion.

### 6. Session Persistence
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

**Knowledge Base**: Results are persisted in `cve_knowledge_base.json` in the project root. On future runs, previously successful scripts for the same CVE are passed back to the LLM as context, improving quality over time.

**Verdicts**:
- `VULNERABLE` — at least 1 script returned VULNERABLE
- `NOT_VULNERABLE` — majority of scripts returned NOT_VULNERABLE with no VULNERABLE result
- `INCONCLUSIVE` — scripts ran but could not determine vulnerability status

> Note: These are heuristic probes generated by a small local LLM, not actual exploits. A VULNERABLE verdict means the probe's logic triggered — treat it as a lead to investigate, not a confirmed exploitation.

---

## Output Structure

```
sessions/
└── localhost_20260424_102554/
    ├── session.json              ← live state (for --resume)
    ├── report_localhost.json     ← full JSON report
    ├── report_localhost.html     ← styled HTML report
    ├── report_localhost.pdf      ← PDF report
    └── cve_tests/
        ├── CVE-2002-1367_attempt_01.py
        ├── CVE-2002-1367_attempt_02.sh
        └── ...

cve_knowledge_base.json           ← cross-engagement CVE test KB (project root)
```

---

## Configuration (top of `noctis.py`)

| Constant | Default | Description |
|----------|---------|-------------|
| `MODEL` | `hf.co/RCorvalan/Qwen2.5-7B-Instruct-1M-Q4_K_M-GGUF` | Ollama model to use |
| `OLLAMA_URL` | `http://localhost:11434/api/generate` | Ollama API endpoint |
| `MAX_ITERATIONS` | `10` | Max LLM scan loop iterations |
| `MAX_LLM_RETRIES` | `3` | LLM call retries per iteration |
| `CVE_TEST_ATTEMPTS` | `5` | LLM script attempts per CVE in `--cve-test` |
| `SAFE_MODE` | `True` | Require approval for aggressive tools (override with `--aggressive`) |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Port and service discovery |
| `curl` | HTTP probing |
| `nikto` | Web server vulnerability scanning (bundled in `nikto/`) |
| `nuclei` | Template-based scanning |
| `gobuster` | Directory brute-forcing |
| `ffuf` | Web fuzzing |
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

# Pull the model:
ollama pull hf.co/RCorvalan/Qwen2.5-7B-Instruct-1M-Q4_K_M-GGUF
```

Ollama will be started automatically by `noctis.py` on first use. On CPU-only machines expect 1–3 minutes per LLM call. The program prints a spinner while waiting.

---

## Monthly Maintenance

Run `./update.sh` to update everything:

```bash
./update.sh
```

This updates: apt packages, SecLists (snap), pip dependencies, nuclei binary + templates, Ollama model, CVE database.

---

## Scripts

| Script | Purpose |
|--------|---------|
| `setup.sh` | One-shot setup for a fresh install — run once after cloning |
| `update.sh` | Monthly refresh of all components |

---

---

## What Is NOT Committed to Git

The following are excluded from version control (see `.gitignore`):

| Path | Reason |
|------|--------|
| `sessions/` | Runtime scan output |
| `cve_knowledge_base.json` | Machine-specific accumulated data |
| `WordLists/rockyou.txt` | 139 MB — not needed for directory enumeration |
| `CVE/cve-offline/cve-summary.csv` | 57 MB — regenerate with `updatecsv.sh` |
| `CVE/cve-offline/` | Separate git repo |
| `rdpscan/` | Separate git repo |
