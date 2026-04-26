# Noctis Edge — Setup & Requirements

A complete, repeatable setup guide for the Noctis Edge AI-Assisted Penetration Testing Platform.
Follow each section in order on a fresh Kali/Parrot/Debian-based system.

---

## 1. Clone the Repository

```bash
git clone --recurse-submodules https://github.com/PearceTech335/NoctisEdge.git
cd NoctisEdge
```

---

## 2. System Dependencies (apt)

Install all required system packages in one command:

```bash
sudo apt update && sudo apt install -y \
    python3 \
    python3-venv \
    python3-pip \
    nmap \
    curl \
    gobuster \
    ffuf \
    hydra \
    ssh-audit \
    dnsutils \
    perl \
    libxml-writer-perl \
    libjson-perl \
    git
```

| Package              | Purpose                                                  |
|----------------------|----------------------------------------------------------|
| `python3`            | Runtime for Noctis Edge                                  |
| `python3-venv`       | Creates isolated Python virtual environments             |
| `python3-pip`        | Python package installer                                 |
| `nmap`               | Port and service discovery                               |
| `curl`               | HTTP probing of discovered services                      |
| `gobuster`           | Directory and path brute-forcing                         |
| `ffuf`               | Web fuzzing                                              |
| `hydra`              | Credential brute-forcing (requires operator approval)    |
| `ssh-audit`          | SSH configuration auditing                               |
| `dnsutils`           | Provides `dig` for DNS enumeration and zone-transfer checks |
| `perl`               | Runtime for Nikto (bundled in `nikto/`)                  |
| `libxml-writer-perl` | Perl XML module required by Nikto                        |
| `libjson-perl`       | Perl JSON module required by Nikto                       |
| `git`                | Version control and CVE database updates                 |

---

## 2b. SecLists (snap)

`seclists` is not available via apt on this system — install it via snap:

```bash
sudo snap install seclists
```

Snap installs the wordlists to `/snap/seclists/current/`. Noctis Edge will look for
its primary wordlist at `/snap/seclists/current/Discovery/Web-Content/common.txt`
automatically at startup.

---

## 3. Python Virtual Environment

> **Always create and activate the venv before running any `pip install` commands.**
> This keeps Noctis Edge's dependencies isolated from system Python packages
> and makes the environment fully reproducible.

```bash
# From the Noctis Edge project root:
python3 -m venv .venv

# Activate the venv (do this every time you open a new terminal):
source .venv/bin/activate
```

You should see `(.venv)` at the start of your prompt when the venv is active.

To deactivate when you are finished:
```bash
deactivate
```

---

## 4. Python Dependencies (pip)

With the venv active, install all required Python packages:

```bash
pip install --upgrade pip
pip install requests jinja2 pycryptodome weasyprint
```

| Package        | Purpose                                             |
|----------------|-----------------------------------------------------|
| `requests`     | HTTP calls to the Ollama LLM API                    |
| `jinja2`       | HTML report templating                              |
| `pycryptodome` | DES3 decryption used by `rdpscan/RPDscan.py`        |
| `weasyprint`   | PDF report generation from HTML                     |

| Package        | Purpose                                             |
|----------------|-----------------------------------------------------|
| `requests`     | HTTP calls to the Ollama LLM API                    |
| `jinja2`       | HTML report templating                              |
| `pycryptodome` | DES3 decryption used by `rdpscan/RPDscan.py`        |

All other imports (`asyncio`, `subprocess`, `json`, `os`, `re`, `shutil`, `sys`, `time`,
`hashlib`, `threading`, `dataclasses`, `xml.etree.ElementTree`, `datetime`) are Python
standard library and require no installation.

---

## 5. Nuclei (Go binary)

Nuclei is not available via apt and must be installed separately:

```bash
# Install Go if not already present:
sudo apt install -y golang-go

# Install nuclei:
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# The binary will be placed at ~/go/bin/nuclei
# Add Go binaries to your PATH if not already set:
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc
source ~/.bashrc

# Update nuclei templates on first run:
nuclei -update-templates
```

---

## 6. Ollama (Local LLM)

Noctis Edge uses a local Ollama instance to drive its AI reasoning loop.

```bash
# Install Ollama:
curl -fsSL https://ollama.com/install.sh | sh

# Pull the model used by Noctis Edge:
ollama pull qwen2.5-coder:7b-instruct-q4_k_m

# Start the Ollama server (must be running before launching Noctis Edge):
ollama serve
```

Ollama listens on `http://localhost:11434` by default. Noctis Edge will fail to start if
this service is not running.

---

## 7. Nikto (Git Submodule)

Nikto is included as a **git submodule** pointing to [sullo/nikto](https://github.com/sullo/nikto).
No separate install is required — it is cloned automatically when you use `--recurse-submodules`:

```bash
git clone --recurse-submodules https://github.com/PearceTech335/NoctisEdge.git
```

If you already cloned without that flag, initialise it manually:

```bash
git submodule update --init --recursive
```

`setup.sh` also runs this automatically as its first step.

Nikto runs via Perl; the `perl`, `libxml-writer-perl`, and `libjson-perl` packages
from Section 2 are all it needs.

---

## 8. CVE Offline Database

The CVE database lives in `CVE/cve-offline/` and is tracked as a separate Git repository.
The large CSV file (`cve-summary.csv`) is excluded from version control and must be generated
locally:

```bash
cd CVE/cve-offline
./updatecsv.sh
cd ../..
```

Refresh it monthly to keep CVE matches current:
```bash
cd CVE/cve-offline && git pull && ./updatecsv.sh && cd ../..
```

---

## 9. Wordlists

Noctis Edge uses `seclists` (installed via snap in Section 2b) as its primary wordlist source.
No internet access is required at runtime — the files are on disk after the snap install.

At startup the program looks for the wordlist in this order:
1. `/snap/seclists/current/Discovery/Web-Content/common.txt` — system SecLists via snap (preferred)
2. `WordLists/common.txt` — small bundled fallback included in the repository
3. If neither is found, the program exits with an install reminder

To verify the wordlist is present after a fresh install:

```bash
ls /snap/seclists/current/Discovery/Web-Content/common.txt
```

`rockyou.txt` is a password list and is **not used** by Noctis Edge for directory enumeration.
It does not need to be present.

---

## 10. CVE Test Phase (`--cve-test`)

The `--cve-test` flag enables an additional post-scan phase where Noctis Edge uses the LLM
to generate and execute safe, read-only probe scripts for each CVE discovered during the scan.

### How it works

1. After the main scan completes and base reports are saved, you are prompted to approve CVE testing.
2. For each matched CVE, the LLM generates up to **5 independent test scripts** (Python or Bash).
3. Each script is executed in a temporary directory with a 30-second timeout.
4. Scripts must print `VERDICT: VULNERABLE`, `VERDICT: NOT_VULNERABLE`, or `VERDICT: INCONCLUSIVE`.
5. Results are aggregated into an overall per-CVE verdict and written into the HTML/JSON reports.

### Knowledge Base

Results are persisted in a **cross-engagement knowledge base** at `cve_knowledge_base.json`
in the project root. This file is auto-created on first use and grows over time — scripts
that worked (or produced interesting results) on previous targets are fed back to the LLM
as context for new engagements, improving quality over time.

> `cve_knowledge_base.json` is excluded from version control (see `.gitignore`).
> Back it up separately if you want to retain accumulated knowledge.

### No additional dependencies

`--cve-test` uses only standard library modules (`threading`, `hashlib`, `tempfile`) plus
the same `requests` dependency already required for Ollama communication. No extra
`pip install` is needed.

### Usage

```bash
# Run a scan and enable CVE testing:
python reconotron.py <target> web --cve-test

# Run with Metasploit validation AND CVE testing:
python reconotron.py <target> --msf-validate --cve-test
```

### Timing expectations

Each LLM script generation call has a **180-second timeout** (CPU-only Ollama is slow).
With 5 CVEs × 5 attempts each, worst-case is ~25 LLM calls. Expect **15–45 minutes** on
a CPU-only machine. Progress is shown as:

```
  [02/05] Generating script ... /        ← live spinner
  Strategy: connect to IPP port and check response headers
  ---- script (python) ----
  ...
  ---- end script ----
  [02/05] Running (python) ... INCONCLUSIVE
  Elapsed: 4m 12s  |  ETA: ~38m 00s  (2/25 attempts)
```

---

## 11. Optional Tools (OSINT / AD Assessment)

These tools are only needed for specific assessment profiles. They are skipped
automatically in `--airgap` mode.

```bash
# NetExec (replaces CrackMapExec) — internal AD / SMB / MSSQL enumeration:
pip install netexec          # or follow https://github.com/Pennyw0rth/NetExec

# amass — external subdomain enumeration (internet required):
sudo apt install -y amass

# dnsenum / dnsrecon — DNS enumeration:
sudo apt install -y dnsenum dnsrecon

# Metasploit — non-destructive CVE validation probes (--msf-validate flag):
# Follow the official installer: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html
# or on Kali it is pre-installed:
sudo apt install -y metasploit-framework
```

---

## 12. Quick-Start Checklist

Before running `python reconotron.py`, confirm:

- [ ] Virtual environment is activated: `source .venv/bin/activate`
- [ ] Ollama is running: `ollama serve`
- [ ] CVE database CSV exists: `CVE/cve-offline/cve-summary.csv`
- [ ] SecLists installed: `ls /snap/seclists/current/Discovery/Web-Content/common.txt`
- [ ] `nuclei` binary is on PATH: `which nuclei`

```bash
# Standard scan:
source .venv/bin/activate
python reconotron.py 192.168.0.1

# Web assessment with CVE testing enabled:
python reconotron.py 192.168.0.1 web --cve-test

# Aggressive scan with Metasploit validation and CVE testing:
python reconotron.py 192.168.0.1 --aggressive --msf-validate --cve-test
```
