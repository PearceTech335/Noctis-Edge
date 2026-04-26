#!/usr/bin/env bash
# =============================================================================
#  Noctis Edge — One-Shot Setup Script
#
#  Run once on a fresh Kali / Parrot / Debian-based system after cloning:
#
#    git clone https://github.com/PearceTech335/NoctisEdge.git
#    cd NoctisEdge
#    chmod +x setup.sh
#    ./setup.sh
#
#  What this script does (in order):
#    1.  Git submodules — nikto (bundled scanner)
#    2.  apt  — core system packages
#    3.  snap — SecLists wordlists
#    4.  Go   — language runtime (needed for Nuclei)
#    5.  Nuclei — template-based vulnerability scanner
#    6.  Ollama — local LLM server + model pull
#    7.  Python venv + pip dependencies
#    8.  CVE/cve-offline — clone & build the offline CVE database
#    9.  rdpscan         — clone the RDP scanner helper
#   10.  Optional tools  — amass, dnsenum, dnsrecon, metasploit-framework
#
#  Skip any step by setting the corresponding NO_* variable, e.g.:
#    NO_MSF=1 ./setup.sh          ← skip Metasploit install
#    NO_OPTIONAL=1 ./setup.sh     ← skip all optional tools
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OLLAMA_MODEL="qwen2.5-coder:7b-instruct-q4_k_m"

CVE_REPO="https://github.com/trickest/cve.git"
CVE_OFFLINE_REPO="https://github.com/trickest/cve-offline.git"

# Fallback upstream for cve-offline scripts
CVE_OFFLINE_ACTUAL="https://github.com/trickest/cve-offline.git"

RDPSCAN_REPO="https://github.com/PearceTech335/NoctisEdge.git"

# ── colour helpers ──────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
info()    { echo -e "${YELLOW}[ > ]${NC}   $*"; }
err()     { echo -e "${RED}[ERR]${NC}   $*"; }
header()  {
    echo ""
    echo -e "${CYAN}============================================================${NC}"
    echo -e "${CYAN}  $*${NC}"
    echo -e "${CYAN}============================================================${NC}"
}
skip()    { echo -e "${YELLOW}[SKIP]${NC}  $*"; }

# ── require root for apt/snap steps ────────────────────────────────────────
need_sudo() {
    if ! sudo -n true 2>/dev/null; then
        echo "This step requires sudo. You may be prompted for your password."
    fi
}

# =============================================================================
# 1.  Git submodules
# =============================================================================
header "1/10  Git submodules (nikto)"
if [[ -f "$SCRIPT_DIR/.gitmodules" ]]; then
    info "Initialising and updating git submodules ..."
    git -C "$SCRIPT_DIR" submodule update --init --recursive \
        && ok "Submodules up to date (nikto cloned at nikto/)" \
        || err "Submodule update failed — run: git submodule update --init --recursive"
else
    skip ".gitmodules not found — no submodules to initialise"
fi

# =============================================================================
# 2.  apt — system packages
# =============================================================================
header "2/10  System packages (apt)"
need_sudo
info "Updating package lists ..."
sudo apt update -qq

info "Installing core dependencies ..."
sudo apt install -y \
    python3 \
    python3-venv \
    python3-pip \
    nmap \
    curl \
    wget \
    gobuster \
    ffuf \
    hydra \
    ssh-audit \
    dnsutils \
    perl \
    libxml-writer-perl \
    libjson-perl \
    golang-go \
    git \
    libssl-dev \
    build-essential

ok "apt packages installed"

# =============================================================================
# 2.  snap — SecLists
# =============================================================================
header "3/10  SecLists wordlists (snap)"
if command -v snap &>/dev/null; then
    info "Installing seclists via snap ..."
    sudo snap install seclists 2>/dev/null \
        && ok "seclists installed at /snap/seclists/current/" \
        || { skip "seclists snap already installed or snap unavailable"; }
else
    skip "snap not found — install snap or manually copy wordlists to WordLists/"
fi

# =============================================================================
# 3.  Go PATH — ensure ~/go/bin is in PATH for this session
# =============================================================================
header "4/10  Go runtime PATH"
export PATH="$PATH:$HOME/go/bin"
if ! grep -qF 'go/bin' ~/.bashrc 2>/dev/null; then
    echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc
    info "Added ~/go/bin to ~/.bashrc"
fi
ok "Go PATH configured ($(go version 2>/dev/null || echo 'version unknown'))"

# =============================================================================
# 4.  Nuclei
# =============================================================================
header "5/10  Nuclei (template-based scanner)"
if command -v nuclei &>/dev/null; then
    skip "nuclei already installed at $(command -v nuclei)"
else
    info "Installing nuclei via go install ..."
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    ok "nuclei installed at ~/go/bin/nuclei"
fi

info "Updating nuclei templates ..."
nuclei -update-templates -silent 2>/dev/null \
    && ok "nuclei templates updated" \
    || err "nuclei template update failed (run 'nuclei -update-templates' manually later)"

# =============================================================================
# 5.  Ollama + model
# =============================================================================
header "6/10  Ollama (local LLM server)"
if command -v ollama &>/dev/null; then
    skip "ollama already installed at $(command -v ollama)"
else
    info "Downloading and installing Ollama ..."
    curl -fsSL https://ollama.com/install.sh | sh
    ok "Ollama installed"
fi

info "Starting Ollama server temporarily to pull model ..."
if curl -s --max-time 3 http://localhost:11434/api/tags &>/dev/null; then
    info "Ollama server is already running"
    STARTED_OLLAMA=0
else
    ollama serve &>/dev/null &
    OLLAMA_PID=$!
    STARTED_OLLAMA=1
    sleep 6
    info "Ollama server started (PID $OLLAMA_PID)"
fi

info "Pulling model: $OLLAMA_MODEL (this may take several minutes on first run) ..."
ollama pull "$OLLAMA_MODEL" \
    && ok "Model $OLLAMA_MODEL ready" \
    || err "Model pull failed — run 'ollama pull $OLLAMA_MODEL' manually after setup"

if [[ "${STARTED_OLLAMA:-0}" == "1" ]]; then
    kill "$OLLAMA_PID" 2>/dev/null || true
    info "Ollama server stopped (start it again with: ollama serve)"
fi

# =============================================================================
# 6.  Python virtual environment + pip packages
# =============================================================================
header "7/10  Python virtual environment"
VENV="$SCRIPT_DIR/.venv"
if [[ -d "$VENV" ]]; then
    skip "venv already exists at $VENV"
else
    info "Creating venv at $VENV ..."
    python3 -m venv "$VENV"
    ok "venv created"
fi

info "Installing Python dependencies into venv ..."
# shellcheck disable=SC1091
source "$VENV/bin/activate"
pip install --upgrade pip --quiet
pip install --upgrade requests jinja2 pycryptodome weasyprint --quiet
deactivate
ok "Python packages installed (requests, jinja2, pycryptodome)"

# =============================================================================
# 7.  CVE offline database
# =============================================================================
header "8/10  CVE offline database"
CVE_DIR="$SCRIPT_DIR/CVE/cve-offline"

if [[ -d "$CVE_DIR" && -f "$CVE_DIR/updatecsv.sh" ]]; then
    skip "CVE/cve-offline already present — skipping (run ./update.sh to refresh)"
else
    info "Cloning CVE offline database ..."
    mkdir -p "$SCRIPT_DIR/CVE"

    if git clone --depth=1 "$CVE_OFFLINE_ACTUAL" "$CVE_DIR" 2>/dev/null; then
        ok "CVE/cve-offline cloned"
    else
        err "Could not clone $CVE_OFFLINE_ACTUAL"
        err "Clone the CVE offline repo manually into CVE/cve-offline/ then run:"
        err "  cd CVE/cve-offline && ./updatecsv.sh"
        CVE_DIR=""
    fi
fi

if [[ -n "${CVE_DIR:-}" && -x "$CVE_DIR/updatecsv.sh" ]]; then
    info "Building cve-summary.csv (this downloads ~100 MB of CVE data — may take a few minutes) ..."
    (cd "$CVE_DIR" && bash updatecsv.sh) \
        && ok "cve-summary.csv built at CVE/cve-offline/cve-summary.csv" \
        || err "updatecsv.sh failed — run it manually: cd CVE/cve-offline && ./updatecsv.sh"
elif [[ -n "${CVE_DIR:-}" ]]; then
    err "updatecsv.sh not found in $CVE_DIR — cannot build CVE database automatically"
fi

# =============================================================================
# 8.  rdpscan helper
# =============================================================================
header "9/10  rdpscan (RDP scanner helper)"
RDPSCAN_DIR="$SCRIPT_DIR/rdpscan"

if [[ -d "$RDPSCAN_DIR" && -n "$(ls -A "$RDPSCAN_DIR" 2>/dev/null)" ]]; then
    skip "rdpscan already present at $RDPSCAN_DIR"
else
    info "Cloning rdpscan ..."
    if git clone --depth=1 "$RDPSCAN_REPO" "$RDPSCAN_DIR" 2>/dev/null; then
        ok "rdpscan cloned"
    else
        err "Could not clone rdpscan from $RDPSCAN_REPO"
        err "Clone it manually into rdpscan/ if you need RDP scanning"
    fi
fi

# =============================================================================
# 9.  Optional tools  (amass, dnsenum, dnsrecon, Metasploit)
# =============================================================================
if [[ "${NO_OPTIONAL:-0}" != "1" ]]; then
    header "10/10  Optional tools"

    info "Installing amass, dnsenum, dnsrecon ..."
    sudo apt install -y amass dnsenum dnsrecon 2>/dev/null \
        && ok "amass / dnsenum / dnsrecon installed" \
        || skip "One or more optional DNS tools unavailable via apt on this system"

    if [[ "${NO_MSF:-0}" != "1" ]]; then
        info "Checking for Metasploit Framework ..."
        if command -v msfconsole &>/dev/null; then
            skip "msfconsole already installed at $(command -v msfconsole)"
        else
            info "Installing metasploit-framework via apt (Kali / Parrot only) ..."
            sudo apt install -y metasploit-framework 2>/dev/null \
                && ok "metasploit-framework installed" \
                || {
                    skip "metasploit-framework not available via apt on this distro"
                    info "Install Metasploit manually: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html"
                }
        fi
    else
        skip "Metasploit install skipped (NO_MSF=1)"
    fi
else
    skip "Optional tools skipped (NO_OPTIONAL=1)"
fi

# =============================================================================
# Done
# =============================================================================
echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  Setup complete!${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo "  Next steps:"
echo ""
echo "  1. Start Ollama:           ollama serve"
echo "  2. Activate the venv:      source .venv/bin/activate"
echo "  3. Run a scan:             python3 noctis.py <target>"
echo ""
echo "  Run ./update.sh monthly to keep everything current."
echo ""
