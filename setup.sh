#!/usr/bin/env bash
# =============================================================================
#  Noctis Edge — One-Shot Setup Script
#
#  Run once on a fresh Kali / Parrot / Ubuntu / Debian-based system after cloning:
#
#    git clone https://github.com/PearceTech335/Noctis-Edge.git
#    cd Noctis-Edge
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
#   10.  Additional tools — amass, metasploit-framework
#
#  Skip any step by setting the corresponding NO_* variable, e.g.:
#    NO_MSF=1 ./setup.sh          ← skip Metasploit install
#    NO_OPTIONAL=1 ./setup.sh     ← skip extra tools (amass + Metasploit)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OLLAMA_MODEL="phi4-mini:3.8b"
OLLAMA_SCRIPT_MODEL="qwen2.5-coder:3b-instruct"

CVE_REPO="https://github.com/trickest/cve.git"
CVE_OFFLINE_REPO="https://github.com/trickest/cve-offline.git"

# Fallback upstream for cve-offline scripts
CVE_OFFLINE_ACTUAL="https://github.com/trickest/cve-offline.git"

RDPSCAN_REPO="https://github.com/robertdavidgraham/rdpscan.git"

# ── colour helpers ──────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
info()    { echo -e "${YELLOW}[ > ]${NC}   $*"; }
err()     { echo -e "${RED}[ERR]${NC}   $*"; }
fail()    { err "$*"; SETUP_INCOMPLETE=1; }
header()  {
    echo ""
    echo -e "${CYAN}============================================================${NC}"
    echo -e "${CYAN}  $*${NC}"
    echo -e "${CYAN}============================================================${NC}"
}
skip()    { echo -e "${YELLOW}[SKIP]${NC}  $*"; }
SETUP_INCOMPLETE=0

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
    python3-tk \
    nmap \
    curl \
    wget \
    ffuf \
    hydra \
    ssh-audit \
    dnsutils \
    dnsenum \
    dnsrecon \
    perl \
    libxml-writer-perl \
    libjson-perl \
    golang-go \
    git \
    libssl-dev \
    build-essential

ok "apt packages installed"


for required_cmd in dnsenum dnsrecon; do
    if command -v "$required_cmd" &>/dev/null; then
        ok "$required_cmd installed at $(command -v "$required_cmd")"
    else
        fail "$required_cmd is required but was not installed successfully"
    fi
done

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
export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin"
if ! grep -qF 'go/bin' ~/.bashrc 2>/dev/null; then
    echo 'export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin"' >> ~/.bashrc
    info "Added ~/go/bin and ~/.local/bin to ~/.bashrc"
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

info "Pulling model: $OLLAMA_SCRIPT_MODEL (code-specialist — script generation) ..."
ollama pull "$OLLAMA_SCRIPT_MODEL" \
    && ok "Model $OLLAMA_SCRIPT_MODEL ready" \
    || err "Model pull failed — run 'ollama pull $OLLAMA_SCRIPT_MODEL' manually after setup"

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
"$VENV/bin/python3" -m pip install --upgrade pip --quiet
"$VENV/bin/python3" -m pip install --upgrade \
    requests \
    jinja2 \
    pycryptodome \
    flask \
    flask-sock \
    --quiet \
    && ok "Python packages installed (requests, jinja2, pycryptodome, flask, flask-sock)" \
    || fail "Python package installation failed"

if command -v nxc &>/dev/null; then
    ok "NetExec already available at $(command -v nxc)"
else
    info "Installing NetExec (nxc) ..."
    if sudo apt install -y netexec 2>/dev/null && command -v nxc &>/dev/null; then
        ok "NetExec installed via apt"
    else
        # netexec is not on PyPI — install from source via pipx
        info "Using pipx to install NetExec from GitHub source ..."
        sudo apt install -y pipx libkrb5-dev 2>/dev/null || true
        # Ensure ~/.local/bin is on PATH for this session and future shells
        export PATH="$HOME/.local/bin:$PATH"
        pipx ensurepath 2>/dev/null || true
        if pipx install "git+https://github.com/Pennyw0rth/NetExec"; then
            ok "NetExec installed via pipx (~/.local/bin/nxc)"
        else
            fail "NetExec (nxc) could not be installed — internal_ad profile will not function"
        fi
    fi
fi

chmod +x "$SCRIPT_DIR/noctis.py" "$SCRIPT_DIR/noctis_web.py" 2>/dev/null || true
ok "Executable entry points prepared"

# =============================================================================
# 7.  CVE offline database
# =============================================================================
header "8/10  CVE offline database"
CVE_DIR="$SCRIPT_DIR/CVE/cve-offline"

if [[ -d "$CVE_DIR" && -f "$CVE_DIR/updatecsv.sh" ]]; then
    skip "CVE/cve-offline already present — skipping (run ./update.sh to refresh)"
else
    info "Building CVE database from trickest/cve source ..."
    mkdir -p "$SCRIPT_DIR/CVE"
    # trickest/cve-offline was retired — build the CSV directly from trickest/cve
    CVE_DIR=""
fi

build_cve_fallback_csv() {
    local fallback_repo_dir="$SCRIPT_DIR/CVE/cve"
    local csv_out="$SCRIPT_DIR/CVE/cve-offline/cve-summary.csv"

    info "Attempting fallback CVE dataset from $CVE_REPO ..."
    mkdir -p "$SCRIPT_DIR/CVE"

    if [[ -d "$fallback_repo_dir/.git" ]]; then
        (cd "$fallback_repo_dir" && git pull --ff-only >/dev/null 2>&1) \
            && ok "Updated fallback CVE source repo" \
            || err "Could not update existing fallback CVE source repo"
    else
        git clone --depth=1 "$CVE_REPO" "$fallback_repo_dir" >/dev/null 2>&1 \
            && ok "Fallback CVE source repo cloned" \
            || { err "Fallback CVE source clone failed"; return 1; }
    fi

    mkdir -p "$(dirname "$csv_out")"
    : > "$csv_out"

    # Count total files upfront so we can show progress
    local _cve_files
    mapfile -t _cve_files < <(find "$fallback_repo_dir" -type f -regextype posix-extended -regex '.*/[0-9]{4}/CVE-[0-9]{4}-[0-9]+\.md' | sort)
    local total="${#_cve_files[@]}"
    local count=0

    info "Processing $total CVE records — this will take several minutes ..."

    for md_file in "${_cve_files[@]}"; do
        cve_id="$(basename "$md_file" .md)"
        summary="$(awk '
            BEGIN { in_desc=0 }
            tolower($0) ~ /^### description/ { in_desc=1; next }
            in_desc {
                if ($0 ~ /^### /) exit
                if ($0 !~ /^[[:space:]]*$/) {
                    gsub(/\r/, "", $0)
                    print $0
                    exit
                }
            }
        ' "$md_file")"

        if [[ -z "$summary" ]]; then
            summary="No description available."
        fi

        summary="${summary//\"/\"\"}"
        echo "$cve_id,NONE,\"$summary\"" >> "$csv_out"

        (( count++ ))
        # Print progress every 5000 records
        if (( count % 5000 == 0 )); then
            printf "\r  [ > ]   Progress: %d / %d records written (%.0f%%)   " \
                "$count" "$total" "$(( count * 100 / total ))"
        fi
    done
    printf "\r  [ > ]   Progress: %d / %d records written (100%%)   \n" "$total" "$total"

    if [[ -s "$csv_out" ]]; then
        ok "Fallback CVE CSV generated at CVE/cve-offline/cve-summary.csv"
        return 0
    fi

    err "Fallback CVE CSV generation produced no records"
    return 1
}

if [[ -n "${CVE_DIR:-}" && -x "$CVE_DIR/updatecsv.sh" ]]; then
    info "Building cve-summary.csv (this downloads ~100 MB of CVE data — may take a few minutes) ..."
    (cd "$CVE_DIR" && bash updatecsv.sh) \
        && ok "cve-summary.csv built at CVE/cve-offline/cve-summary.csv" \
        || {
            err "updatecsv.sh failed — attempting fallback CVE CSV build"
            build_cve_fallback_csv || true
        }
elif [[ -n "${CVE_DIR:-}" ]]; then
    err "updatecsv.sh not found in $CVE_DIR — cannot build CVE database automatically"
fi

if [[ ! -f "$SCRIPT_DIR/CVE/cve-offline/cve-summary.csv" ]]; then
    build_cve_fallback_csv || true
fi

if [[ -f "$SCRIPT_DIR/CVE/cve-offline/cve-summary.csv" ]]; then
    ok "CVE database ready"
else
    fail "CVE database missing — Noctis will run without offline CVE enrichment until CVE/cve-offline/cve-summary.csv exists"
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

if [[ -f "$RDPSCAN_DIR/RPDscan.py" ]]; then
    ok "rdpscan helper ready"
else
    fail "rdpscan clone incomplete — rdp validation will be unavailable"
fi

# =============================================================================
# 9.  Additional tools  (amass, Metasploit)
# =============================================================================
if [[ "${NO_OPTIONAL:-0}" != "1" ]]; then
    header "10/10  Additional tools"

    info "Installing amass ..."
    if command -v amass &>/dev/null; then
        skip "amass already installed at $(command -v amass)"
    elif sudo apt install -y amass 2>/dev/null; then
        ok "amass installed via apt"
    elif command -v snap &>/dev/null && sudo snap install amass 2>/dev/null; then
        ok "amass installed via snap"
    else
        info "apt/snap failed — trying go install fallback ..."
        go install github.com/owasp-amass/amass/v4/...@latest 2>/dev/null \
            && ok "amass installed via go install" \
            || skip "amass could not be installed (external recon profile will run without it)"
    fi

    if [[ "${NO_MSF:-0}" != "1" ]]; then
        info "Checking for Metasploit Framework ..."
        if command -v msfconsole &>/dev/null; then
            skip "msfconsole already installed at $(command -v msfconsole)"
        else
            info "Installing metasploit-framework via apt (Kali / Parrot only) ..."
            if sudo apt install -y metasploit-framework 2>/dev/null; then
                ok "metasploit-framework installed via apt"
            else
                info "apt install failed — trying Metasploit nightly installer ..."
                curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb \
                    -o /tmp/msfinstall 2>/dev/null \
                    && chmod 755 /tmp/msfinstall \
                    && sudo /tmp/msfinstall \
                    && ok "metasploit-framework installed via nightly installer" \
                    || {
                        skip "metasploit-framework could not be installed automatically"
                        info "Install manually: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html"
                    }
            fi
        fi
    else
        skip "Metasploit install skipped (NO_MSF=1)"
    fi
else
    skip "Additional tools skipped (NO_OPTIONAL=1)"
fi

# =============================================================================
# Logo
# =============================================================================
header "Logo (noctis_logo.png)"
LOGO_URL="https://github.com/user-attachments/assets/b21bff80-43a9-4952-a25f-f4d3fa4e87b2"
if [[ -f "$SCRIPT_DIR/noctis_logo.png" ]]; then
    ok "noctis_logo.png already present — skipping download"
else
    info "Downloading Noctis Edge logo ..."
    if curl -fsSL "$LOGO_URL" -o "$SCRIPT_DIR/noctis_logo.png" 2>/dev/null \
       && [[ $(file -b --mime-type "$SCRIPT_DIR/noctis_logo.png" 2>/dev/null) == "image/png" ]]; then
        ok "Logo downloaded to noctis_logo.png"
    else
        rm -f "$SCRIPT_DIR/noctis_logo.png"
        skip "Logo download failed — the GUI will attempt to download it on first launch"
    fi
fi

# =============================================================================
# Per-user configuration  (noctis.conf)
# =============================================================================
header "Per-user configuration (noctis.conf)"

CONF_FILE="$SCRIPT_DIR/noctis.conf"

# Create noctis.conf with defaults if it doesn't exist yet
if [[ ! -f "$CONF_FILE" ]]; then
    info "Creating noctis.conf ..."
    cat > "$CONF_FILE" << 'CONF_EOF'
# Noctis Edge — per-user configuration
# DO NOT COMMIT this file — it is listed in .gitignore
# =============================================================================

# Your unique installation ID (auto-generated by setup.sh — do not edit)
KB_USER_ID=""

# Optional: override the Cloudflare relay URL used for KB submissions.
# Leave empty to use the default URL built into scripts/submit_kb.py.
# Only needed for local testing or self-hosted relay deployments.
KB_RELAY_URL=""

# =============================================================================
# PAID TIER
# =============================================================================

KB_LICENSE_KEY=""
# ↑ Paste your Polar.sh license key here to enable the community CVE KB download.
#   Subscribe at: https://buy.polar.sh/polar_cl_rEP2IebC07PDSnIal0HF4kZSBJVecdZSmkREx3Emnin
CONF_EOF
    ok "noctis.conf created"
else
    info "noctis.conf already exists — skipping creation"
fi

# shellcheck source=/dev/null
source "$CONF_FILE" 2>/dev/null || true

# Generate a UUID if KB_USER_ID is not yet set
if [[ -z "${KB_USER_ID:-}" ]]; then
    info "Generating unique installation ID ..."
    _new_uuid="$(python3 -c 'import uuid; print(uuid.uuid4())')"
    sed -i "s/^KB_USER_ID=\"\"/KB_USER_ID=\"$_new_uuid\"/" "$CONF_FILE"
    ok "Installation ID assigned: $_new_uuid"
else
    ok "Installation ID: $KB_USER_ID"
fi

info "KB submission runs automatically on ./update.sh — no token required"

# =============================================================================
# Done
# =============================================================================
echo ""
if [[ "$SETUP_INCOMPLETE" == "0" ]]; then
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${GREEN}  Setup complete!${NC}"
    echo -e "${GREEN}============================================================${NC}"
else
    echo -e "${RED}============================================================${NC}"
    echo -e "${RED}  Setup finished with missing core components${NC}"
    echo -e "${RED}============================================================${NC}"
fi
echo ""
echo "  Next steps:"
echo ""
echo "  1. Run a scan:             ./noctis.py <target>"
echo "     (Ollama will start automatically if not already running)"
echo "  2. Launch the Web UI:      ./noctis_web.py  (then open http://127.0.0.1:5000)"
echo "  3. Optional shell access:  source .venv/bin/activate"
echo ""
echo "  Run ./update.sh monthly to keep everything current."
echo ""

if [[ "$SETUP_INCOMPLETE" != "0" ]]; then
    exit 1
fi
