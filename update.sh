#!/usr/bin/env bash
# =============================================================================
#  ReconoTron — Monthly Update Script
#  Run: ./update.sh
#  Updates: apt packages, snap, pip deps, nuclei, Ollama model, CVE database
# =============================================================================

set -euo pipefail

OLLAMA_MODEL="qwen2.5-coder:7b-instruct-q4_k_m"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colour helpers
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}  $*"; }
info() { echo -e "${YELLOW}[--]${NC}  $*"; }
err()  { echo -e "${RED}[!!]${NC}  $*"; }

header() {
    echo ""
    echo "============================================================"
    echo "  $*"
    echo "============================================================"
}

# =============================================================================
# 1. apt — system packages
# =============================================================================
header "1/7  System packages (apt)"
info "Running apt update + upgrade ..."
sudo apt update -qq
sudo apt upgrade -y
sudo apt autoremove -y
ok "apt done"

# =============================================================================
# 2. snap — SecLists
# =============================================================================
header "2/7  Snap packages (seclists)"
if command -v snap &>/dev/null; then
    info "Refreshing snap packages ..."
    sudo snap refresh
    ok "snap done"
else
    err "snap not found — skipping"
fi

# =============================================================================
# 3. pip — Python dependencies
# =============================================================================
header "3/7  Python dependencies (pip)"
VENV="$SCRIPT_DIR/.venv"
if [[ -f "$VENV/bin/activate" ]]; then
    info "Activating venv at $VENV ..."
    # shellcheck disable=SC1091
    source "$VENV/bin/activate"
    pip install --upgrade pip --quiet
    pip install --upgrade requests jinja2 pycryptodome netexec --quiet
    ok "pip done (requests, jinja2, pycryptodome, netexec)"
    deactivate
else
    info "No venv found — installing to system Python (consider creating a venv)"
    pip3 install --upgrade requests jinja2 pycryptodome netexec --quiet
    ok "pip done"
fi

# =============================================================================
# 4. Nuclei — binary + templates
# =============================================================================
header "4/7  Nuclei (Go binary + templates)"
if command -v nuclei &>/dev/null; then
    info "Updating nuclei binary ..."
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null \
        && ok "nuclei binary updated" \
        || err "nuclei binary update failed (Go may not be installed)"

    info "Updating nuclei templates ..."
    nuclei -update-templates -silent \
        && ok "nuclei templates updated" \
        || err "nuclei template update failed"
else
    err "nuclei not found — install it first (see Readme/requirements.md section 5)"
fi

# =============================================================================
# 5. Ollama — model refresh
# =============================================================================
header "5/7  Ollama model ($OLLAMA_MODEL)"
if command -v ollama &>/dev/null; then
    # Check if server is running; if not, start it temporarily
    if curl -s --max-time 3 http://localhost:11434/api/tags &>/dev/null; then
        info "Ollama server is running — pulling latest model ..."
        ollama pull "$OLLAMA_MODEL" \
            && ok "Ollama model up to date" \
            || err "Ollama model pull failed"
    else
        info "Ollama server not running — starting temporarily ..."
        ollama serve &>/dev/null &
        OLLAMA_PID=$!
        sleep 5
        ollama pull "$OLLAMA_MODEL" \
            && ok "Ollama model up to date" \
            || err "Ollama model pull failed"
        kill "$OLLAMA_PID" 2>/dev/null || true
    fi
else
    err "ollama not found — install it first (see Readme/requirements.md section 6)"
fi

# =============================================================================
# 6. CVE offline database
# =============================================================================
header "6/7  CVE offline database"
CVE_DIR="$SCRIPT_DIR/CVE/cve-offline"
if [[ -d "$CVE_DIR/.git" ]]; then
    info "Pulling latest CVE repo ..."
    git -C "$CVE_DIR" pull --quiet \
        && ok "CVE repo up to date" \
        || err "CVE git pull failed"

    if [[ -x "$CVE_DIR/updatecsv.sh" ]]; then
        info "Regenerating cve-summary.csv ..."
        (cd "$CVE_DIR" && bash updatecsv.sh) \
            && ok "cve-summary.csv regenerated" \
            || err "updatecsv.sh failed"
    else
        err "updatecsv.sh not found or not executable in $CVE_DIR"
    fi
else
    err "CVE/cve-offline is not a git repo — clone it first (see Readme/requirements.md section 8)"
fi

# =============================================================================
# 7. ReconoTron itself
# =============================================================================
header "7/7  ReconoTron repository"
if [[ -d "$SCRIPT_DIR/.git" ]]; then
    info "Pulling latest ReconoTron ..."
    git -C "$SCRIPT_DIR" pull --quiet \
        && ok "ReconoTron up to date" \
        || err "git pull failed (may have uncommitted changes)"
else
    info "No .git directory found — skipping self-update"
fi

# =============================================================================
# Done
# =============================================================================
echo ""
echo "============================================================"
echo "  All updates complete."
echo "  Remember to restart Ollama if it was already running:"
echo "    sudo systemctl restart ollama"
echo "============================================================"
echo ""
