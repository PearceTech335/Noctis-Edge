#!/usr/bin/env bash
# =============================================================================
#  Noctis Edge — Monthly Update Script
#  Run: ./update.sh
#  Updates: apt packages, snap, pip deps, nuclei, Ollama model, CVE database
# =============================================================================

set -euo pipefail

# Never prompt for git credentials — if auth is required and unavailable,
# fail immediately rather than hanging the terminal waiting for a password.
export GIT_TERMINAL_PROMPT=0

OLLAMA_MODEL="hf.co/RCorvalan/Qwen2.5-7B-Instruct-1M-Q4_K_M-GGUF"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load per-user configuration (tokens, UUID, paid-tier flag)
# shellcheck source=/dev/null
if [[ -f "$SCRIPT_DIR/noctis.conf" ]]; then
    source "$SCRIPT_DIR/noctis.conf"
fi
KB_USER_ID="${KB_USER_ID:-}"
KB_RELAY_URL="${KB_RELAY_URL:-}"
KB_LICENSE_KEY="${KB_LICENSE_KEY:-}"

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
sudo apt update -qq      || err "apt update failed — continuing"
sudo apt upgrade -y      || err "apt upgrade failed — continuing"
info "Ensuring required DNS tools are installed ..."
sudo apt install -y dnsenum dnsrecon || err "apt install failed — continuing"
sudo apt autoremove -y   || true
ok "apt done"

# =============================================================================
# 2. snap — SecLists
# =============================================================================
header "2/7  Snap packages (seclists)"
if command -v snap &>/dev/null; then
    info "Refreshing snap packages ..."
    sudo snap refresh || err "snap refresh failed — continuing"
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
    info "Updating packages in venv at $VENV ..."
    "$VENV/bin/python3" -m pip install --upgrade pip --quiet
    "$VENV/bin/python3" -m pip install --upgrade \
        requests \
        jinja2 \
        pycryptodome \
        flask \
        flask-sock \
        --quiet
    ok "pip done (requests, jinja2, pycryptodome, flask, flask-sock)"
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
    # Always pull via HTTPS — no credentials needed for a public repo.
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
# 7. Noctis Edge itself
# =============================================================================
header "7/7  Noctis Edge repository"
if [[ -d "$SCRIPT_DIR/.git" ]]; then
    info "Pulling latest Noctis Edge ..."
    # Always pull via HTTPS so no SSH key or GitHub credentials are required.
    git -C "$SCRIPT_DIR" pull --rebase --quiet \
        https://github.com/PearceTech335/Noctis-Edge.git master \
        && ok "Noctis Edge up to date" \
        || err "git pull failed (may have uncommitted changes)"
else
    info "No .git directory found — skipping self-update"
fi

# =============================================================================
# 8. CVE Knowledge Base sync
# =============================================================================
header "8/8  CVE Knowledge Base sync"

KB_LOCAL="$SCRIPT_DIR/cve_knowledge_base.json"
VENV="$SCRIPT_DIR/.venv"
PYTHON="${VENV}/bin/python3"
[[ -f "$PYTHON" ]] || PYTHON="python3"

# ── Submit (all users) ────────────────────────────────────────────────────────
if [[ -z "$KB_USER_ID" ]]; then
    err  "KB submission skipped — KB_USER_ID missing; run ./setup.sh to generate one"
else
    info "Submitting CVE knowledge base via community relay ..."
    # Optionally pass a relay URL override from noctis.conf (for testing)
    RELAY_ARGS=("$KB_LOCAL" "$KB_USER_ID")
    [[ -n "$KB_RELAY_URL" ]] && RELAY_ARGS+=("$KB_RELAY_URL")
    "$PYTHON" "$SCRIPT_DIR/scripts/submit_kb.py" "${RELAY_ARGS[@]}" \
        && ok "KB submission complete" \
        || err "KB submission failed — will retry on next update"
fi

# ── Pull community KB (subscribers only) ────────────────────────────────────────
if [[ -z "$KB_LICENSE_KEY" ]]; then
    info "Community KB pull skipped (KB_LICENSE_KEY not set in noctis.conf)"
    info "Subscribe at: https://polar.sh/PearceTech335"
else
    info "Pulling community CVE knowledge base ..."
    TMP_KB_DIR="$(mktemp -d)"

    _cleanup_tmp() { rm -rf "$TMP_KB_DIR"; }
    trap _cleanup_tmp EXIT

    CLONE_URL="https://${KB_LICENSE_KEY}@github.com/PearceTech335/Noctis-Edge-KB.git"

    if git clone --depth=1 --quiet "$CLONE_URL" "$TMP_KB_DIR" 2>/dev/null; then
        if [[ -f "$TMP_KB_DIR/community_kb.json" ]]; then
            MERGE_OUTPUT=$("$PYTHON" "$SCRIPT_DIR/scripts/merge_kb.py" \
                "$TMP_KB_DIR/community_kb.json" \
                "$KB_LOCAL" 2>&1)
            MERGE_EXIT=$?
            if [[ "$MERGE_EXIT" == "0" ]]; then
                ok "$MERGE_OUTPUT"
            else
                err "KB merge failed: $MERGE_OUTPUT"
            fi
        else
            err "community_kb.json not found in Noctis-Edge-KB — check the repository is correctly populated"
        fi
    else
        err "Could not clone community KB — verify KB_LICENSE_KEY is valid and you have repository access"
        info "Access is granted via Polar.sh after subscribing at https://polar.sh/PearceTech335"
    fi

    _cleanup_tmp
    trap - EXIT
fi

ok "KB sync done"

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
