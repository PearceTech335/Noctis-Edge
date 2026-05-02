#!/usr/bin/env bash
# =============================================================================
#  Noctis Edge — Update Script
#  Run: ./update.sh
#  Updates: apt packages, snap, pip deps, nuclei, Ollama models, CVE database,
#           CVE knowledge base (submit + pull), Tool knowledge base (submit + pull)
# =============================================================================

set -euo pipefail

# Never prompt for git credentials — if auth is required and unavailable,
# fail immediately rather than hanging the terminal waiting for a password.
export GIT_TERMINAL_PROMPT=0

OLLAMA_MODEL="qwen2.5-coder:3b-instruct"
OLLAMA_SCRIPT_MODEL="qwen2.5-coder:3b-instruct"
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
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[1;36m'; NC='\033[0m'
ok()    { echo -e "${GREEN}[OK]${NC}  $*"; }
info()  { echo -e "${YELLOW}[--]${NC}  $*"; }
err()   { echo -e "${RED}[!!]${NC}  $*"; }
promo() { echo -e "${CYAN}[**]${NC}  $*"; }

header() {
    echo ""
    echo "============================================================"
    echo "  $*"
    echo "============================================================"
}

# =============================================================================
# 0. Sudo — cache credentials up-front
# =============================================================================
# Prompt for the sudo password NOW, before any long-running network operation
# (apt update can take 30-60 s reaching mirrors, which would otherwise delay
# the password prompt and make the web UI appear frozen).
info "This script requires sudo for apt and snap steps."
info "Please enter your sudo password when prompted below."
if ! sudo -v; then
    err "sudo authentication failed — aborting"
    exit 1
fi
ok "sudo credentials cached"

# =============================================================================
# 1. apt — system packages
# =============================================================================
header "1/9  System packages (apt)"
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
header "2/9  Snap packages (seclists)"
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
header "3/9  Python dependencies (pip)"
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
header "4/9  Nuclei (Go binary + templates)"
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
header "5/9  Ollama models"
if command -v ollama &>/dev/null; then
    # Check if server is running; if not, start it temporarily
    if curl -s --max-time 3 http://localhost:11434/api/tags &>/dev/null; then
        info "Ollama server is running — pulling latest models ..."
        ollama pull "$OLLAMA_MODEL" \
            && ok "$OLLAMA_MODEL up to date" \
            || err "$OLLAMA_MODEL pull failed"
        ollama pull "$OLLAMA_SCRIPT_MODEL" \
            && ok "$OLLAMA_SCRIPT_MODEL up to date" \
            || err "$OLLAMA_SCRIPT_MODEL pull failed"
    else
        info "Ollama server not running — starting temporarily ..."
        ollama serve &>/dev/null &
        OLLAMA_PID=$!
        info "Waiting up to 30s for Ollama to become ready ..."
        _waited=0
        until curl -s --max-time 2 http://localhost:11434/api/tags &>/dev/null; do
            if [[ $_waited -ge 30 ]]; then
                err "Ollama did not become ready within 30s — model pull may fail"
                break
            fi
            sleep 1
            _waited=$(( _waited + 1 ))
        done
        [[ $_waited -lt 30 ]] && info "Ollama ready after ${_waited}s"
        ollama pull "$OLLAMA_MODEL" \
            && ok "$OLLAMA_MODEL up to date" \
            || err "$OLLAMA_MODEL pull failed"
        ollama pull "$OLLAMA_SCRIPT_MODEL" \
            && ok "$OLLAMA_SCRIPT_MODEL up to date" \
            || err "$OLLAMA_SCRIPT_MODEL pull failed"
        kill "$OLLAMA_PID" 2>/dev/null || true
    fi
else
    err "ollama not found — install it first (see Readme/requirements.md section 6)"
fi

# =============================================================================
# 6. CVE offline database
# =============================================================================
header "6/9  CVE offline database"
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
header "7/10  Noctis Edge repository"
if [[ -d "$SCRIPT_DIR/.git" ]]; then
    info "Fetching latest Noctis Edge from GitHub ..."
    # fetch + reset guarantees the working tree matches origin/master regardless
    # of any local modifications (dirty working tree, failed rebase, etc.)
    git -C "$SCRIPT_DIR" fetch --quiet \
        https://github.com/PearceTech335/Noctis-Edge.git master:refs/remotes/origin/master \
        && git -C "$SCRIPT_DIR" reset --hard origin/master --quiet \
        && ok "Noctis Edge updated to latest" \
        || err "Noctis Edge update failed — check network or run 'git fetch && git reset --hard origin/master' manually"
else
    info "No .git directory found — skipping self-update"
fi

# =============================================================================
# 8. Nikto submodule
# =============================================================================
header "8/10  Nikto (submodule update)"
NIKTO_DIR="$SCRIPT_DIR/nikto"
if [[ -d "$NIKTO_DIR/.git" ]]; then
    info "Pulling latest nikto ..."
    git -C "$NIKTO_DIR" pull --quiet \
        && ok "nikto up to date" \
        || err "nikto git pull failed — continuing"
elif [[ -d "$NIKTO_DIR" ]]; then
    info "nikto/ exists but is not a git repo — initialising submodule ..."
    git -C "$SCRIPT_DIR" submodule update --init --remote nikto \
        && ok "nikto submodule initialised and up to date" \
        || err "nikto submodule update failed — run 'git submodule update --init --remote nikto' manually"
else
    err "nikto/ directory not found — run 'git submodule update --init --recursive' to clone it"
fi

# =============================================================================
# 9. CVE Knowledge Base sync
# =============================================================================
header "9/10  CVE Knowledge Base sync"

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
    promo "Community KB pull skipped — KB_LICENSE_KEY not set in noctis.conf"
    promo "Unlock community CVE intelligence: https://buy.polar.sh/polar_cl_rEP2IebC07PDSnIal0HF4kZSBJVecdZSmkREx3Emnin"
else
    info "Pulling community CVE knowledge base (license key found) ..."
    _RELAY="https://noctis-kb-relay.pearcetechnologies1.workers.dev"
    _TMP_KB="/tmp/_noctis_community_kb_$$.json"
    HTTP_CODE=$(curl -sS -w "%{http_code}" -o "$_TMP_KB" \
        --max-time 30 \
        -X POST "$_RELAY/community-kb" \
        -H "Content-Type: application/json" \
        -d "{\"license_key\":\"$KB_LICENSE_KEY\"}" 2>/dev/null)
    CURL_EXIT=$?
    if [[ "$CURL_EXIT" != "0" ]]; then
        err "Community KB download failed (curl error $CURL_EXIT) — will retry on next update"
        rm -f "$_TMP_KB"
    elif [[ "$HTTP_CODE" == "200" ]]; then
        MERGE_OUTPUT=$("$PYTHON" "$SCRIPT_DIR/scripts/merge_kb.py" \
            "$_TMP_KB" "$KB_LOCAL" 2>&1)
        MERGE_EXIT=$?
        if [[ "$MERGE_EXIT" == "0" ]]; then
            ok "Community KB merged: $MERGE_OUTPUT"
        else
            err "KB merge failed: $MERGE_OUTPUT"
        fi
        rm -f "$_TMP_KB"
    elif [[ "$HTTP_CODE" == "403" ]]; then
        err "License key rejected — check your subscription at https://buy.polar.sh/polar_cl_rEP2IebC07PDSnIal0HF4kZSBJVecdZSmkREx3Emnin"
        rm -f "$_TMP_KB"
    else
        err "Community KB download failed (HTTP $HTTP_CODE) — will retry on next update"
        rm -f "$_TMP_KB"
    fi
fi

ok "KB sync done"

# =============================================================================
# 10. Tool Knowledge Base sync
# =============================================================================
header "10/10  Tool Knowledge Base sync"

TOOL_KB_LOCAL="$SCRIPT_DIR/tool_knowledge_base.json"

# ── Submit (all users) ────────────────────────────────────────────────────────
if [[ -z "$KB_USER_ID" ]]; then
    err "Tool KB submission skipped — KB_USER_ID missing"
else
    info "Submitting tool knowledge base via community relay ..."
    TOOL_RELAY_ARGS=("$TOOL_KB_LOCAL" "$KB_USER_ID")
    [[ -n "$KB_RELAY_URL" ]] && TOOL_RELAY_ARGS+=("$KB_RELAY_URL")
    "$PYTHON" "$SCRIPT_DIR/scripts/submit_tool_kb.py" "${TOOL_RELAY_ARGS[@]}" \
        && ok "Tool KB submission complete" \
        || err "Tool KB submission failed — will retry on next update"
fi

# ── Pull community tool KB (subscribers only) ─────────────────────────────────
if [[ -z "$KB_LICENSE_KEY" ]]; then
    promo "Community tool KB pull skipped — KB_LICENSE_KEY not set in noctis.conf"
else
    info "Pulling community tool knowledge base (license key found) ..."
    _TOOL_RELAY="https://noctis-kb-relay.pearcetechnologies1.workers.dev"
    _TMP_TOOL_KB="/tmp/_noctis_community_tool_kb_$$.json"
    HTTP_CODE=$(curl -sS -w "%{http_code}" -o "$_TMP_TOOL_KB" \
        --max-time 30 \
        -X POST "$_TOOL_RELAY/community-tool-kb" \
        -H "Content-Type: application/json" \
        -d "{\"license_key\":\"$KB_LICENSE_KEY\"}" 2>/dev/null)
    CURL_EXIT=$?
    if [[ "$CURL_EXIT" != "0" ]]; then
        err "Community tool KB download failed (curl error $CURL_EXIT) — will retry on next update"
        rm -f "$_TMP_TOOL_KB"
    elif [[ "$HTTP_CODE" == "200" ]]; then
        MERGE_OUTPUT=$("$PYTHON" "$SCRIPT_DIR/scripts/merge_tool_kb.py" \
            "$_TMP_TOOL_KB" "$TOOL_KB_LOCAL" 2>&1)
        MERGE_EXIT=$?
        [[ "$MERGE_EXIT" == "0" ]] && ok "Community tool KB merged: $MERGE_OUTPUT" \
            || err "Tool KB merge failed: $MERGE_OUTPUT"
        rm -f "$_TMP_TOOL_KB"
    elif [[ "$HTTP_CODE" == "403" ]]; then
        err "License key rejected — check your subscription at https://buy.polar.sh/polar_cl_rEP2IebC07PDSnIal0HF4kZSBJVecdZSmkREx3Emnin"
        rm -f "$_TMP_TOOL_KB"
    else
        err "Community tool KB download failed (HTTP $HTTP_CODE) — will retry on next update"
        rm -f "$_TMP_TOOL_KB"
    fi
fi

ok "Tool KB sync done"

# =============================================================================
# Done
# =============================================================================
echo ""
echo "============================================================"
echo "  All updates complete (10/10 steps)."
echo "  Remember to restart Ollama if it was already running:"
echo "    sudo systemctl restart ollama"
echo "============================================================"
echo ""
