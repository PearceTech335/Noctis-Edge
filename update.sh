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
OLLAMA_REPORT_MODEL="qwen3:4b"
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
# 0. Sudo / root detection
# =============================================================================
# Inside Docker the container runs as root — sudo is not installed and not
# needed. On a regular host we need sudo for apt/snap. Set SUDO accordingly.
if [[ "$(id -u)" == "0" ]]; then
    SUDO=""
    ok "Running as root — sudo not required"
else
    SUDO="sudo"
    info "This script requires sudo for apt and snap steps."
    info "Please enter your sudo password when prompted below."
    if ! sudo -v; then
        err "sudo authentication failed — aborting"
        exit 1
    fi
    ok "sudo credentials cached"
fi

# =============================================================================
# 1. apt — system packages
# =============================================================================
header "1/10  System packages (apt)"
info "Running apt update + upgrade ..."
$SUDO apt update -qq      || err "apt update failed — continuing"
$SUDO apt upgrade -y      || err "apt upgrade failed — continuing"
info "Ensuring required DNS tools are installed ..."
$SUDO apt install -y dnsenum dnsrecon || err "apt install failed — continuing"
$SUDO apt autoremove -y   || true
ok "apt done"

# =============================================================================
# 1b. Additional tools — amass, NetExec (nxc)
#     Mirrors the fixed logic in setup.sh so reinstalls / fresh VMs get the
#     same correct behaviour from update.sh.
# =============================================================================
header "1b  Additional tools (amass, NetExec)"

# Ensure go/bin and pipx bin are findable for this session
export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin"

info "Checking amass ..."
if command -v amass &>/dev/null; then
    if command -v go &>/dev/null; then
        info "Updating amass via go install ..."
        go install -v github.com/owasp-amass/amass/v4/cmd/amass@latest 2>/dev/null \
            && ok "amass updated" \
            || err "amass update failed — continuing"
    else
        ok "amass already installed ($(command -v amass)) — skipping go update (go not found)"
    fi
else
    if $SUDO apt install -y amass 2>/dev/null; then
        ok "amass installed via apt"
    elif command -v snap &>/dev/null && $SUDO snap install amass 2>/dev/null; then
        ok "amass installed via snap"
    elif command -v go &>/dev/null; then
        go install -v github.com/owasp-amass/amass/v4/cmd/amass@latest 2>/dev/null \
            && ok "amass installed via go install" \
            || err "amass could not be installed — external recon profile will run without it"
    else
        err "amass not found and go is not installed — external recon profile will run without it"
    fi
fi

info "Checking NetExec (nxc) ..."
if command -v nxc &>/dev/null; then
    pipx upgrade netexec 2>/dev/null \
        && ok "nxc updated via pipx" \
        || { ok "nxc already up to date (pipx upgrade skipped — not a pipx install)"; }
else
    if $SUDO apt install -y netexec 2>/dev/null && command -v nxc &>/dev/null; then
        ok "NetExec installed via apt"
    else
        info "Using pipx to install NetExec ..."
        $SUDO apt install -y libkrb5-dev 2>/dev/null || true
        if ! $SUDO apt install -y pipx 2>/dev/null; then
            python3 -m pip install pipx --break-system-packages 2>/dev/null \
                || python3 -m pip install pipx 2>/dev/null || true
        fi
        export PATH="$HOME/.local/bin:$PATH"
        pipx ensurepath 2>/dev/null || true
        if pipx install netexec 2>/dev/null || pipx install "git+https://github.com/Pennyw0rth/NetExec" 2>/dev/null; then
            ok "NetExec installed via pipx (~/.local/bin/nxc)"
        else
            err "NetExec (nxc) could not be installed — internal_ad profile will not function"
        fi
    fi
fi

# =============================================================================
# 1c. Tool manifest health check — install any missing manifest-listed binaries
# =============================================================================
header "1c  Tool manifest health check"

# Install a single manifest tool's backing binary if absent.
# Called once per tool name found in tool_manifest.json.
_ensure_manifest_tool() {
    local tool="$1"
    case "$tool" in
        ssh_enum)
            command -v ssh-audit &>/dev/null && return 0
            info "ssh-audit missing — installing ..."
            $SUDO apt install -y ssh-audit \
                && ok "ssh-audit installed" \
                || err "ssh-audit install failed — ssh_enum will be unavailable"
            ;;
        ffuf)
            command -v ffuf &>/dev/null && return 0
            info "ffuf missing — installing ..."
            $SUDO apt install -y ffuf 2>/dev/null \
                || ( command -v go &>/dev/null \
                     && go install -v github.com/ffuf/ffuf/v2@latest \
                     && ok "ffuf installed via go install" ) \
                || err "ffuf install failed — directory fuzzing will be unavailable"
            ;;
        rdp_enum)
            [[ -f "$SCRIPT_DIR/rdpscan/RPDscan.py" ]] && return 0
            info "rdpscan missing — cloning ..."
            git clone --depth=1 https://github.com/robertdavidgraham/rdpscan.git \
                "$SCRIPT_DIR/rdpscan" 2>/dev/null \
                && ok "rdpscan cloned" \
                || err "rdpscan clone failed — RDP scanning will be unavailable"
            ;;
        nikto|nikto_cgi)
            [[ -f "$SCRIPT_DIR/nikto/program/nikto.pl" ]] && return 0
            info "nikto submodule missing — initialising ..."
            git -C "$SCRIPT_DIR" submodule update --init --recursive \
                && ok "nikto submodule ready" \
                || err "nikto submodule init failed"
            ;;
        nuclei)
            ( command -v nuclei &>/dev/null \
              || [[ -x "$HOME/go/bin/nuclei" ]] ) && return 0
            info "nuclei missing — installing ..."
            command -v go &>/dev/null \
                && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
                && ok "nuclei installed" \
                || err "nuclei install failed (go not found)"
            ;;
        dns_enum)
            command -v dnsenum &>/dev/null && command -v dnsrecon &>/dev/null && return 0
            info "dns tools missing — installing ..."
            $SUDO apt install -y dnsenum dnsrecon \
                && ok "dnsenum + dnsrecon installed" \
                || err "dns tools install failed"
            ;;
        nxc_smb|nxc_ldap|mssql_enum)
            # nxc already handled above in section 1b
            command -v nxc &>/dev/null && return 0
            info "nxc missing — will be handled by section 1b on next run"
            ;;
        curl)
            command -v curl &>/dev/null && return 0
            info "curl missing — installing ..."
            $SUDO apt install -y curl \
                && ok "curl installed" \
                || err "curl install failed"
            ;;
        mysql_enum)
            # backed by nmap NSE scripts — nmap is a hard dependency
            command -v nmap &>/dev/null && return 0
            info "nmap missing — installing ..."
            $SUDO apt install -y nmap \
                && ok "nmap installed" \
                || err "nmap install failed"
            ;;
        # nikto/nuclei/ffuf already covered; remaining tools need no extra binary
        *) return 0 ;;
    esac
}

_MANIFEST_FILE="$SCRIPT_DIR/tool_manifest.json"
if [[ -f "$_MANIFEST_FILE" ]]; then
    _MANIFEST_TOOLS=$(python3 -c "
import json, sys
try:
    d = json.load(open('$_MANIFEST_FILE'))
    print(' '.join(k for k in d if not k.startswith('_')))
except Exception as e:
    sys.exit(1)
" 2>/dev/null || echo "")

    if [[ -n "$_MANIFEST_TOOLS" ]]; then
        for _tool in $_MANIFEST_TOOLS; do
            _ensure_manifest_tool "$_tool"
        done
        ok "Tool manifest health check complete"
    else
        err "Could not parse tool manifest — skipping tool health check"
    fi
else
    info "tool_manifest.json not found — skipping manifest tool check"
fi

# =============================================================================
# 2. snap — SecLists
# =============================================================================
header "2/10  Snap packages (seclists)"
if command -v snap &>/dev/null; then
    info "Refreshing snap packages ..."
    $SUDO snap refresh || err "snap refresh failed — continuing"
    ok "snap done"
else
    err "snap not found — skipping"
fi

# =============================================================================
# 3. pip — Python dependencies
# =============================================================================
header "3/10  Python dependencies (pip)"
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
    pip3 install --upgrade requests jinja2 pycryptodome flask flask-sock --quiet
    ok "pip done"
fi

# =============================================================================
# 4. Nuclei — binary + templates
# =============================================================================
header "4/10  Nuclei (Go binary + templates)"
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
header "5/10  Ollama models"
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
        ollama pull "$OLLAMA_REPORT_MODEL" \
            && ok "$OLLAMA_REPORT_MODEL up to date" \
            || err "$OLLAMA_REPORT_MODEL pull failed"
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
        ollama pull "$OLLAMA_REPORT_MODEL" \
            && ok "$OLLAMA_REPORT_MODEL up to date" \
            || err "$OLLAMA_REPORT_MODEL pull failed"
        kill "$OLLAMA_PID" 2>/dev/null || true
    fi
else
    err "ollama not found — install it first (see Readme/requirements.md section 6)"
fi

# =============================================================================
# 5a. EPSS offline database — daily exploit-probability scores
# =============================================================================
header "5a  EPSS offline database (exploit probability scores)"
EPSS_SCRIPT="$SCRIPT_DIR/scripts/build_epss_db.py"
if [[ -f "$EPSS_SCRIPT" ]]; then
    info "Downloading daily EPSS scores to CVE/epss-scores.csv ..."
    "$SCRIPT_DIR/.venv/bin/python3" "$EPSS_SCRIPT" \
        && ok "EPSS database updated" \
        || err "EPSS download failed (network issue?) — existing file retained"
else
    err "scripts/build_epss_db.py not found — skipping EPSS update"
fi

# =============================================================================
# 5b. NVD CVSS offline database — real CVSS scores from NVD JSON 2.0 feeds
# =============================================================================
header "5b  NVD CVSS offline database (real CVSS scores from NVD)"
NVD_SCRIPT="$SCRIPT_DIR/scripts/build_nvd_cvss.py"
if [[ -f "$NVD_SCRIPT" ]]; then
    info "Downloading/updating NVD CVSS feeds to CVE/nvd-cvss.csv ..."
    "$SCRIPT_DIR/.venv/bin/python3" "$NVD_SCRIPT" \
        && ok "NVD CVSS database updated" \
        || err "NVD CVSS download failed — existing file retained"
else
    err "scripts/build_nvd_cvss.py not found — skipping NVD CVSS update"
fi

# =============================================================================
# 5c. CWE offline dictionary — MITRE CWE weakness names, descriptions,
#     consequences and mitigations (refreshed monthly is sufficient)
# =============================================================================
header "5c  CWE offline dictionary (MITRE weakness database)"
CWE_SCRIPT="$SCRIPT_DIR/scripts/build_cwe_db.py"
if [[ -f "$CWE_SCRIPT" ]]; then
    info "Downloading MITRE CWE dictionary to CVE/cwe-data.csv ..."
    "$SCRIPT_DIR/.venv/bin/python3" "$CWE_SCRIPT" \
        && ok "CWE database updated" \
        || err "CWE download failed (network issue?) — existing file retained"
else
    err "scripts/build_cwe_db.py not found — skipping CWE update"
fi

# =============================================================================
# 5d. CISA KEV catalog — Known Exploited Vulnerabilities (active exploitation
#     ground truth; used to boost risk scores and flag MUST-PATCH findings)
# =============================================================================
header "5d  CISA KEV catalog (Known Exploited Vulnerabilities)"
KEV_SCRIPT="$SCRIPT_DIR/scripts/build_kev_db.py"
if [[ -f "$KEV_SCRIPT" ]]; then
    info "Downloading CISA KEV catalog to CVE/kev-catalog.csv ..."
    "$SCRIPT_DIR/.venv/bin/python3" "$KEV_SCRIPT" \
        && ok "KEV catalog updated" \
        || err "KEV download failed (network issue?) — existing file retained"
else
    err "scripts/build_kev_db.py not found — skipping KEV update"
fi

# =============================================================================
# 6. CVE offline database
# =============================================================================
header "6/10  CVE offline database"
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

# Detect whether we are running inside a Docker install.
# Heuristic: docker-compose.yml is present AND either docker or docker-compose
# is available on PATH.  The KB/CVE files are bind-mounted so they update
# immediately, but noctis.py and other source files are baked into the image
# — a rebuild + restart is required to deploy code changes.
_DOCKER_MODE=false
_DC=""
if [[ -f "$SCRIPT_DIR/docker-compose.yml" ]]; then
    if docker compose version > /dev/null 2>&1; then
        _DC="docker compose"
        _DOCKER_MODE=true
    elif command -v docker-compose > /dev/null 2>&1; then
        _DC="docker-compose"
        _DOCKER_MODE=true
    fi
fi

if [[ -d "$SCRIPT_DIR/.git" ]]; then
    info "Fetching latest Noctis Edge from GitHub ..."
    # fetch + reset guarantees the working tree matches origin/master regardless
    # of any local modifications (dirty working tree, failed rebase, etc.)
    git -C "$SCRIPT_DIR" fetch --quiet \
        https://github.com/PearceTech335/Noctis-Edge.git master:refs/remotes/origin/master \
        && git -C "$SCRIPT_DIR" reset --hard origin/master --quiet \
        && ok "Noctis Edge updated to latest" \
        || err "Noctis Edge update failed — check network or run 'git fetch && git reset --hard origin/master' manually"

    # ── Docker: rebuild image + restart noctis container ─────────────────────
    # The git pull above updates source on the host, but the running container
    # still has the old code baked into its image layer.  Rebuild and do a
    # rolling restart so the new code goes live automatically.
    if [[ "$_DOCKER_MODE" == true ]]; then
        info "Docker install detected — rebuilding noctis image with updated source ..."
        $_DC build noctis \
            && ok "Docker image rebuilt" \
            || { err "Docker image build failed — container still running old code"; }
        info "Restarting noctis container ..."
        $_DC up -d --no-deps noctis \
            && ok "noctis container restarted with new image" \
            || err "Container restart failed — run '$_DC up -d noctis' manually"
    fi
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
    promo "Unlock community CVE intelligence: https://noctisedge.lemonsqueezy.com"
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
        err "License key rejected — check your subscription at https://noctisedge.lemonsqueezy.com"
        rm -f "$_TMP_KB"
    else
        err "Community KB download failed (HTTP $HTTP_CODE) — will retry on next update"
        rm -f "$_TMP_KB"
    fi
fi

ok "KB sync done"

# =============================================================================
# 9b. Nuclei Template Knowledge Base sync
# =============================================================================
header "9b/10  Nuclei Template Knowledge Base sync"

NUCLEI_KB_LOCAL="$SCRIPT_DIR/nuclei_kb.json"

# Ensure the file exists (created empty on first run)
if [[ ! -f "$NUCLEI_KB_LOCAL" ]]; then
    echo '{}' > "$NUCLEI_KB_LOCAL"
    ok "Created empty nuclei_kb.json"
fi

# ── Submit (all users) ────────────────────────────────────────────────────────
if [[ -z "$KB_USER_ID" ]]; then
    err "Nuclei KB submission skipped — KB_USER_ID missing"
else
    info "Submitting Nuclei template KB via community relay ..."
    NUCLEI_RELAY_ARGS=("$NUCLEI_KB_LOCAL" "$KB_USER_ID")
    [[ -n "$KB_RELAY_URL" ]] && NUCLEI_RELAY_ARGS+=("$KB_RELAY_URL")
    "$PYTHON" "$SCRIPT_DIR/scripts/submit_nuclei_kb.py" "${NUCLEI_RELAY_ARGS[@]}" \
        && ok "Nuclei KB submission complete" \
        || err "Nuclei KB submission failed — will retry on next update"
fi

# ── Pull community Nuclei KB (subscribers only) ───────────────────────────────
if [[ -z "$KB_LICENSE_KEY" ]]; then
    promo "Community Nuclei KB pull skipped — KB_LICENSE_KEY not set in noctis.conf"
else
    info "Pulling community Nuclei template KB (license key found) ..."
    _NKB_RELAY="https://noctis-kb-relay.pearcetechnologies1.workers.dev"
    _TMP_NKB="/tmp/_noctis_community_nuclei_kb_$$.json"
    HTTP_CODE=$(curl -sS -w "%{http_code}" -o "$_TMP_NKB" \
        --max-time 30 \
        -X POST "$_NKB_RELAY/community-nuclei-kb" \
        -H "Content-Type: application/json" \
        -d "{\"license_key\":\"$KB_LICENSE_KEY\"}" 2>/dev/null)
    CURL_EXIT=$?
    if [[ "$CURL_EXIT" != "0" ]]; then
        err "Community Nuclei KB download failed (curl error $CURL_EXIT) — will retry on next update"
        rm -f "$_TMP_NKB"
    elif [[ "$HTTP_CODE" == "200" ]]; then
        MERGE_OUTPUT=$("$PYTHON" "$SCRIPT_DIR/scripts/merge_nuclei_kb.py" \
            "$_TMP_NKB" "$NUCLEI_KB_LOCAL" 2>&1)
        MERGE_EXIT=$?
        [[ "$MERGE_EXIT" == "0" ]] && ok "Community Nuclei KB merged: $MERGE_OUTPUT" \
            || err "Nuclei KB merge failed: $MERGE_OUTPUT"
        rm -f "$_TMP_NKB"
    elif [[ "$HTTP_CODE" == "403" ]]; then
        err "License key rejected — check your subscription at https://noctisedge.lemonsqueezy.com"
        rm -f "$_TMP_NKB"
    else
        err "Community Nuclei KB download failed (HTTP $HTTP_CODE) — will retry on next update"
        rm -f "$_TMP_NKB"
    fi
fi

ok "Nuclei KB sync done"

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
        err "License key rejected — check your subscription at https://noctisedge.lemonsqueezy.com"
        rm -f "$_TMP_TOOL_KB"
    else
        err "Community tool KB download failed (HTTP $HTTP_CODE) — will retry on next update"
        rm -f "$_TMP_TOOL_KB"
    fi
fi

ok "Tool KB sync done"

# =============================================================================
# 11. Tool Manifest pull (subscribers only)
# =============================================================================
header "11/11  Tool Manifest pull"

MANIFEST_LOCAL="$SCRIPT_DIR/tool_manifest.json"

if [[ -z "$KB_LICENSE_KEY" ]]; then
    promo "Tool manifest pull skipped — KB_LICENSE_KEY not set in noctis.conf"
    promo "  Subscribe at: https://noctisedge.lemonsqueezy.com to receive the"
    promo "  tool_manifest.json with per-tool flag guidance and service routing."
else
    info "Pulling tool manifest (license key found) ..."
    _MANIFEST_RELAY="https://noctis-kb-relay.pearcetechnologies1.workers.dev"
    _TMP_MANIFEST="/tmp/_noctis_tool_manifest_$$.json"
    HTTP_CODE=$(curl -sS -w "%{http_code}" -o "$_TMP_MANIFEST" \
        --max-time 30 \
        -X POST "$_MANIFEST_RELAY/tool-manifest" \
        -H "Content-Type: application/json" \
        -d "{\"license_key\":\"$KB_LICENSE_KEY\"}" 2>/dev/null)
    CURL_EXIT=$?
    if [[ "$CURL_EXIT" != "0" ]]; then
        err "Tool manifest download failed (curl error $CURL_EXIT) — will retry on next update"
        rm -f "$_TMP_MANIFEST"
    elif [[ "$HTTP_CODE" == "200" ]]; then
        # Validate it looks like JSON before replacing the local copy
        if python3 -c "import json,sys; json.load(open('$_TMP_MANIFEST'))" 2>/dev/null; then
            mv "$_TMP_MANIFEST" "$MANIFEST_LOCAL"
            TOOL_COUNT=$(python3 -c "import json; d=json.load(open('$MANIFEST_LOCAL')); print(sum(1 for k in d if not k.startswith('_')))")
            ok "Tool manifest updated ($TOOL_COUNT tools) at $MANIFEST_LOCAL"
        else
            err "Downloaded manifest is not valid JSON — keeping existing copy"
            rm -f "$_TMP_MANIFEST"
        fi
    elif [[ "$HTTP_CODE" == "403" ]]; then
        err "License key rejected — check your subscription at https://noctisedge.lemonsqueezy.com"
        rm -f "$_TMP_MANIFEST"
    else
        err "Tool manifest download failed (HTTP $HTTP_CODE) — will retry on next update"
        rm -f "$_TMP_MANIFEST"
    fi
fi

ok "Tool manifest sync done"

# =============================================================================
# Done
# =============================================================================
echo ""
echo "============================================================"
echo "  All updates complete (11/11 steps)."
echo "  Remember to restart Ollama if it was already running:"
echo "    sudo systemctl restart ollama"
echo "============================================================"
echo ""
