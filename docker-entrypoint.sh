#!/usr/bin/env bash
# =============================================================================
#  Noctis Edge — Docker Entrypoint
#
#  Usage (via docker-compose.yml CMD):
#    web           → start the browser-based Web UI on port 5000 (default)
#    scan <args>   → run noctis.py directly (CLI mode)
#
#  Example CLI:
#    docker compose run --rm noctis scan 192.168.0.1
#    docker compose run --rm noctis scan 192.168.0.1 web --cve-test
# =============================================================================
set -e

CONF_FILE="/app/noctis.conf"
DATA_DIR="/data"

# ---------------------------------------------------------------------------
# Ensure KB files are regular files, not directories.
# If cve_knowledge_base.json / tool_knowledge_base.json are absent from the
# host at "docker compose up" time, Docker bind-mounts them as empty
# directories instead of files, breaking json.load().  Bootstrap them here.
# ---------------------------------------------------------------------------
for KB_FILE in /app/cve_knowledge_base.json /app/tool_knowledge_base.json; do
    if [[ -d "$KB_FILE" ]]; then
        echo "[!] $KB_FILE was created as a directory by Docker — removing and replacing with empty JSON."
        rm -rf "$KB_FILE"
        echo '{}' > "$KB_FILE"
    elif [[ ! -f "$KB_FILE" ]]; then
        echo '{}' > "$KB_FILE"
    fi
done
# ---------------------------------------------------------------------------
# Tool manifest is a subscriber artifact \u2014 do NOT create a placeholder.
# If Docker created it as a directory (because the host file was missing at
# compose-up time), remove the directory so the scanner can start cleanly.
# The scanner gracefully runs without the manifest (curl catch-all routing).
# ---------------------------------------------------------------------------
if [[ -d "/app/tool_manifest.json" ]]; then
    echo "[!] tool_manifest.json was created as a directory by Docker \u2014 removing."
    echo "    It is an optional subscriber artifact; the scanner will run without it."
    rm -rf "/app/tool_manifest.json"
fi
# ---------------------------------------------------------------------------
# Generate noctis.conf if not present
# A named Docker volume keeps this persistent across container restarts.
# ---------------------------------------------------------------------------
if [[ ! -f "$CONF_FILE" ]] || [[ ! -s "$CONF_FILE" ]]; then
    UUID=$(python3 -c "import uuid; print(str(uuid.uuid4()))")
    cat > "$CONF_FILE" <<EOF
# Noctis Edge -- per-user configuration (Docker)
# DO NOT COMMIT this file -- it is listed in .gitignore
# =============================================================================

# Your unique installation ID (auto-generated -- do not edit)
KB_USER_ID="${UUID}"

# Optional: override the Cloudflare relay URL (leave empty for default)
KB_RELAY_URL=""

# =============================================================================
# PAID TIER
# =============================================================================

KB_LICENSE_KEY=""
# ↑ Paste your Lemon Squeezy license key here to enable the community CVE KB download.
#   Subscribe at: https://noctisedge.lemonsqueezy.com
EOF
    echo "[*] Generated new installation ID: ${UUID}"
    echo "[*] Config written to ${CONF_FILE}"
fi

# ---------------------------------------------------------------------------
# Wait for Ollama to be ready
# NOCTIS_OLLAMA_URL is set by docker-compose.yml to http://ollama:11434/api/generate
# ---------------------------------------------------------------------------
OLLAMA_BASE="${NOCTIS_OLLAMA_URL:-http://ollama:11434/api/generate}"
OLLAMA_TAGS="${OLLAMA_BASE%%/api/generate}/api/tags"

echo "[*] Waiting for Ollama at ${OLLAMA_BASE%%/api/generate} ..."
MAX_WAIT=120
WAITED=0
until curl -sf "$OLLAMA_TAGS" > /dev/null 2>&1; do
    if [[ $WAITED -ge $MAX_WAIT ]]; then
        echo "[!] Ollama did not become ready within ${MAX_WAIT}s — check the ollama container."
        exit 1
    fi
    sleep 3
    WAITED=$((WAITED + 3))
done
echo "[+] Ollama is ready"

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

# Background threat-intel DB refresh (non-blocking)
# EPSS: refresh daily if the file is older than 23 hours
EPSS_CSV="/app/CVE/epss-scores.csv"
if [[ ! -f "$EPSS_CSV" ]] || [[ $(( $(date +%s) - $(stat -c %Y "$EPSS_CSV" 2>/dev/null || echo 0) )) -gt 82800 ]]; then
    echo "[*] Refreshing EPSS scores in background ..."
    /app/.venv/bin/python3 /app/scripts/build_epss_db.py >> /tmp/epss_refresh.log 2>&1 &
fi
# NVD CVSS: only build on first run (incremental on subsequent runs via update.sh)
NVD_CSV="/app/CVE/nvd-cvss.csv"
if [[ ! -f "$NVD_CSV" ]]; then
    echo "[*] Building NVD CVSS database in background (first run — this may take a few minutes) ..."
    /app/.venv/bin/python3 /app/scripts/build_nvd_cvss.py >> /tmp/nvd_refresh.log 2>&1 &
fi
# CWE: refresh monthly if the file is older than 30 days (2592000 seconds)
CWE_CSV="/app/CVE/cwe-data.csv"
if [[ ! -f "$CWE_CSV" ]] || [[ $(( $(date +%s) - $(stat -c %Y "$CWE_CSV" 2>/dev/null || echo 0) )) -gt 2592000 ]]; then
    echo "[*] Refreshing CWE database in background ..."
    /app/.venv/bin/python3 /app/scripts/build_cwe_db.py >> /tmp/cwe_refresh.log 2>&1 &
fi
# CVE summary DB: ALWAYS build synchronously if missing.
# A background build causes a race condition where any scan (CLI or web UI)
# starts before the CSV is ready, producing "no CVEs matched" for every port.
CVE_CSV="/app/CVE/cve-offline/cve-summary.csv"
if [[ ! -f "$CVE_CSV" ]]; then
    echo "[*] CVE database not found — building now (this may take a few minutes) ..."
    /app/.venv/bin/python3 /app/scripts/build_cve_db.py
    if [[ ! -f "$CVE_CSV" ]]; then
        echo "[!] CVE database build failed — CVE matching will be unavailable until resolved"
    else
        echo "[+] CVE database ready"
    fi
fi

case "${1:-web}" in
    web)
        echo "[*] Starting Noctis Edge Web UI on port 5000 ..."
        exec /app/.venv/bin/python3 /app/noctis_web.py
        ;;
    scan)
        shift
        echo "[*] Running scan: $*"
        exec /app/.venv/bin/python3 /app/noctis.py "$@"
        ;;
    *)
        # Pass-through — allows arbitrary python invocations
        exec /app/.venv/bin/python3 "$@"
        ;;
esac
