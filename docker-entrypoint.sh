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
# Generate noctis.conf if not present
# A named Docker volume keeps this persistent across container restarts.
# ---------------------------------------------------------------------------
if [[ ! -f "$CONF_FILE" ]]; then
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
# ↑ Paste your Polar.sh license key here to enable the community CVE KB download.
#   Subscribe at: https://buy.polar.sh/polar_cl_rEP2IebC07PDSnIal0HF4kZSBJVecdZSmkREx3Emnin
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
