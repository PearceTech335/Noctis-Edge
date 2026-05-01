#!/usr/bin/env bash
# =============================================================================
#  Noctis Edge — One-Shot Docker Test
#
#  Builds the full Docker stack, runs an unattended scan against localhost,
#  and tears everything down.  Use this to verify a clean Docker install.
#
#  Usage:
#    chmod +x docker-test.sh
#    ./docker-test.sh
#
#  Exit codes:
#    0 — build + scan completed successfully
#    1 — pre-flight, build, or scan failure
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# LLM models used during the test scan (must match docker-compose.yml)
OLLAMA_MODEL="${NOCTIS_OLLAMA_MODEL:-qwen2.5-coder:3b-instruct}"
REPORT_MODEL="${NOCTIS_REPORT_MODEL:-llama3.2:3b}"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[1;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}  $*"; }
info() { echo -e "${YELLOW}[--]${NC}  $*"; }
err()  { echo -e "${RED}[!!]${NC}  $*"; }
hdr()  { echo -e "\n${CYAN}============================================================${NC}"; \
         echo -e "${CYAN}  $*${NC}"; \
         echo -e "${CYAN}============================================================${NC}"; }

# Track whether we started containers so we can always clean up
CONTAINERS_STARTED=0

cleanup() {
    if [[ $CONTAINERS_STARTED -eq 1 ]]; then
        echo ""
        info "Tearing down test containers ..."
        $DC down --remove-orphans 2>/dev/null || true
        ok "Containers removed"
    fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 0. Pre-flight
# ---------------------------------------------------------------------------
hdr "0/6  Pre-flight checks"

if ! docker info > /dev/null 2>&1; then
    err "Docker is not running. Start Docker Desktop and try again."
    exit 1
fi
ok "Docker is running"

if docker compose version > /dev/null 2>&1; then
    DC="docker compose"
elif command -v docker-compose > /dev/null 2>&1; then
    DC="docker-compose"
else
    err "Neither 'docker compose' nor 'docker-compose' found."
    exit 1
fi
ok "Compose: $DC"

# ---------------------------------------------------------------------------
# 1. Build the image
# ---------------------------------------------------------------------------
hdr "1/6  Building Noctis Edge image"
info "First build takes ~5–10 min (Go toolchain + CVE DB). Cached builds are fast."
$DC build
ok "Image built"

# ---------------------------------------------------------------------------
# 2. Start Ollama
# ---------------------------------------------------------------------------
hdr "2/6  Starting Ollama sidecar"
$DC up -d ollama
CONTAINERS_STARTED=1

info "Waiting for Ollama health check ..."
WAITED=0
until $DC exec -T ollama curl -sf http://localhost:11434/api/tags > /dev/null 2>&1; do
    if [[ $WAITED -ge 120 ]]; then
        err "Ollama did not become healthy within 2 minutes."
        $DC logs ollama --tail 30
        exit 1
    fi
    sleep 3
    WAITED=$((WAITED + 3))
done
ok "Ollama ready"

# ---------------------------------------------------------------------------
# 3. Pull required models (skip if already in volume)
# ---------------------------------------------------------------------------
hdr "3/6  Ensuring LLM models are present"

for MODEL in "$OLLAMA_MODEL" "$REPORT_MODEL"; do
    if $DC exec -T ollama ollama list 2>/dev/null | grep -q "^${MODEL%:*}"; then
        ok "${MODEL} already present"
    else
        info "Pulling ${MODEL} ..."
        $DC exec -T ollama ollama pull "$MODEL"
        ok "${MODEL} pulled"
    fi
done

# ---------------------------------------------------------------------------
# 4. Run a test scan (unattended, no browser needed)
# ---------------------------------------------------------------------------
hdr "4/6  Running test scan against localhost"
info "Flags: --aggressive --cve-test --unattended"
info "Scan output will stream below — this takes a few minutes."
echo ""

# Run the scan and capture exit code without triggering set -e
$DC run --rm \
    -e NOCTIS_OLLAMA_URL=http://ollama:11434/api/generate \
    -e NOCTIS_OLLAMA_MODEL="$OLLAMA_MODEL" \
    -e NOCTIS_REPORT_MODEL="$REPORT_MODEL" \
    noctis scan localhost --aggressive --cve-test --unattended \
    && SCAN_EXIT=0 || SCAN_EXIT=$?

echo ""

# ---------------------------------------------------------------------------
# 5. Report results
# ---------------------------------------------------------------------------
hdr "5/6  Scan result"
if [[ $SCAN_EXIT -eq 0 ]]; then
    ok "Scan completed successfully (exit 0)"
else
    err "Scan exited with code ${SCAN_EXIT}"
fi

# ---------------------------------------------------------------------------
# 6. Summary
# ---------------------------------------------------------------------------
hdr "6/6  Done"
if [[ $SCAN_EXIT -eq 0 ]]; then
    echo -e "${GREEN}  All checks passed — Docker install is working correctly.${NC}"
    echo ""
    echo -e "  To start the persistent Web UI run:"
    echo -e "    ${YELLOW}./docker-run.sh${NC}"
    echo ""
else
    echo -e "${RED}  Test scan failed (exit ${SCAN_EXIT}).${NC}"
    echo -e "  Check the output above for errors."
    echo ""
    exit 1
fi
