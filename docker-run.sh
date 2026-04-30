#!/usr/bin/env bash
# =============================================================================
#  Noctis Edge — One-Shot Docker Launcher  (Linux / macOS)
#
#  Usage:
#    chmod +x docker-run.sh
#    ./docker-run.sh
#
#  What this script does:
#    1. Checks Docker is running
#    2. Pulls the latest Noctis Edge source (git pull)
#    3. Builds the Docker image
#    4. Starts the Ollama sidecar and waits for it to be healthy
#    5. Pulls the LLM model into the persistent volume (first run only)
#    6. Starts the Noctis Edge web UI
#    7. Prints the URL
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

OLLAMA_MODEL="qwen2.5-coder:3b-instruct"
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[1;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}  $*"; }
info() { echo -e "${YELLOW}[--]${NC}  $*"; }
err()  { echo -e "${RED}[!!]${NC}  $*"; }
hdr()  { echo -e "\n${CYAN}============================================================${NC}"; \
         echo -e "${CYAN}  $*${NC}"; \
         echo -e "${CYAN}============================================================${NC}"; }

# ---------------------------------------------------------------------------
# 0. Pre-flight: Docker must be running
# ---------------------------------------------------------------------------
hdr "0/5  Pre-flight checks"
if ! docker info > /dev/null 2>&1; then
    err "Docker is not running. Please start Docker Desktop and try again."
    exit 1
fi
ok "Docker is running"

# docker compose (v2) or docker-compose (v1)?
if docker compose version > /dev/null 2>&1; then
    DC="docker compose"
elif command -v docker-compose > /dev/null 2>&1; then
    DC="docker-compose"
else
    err "Neither 'docker compose' nor 'docker-compose' found. Please install Docker Desktop."
    exit 1
fi
ok "Using: $DC"

# ---------------------------------------------------------------------------
# 1. Pull latest source
# ---------------------------------------------------------------------------
hdr "1/5  Pulling latest Noctis Edge"
if git -C "$SCRIPT_DIR" rev-parse --is-inside-work-tree > /dev/null 2>&1; then
    git -C "$SCRIPT_DIR" pull --rebase origin master 2>/dev/null && ok "Source up to date" \
        || info "git pull failed (may have local changes) — continuing with current source"
else
    info "Not a git repo — skipping git pull"
fi

# ---------------------------------------------------------------------------
# 2. Build the image
# ---------------------------------------------------------------------------
hdr "2/5  Building Noctis Edge Docker image"
info "This takes ~5–10 minutes on first build (Go tools + CVE database)"
info "Subsequent builds use Docker layer cache and are much faster"
$DC build
ok "Image built"

# ---------------------------------------------------------------------------
# 3. Start Ollama sidecar
# ---------------------------------------------------------------------------
hdr "3/5  Starting Ollama"
$DC up -d ollama
info "Waiting for Ollama to become healthy ..."
WAITED=0
until $DC exec ollama curl -sf http://localhost:11434/api/tags > /dev/null 2>&1; do
    if [[ $WAITED -ge 120 ]]; then
        err "Ollama did not start within 2 minutes."
        $DC logs ollama --tail 20
        exit 1
    fi
    sleep 3
    WAITED=$((WAITED + 3))
done
ok "Ollama is ready"

# ---------------------------------------------------------------------------
# 4. Pull the LLM model (skips if already in the volume)
# ---------------------------------------------------------------------------
hdr "4/5  Pulling LLM model ($OLLAMA_MODEL)"
if $DC exec ollama ollama list 2>/dev/null | grep -q "$OLLAMA_MODEL"; then
    ok "Model already present — skipping download"
else
    info "Downloading model (~1.9 GB). This only happens once ..."
    $DC exec ollama ollama pull "$OLLAMA_MODEL"
    ok "Model downloaded"
fi

# ---------------------------------------------------------------------------
# 5. Start Noctis Edge
# ---------------------------------------------------------------------------
hdr "5/5  Starting Noctis Edge Web UI"
$DC up -d noctis
ok "Noctis Edge is running"

echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  Noctis Edge is ready!${NC}"
echo -e "${GREEN}  Open your browser: http://localhost:5000${NC}"
echo ""
echo -e "  Stop:    ${YELLOW}$DC down${NC}"
echo -e "  Logs:    ${YELLOW}$DC logs -f noctis${NC}"
echo -e "  CLI:     ${YELLOW}$DC run --rm noctis scan <target>${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
