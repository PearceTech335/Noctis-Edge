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

OLLAMA_MODEL="qwen2.5-coder:3b-instruct"    # planning + scan decisions (NOCTIS_OLLAMA_MODEL)
SCRIPT_MODEL="qwen2.5-coder:3b-instruct"    # CVE scripts + tool scripts (NOCTIS_OLLAMA_SCRIPT_MODEL)
REPORT_MODEL="qwen3:8b"                     # narrative prose: conclusion, attacker perspective, remediation (NOCTIS_OLLAMA_REPORT_MODEL)
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

# Minimum free disk space required (GB): Ollama image ~2.5 GB + two models ~4 GB + headroom
MIN_FREE_GB=8
# macOS df uses 512-byte blocks by default; Linux df uses 1 KB blocks.
# -k forces 1 KB blocks on both platforms; column 4 is available space.
FREE_KB=$(df -k / | awk 'NR==2 {print $4}')
FREE_GB=$(( FREE_KB / 1024 / 1024 ))
if [[ $FREE_GB -lt $MIN_FREE_GB ]]; then
    err "Insufficient disk space: ${FREE_GB} GB free, need at least ${MIN_FREE_GB} GB."
    err "Free up disk space and try again."
    exit 1
fi
ok "Disk space: ${FREE_GB} GB free"

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
# 1. Pull latest source — record HEAD before/after to detect new commits
# ---------------------------------------------------------------------------
hdr "1/5  Pulling latest Noctis Edge"
GIT_BEFORE=""
GIT_AFTER=""
if git -C "$SCRIPT_DIR" rev-parse --is-inside-work-tree > /dev/null 2>&1; then
    GIT_BEFORE=$(git -C "$SCRIPT_DIR" rev-parse HEAD 2>/dev/null || true)
    git -C "$SCRIPT_DIR" pull --rebase origin master 2>/dev/null && ok "Source up to date" \
        || info "git pull failed (may have local changes) — continuing with current source"
    GIT_AFTER=$(git -C "$SCRIPT_DIR" rev-parse HEAD 2>/dev/null || true)
else
    info "Not a git repo — skipping git pull"
fi

# ---------------------------------------------------------------------------
# 2. Build the image — only when necessary
#    * First run  : image does not exist yet          → build
#    * After pull : git HEAD changed                  → rebuild for new code
#    * No changes : same HEAD, image already exists   → skip (saves ~10 min)
#    * --rebuild  : force a full rebuild              → ./docker-run.sh --rebuild
# ---------------------------------------------------------------------------
hdr "2/5  Building Noctis Edge Docker image"
FORCE_REBUILD=false
[[ "${1:-}" == "--rebuild" ]] && FORCE_REBUILD=true
IMAGE_EXISTS=false
docker image inspect noctis-edge:latest > /dev/null 2>&1 && IMAGE_EXISTS=true
CODE_CHANGED=false
[[ -n "$GIT_BEFORE" && -n "$GIT_AFTER" && "$GIT_BEFORE" != "$GIT_AFTER" ]] && CODE_CHANGED=true

if $FORCE_REBUILD || ! $IMAGE_EXISTS || $CODE_CHANGED; then
    if ! $IMAGE_EXISTS; then
        info "First run — building Docker image (~10 min; only happens once)"
    elif $CODE_CHANGED; then
        info "Source updated ($GIT_BEFORE → $GIT_AFTER) — rebuilding image"
    else
        info "Forced rebuild requested"
    fi
    $DC build
    ok "Image built"
else
    ok "Image is up to date — skipping rebuild"
    info "To force a rebuild: ./docker-run.sh --rebuild"
fi

# ---------------------------------------------------------------------------
# 3. Start Ollama sidecar
# ---------------------------------------------------------------------------
hdr "3/5  Starting Ollama"
$DC up -d ollama
info "Waiting for Ollama to become healthy ..."
WAITED=0
until $DC exec -T ollama bash -c '</dev/tcp/localhost/11434' 2>/dev/null; do
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
# 4. Pull required LLM models (skips models already in the volume)
# ---------------------------------------------------------------------------
hdr "4/5  Pulling LLM models"
for MODEL in "$OLLAMA_MODEL" "$SCRIPT_MODEL" "$REPORT_MODEL"; do
    if $DC exec -T ollama ollama list 2>/dev/null | grep -qF "$MODEL"; then
        ok "${MODEL} already present — skipping download"
    else
        info "Downloading ${MODEL}. This only happens once ..."
        $DC exec -T ollama ollama pull "$MODEL"
        ok "${MODEL} downloaded"
    fi
done

# ---------------------------------------------------------------------------
# 5. Start Noctis Edge
# ---------------------------------------------------------------------------
hdr "5/5  Starting Noctis Edge Web UI"
# Ensure host-side JSON files exist as files before bind-mounting.
# If absent, Docker would auto-create them as directories instead of files,
# which causes "device or resource busy" errors on macOS at container start.
for f in cve_knowledge_base.json tool_knowledge_base.json nuclei_kb.json tool_manifest.json; do
    [[ -f "$SCRIPT_DIR/$f" ]] || { printf '{}' > "$SCRIPT_DIR/$f"; info "Created placeholder: $f"; }
done
# noctis.conf is generated by the entrypoint on first run; just ensure the inode exists.
[[ -f "$SCRIPT_DIR/noctis.conf" ]] || touch "$SCRIPT_DIR/noctis.conf"
$DC up -d noctis
ok "Noctis Edge is running"

echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  Noctis Edge is ready!${NC}"
echo -e "${GREEN}  Open your browser: http://localhost:8888${NC}"
echo ""
echo -e "  Stop:    ${YELLOW}$DC down${NC}"
echo -e "  Logs:    ${YELLOW}$DC logs -f noctis${NC}"
echo -e "  CLI:     ${YELLOW}$DC run --rm noctis scan <target>${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
