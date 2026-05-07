# =============================================================================
#  Noctis Edge -- One-Shot Docker Launcher  (Windows PowerShell)
#
#  Usage (run from the Noctis-Edge directory):
#    .\docker-run.ps1
#
#  Requirements:
#    - Docker Desktop for Windows (with WSL2 backend recommended)
#    - PowerShell 5.1+ or PowerShell 7+
#
#  What this script does:
#    1. Checks Docker Desktop is running
#    2. Pulls the latest Noctis Edge source (git pull)
#    3. Builds the Docker image
#    4. Starts the Ollama sidecar and waits for it to be healthy
#    5. Pulls the LLM model into the persistent volume (first run only)
#    6. Starts the Noctis Edge web UI
#    7. Opens the browser
# =============================================================================

$ErrorActionPreference = "Stop"

$OLLAMA_MODEL  = "gemma3:4b"                    # planning + reasoning (NOCTIS_OLLAMA_MODEL)
$SCRIPT_MODEL  = "qwen2.5-coder:3b-instruct"   # CVE scripts + tool scripts (NOCTIS_OLLAMA_SCRIPT_MODEL)
$REPORT_MODEL  = "gemma3:4b"                   # narrative prose: conclusion, attacker perspective, remediation (NOCTIS_OLLAMA_REPORT_MODEL)
$SCRIPT_DIR    = Split-Path -Parent $MyInvocation.MyCommand.Definition

function Write-Header($msg) {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  $msg" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
}
function Write-Ok($msg)   { Write-Host "[OK]  $msg" -ForegroundColor Green  }
function Write-Info($msg) { Write-Host "[--]  $msg" -ForegroundColor Yellow }
function Write-Err($msg)  { Write-Host "[!!]  $msg" -ForegroundColor Red    }

Set-Location $SCRIPT_DIR

# ---------------------------------------------------------------------------
# 0. Pre-flight: Docker must be running
# ---------------------------------------------------------------------------
Write-Header "0/5  Pre-flight checks"
try {
    docker info > $null 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Docker not ready" }
    Write-Ok "Docker is running"
} catch {
    Write-Err "Docker Desktop is not running. Please start it and try again."
    exit 1
}

# Prefer 'docker compose' (v2) over legacy 'docker-compose'
$dc_cmd = "docker"
$dc_args_prefix = @("compose")
try {
    docker compose version > $null 2>&1
    Write-Ok "Using: docker compose (v2)"
} catch {
    $dc_cmd = "docker-compose"
    $dc_args_prefix = @()
    Write-Info "Falling back to: docker-compose (v1)"
}

function Invoke-DC {
    param([string[]]$ArgList)
    & $dc_cmd ($dc_args_prefix + $ArgList)
}

# ---------------------------------------------------------------------------
# 1. Pull latest source
# ---------------------------------------------------------------------------
Write-Header "1/5  Pulling latest Noctis Edge"
try {
    $gitStatus = git -C $SCRIPT_DIR rev-parse --is-inside-work-tree 2>&1
    if ($LASTEXITCODE -eq 0) {
        git -C $SCRIPT_DIR pull --rebase origin master 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Ok "Source up to date" }
        else { Write-Info "git pull failed (may have local changes) -- continuing" }
    }
} catch {
    Write-Info "git not found or not a repo -- skipping git pull"
}

# ---------------------------------------------------------------------------
# 2. Build the image
# ---------------------------------------------------------------------------
Write-Header "2/5  Building Noctis Edge Docker image"
Write-Info "This takes ~5-10 minutes on first build (Go tools + CVE database)"
Write-Info "Subsequent builds use Docker layer cache and are much faster"
Invoke-DC @("build")
if ($LASTEXITCODE -ne 0) { Write-Err "Build failed."; exit 1 }
Write-Ok "Image built"

# ---------------------------------------------------------------------------
# 3. Start Ollama sidecar
# ---------------------------------------------------------------------------
Write-Header "3/5  Starting Ollama"
Invoke-DC @("up", "-d", "ollama")
Write-Info "Waiting for Ollama to become healthy ..."
$waited = 0
$ready  = $false
while ($waited -lt 120) {
    try {
        Invoke-DC @("exec", "-T", "ollama", "bash", "-c", "</dev/tcp/localhost/11434") 2>$null
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
    } catch {}
    Start-Sleep -Seconds 3
    $waited += 3
}
if (-not $ready) {
    Write-Err "Ollama did not start within 2 minutes."
    Invoke-DC @("logs", "ollama", "--tail", "20")
    exit 1
}
Write-Ok "Ollama is ready"

# ---------------------------------------------------------------------------
# 4. Pull required LLM models (skips models already in the volume)
# ---------------------------------------------------------------------------
Write-Header "4/5  Pulling LLM models"
$modelList = Invoke-DC @("exec", "-T", "ollama", "ollama", "list") 2>&1
foreach ($MODEL in @($OLLAMA_MODEL, $SCRIPT_MODEL, $REPORT_MODEL) | Select-Object -Unique) {
    if ($modelList -match [regex]::Escape($MODEL)) {
        Write-Ok "${MODEL} already present -- skipping download"
    } else {
        Write-Info "Downloading ${MODEL}. This only happens once ..."
        Invoke-DC @("exec", "-T", "ollama", "ollama", "pull", $MODEL)
        Write-Ok "${MODEL} downloaded"
    }
}

# ---------------------------------------------------------------------------
# 5. Start Noctis Edge
# ---------------------------------------------------------------------------
Write-Header "5/5  Starting Noctis Edge Web UI"
Invoke-DC @("up", "-d", "noctis")
Write-Ok "Noctis Edge is running"

# Open browser automatically
Start-Process "http://localhost:5000"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Noctis Edge is ready!" -ForegroundColor Green
Write-Host "  Browser opened: http://localhost:5000" -ForegroundColor Green
Write-Host ""
Write-Host "  Stop:    docker compose down" -ForegroundColor Yellow
Write-Host "  Logs:    docker compose logs -f noctis" -ForegroundColor Yellow
Write-Host "  CLI:     docker compose run --rm noctis scan <target>" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
