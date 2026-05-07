# =============================================================================
#  Noctis Edge — Dockerfile
#  Builds a self-contained image with all scanning tools and the offline CVE
#  database baked in.  Ollama runs as a separate sidecar container (see
#  docker-compose.yml).
#
#  Build:   docker compose build
#  Run:     docker compose up          (starts web UI on http://localhost:5000)
#  CLI:     docker compose run --rm noctis scan <target>
# =============================================================================

FROM debian:bookworm-slim

# Silence interactive apt prompts
ENV DEBIAN_FRONTEND=noninteractive

# ---------------------------------------------------------------------------
# 1. System packages
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        # Network scanning
        nmap \
        curl \
        # Web scanning dependencies (Nikto is Perl-based)
        perl \
        libnet-ssleay-perl \
        liburi-perl \
        # Python
        python3 \
        python3-pip \
        python3-venv \
        # SSH auditing
        ssh-audit \
        # DNS enumeration
        dnsenum \
        dnsrecon \
        # Password brute-forcing
        hydra \
        # General utilities
        git \
        ca-certificates \
        wget \
        tar \
        gnupg \
        # Required by some Perl modules
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# 2. Go toolchain (needed for nuclei, gobuster, ffuf)
#    Detects host architecture so the image builds on both amd64 and arm64
#    (Docker Desktop on Apple Silicon).
# ---------------------------------------------------------------------------
ENV GOROOT=/usr/local/go
ENV GOPATH=/root/go
ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin:/root/.local/bin

ARG GO_VERSION=1.26.2
RUN ARCH=$(dpkg --print-architecture) && \
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" \
        -O /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz

# ---------------------------------------------------------------------------
# 3. Go-based security tools
# ---------------------------------------------------------------------------
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/OJ/gobuster/v3@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    # Strip the module download cache — binaries are already in /root/go/bin
    rm -rf /root/go/pkg/mod /root/go/pkg/cache /root/.cache/go-build

# Pre-fetch Nuclei templates so the first scan doesn't need internet
RUN nuclei -update-templates -silent 2>/dev/null || true

# ---------------------------------------------------------------------------
# 3b. amass — DNS and attack-surface reconnaissance
#     Try go install (already have the toolchain); apt fallback for distros
#     that package it.
# ---------------------------------------------------------------------------
RUN go install -v github.com/owasp-amass/amass/v4/cmd/amass@latest 2>/dev/null || \
    apt-get install -y --no-install-recommends amass 2>/dev/null || \
    echo "[!] amass could not be installed — external recon profile will run without it"

# ---------------------------------------------------------------------------
# 3c. NetExec (nxc) — internal Active Directory enumeration
#     pipx is the only reliable cross-distro install path; try apt first
#     (available on Ubuntu 23.04+ / Debian 12+), fall back to pip.
# ---------------------------------------------------------------------------
RUN apt-get install -y --no-install-recommends libkrb5-dev 2>/dev/null || true
RUN apt-get install -y --no-install-recommends pipx 2>/dev/null || \
    pip3 install pipx --break-system-packages 2>/dev/null || \
    pip3 install pipx 2>/dev/null || true
RUN pipx ensurepath 2>/dev/null || true && \
    (pipx install netexec 2>/dev/null || \
     pipx install "git+https://github.com/Pennyw0rth/NetExec" 2>/dev/null) || \
    echo "[!] NetExec (nxc) could not be installed — internal_ad profile will not function"

# ---------------------------------------------------------------------------
# 3d. Metasploit Framework — mandatory install for offline operation.
#     Uses the official Rapid7 apt repository.
# ---------------------------------------------------------------------------
RUN curl -fsSL https://apt.metasploit.com/metasploit-framework.gpg.key \
        | gpg --dearmor -o /etc/apt/trusted.gpg.d/metasploit.gpg && \
    echo "deb [signed-by=/etc/apt/trusted.gpg.d/metasploit.gpg] https://apt.metasploit.com/ buster main" \
        > /etc/apt/sources.list.d/metasploit-framework.list && \
    apt-get update -qq && \
    apt-get install -y metasploit-framework && \
    rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# 4. Application source
# ---------------------------------------------------------------------------
WORKDIR /app
COPY . .

# ---------------------------------------------------------------------------
# 5. Nikto (clone fresh — avoids submodule state dependency)
# ---------------------------------------------------------------------------
RUN git clone --depth=1 https://github.com/sullo/nikto.git nikto

# ---------------------------------------------------------------------------
# 6. CVE offline database
#    cve-summary.csv is copied from the build context (generated by setup.sh
#    or update.sh on the host). trickest/cve-offline was retired — the CSV
#    is built locally and committed to the build context via .dockerignore
#    negation: CVE/cve-offline/ is excluded but !CVE/cve-offline/cve-summary.csv
#    is re-included.
# ---------------------------------------------------------------------------
RUN if [ -f CVE/cve-offline/cve-summary.csv ]; then \
        echo "[OK] CVE database present ($(wc -l < CVE/cve-offline/cve-summary.csv) records)"; \
    else \
        echo "[!] CVE CSV not found in build context — CVE matching will be unavailable"; \
        mkdir -p CVE/cve-offline; \
    fi

# ---------------------------------------------------------------------------
# 7. Python virtual environment + dependencies
# ---------------------------------------------------------------------------
RUN python3 -m venv .venv && \
    .venv/bin/pip install --upgrade pip --quiet && \
    .venv/bin/pip install \
        requests \
        jinja2 \
        pycryptodome \
        flask \
        flask-sock \
        --quiet

# ---------------------------------------------------------------------------
# 7b. EPSS offline database — bake daily exploit-probability scores at build
#     time so the first scan can show EPSS data without waiting for an update.
#     Best-effort: build succeeds even if the CDN is unreachable.
# ---------------------------------------------------------------------------
RUN .venv/bin/python3 scripts/build_epss_db.py || \
    echo "[!] EPSS pre-fetch failed (network unavailable at build time) — will retry at first run"

# ---------------------------------------------------------------------------
# 8. Entrypoint + runtime directories
# ---------------------------------------------------------------------------
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh && \
    mkdir -p /app/sessions /data

EXPOSE 5000

# Default: start the web UI.  Override CMD for CLI use:
#   docker compose run --rm noctis scan 192.168.0.1
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["web"]
