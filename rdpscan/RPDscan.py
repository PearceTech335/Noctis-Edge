#!/usr/bin/env python3
# Copyright (C) 2026 Pearce Technologies Pty Ltd
# SPDX-License-Identifier: AGPL-3.0-or-later
# <https://www.gnu.org/licenses/agpl-3.0.html>
"""
RPDscan.py — Noctis Edge RDP scan helper

Wraps nmap rdp-enum-encryption for use by noctis.py.
Can also be run standalone: python3 RPDscan.py <host> [port]
"""

import subprocess
import sys


def rdp_scan(host: str, port: int = 3389) -> str:
    """Run RDP enumeration against host:port using nmap scripts."""
    cmd = [
        "nmap", "-p", str(port),
        "--script", "rdp-enum-encryption",
        "-Pn", "--open", host,
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60
        )
        return result.stdout + result.stderr
    except FileNotFoundError:
        return "[ERROR] nmap not found — install nmap to use rdp_enum"
    except subprocess.TimeoutExpired:
        return "[ERROR] RDP scan timed out"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <host> [port]")
        sys.exit(1)
    target_host = sys.argv[1]
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 3389
    print(rdp_scan(target_host, target_port))
