#!/bin/bash
# PACT v0.3 — RISC Zero Prover Installation
# Installs the RISC Zero toolchain and builds the guest program.
set -e
cd "$(dirname "$0")"

echo "[setup-risc0] Installing RISC Zero toolchain..."
if [ -d "$HOME/.risc0" ]; then
    echo "[setup-risc0] Already installed at ~/.risc0"
else
    curl -fsSL https://risczero.com/install.sh 2>&1 | bash
    source "$HOME/.risc0/env" 2>/dev/null || export PATH="$HOME/.risc0/bin:$PATH"
fi

# Ensure risc0 tools are on PATH
export PATH="$HOME/.risc0/bin:$PATH"

echo "[setup-risc0] Checking RISC Zero installation..."
if command -v rz &>/dev/null; then
    echo "[setup-risc0] rz found: $(rz --version 2>&1 | head -1)"
else
    echo "[setup-risc0] ERROR: rz not found after install"
    exit 1
fi

echo "[setup-risc0] Building guest program..."
cd guest
cargo build --release 2>&1

GUEST_BIN="$(pwd)/target/release/pact-guest"
if [ -f "$GUEST_BIN" ]; then
    echo "[setup-risc0] Guest binary built: $GUEST_BIN"
    # Write location to ../python/pact/risc0_guest_bin.txt for zk_host.py to read
    echo "$GUEST_BIN" > ../python/pact/risc0_guest_bin.txt
    echo "[setup-risc0] Prover path written to python/pact/risc0_guest_bin.txt"
else
    echo "[setup-risc0] ERROR: guest binary not found after build"
    exit 1
fi

echo "[setup-risc0] Done."
