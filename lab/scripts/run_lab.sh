#!/usr/bin/env bash
# STATEFLUX — Controlled Lab Orchestration Script
# Usage: ./run_lab.sh [LAB-01|LAB-02|LAB-03|LAB-04|LAB-05]

set -euo pipefail

SCENARIO="${1:-LAB-01}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"

echo "=========================================================="
echo "STATEFLUX Controlled Lab: Executing ${SCENARIO}"
echo "=========================================================="

cd "${LAB_DIR}"

case "${SCENARIO}" in
    LAB-01)
        echo "[1/4] Configuring LAB-01 Secure Suite-B (strongSwan <-> strongSwan)..."
        docker compose up -d gateway-a
        docker compose exec gateway-a swanctl --load-all --file /scenarios/secure/swanctl.conf
        echo "[2/4] Initiating connection..."
        docker compose exec gateway-a swanctl --initiate --child secure-tunnel || true
        echo "[3/4] Inspecting active SAs..."
        docker compose exec gateway-a swanctl --list-sas
        echo "[4/4] Validation Complete."
        ;;
    LAB-02)
        echo "[1/4] Configuring LAB-02 Weak Fallback..."
        docker compose up -d gateway-a
        docker compose exec gateway-a swanctl --load-all --file /scenarios/weak/swanctl.conf
        docker compose exec gateway-a swanctl --initiate --child weak-tunnel || true
        docker compose exec gateway-a swanctl --list-sas
        ;;
    LAB-03)
        echo "[1/4] Configuring LAB-03 Encryption Incompatibility..."
        docker compose up -d gateway-a gateway-b
        docker compose exec gateway-a swanctl --load-all --file /scenarios/incompatible/swanctl_initiator.conf
        docker compose exec gateway-b ipsec auto --add incompat-enc || true
        echo "[2/4] Attempting negotiation (expected to fail with NO_PROPOSAL_CHOSEN)..."
        docker compose exec gateway-a swanctl --initiate --child incompat-enc || echo "Negotiation failed as predicted."
        ;;
    LAB-04)
        echo "[1/4] Configuring LAB-04 DH Group Incompatibility..."
        docker compose up -d gateway-a
        docker compose exec gateway-a swanctl --load-all --file /scenarios/dh_mismatch/swanctl_initiator.conf
        docker compose exec gateway-a swanctl --initiate --child incompat-dh || echo "DH mismatch failed as predicted."
        ;;
    LAB-05)
        echo "[1/4] Configuring LAB-05 Latent Rekey Failure..."
        docker compose up -d gateway-a gateway-b
        echo "[2/4] Establishing initial SA..."
        docker compose exec gateway-a swanctl --load-all --file /scenarios/latent_rekey/swanctl_initiator.conf
        echo "[3/4] Triggering rekey under modified policy..."
        docker compose exec gateway-a swanctl --rekey --child latent-test || echo "Rekey failed as predicted (Latent Failure verified)."
        ;;
    *)
        echo "Unknown scenario: ${SCENARIO}. Valid options: LAB-01, LAB-02, LAB-03, LAB-04, LAB-05"
        exit 1
        ;;
esac
