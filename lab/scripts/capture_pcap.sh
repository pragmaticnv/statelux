#!/usr/bin/env bash
# STATEFLUX — Capture PCAP Artifacts during Controlled Lab Runs
# Usage: ./capture_pcap.sh [interface] [duration_seconds] [output_filename]

set -euo pipefail

INTERFACE="${1:-eth0}"
DURATION="${2:-10}"
OUTPUT_FILE="${3:-/captures/negotiation.pcap}"

echo "Starting packet capture on ${INTERFACE} for ${DURATION}s -> ${OUTPUT_FILE}"

if command -v tshark &> /dev/null; then
    tshark -i "${INTERFACE}" -f "udp port 500 or udp port 4500 or esp" -a duration:"${DURATION}" -w "${OUTPUT_FILE}"
elif command -v tcpdump &> /dev/null; then
    timeout "${DURATION}" tcpdump -i "${INTERFACE}" -w "${OUTPUT_FILE}" "udp port 500 or udp port 4500 or esp" || true
else
    echo "Neither tshark nor tcpdump available in container."
    exit 1
fi

echo "Capture complete: ${OUTPUT_FILE}"
