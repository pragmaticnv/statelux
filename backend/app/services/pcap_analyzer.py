"""
STATEFLUX — PCAP Analysis Engine
================================
Phase 5 — AI + Evidence Engine + PCAP Analysis + Security Reporting

Safe, local PCAP analysis service.
Parses libpcap captures using a robust, self-contained binary packet parser:
  - Extracts network flow metadata (IPs, ports, packet counts, byte volumes, duration)
  - Detects IPsec protocols: IKE (UDP 500/4500), ESP (protocol 50), AH (protocol 51)
  - Identifies IKEv2 exchange indicators (IKE_SA_INIT, IKE_AUTH, CREATE_CHILD_SA)
  - Emits structured TrafficObservations and Evidence objects
  - Strictly preserves encryption boundaries: NEVER claims to decrypt encrypted payloads
  - Handles empty, truncated, or malformed files gracefully
"""

import struct
import socket
from pathlib import Path
from typing import Optional, Any
from datetime import datetime, timezone

from app.models.evidence import Evidence, EvidenceType, EvidenceProvenance
from app.models.traffic_observation import TrafficObservation, TrafficObservationType
from app.models.negotiation_space import ConfidenceLevel


class PCAPAnalyzer:
    """Pure-Python libpcap packet parser and IPsec metadata extractor."""

    @staticmethod
    def _ip_to_str(ip_bytes: bytes) -> str:
        try:
            return socket.inet_ntoa(ip_bytes)
        except Exception:
            return "0.0.0.0"

    def analyze_pcap_file(
        self,
        pcap_path: str,
        tunnel_id: Optional[str] = None,
    ) -> tuple[list[TrafficObservation], list[Evidence], dict[str, Any]]:
        """Parse a PCAP file and produce TrafficObservations and Evidence records."""
        path = Path(pcap_path)
        if not path.exists():
            # Return empty if file does not exist
            return [], [], {"error": f"File not found: {pcap_path}", "packet_count": 0}

        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception as exc:
            return [], [], {"error": f"Read error: {str(exc)}", "packet_count": 0}

        return self.analyze_pcap_bytes(data, source_name=path.name, tunnel_id=tunnel_id)

    def analyze_pcap_bytes(
        self,
        data: bytes,
        source_name: str = "capture.pcap",
        tunnel_id: Optional[str] = None,
    ) -> tuple[list[TrafficObservation], list[Evidence], dict[str, Any]]:
        """Parse raw PCAP bytes into structured observations and evidence."""
        observations: list[TrafficObservation] = []
        evidence_items: list[Evidence] = []

        summary_meta: dict[str, Any] = {
            "source_name": source_name,
            "packet_count": 0,
            "total_bytes": len(data),
            "ike_packets": 0,
            "esp_packets": 0,
            "ah_packets": 0,
            "other_packets": 0,
            "first_seen": None,
            "last_seen": None,
            "endpoints": set(),
            "exchanges_seen": set(),
        }

        # Check minimal PCAP global header length (24 bytes)
        if len(data) < 24:
            return observations, evidence_items, {
                "source_name": source_name,
                "packet_count": 0,
                "status": "EMPTY_OR_TRUNCATED",
                "notes": "Capture contains fewer than 24 bytes; no global header found.",
            }

        # Validate magic number
        magic = struct.unpack("<I", data[:4])[0]
        little_endian = True
        if magic == 0xA1B2C3D4:
            little_endian = True
        elif magic == 0xD4C3B2A1:
            little_endian = False
        else:
            # Not a standard PCAP file
            return observations, evidence_items, {
                "source_name": source_name,
                "packet_count": 0,
                "status": "MALFORMED_HEADER",
                "notes": f"Invalid PCAP magic number: {hex(magic)}",
            }

        endian = "<" if little_endian else ">"
        offset = 24
        packet_idx = 0
        first_ts: Optional[float] = None
        last_ts: Optional[float] = None

        flows: dict[str, dict[str, Any]] = {}

        while offset + 16 <= len(data):
            packet_idx += 1
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                f"{endian}IIII", data[offset:offset + 16]
            )
            offset += 16

            pkt_ts = ts_sec + (ts_usec / 1_000_000.0)
            if first_ts is None or pkt_ts < first_ts:
                first_ts = pkt_ts
            if last_ts is None or pkt_ts > last_ts:
                last_ts = pkt_ts

            pkt_data = data[offset:offset + incl_len]
            offset += incl_len

            if len(pkt_data) < 14:
                # Truncated ethernet frame
                continue

            # Parse Ethernet (14 bytes)
            eth_type = struct.unpack("!H", pkt_data[12:14])[0]

            if eth_type == 0x0800 and len(pkt_data) >= 34:  # IPv4
                ip_header = pkt_data[14:]
                ihl = (ip_header[0] & 0x0F) * 4
                proto = ip_header[9]
                src_ip = self._ip_to_str(ip_header[12:16])
                dst_ip = self._ip_to_str(ip_header[16:20])
                summary_meta["endpoints"].add(src_ip)
                summary_meta["endpoints"].add(dst_ip)

                ip_payload = ip_header[ihl:]

                if proto == 50:  # ESP
                    summary_meta["esp_packets"] += 1
                    spi = struct.unpack("!I", ip_payload[:4])[0] if len(ip_payload) >= 4 else 0
                    flow_key = f"ESP:{src_ip}->{dst_ip}:SPI_{hex(spi)}"
                    if flow_key not in flows:
                        flows[flow_key] = {
                            "proto": "ESP",
                            "src": src_ip,
                            "dst": dst_ip,
                            "packets": 0,
                            "bytes": 0,
                            "spi": hex(spi),
                        }
                    flows[flow_key]["packets"] += 1
                    flows[flow_key]["bytes"] += incl_len

                elif proto == 51:  # AH
                    summary_meta["ah_packets"] += 1
                    flow_key = f"AH:{src_ip}->{dst_ip}"
                    if flow_key not in flows:
                        flows[flow_key] = {
                            "proto": "AH",
                            "src": src_ip,
                            "dst": dst_ip,
                            "packets": 0,
                            "bytes": 0,
                        }
                    flows[flow_key]["packets"] += 1
                    flows[flow_key]["bytes"] += incl_len

                elif proto == 17 and len(ip_payload) >= 8:  # UDP
                    src_port, dst_port = struct.unpack("!HH", ip_payload[:4])
                    udp_payload = ip_payload[8:]

                    if src_port in (500, 4500) or dst_port in (500, 4500):
                        summary_meta["ike_packets"] += 1
                        # If port 4500, check for Non-ESP Marker (4 zero bytes)
                        ike_data = udp_payload
                        if len(udp_payload) >= 4 and udp_payload[:4] == b"\x00\x00\x00\x00":
                            ike_data = udp_payload[4:]

                        exchange_name = "IKE_EXCHANGE"
                        if len(ike_data) >= 28:
                            # IKE Header: Exchange type is byte at index 18
                            exch_type = ike_data[18]
                            exchange_map = {
                                34: "IKE_SA_INIT",
                                35: "IKE_AUTH",
                                36: "CREATE_CHILD_SA",
                                37: "INFORMATIONAL",
                            }
                            exchange_name = exchange_map.get(exch_type, f"IKE_EXCHANGE_{exch_type}")
                            summary_meta["exchanges_seen"].add(exchange_name)

                        flow_key = f"IKE:{src_ip}:{src_port}->{dst_ip}:{dst_port}"
                        if flow_key not in flows:
                            flows[flow_key] = {
                                "proto": "IKE",
                                "src": f"{src_ip}:{src_port}",
                                "dst": f"{dst_ip}:{dst_port}",
                                "packets": 0,
                                "bytes": 0,
                                "exchanges": set(),
                            }
                        flows[flow_key]["packets"] += 1
                        flows[flow_key]["bytes"] += incl_len
                        flows[flow_key]["exchanges"].add(exchange_name)
                    else:
                        summary_meta["other_packets"] += 1
                else:
                    summary_meta["other_packets"] += 1
            else:
                summary_meta["other_packets"] += 1

        summary_meta["packet_count"] = packet_idx
        summary_meta["duration_seconds"] = (last_ts - first_ts) if (last_ts and first_ts) else 0.0
        summary_meta["endpoints"] = sorted(list(summary_meta["endpoints"]))
        summary_meta["exchanges_seen"] = sorted(list(summary_meta["exchanges_seen"]))

        # Build Primary PCAP Evidence record
        ev_id = f"ev-pcap-{source_name.lower().replace('.', '-')}"
        pcap_evidence = Evidence(
            evidence_id=ev_id,
            evidence_type=EvidenceType.PCAP,
            provenance=EvidenceProvenance.OBSERVED,
            source_id=source_name,
            source_path=source_name,
            source_reference=f"packets_1_to_{packet_idx}",
            tunnel_ids=[tunnel_id] if tunnel_id else [],
            content_summary=(
                f"PCAP {source_name}: {packet_idx} packets parsed. "
                f"IKE={summary_meta['ike_packets']}, ESP={summary_meta['esp_packets']}, AH={summary_meta['ah_packets']}."
            ),
            confidence=ConfidenceLevel.HIGH,
            metadata=summary_meta,
        )
        evidence_items.append(pcap_evidence)

        # Build Observations from aggregated flows
        obs_idx = 1
        for key, flow in flows.items():
            proto = flow["proto"]
            obs_type = (
                TrafficObservationType.ESP_METADATA_OBSERVED
                if proto == "ESP"
                else (
                    TrafficObservationType.IKE_METADATA_OBSERVED
                    if proto == "IKE"
                    else TrafficObservationType.AH_METADATA_OBSERVED
                )
            )

            obs = TrafficObservation(
                observation_id=f"obs-pcap-{source_name[:8]}-{obs_idx:03d}",
                evidence_id=ev_id,
                tunnel_id=tunnel_id,
                protocol=proto,
                observation_type=obs_type,
                timestamp=datetime.now(timezone.utc),
                source=flow["src"],
                destination=flow["dst"],
                packet_count=flow["packets"],
                byte_count=flow["bytes"],
                duration_seconds=summary_meta["duration_seconds"],
                confidence=ConfidenceLevel.HIGH,
                observed=True,
                metadata={
                    "flow_key": key,
                    "exchanges": list(flow.get("exchanges", [])),
                    "spi": flow.get("spi"),
                },
            )
            observations.append(obs)
            pcap_evidence.observation_ids.append(obs.observation_id)
            obs_idx += 1

        return observations, evidence_items, summary_meta
