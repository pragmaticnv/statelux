"""
STATEFLUX — Daemon Log Analysis Engine
======================================
Phase 5 — AI + Evidence Engine + PCAP Analysis + Security Reporting

Normalizes syslog/charon/pluto daemon logs into structured IPsec event records:
  - IKE_SA_ESTABLISHED / IKE_SA_FAILED
  - CHILD_SA_ESTABLISHED / CHILD_SA_FAILED
  - CREATE_CHILD_SA / REKEY_ATTEMPT / REKEY_SUCCESS / REKEY_FAILURE
  - NO_PROPOSAL_CHOSEN / AUTHENTICATION_FAILURE / PROPOSAL_NEGOTIATION

Preserves exact raw log lines and links events to Evidence objects.
"""

import re
from typing import Optional, Any
from datetime import datetime, timezone

from app.models.evidence import Evidence, EvidenceType, EvidenceProvenance
from app.models.negotiation_space import ConfidenceLevel


class ParsedLogEvent:
    """A normalized event extracted from raw IPsec daemon logs."""
    def __init__(
        self,
        event_type: str,
        raw_line: str,
        line_number: int,
        timestamp: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        self.event_type = event_type
        self.raw_line = raw_line
        self.line_number = line_number
        self.timestamp = timestamp
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "line_number": self.line_number,
            "raw_line": self.raw_line,
            "timestamp": self.timestamp,
            "details": self.details,
        }


class LogAnalyzer:
    """Parses strongSwan charon and Libreswan pluto logs into structured events."""

    EVENT_PATTERNS = [
        # Rekey Failure
        (r"rekey failed|CHILD_SA rekey failed", "REKEY_FAILURE"),
        # Rekey Attempt
        (r"rekeying CHILD_SA|rekeying IKE_SA|initiating rekey", "REKEY_ATTEMPT"),
        # Rekey Success
        (r"rekey.*established|rekey.*successful", "REKEY_SUCCESS"),
        # Child SA Established
        (r"CHILD_SA.*established|CHILD_SA.*installed|IPsec SA established", "CHILD_SA_ESTABLISHED"),
        # Child SA Failed
        (r"CHILD_SA.*failed|closing old CHILD_SA.*dropped", "CHILD_SA_FAILED"),
        # IKE SA Established
        (r"IKE_SA.*established|parent SA.*established", "IKE_SA_ESTABLISHED"),
        # IKE SA Failed
        (r"IKE_SA.*failed|fatal negotiation error|connection failed", "IKE_SA_FAILED"),
        # No Proposal Chosen
        (r"NO_PROPOSAL_CHOSEN|no acceptable proposal", "NO_PROPOSAL_CHOSEN"),
        # Authentication Failure
        (r"authentication.*failed|AUTH_FAILED|verification failed", "AUTHENTICATION_FAILURE"),
        # Create Child SA
        (r"CREATE_CHILD_SA", "CREATE_CHILD_SA"),
        # Proposal Negotiation
        (r"selected proposal|parsed.*SA_INIT|received.*SA_INIT", "PROPOSAL_NEGOTIATION"),
    ]

    def parse_log_lines(
        self,
        lines: list[str],
        source_id: str = "charon.log",
        tunnel_id: Optional[str] = None,
    ) -> tuple[list[ParsedLogEvent], Evidence]:
        """Parse raw log lines and generate a linked Evidence record."""
        parsed_events: list[ParsedLogEvent] = []

        for idx, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str:
                continue

            # Extract timestamp if present [00:00.123] or standard syslog
            ts_match = re.match(r"\[(.*?)\]", line_str)
            ts_str = ts_match.group(1) if ts_match else None

            matched = False
            for pattern, ev_type in self.EVENT_PATTERNS:
                if re.search(pattern, line_str, re.IGNORECASE):
                    parsed_events.append(
                        ParsedLogEvent(
                            event_type=ev_type,
                            raw_line=line_str,
                            line_number=idx,
                            timestamp=ts_str,
                        )
                    )
                    matched = True
                    break

            if not matched and "charon:" in line_str or "pluto[" in line_str:
                parsed_events.append(
                    ParsedLogEvent(
                        event_type="DAEMON_LOG",
                        raw_line=line_str,
                        line_number=idx,
                        timestamp=ts_str,
                    )
                )

        ev_id = f"ev-log-{source_id.lower().replace('.', '-')}"
        event_types_found = list({e.event_type for e in parsed_events})

        evidence = Evidence(
            evidence_id=ev_id,
            evidence_type=EvidenceType.LOG,
            provenance=EvidenceProvenance.OBSERVED,
            source_id=source_id,
            source_path=source_id,
            source_reference=f"lines_1_to_{len(lines)}",
            tunnel_ids=[tunnel_id] if tunnel_id else [],
            content_summary=f"Log {source_id}: {len(lines)} lines parsed, events: {', '.join(event_types_found[:5])}",
            confidence=ConfidenceLevel.HIGH,
            raw_data={"events": [e.to_dict() for e in parsed_events]},
            metadata={"total_lines": len(lines), "events_detected": len(parsed_events)},
        )

        return parsed_events, evidence
