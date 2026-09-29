"""
STATEFLUX — Shared Enumerations and Base Model
================================================
All canonical enums used across the STATEFLUX data model.
These are the controlled vocabularies for every field that
admits a finite set of valid values.

DO NOT add business logic here.
DO NOT add security rules here.
This module is pure type definitions.
"""

from enum import Enum
from pydantic import BaseModel, ConfigDict


# ---------------------------------------------------------------------------
# Protocol Layer
# ---------------------------------------------------------------------------

class Protocol(str, Enum):
    """IPsec protocol a Proposal belongs to."""
    IKE = "IKE"
    ESP = "ESP"
    AH = "AH"


class IKEVersion(str, Enum):
    """IKE protocol version."""
    V1 = "IKEv1"
    V2 = "IKEv2"


# ---------------------------------------------------------------------------
# Cryptographic Algorithms
# ---------------------------------------------------------------------------

class EncryptionAlgorithm(str, Enum):
    """Supported encryption algorithms.
    AEAD algorithms (GCM variants) provide both confidentiality and integrity.
    Non-AEAD algorithms (CBC, 3DES) require a separate integrity algorithm.
    """
    AES_256_GCM = "AES-256-GCM"
    AES_256_CBC = "AES-256-CBC"
    AES_128_GCM = "AES-128-GCM"
    AES_128_CBC = "AES-128-CBC"
    TDES        = "3DES"


class IntegrityAlgorithm(str, Enum):
    """HMAC-based integrity / authentication algorithms."""
    SHA512 = "HMAC-SHA-512"
    SHA384 = "HMAC-SHA-384"
    SHA256 = "HMAC-SHA-256"
    SHA1   = "HMAC-SHA-1"


class PRFAlgorithm(str, Enum):
    """Pseudo-Random Function — IKE only, not used in ESP."""
    PRF_HMAC_SHA512 = "PRF-HMAC-SHA-512"
    PRF_HMAC_SHA384 = "PRF-HMAC-SHA-384"
    PRF_HMAC_SHA256 = "PRF-HMAC-SHA-256"
    PRF_HMAC_SHA1   = "PRF-HMAC-SHA-1"


# ---------------------------------------------------------------------------
# Tunnel and SA State
# ---------------------------------------------------------------------------

class TunnelMode(str, Enum):
    """IPsec encapsulation mode."""
    TUNNEL    = "TUNNEL"
    TRANSPORT = "TRANSPORT"


class TunnelStatus(str, Enum):
    """Observed operational status of an IPsec tunnel."""
    UP       = "UP"
    DOWN     = "DOWN"
    DEGRADED = "DEGRADED"
    UNKNOWN  = "UNKNOWN"


class NegotiationStatus(str, Enum):
    """Result of an IKE negotiation attempt."""
    SUCCESS = "SUCCESS"
    FAILED  = "FAILED"
    UNKNOWN = "UNKNOWN"


# ---------------------------------------------------------------------------
# Endpoint Classification
# ---------------------------------------------------------------------------

class ProfileType(str, Enum):
    """Broad operational profile category for an endpoint."""
    HIGH_SECURITY = "HIGH_SECURITY"
    MODERN_STRONG = "MODERN_STRONG"
    ENTERPRISE    = "ENTERPRISE"
    LEGACY        = "LEGACY"
    RESTRICTED    = "RESTRICTED"


class SelectionPreference(str, Enum):
    """How an endpoint orders or selects from its proposal list."""
    STRONGEST_FIRST  = "STRONGEST_FIRST"
    ORDERED_PRIORITY = "ORDERED_PRIORITY"
    VENDOR_DEFAULT   = "VENDOR_DEFAULT"
    UNKNOWN          = "UNKNOWN"


class ValidationStatus(str, Enum):
    """Confidence level in the accuracy of an endpoint profile.

    VALIDATED means the profile has been confirmed against real vendor
    documentation or lab testing.
    UNVALIDATED_PROFILE means the profile is a synthetic approximation
    and MUST NOT be presented as a real-world vendor claim.
    """
    VALIDATED            = "VALIDATED"
    UNVALIDATED_PROFILE  = "UNVALIDATED_PROFILE"


# ---------------------------------------------------------------------------
# Observation and Evidence
# ---------------------------------------------------------------------------

class SourceType(str, Enum):
    """Origin of an observed data point."""
    CONFIG       = "CONFIG"
    PCAP         = "PCAP"
    LIVE_CAPTURE = "LIVE_CAPTURE"
    LAB          = "LAB"
    SIMULATION   = "SIMULATION"
    USER         = "USER"


class EntityType(str, Enum):
    """Type of entity that an Observation refers to."""
    FLEET       = "fleet"
    ENDPOINT    = "endpoint"
    PROPOSAL    = "proposal"
    TUNNEL      = "tunnel"
    NEGOTIATION = "negotiation"


# ---------------------------------------------------------------------------
# Risk and Assessment
# ---------------------------------------------------------------------------

class RiskLevel(str, Enum):
    """Categorical risk level, ordered from lowest to highest severity."""
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# IP Version
# ---------------------------------------------------------------------------

class IPVersion(str, Enum):
    """Supported IP protocol version."""
    V4 = "IPv4"
    V6 = "IPv6"


# ---------------------------------------------------------------------------
# Base Pydantic Model
# ---------------------------------------------------------------------------

class StatefluxBaseModel(BaseModel):
    """Common configuration applied to all STATEFLUX Pydantic models.

    - extra='forbid': unknown fields raise a validation error rather than
      silently being ignored. This prevents schema drift and catches bugs
      early when loading JSON that has drifted from the expected structure.
    - populate_by_name=True: allows both alias and field name to populate
      a field. Useful for API response shapes.
    """
    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )
