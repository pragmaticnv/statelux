"""
STATEFLUX — Change Request Model
================================
Phase 3 — Fleet Intelligence & Change-Impact Engine

Represents a structured, policy-like change request for the VPN fleet:
  - Scoped to FLEET, ENDPOINT_GROUP, ENDPOINT, or SINGLE_TUNNEL.
  - Expresses additions, removals, and minimum requirements for:
      * Encryption algorithms (e.g. remove 3DES, AES-128-CBC; require AES-256-GCM)
      * Diffie-Hellman groups (e.g. remove 14; require minimum group 20)
      * Perfect Forward Secrecy (e.g. require PFS on all Child SAs)
      * IKE version (e.g. require IKEv2, remove IKEv1)
"""

from enum import Enum
from typing import Optional
from datetime import datetime, timezone
from pydantic import Field

from app.models.base import StatefluxBaseModel


class ChangeScopeType(str, Enum):
    FLEET = "FLEET"
    ENDPOINT_GROUP = "ENDPOINT_GROUP"
    ENDPOINT = "ENDPOINT"
    SINGLE_TUNNEL = "SINGLE_TUNNEL"


class ChangeScope(StatefluxBaseModel):
    type: ChangeScopeType
    target_ids: list[str] = Field(
        default_factory=list,
        description="Target endpoint IDs, tunnel IDs, or group names. Empty for FLEET.",
    )


class EncryptionAction(StatefluxBaseModel):
    add: list[str] = Field(default_factory=list, description="Algorithms to add to offer lists.")
    remove: list[str] = Field(default_factory=list, description="Algorithms to remove from offer lists.")
    require: list[str] = Field(default_factory=list, description="Algorithms that must be supported.")


class DHAction(StatefluxBaseModel):
    add: list[int] = Field(default_factory=list, description="DH groups to add to offer lists.")
    remove: list[int] = Field(default_factory=list, description="DH groups to remove.")
    minimum_dh: Optional[int] = Field(None, description="Minimum acceptable DH group number (e.g. 20).")


class PFSAction(StatefluxBaseModel):
    mode: Optional[str] = Field(
        None,
        description="PFS requirement mode: 'REQUIRE' | 'PERMIT' | 'PROHIBIT'.",
    )


class IKEAction(StatefluxBaseModel):
    require_ikev2: bool = Field(False, description="Disallow IKEv1 and require IKEv2.")
    remove_ikev1: bool = Field(False, description="Remove all IKEv1 proposals.")


class ChangeRequest(StatefluxBaseModel):
    """Structured change request payload for what-if simulation."""
    change_id: str
    title: str = "Proposed Security Hardening Policy"
    description: Optional[str] = None
    scope: ChangeScope = Field(default_factory=lambda: ChangeScope(type=ChangeScopeType.FLEET))
    encryption: Optional[EncryptionAction] = None
    dh_groups: Optional[DHAction] = None
    pfs: Optional[PFSAction] = None
    ike: Optional[IKEAction] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    author: Optional[str] = "security-admin"
