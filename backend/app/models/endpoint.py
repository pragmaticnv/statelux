"""
STATEFLUX — Endpoint Model
===========================
An Endpoint represents one side of one or more IPsec tunnels.
In practice this is a VPN gateway: a hardware appliance, a software
router, or a cloud gateway instance.

CAPABILITY vs CONFIGURATION:
  These two concepts are intentionally separated:

  - capabilities:    What the device is capable of (hardware/OS level).
                     A device may SUPPORT AES-128 even if its current
                     policy does not PERMIT it.

  - configuration:   What the device is currently configured to offer
                     in IKE/ESP negotiations.

  This distinction matters for security floor analysis. The floor is
  determined by the configuration (permitted proposals), not by the
  full capability set.

PROVENANCE:
  In Phase 1, all endpoints are loaded from synthetic configuration data.
  The validation_status field must be set to UNVALIDATED_PROFILE for
  any endpoint whose profile is not derived from real vendor documentation
  or lab testing.
"""

from typing import Optional

from pydantic import field_validator

from app.models.base import (
    StatefluxBaseModel,
    IKEVersion,
    EncryptionAlgorithm,
    IntegrityAlgorithm,
    ProfileType,
    SelectionPreference,
    ValidationStatus,
    IPVersion,
)


class EndpointCapabilities(StatefluxBaseModel):
    """What the endpoint hardware/software is capable of.

    This reflects the device's maximum capability set, not what it
    is currently configured to negotiate. A device may support algorithms
    it does not advertise in its current IKE/ESP proposals.
    """
    ike_versions:                 list[IKEVersion]
    encryption_algorithms:        list[EncryptionAlgorithm]
    integrity_algorithms:         list[IntegrityAlgorithm]
    dh_groups:                    list[int]
    pfs_supported:                bool
    replay_protection_supported:  bool


class EndpointConfiguration(StatefluxBaseModel):
    """What the endpoint is currently configured to offer in negotiations.

    ike_proposals and esp_proposals are ordered lists of Proposal IDs.
    The order reflects the endpoint's preference (index 0 = highest priority).
    """
    ike_proposals:       list[str]   # Proposal IDs (IKE phase)
    esp_proposals:       list[str]   # Proposal IDs (ESP phase)
    selection_preference: SelectionPreference = SelectionPreference.ORDERED_PRIORITY


class EndpointNetwork(StatefluxBaseModel):
    """Network-level parameters for the endpoint."""
    ip_versions: list[IPVersion]
    mtu:         int

    @field_validator("mtu")
    @classmethod
    def mtu_must_be_valid(cls, v: int) -> int:
        if not (576 <= v <= 9000):
            raise ValueError(f"MTU {v} is outside the valid range [576, 9000]")
        return v


class EndpointRekey(StatefluxBaseModel):
    """Rekey / lifetime configuration for the endpoint.

    Lifetimes are in seconds. The child SA lifetime is typically
    shorter than the IKE SA lifetime.
    """
    ike_lifetime:      int   # IKE SA / Phase-1 lifetime in seconds
    child_sa_lifetime: int   # IPsec SA / Phase-2 / Child-SA lifetime in seconds

    @field_validator("ike_lifetime", "child_sa_lifetime")
    @classmethod
    def lifetime_must_be_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("Lifetime must be a positive number of seconds")
        return v


class Endpoint(StatefluxBaseModel):
    """A single VPN gateway participating in the fleet.

    Attributes:
        endpoint_id:       Stable unique identifier (e.g., "ep-001").
        fleet_id:          The fleet this endpoint belongs to.
        name:              Human-readable label (e.g., "DELHI-HUB-01").
        platform:          Software platform (e.g., "strongSwan", "Libreswan").
        platform_version:  Detected or declared software version.
        profile_type:      Broad security profile category.
        validation_status: Whether this profile is validated against real data.
                           UNVALIDATED_PROFILE endpoints must be labeled clearly
                           in all reports and UI displays.
        capabilities:      Full device capability set.
        configuration:     Currently configured proposal sets.
        network:           Network parameters.
        rekey:             SA lifetime/rekey configuration.
        annotations:       Free-form key-value pairs for analyst notes or
                           scenario tagging (e.g., {"scenario": "S07"}).
    """

    endpoint_id:       str
    fleet_id:          str
    name:              str
    platform:          str
    platform_version:  str
    profile_type:      ProfileType
    validation_status: ValidationStatus

    capabilities:  EndpointCapabilities
    configuration: EndpointConfiguration
    network:       EndpointNetwork
    rekey:         EndpointRekey

    annotations: dict[str, str] = {}
    notes:       Optional[str]  = None
