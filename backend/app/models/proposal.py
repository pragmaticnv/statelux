"""
STATEFLUX — Proposal Model
===========================
A Proposal is a specific combination of cryptographic algorithms for
one IPsec protocol context (IKE or ESP).

IMPORTANT DESIGN PRINCIPLE:
  Proposals in Phase 1 are per-endpoint instances, not a canonical
  global catalogue. Each endpoint owns its own set of Proposal objects
  with its own priority ordering. This correctly models how real VPN
  devices work: two devices may advertise AES-256-GCM with DH-20, but
  each assigns its own priority to that suite based on local policy.

  'priority' = position in the endpoint's ordered preference list.
  Lower number = higher preference (1 = first choice).

  The Negotiation model records which proposals are offered by each
  side and which algorithms matched.

VALIDATION RULES:
  - For ESP + non-AEAD: integrity_algorithm must be set.
  - For ESP: prf must be None (PRF is an IKE-only concept).
  - For IKE + non-AEAD: integrity_algorithm must be set.
  - pfs=True in an ESP proposal requires dh_group to be set.
  - key_size must be consistent with encryption_algorithm.
"""

from typing import Optional

from pydantic import model_validator, field_validator

from app.models.base import (
    StatefluxBaseModel,
    Protocol,
    IKEVersion,
    EncryptionAlgorithm,
    IntegrityAlgorithm,
    PRFAlgorithm,
)


# Canonical key sizes for each algorithm
_ALGORITHM_KEY_SIZES: dict[EncryptionAlgorithm, int] = {
    EncryptionAlgorithm.AES_256_GCM: 256,
    EncryptionAlgorithm.AES_256_CBC: 256,
    EncryptionAlgorithm.AES_128_GCM: 128,
    EncryptionAlgorithm.AES_128_CBC: 128,
    EncryptionAlgorithm.TDES:        168,
}

# AEAD algorithms provide combined confidentiality + authentication
_AEAD_ALGORITHMS: set[EncryptionAlgorithm] = {
    EncryptionAlgorithm.AES_256_GCM,
    EncryptionAlgorithm.AES_128_GCM,
}


class Proposal(StatefluxBaseModel):
    """A single cryptographic proposal for IKE or ESP negotiation.

    Attributes:
        proposal_id:          Unique identifier (e.g., "ep-001-ike-01").
        owner_endpoint_id:    The endpoint that owns/offers this proposal.
        protocol:             IKE or ESP (AH not implemented in Phase 1).
        ike_version:          IKEv1 or IKEv2; None is acceptable for ESP proposals.
        encryption_algorithm: The encryption transform.
        key_size:             Key length in bits (derived from algorithm if omitted).
        integrity_algorithm:  HMAC integrity; None for AEAD algorithms in ESP;
                              may be None for AEAD in IKE (implicit from GCM auth).
        prf:                  Pseudo-Random Function — IKE only, must be None for ESP.
        dh_group:             Diffie-Hellman group number (IANA).
                              Required for IKE. Required for ESP when pfs=True.
        pfs:                  Whether this proposal uses Perfect Forward Secrecy.
                              Meaningful primarily for ESP proposals.
        priority:             Position in the owner endpoint's preference list (1=first).
        is_aead:              Computed: True when encryption provides authentication.
    """

    proposal_id:          str
    owner_endpoint_id:    str
    protocol:             Protocol
    ike_version:          Optional[IKEVersion]       = None
    encryption_algorithm: EncryptionAlgorithm
    key_size:             Optional[int]              = None  # derived in validator
    integrity_algorithm:  Optional[IntegrityAlgorithm] = None
    prf:                  Optional[PRFAlgorithm]     = None
    dh_group:             Optional[int]              = None
    pfs:                  bool                       = False
    priority:             int

    # Computed flag — set by validator, not stored independently
    is_aead: bool = False

    @field_validator("priority")
    @classmethod
    def priority_must_be_positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError(f"priority must be >= 1, got {v}")
        return v

    @field_validator("dh_group")
    @classmethod
    def dh_group_must_be_known(cls, v: Optional[int]) -> Optional[int]:
        if v is None:
            return v
        known_groups = {1, 2, 5, 14, 15, 16, 17, 18, 19, 20, 21, 31, 32}
        if v not in known_groups:
            raise ValueError(
                f"DH group {v} is not a recognised IANA group number. "
                f"Known groups: {sorted(known_groups)}"
            )
        return v

    @model_validator(mode="after")
    def derive_and_validate(self) -> "Proposal":
        # 1. Derive/validate key_size
        expected_key_size = _ALGORITHM_KEY_SIZES[self.encryption_algorithm]
        if self.key_size is None:
            self.key_size = expected_key_size
        elif self.key_size != expected_key_size:
            raise ValueError(
                f"key_size={self.key_size} is inconsistent with "
                f"{self.encryption_algorithm} (expected {expected_key_size})"
            )

        # 2. Compute is_aead
        self.is_aead = self.encryption_algorithm in _AEAD_ALGORITHMS

        # 3. ESP must not have a PRF
        if self.protocol == Protocol.ESP and self.prf is not None:
            raise ValueError(
                "PRF is an IKE-only concept; ESP proposals must have prf=None"
            )

        # 4. Non-AEAD ESP must have an integrity algorithm
        if (
            self.protocol == Protocol.ESP
            and not self.is_aead
            and self.integrity_algorithm is None
        ):
            raise ValueError(
                f"Non-AEAD ESP proposals require an integrity_algorithm "
                f"(encryption={self.encryption_algorithm})"
            )

        # 5. Non-AEAD IKE must have an integrity algorithm
        if (
            self.protocol == Protocol.IKE
            and not self.is_aead
            and self.integrity_algorithm is None
        ):
            raise ValueError(
                f"Non-AEAD IKE proposals require an integrity_algorithm "
                f"(encryption={self.encryption_algorithm})"
            )

        # 6. PFS=True requires a DH group in ESP proposals
        if self.protocol == Protocol.ESP and self.pfs and self.dh_group is None:
            raise ValueError(
                "ESP proposal with pfs=True must specify dh_group"
            )

        # 7. IKE proposals must always have a DH group
        if self.protocol == Protocol.IKE and self.dh_group is None:
            raise ValueError(
                "IKE proposals must specify dh_group "
                "(DH is always required for IKE)"
            )

        return self
