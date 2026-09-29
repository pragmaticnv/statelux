"""
STATEFLUX — Cryptographic Proposal Normalizer
=============================================
Phase 2 — Security Intelligence Layer

Converts raw Proposal records into normalized multidimensional SecurityVectors.
Classification is based on versioned cryptographic criteria:
  - NIST SP 800-77r1 (Guide to IPsec VPNs)
  - NIST SP 800-131Ar2 (Transitioning the Use of Cryptographic Algorithms and Key Lengths)
  - RFC 9395 (Deprecation of IKEv1 and Related Algorithms)
  - BSI TR-02102-3 (Cryptographic Mechanisms: IPsec)

STRENGTH TIERS:
  STRONG:      AES-256-GCM, DH >= 19 (ECP/Curve), SHA-384/512, PFS enabled
  ACCEPTABLE:  AES-256-CBC, AES-128-GCM, DH 14 (2048-bit MODP), SHA-256
  WEAK:        AES-128-CBC, DH 5 (1536-bit), SHA-1, PFS disabled
  LEGACY:      IKEv1, 3DES, DH <= 2
  DISALLOWED:  3DES (Sweet32), DH 1/2, MD5, NULL encryption
  UNKNOWN:     Missing / unobserved data
"""

from typing import Optional, Any

from app.models.base import Protocol, IKEVersion, EncryptionAlgorithm, IntegrityAlgorithm
from app.models.proposal import Proposal
from app.models.security_vector import (
    SecurityVector,
    NormalizedTransform,
    StrengthClass,
)


class ProposalNormalizer:
    """Normalizes Proposal instances into multidimensional SecurityVectors."""

    RULE_PACK_VERSION = "2026.1-sp800-77r1"

    # ------------------------------------------------------------------
    # Classification tables
    # ------------------------------------------------------------------

    ENCRYPTION_CLASSIFICATION: dict[str, tuple[StrengthClass, int, Optional[str]]] = {
        "AES-256-GCM": (StrengthClass.STRONG,     256, "Authenticated encryption (AEAD) with 256-bit key"),
        "AES-256-CBC": (StrengthClass.ACCEPTABLE, 256, "Standard 256-bit CBC; requires separate HMAC"),
        "AES-128-GCM": (StrengthClass.ACCEPTABLE, 128, "Authenticated encryption (AEAD) with 128-bit key"),
        "AES-128-CBC": (StrengthClass.WEAK,       128, "128-bit CBC mode; lacks AEAD protection"),
        "3DES":        (StrengthClass.DISALLOWED, 168, "Vulnerable to Sweet32 64-bit block collisions; deprecated"),
        "DES":         (StrengthClass.DISALLOWED, 56,  "Broken 56-bit key; vulnerable to brute force"),
    }

    INTEGRITY_CLASSIFICATION: dict[str, tuple[StrengthClass, Optional[str]]] = {
        "AEAD":         (StrengthClass.STRONG,     "Implicit authenticated encryption authentication tag"),
        "HMAC-SHA-512": (StrengthClass.STRONG,     "512-bit HMAC; collision resistant"),
        "HMAC-SHA-384": (StrengthClass.STRONG,     "384-bit HMAC; collision resistant"),
        "HMAC-SHA-256": (StrengthClass.ACCEPTABLE, "256-bit HMAC; minimum modern standard"),
        "HMAC-SHA-1":   (StrengthClass.WEAK,       "Deprecated 160-bit hash; collision weaknesses"),
        "MD5":          (StrengthClass.DISALLOWED, "Cryptographically broken; disallowed"),
    }

    DH_CLASSIFICATION: dict[int, tuple[StrengthClass, Optional[str]]] = {
        1:  (StrengthClass.DISALLOWED, "768-bit MODP; broken"),
        2:  (StrengthClass.DISALLOWED, "1024-bit MODP; vulnerable to Logjam and discrete log precomputation"),
        5:  (StrengthClass.WEAK,       "1536-bit MODP; below current 2048-bit minimum"),
        14: (StrengthClass.ACCEPTABLE, "2048-bit MODP; NIST SP 800-77r1 acceptable minimum"),
        15: (StrengthClass.ACCEPTABLE, "3072-bit MODP; adequate"),
        16: (StrengthClass.ACCEPTABLE, "4096-bit MODP; adequate"),
        17: (StrengthClass.ACCEPTABLE, "6144-bit MODP; adequate"),
        18: (StrengthClass.ACCEPTABLE, "8192-bit MODP; adequate"),
        19: (StrengthClass.STRONG,     "256-bit ECP (NIST P-256); strong elliptic curve"),
        20: (StrengthClass.STRONG,     "384-bit ECP (NIST P-384); strong elliptic curve"),
        21: (StrengthClass.STRONG,     "521-bit ECP (NIST P-521); high-security elliptic curve"),
        31: (StrengthClass.STRONG,     "Curve25519 (X25519); high-performance modern curve"),
        32: (StrengthClass.STRONG,     "Curve448 (X448); high-security modern curve"),
    }

    def normalize_encryption(self, enc_name: Optional[str]) -> NormalizedTransform:
        if not enc_name or enc_name == "UNKNOWN":
            return NormalizedTransform(
                name="UNKNOWN",
                strength_class=StrengthClass.UNKNOWN,
                notes="Encryption algorithm unobserved or unspecified",
            )
        info = self.ENCRYPTION_CLASSIFICATION.get(enc_name)
        if info:
            st, key_size, notes = info
            return NormalizedTransform(name=enc_name, strength_class=st, key_size=key_size, notes=notes)
        return NormalizedTransform(
            name=enc_name,
            strength_class=StrengthClass.UNKNOWN,
            notes=f"Unrecognized encryption transform '{enc_name}'",
        )

    def normalize_integrity(self, integ_name: Optional[str], is_aead: bool = False) -> Optional[NormalizedTransform]:
        if is_aead:
            return NormalizedTransform(
                name="AEAD-AUTH",
                strength_class=StrengthClass.STRONG,
                notes="Integrated authentication tag from AEAD cipher",
            )
        if not integ_name:
            return None
        if integ_name == "UNKNOWN":
            return NormalizedTransform(
                name="UNKNOWN",
                strength_class=StrengthClass.UNKNOWN,
                notes="Integrity algorithm unobserved",
            )
        info = self.INTEGRITY_CLASSIFICATION.get(integ_name)
        if info:
            st, notes = info
            return NormalizedTransform(name=integ_name, strength_class=st, notes=notes)
        return NormalizedTransform(
            name=integ_name,
            strength_class=StrengthClass.UNKNOWN,
            notes=f"Unrecognized integrity transform '{integ_name}'",
        )

    def normalize_dh_group(self, group: Optional[int]) -> Optional[NormalizedTransform]:
        if group is None:
            return None
        info = self.DH_CLASSIFICATION.get(group)
        if info:
            st, notes = info
            return NormalizedTransform(name=f"Group {group}", strength_class=st, notes=notes)
        return NormalizedTransform(
            name=f"Group {group}",
            strength_class=StrengthClass.UNKNOWN,
            notes=f"Unrecognized DH group {group}",
        )

    def normalize(self, proposal: Proposal) -> SecurityVector:
        """Normalize a canonical Pydantic Proposal into a SecurityVector."""
        enc_name = proposal.encryption_algorithm.value
        norm_enc = self.normalize_encryption(enc_name)

        is_aead = proposal.is_aead or ("GCM" in enc_name)
        integ_name = proposal.integrity_algorithm.value if proposal.integrity_algorithm else None
        norm_int = self.normalize_integrity(integ_name, is_aead=is_aead)

        norm_dh = self.normalize_dh_group(proposal.dh_group)

        # PFS — strictly Child-SA / ESP dimension; None for IKE
        if proposal.protocol == Protocol.ESP:
            pfs_val: Optional[bool] = proposal.pfs
            pfs_st = StrengthClass.STRONG if proposal.pfs else StrengthClass.WEAK
        else:
            pfs_val = None
            pfs_st = StrengthClass.UNKNOWN

        # Legacy / Disallowed indicators
        is_legacy = (
            norm_enc.strength_class in (StrengthClass.LEGACY, StrengthClass.DISALLOWED, StrengthClass.WEAK)
            or (norm_dh is not None and norm_dh.strength_class in (StrengthClass.LEGACY, StrengthClass.DISALLOWED))
            or (norm_int is not None and norm_int.strength_class in (StrengthClass.LEGACY, StrengthClass.DISALLOWED))
            or (proposal.ike_version == IKEVersion.V1)
        )
        is_disallowed = (
            norm_enc.strength_class == StrengthClass.DISALLOWED
            or (norm_dh is not None and norm_dh.strength_class == StrengthClass.DISALLOWED)
            or (norm_int is not None and norm_int.strength_class == StrengthClass.DISALLOWED)
        )

        return SecurityVector(
            proposal_id=proposal.proposal_id,
            owner_endpoint_id=proposal.owner_endpoint_id,
            protocol=proposal.protocol,
            priority=proposal.priority,
            ike_version=proposal.ike_version,
            encryption=norm_enc,
            integrity=norm_int,
            dh_group=norm_dh,
            prf=None,
            pfs=pfs_val,
            pfs_strength=pfs_st,
            is_aead=is_aead,
            is_legacy=is_legacy,
            is_disallowed=is_disallowed,
        )

    def normalize_dict(
        self,
        data: dict[str, Any],
        proposal_id: str = "ad-hoc-001",
        owner_endpoint_id: str = "ep-generic",
        protocol: Protocol = Protocol.ESP,
    ) -> SecurityVector:
        """Normalize an ad-hoc or partially observed proposal dictionary."""
        enc_name = data.get("encryption") or data.get("encryption_algorithm")
        norm_enc = self.normalize_encryption(enc_name)

        is_aead = "GCM" in str(enc_name).upper()
        integ_name = data.get("integrity") or data.get("integrity_algorithm")
        norm_int = self.normalize_integrity(integ_name, is_aead=is_aead)

        dh_group = data.get("dh_group")
        if isinstance(dh_group, str) and dh_group.isdigit():
            dh_group = int(dh_group)
        elif not isinstance(dh_group, int):
            dh_group = None
        norm_dh = self.normalize_dh_group(dh_group)

        pfs_raw = data.get("pfs")
        if protocol == Protocol.ESP:
            if pfs_raw is True:
                pfs_val: Optional[bool] = True
                pfs_st = StrengthClass.STRONG
            elif pfs_raw is False:
                pfs_val = False
                pfs_st = StrengthClass.WEAK
            else:
                pfs_val = None
                pfs_st = StrengthClass.UNKNOWN
        else:
            pfs_val = None
            pfs_st = StrengthClass.UNKNOWN

        ike_ver_raw = data.get("ike_version")
        ike_ver = None
        if ike_ver_raw:
            try:
                ike_ver = IKEVersion(ike_ver_raw)
            except Exception:
                pass

        is_legacy = (
            norm_enc.strength_class in (StrengthClass.LEGACY, StrengthClass.DISALLOWED, StrengthClass.WEAK)
            or (norm_dh is not None and norm_dh.strength_class in (StrengthClass.LEGACY, StrengthClass.DISALLOWED))
            or (norm_int is not None and norm_int.strength_class in (StrengthClass.LEGACY, StrengthClass.DISALLOWED))
            or (ike_ver == IKEVersion.V1)
        )
        is_disallowed = (
            norm_enc.strength_class == StrengthClass.DISALLOWED
            or (norm_dh is not None and norm_dh.strength_class == StrengthClass.DISALLOWED)
        )

        return SecurityVector(
            proposal_id=proposal_id,
            owner_endpoint_id=owner_endpoint_id,
            protocol=protocol,
            priority=data.get("priority", 1),
            ike_version=ike_ver,
            encryption=norm_enc,
            integrity=norm_int,
            dh_group=norm_dh,
            prf=None,
            pfs=pfs_val,
            pfs_strength=pfs_st,
            is_aead=is_aead,
            is_legacy=is_legacy,
            is_disallowed=is_disallowed,
        )
