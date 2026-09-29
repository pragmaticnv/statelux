"""
STATEFLUX — Dataset Loader and State Manager
=============================================
Loads the seed JSON dataset, validates it against Pydantic schemas,
performs cross-reference integrity checks, and exposes it as a
module-level singleton that API routes can read.

DESIGN:
  - The dataset is loaded once at startup (or on-demand via load_dataset()).
  - All loaded entities are indexed by their IDs for O(1) lookup.
  - Validation errors are explicit and descriptive.
  - The is_loaded flag lets the API return 503 cleanly if data is not ready.

PHASE 1 LIMITATIONS:
  - No SQLite — pure in-memory JSON loading.
  - No incremental loading — dataset is fully replaced on each load call.
  - No concurrent access control — single-threaded access assumed.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.models.fleet import Fleet
from app.models.endpoint import Endpoint
from app.models.proposal import Proposal
from app.models.tunnel import Tunnel
from app.models.negotiation import Negotiation
from app.models.observation import Observation
from app.models.security_state import SecurityState

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dataset State Container
# ---------------------------------------------------------------------------

@dataclass
class DatasetState:
    """In-memory representation of the loaded STATEFLUX dataset.

    All entity collections are indexed by their primary ID for fast lookup.
    The fleet object contains the authoritative list of which entity IDs
    belong to this dataset.
    """
    fleet:           Optional[Fleet]                   = None
    endpoints:       dict[str, Endpoint]               = field(default_factory=dict)
    proposals:       dict[str, Proposal]               = field(default_factory=dict)
    tunnels:         dict[str, Tunnel]                 = field(default_factory=dict)
    negotiations:    dict[str, Negotiation]            = field(default_factory=dict)
    observations:    list[Observation]                 = field(default_factory=list)
    security_states: dict[str, SecurityState]          = field(default_factory=dict)

    is_loaded:        bool                             = False
    load_timestamp:   Optional[datetime]               = None
    is_synthetic:     bool                             = True
    dataset_source:   str                             = "UNKNOWN"

    # Statistics computed after load
    stats: dict[str, int] = field(default_factory=dict)

    def compute_stats(self) -> None:
        """Recompute summary statistics from loaded entities."""
        self.stats = {
            "endpoints":    len(self.endpoints),
            "proposals":    len(self.proposals),
            "tunnels":      len(self.tunnels),
            "negotiations": len(self.negotiations),
            "observations": len(self.observations),
            "security_states": len(self.security_states),
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_current_dataset: DatasetState = DatasetState()


def get_dataset() -> DatasetState:
    """Return the currently loaded dataset state.

    If not yet loaded (e.g. in serverless environments where lifespan may be bypassed),
    automatically loads from settings.SEED_DIR or candidate seed directories.
    """
    if not _current_dataset.is_loaded:
        from app.core.config import settings
        candidates = [
            settings.SEED_DIR,
            Path(__file__).resolve().parent.parent / "data" / "seed",
            Path.cwd() / "data" / "seed",
            Path("/var/task/data/seed"),
            Path("/var/task/backend/app/data/seed"),
            Path(__file__).resolve().parent.parent.parent.parent / "data" / "seed",
        ]
        for c in candidates:
            if c.exists() and any(c.glob("*.json")):
                return load_dataset(c)
        raise RuntimeError(
            f"Dataset has not been loaded and seed data was not found at {[str(c) for c in candidates]}."
        )
    return _current_dataset


# ---------------------------------------------------------------------------
# JSON Loaders
# ---------------------------------------------------------------------------

def _load_json(path: Path, entity_name: str) -> list[dict]:
    """Load and parse a JSON file, returning a list of dicts."""
    if not path.exists():
        raise FileNotFoundError(
            f"Seed file not found: {path}. "
            f"Run 'python scripts/generate_dataset.py' to generate seed data."
        )
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, list):
            raise ValueError(
                f"{entity_name} seed file must contain a JSON array, "
                f"got {type(data).__name__}"
            )
        return data
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc


def _load_fleet_json(path: Path) -> dict:
    """Load the fleet seed file (single JSON object, not array)."""
    if not path.exists():
        raise FileNotFoundError(f"Fleet seed file not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("Fleet seed file must contain a single JSON object")
    return data


# ---------------------------------------------------------------------------
# Cross-Reference Validation
# ---------------------------------------------------------------------------

def _validate_references(state: DatasetState) -> list[str]:
    """Validate referential integrity of the loaded dataset.

    Returns a list of validation error strings. Empty list = no errors.
    """
    errors: list[str] = []
    fleet = state.fleet

    if fleet is None:
        return ["Fleet object is None — dataset failed to load"]

    # Fleet endpoint_ids must all exist
    for ep_id in fleet.endpoint_ids:
        if ep_id not in state.endpoints:
            errors.append(
                f"Fleet references endpoint '{ep_id}' which does not exist"
            )

    # Fleet tunnel_ids must all exist
    for tn_id in fleet.tunnel_ids:
        if tn_id not in state.tunnels:
            errors.append(
                f"Fleet references tunnel '{tn_id}' which does not exist"
            )

    # Each tunnel's endpoints must exist
    for tn_id, tunnel in state.tunnels.items():
        for ep_attr, ep_id in [("endpoint_a", tunnel.endpoint_a),
                                ("endpoint_b", tunnel.endpoint_b)]:
            if ep_id not in state.endpoints:
                errors.append(
                    f"Tunnel '{tn_id}' references {ep_attr}='{ep_id}' "
                    f"which does not exist"
                )

        # Tunnel's negotiation_id must exist (if set)
        if tunnel.negotiation_id and tunnel.negotiation_id not in state.negotiations:
            errors.append(
                f"Tunnel '{tn_id}' references negotiation_id='"
                f"{tunnel.negotiation_id}' which does not exist"
            )

        # Tunnel's security_state_id must exist (if set)
        if (tunnel.security_state_id
                and tunnel.security_state_id not in state.security_states):
            errors.append(
                f"Tunnel '{tn_id}' references security_state_id='"
                f"{tunnel.security_state_id}' which does not exist"
            )

    # Each negotiation's proposals must exist
    for neg_id, neg in state.negotiations.items():
        for prop_id in neg.offers_from_a + neg.offers_from_b + neg.common_proposals:
            if prop_id not in state.proposals:
                errors.append(
                    f"Negotiation '{neg_id}' references proposal '{prop_id}' "
                    f"which does not exist"
                )
        if neg.selected_proposal and neg.selected_proposal not in state.proposals:
            errors.append(
                f"Negotiation '{neg_id}' selected_proposal='"
                f"{neg.selected_proposal}' does not exist"
            )

    # Each endpoint's configured proposals must exist
    for ep_id, endpoint in state.endpoints.items():
        for prop_id in (endpoint.configuration.ike_proposals
                        + endpoint.configuration.esp_proposals):
            if prop_id not in state.proposals:
                errors.append(
                    f"Endpoint '{ep_id}' configuration references proposal "
                    f"'{prop_id}' which does not exist"
                )

    # Each security_state's tunnel must exist
    for ss_id, ss in state.security_states.items():
        if ss.tunnel_id not in state.tunnels:
            errors.append(
                f"SecurityState '{ss_id}' references tunnel '"
                f"{ss.tunnel_id}' which does not exist"
            )

    return errors


# ---------------------------------------------------------------------------
# Main Load Function
# ---------------------------------------------------------------------------

def load_dataset(seed_dir: Path) -> DatasetState:
    """Load and validate the complete seed dataset from disk.

    Args:
        seed_dir: Directory containing the seed JSON files.

    Returns:
        A fully validated DatasetState.

    Raises:
        FileNotFoundError: If any required seed file is missing.
        ValueError: If any data fails Pydantic validation or
                    cross-reference checks.
    """
    global _current_dataset

    logger.info("Loading STATEFLUX seed dataset from %s", seed_dir)
    state = DatasetState()

    # ------------------------------------------------------------------
    # Load Fleet
    # ------------------------------------------------------------------
    fleet_data = _load_fleet_json(seed_dir / "fleet.json")
    state.fleet = Fleet.model_validate(fleet_data)
    logger.debug("Loaded fleet: %s", state.fleet.fleet_id)

    # ------------------------------------------------------------------
    # Load Proposals (before endpoints and negotiations — they reference them)
    # ------------------------------------------------------------------
    for raw in _load_json(seed_dir / "proposals.json", "proposals"):
        proposal = Proposal.model_validate(raw)
        state.proposals[proposal.proposal_id] = proposal
    logger.debug("Loaded %d proposals", len(state.proposals))

    # ------------------------------------------------------------------
    # Load Endpoints
    # ------------------------------------------------------------------
    for raw in _load_json(seed_dir / "endpoints.json", "endpoints"):
        endpoint = Endpoint.model_validate(raw)
        state.endpoints[endpoint.endpoint_id] = endpoint
    logger.debug("Loaded %d endpoints", len(state.endpoints))

    # ------------------------------------------------------------------
    # Load Tunnels
    # ------------------------------------------------------------------
    for raw in _load_json(seed_dir / "tunnels.json", "tunnels"):
        tunnel = Tunnel.model_validate(raw)
        state.tunnels[tunnel.tunnel_id] = tunnel
    logger.debug("Loaded %d tunnels", len(state.tunnels))

    # ------------------------------------------------------------------
    # Load Negotiations
    # ------------------------------------------------------------------
    for raw in _load_json(seed_dir / "negotiations.json", "negotiations"):
        neg = Negotiation.model_validate(raw)
        state.negotiations[neg.negotiation_id] = neg
    logger.debug("Loaded %d negotiations", len(state.negotiations))

    # ------------------------------------------------------------------
    # Load Observations
    # ------------------------------------------------------------------
    for raw in _load_json(seed_dir / "observations.json", "observations"):
        obs = Observation.model_validate(raw)
        state.observations.append(obs)
    logger.debug("Loaded %d observations", len(state.observations))

    # ------------------------------------------------------------------
    # Load Security States
    # ------------------------------------------------------------------
    for raw in _load_json(seed_dir / "security_states.json", "security_states"):
        ss = SecurityState.model_validate(raw)
        state.security_states[ss.security_state_id] = ss
    logger.debug("Loaded %d security states", len(state.security_states))

    # ------------------------------------------------------------------
    # Cross-reference validation
    # ------------------------------------------------------------------
    errors = _validate_references(state)
    if errors:
        error_list = "\n  - ".join(errors)
        raise ValueError(
            f"Dataset failed cross-reference validation "
            f"({len(errors)} error(s)):\n  - {error_list}"
        )

    # ------------------------------------------------------------------
    # Finalize
    # ------------------------------------------------------------------
    state.is_loaded      = True
    state.load_timestamp = datetime.now(timezone.utc)
    state.is_synthetic   = True
    state.dataset_source = str(seed_dir)
    state.compute_stats()

    _current_dataset = state

    logger.info(
        "Dataset loaded successfully: %d tunnels, %d endpoints, "
        "%d proposals, %d observations",
        len(state.tunnels),
        len(state.endpoints),
        len(state.proposals),
        len(state.observations),
    )
    return state
