"""
STATEFLUX — Core Configuration
================================
Centralised application configuration using dataclasses.
All path resolution is relative to this file's location so the
project can be run from any working directory.
"""

from dataclasses import dataclass, field
from pathlib import Path


def _project_root() -> Path:
    """Resolve the project root (stateflux/) regardless of CWD."""
    # This file is at: stateflux/backend/app/core/config.py
    # Project root is 3 levels up
    return Path(__file__).resolve().parent.parent.parent.parent


@dataclass
class Settings:
    APP_NAME:    str  = "STATEFLUX"
    VERSION:     str  = "1.0.0-phase1a"
    DESCRIPTION: str  = (
        "AI-assisted IPsec security assessment and "
        "change-impact intelligence platform — Phase 1A"
    )

    # Directory layout
    BASE_DIR:      Path = field(default_factory=_project_root)
    DATA_DIR:      Path = field(init=False)
    SEED_DIR:      Path = field(init=False)
    SCENARIOS_DIR: Path = field(init=False)
    GENERATED_DIR: Path = field(init=False)

    def __post_init__(self) -> None:
        self.DATA_DIR      = self.BASE_DIR / "data"
        self.SEED_DIR      = self.DATA_DIR / "seed"
        self.SCENARIOS_DIR = self.DATA_DIR / "scenarios"
        self.GENERATED_DIR = self.DATA_DIR / "generated"

    # Dataset generation
    DATASET_SEED:          int = 42
    DATASET_IS_SYNTHETIC:  bool = True

    # API
    API_PREFIX:  str  = "/api/v1"
    DEBUG:       bool = True


settings = Settings()
