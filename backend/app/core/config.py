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
    """Resolve the project root (stateflux/) regardless of CWD or serverless environment."""
    # Candidate 1: 4 levels up from this file (backend/app/core/config.py)
    candidate = Path(__file__).resolve().parent.parent.parent.parent
    if (candidate / "data" / "seed").exists():
        return candidate

    # Candidate 2: Current working directory
    cwd = Path.cwd()
    if (cwd / "data" / "seed").exists():
        return cwd

    # Candidate 3: /var/task (standard AWS Lambda / Vercel runtime directory)
    var_task = Path("/var/task")
    if (var_task / "data" / "seed").exists():
        return var_task

    return candidate


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
