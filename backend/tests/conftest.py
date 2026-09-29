"""
STATEFLUX — Test Fixtures (conftest.py)
========================================
Shared fixtures for all test modules.
Provides:
  - A minimal in-memory dataset generated fresh for each test session
  - A TestClient with the app pre-loaded with the test dataset
"""

import pytest
from pathlib import Path

from app.services.dataset_generator import StatefluxDatasetGenerator
from app.services.data_loader import load_dataset


@pytest.fixture(scope="session")
def seed_dir(tmp_path_factory) -> Path:
    """Generate synthetic dataset to a temp directory (once per session)."""
    tmp_dir = tmp_path_factory.mktemp("stateflux_seed")
    gen = StatefluxDatasetGenerator()
    gen.generate(output_dir=tmp_dir)
    return tmp_dir


@pytest.fixture(scope="session")
def dataset(seed_dir):
    """Load and return the generated dataset state."""
    return load_dataset(seed_dir)


@pytest.fixture(scope="session")
def client(seed_dir):
    """Return a TestClient with the dataset pre-loaded."""
    from fastapi.testclient import TestClient
    from app.main import app
    from app.services import data_loader

    # Pre-load the dataset into the module-level singleton
    data_loader.load_dataset(seed_dir)

    with TestClient(app) as c:
        yield c
