"""
STATEFLUX — Dataset Generation CLI Script
==========================================
Generates the deterministic canonical synthetic dataset into data/seed/*.json

Usage:
    python scripts/generate_dataset.py
    python scripts/generate_dataset.py --output-dir data/seed
"""

import sys
import argparse
from pathlib import Path

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add backend directory to sys.path so app modules are importable
backend_dir = Path(__file__).resolve().parent.parent / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.services.dataset_generator import StatefluxDatasetGenerator
from app.core.constants import SYNTHETIC_DATA_DISCLAIMER


def main():
    parser = argparse.ArgumentParser(
        description="Generate STATEFLUX canonical synthetic dataset."
    )
    parser.add_argument(
        "--output-dir", "-o",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "data" / "seed",
        help="Directory to write JSON files to (default: data/seed)",
    )
    args = parser.parse_args()

    out_dir = args.output_dir.resolve()
    print("=" * 60)
    print("STATEFLUX — Synthetic Dataset Generator")
    print(f"Target directory: {out_dir}")
    print("=" * 60)

    generator = StatefluxDatasetGenerator()
    stats = generator.generate(output_dir=out_dir)

    print("\nGeneration Complete:")
    for entity, count in stats.items():
        print(f"  - {entity:16s}: {count:4d} records")

    print("\n" + SYNTHETIC_DATA_DISCLAIMER)
    print("=" * 60)


if __name__ == "__main__":
    main()
