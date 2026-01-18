"""Shared EC2 service model accessors."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

MODEL_PATH = Path(__file__).resolve().parents[2] / "specs" / "ec2-2016-11-15.normal.json"


@lru_cache(maxsize=1)
def load_model() -> dict | None:
    """Load the EC2 service model from disk."""
    if not MODEL_PATH.exists():
        return None
    return json.loads(MODEL_PATH.read_text())


def get_operation(action: str) -> dict | None:
    """Return the operation definition for an action."""
    model = load_model()
    if not model:
        return None
    return model.get("operations", {}).get(action)


def get_shapes() -> dict:
    """Return the shapes dictionary."""
    model = load_model()
    if not model:
        return {}
    return model.get("shapes", {})
