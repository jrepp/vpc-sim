"""Shared serialization helpers."""
from __future__ import annotations

from .models import Route


def route_summary(route: Route) -> dict:
    """Summarize a route for JSON responses."""
    return {
        "id": route.id,
        "destination_cidr": route.destination_cidr,
        "target_type": route.target_type,
        "target_id": route.target_id,
        "state": route.state,
    }
