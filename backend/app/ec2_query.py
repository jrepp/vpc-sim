"""EC2 Query parameter parsing into structured input."""
from __future__ import annotations

import re
from typing import Any, Dict

from .ec2_spec import get_operation, get_shapes


def _shape(name: str) -> dict:
    """Fetch a shape definition by name."""
    return get_shapes().get(name, {})


def _member_location(member_name: str, member: dict) -> str:
    """Resolve the on-wire name for a member."""
    return member.get("locationName", member_name)


def _parse_scalar(params: Dict[str, str], key: str) -> str | None:
    """Return a scalar value from the query params."""
    return params.get(key)


def _parse_list(params: Dict[str, str], prefix: str, member_shape: str) -> list:
    """Parse a numbered list (Param.1, Param.2, ...) into a list."""
    member = _shape(member_shape)
    values = []
    pattern = re.compile(rf"^{re.escape(prefix)}\.(\d+)(?:\.|$)")
    indices = sorted(
        {int(m.group(1)) for key in params for m in [pattern.match(key)] if m},
    )
    for idx in indices:
        item_prefix = f"{prefix}.{idx}"
        if member.get("type") == "structure":
            item = _parse_structure(params, item_prefix + ".", member_shape)
            if item:
                values.append(item)
        else:
            value = params.get(item_prefix)
            if value is not None:
                values.append(value)
    return values


def _parse_map(params: Dict[str, str], prefix: str, _key_shape: str, _value_shape: str) -> dict:
    """Parse a map from EC2 Query Key/Value entries."""
    entries = {}
    pattern = re.compile(rf"^{re.escape(prefix)}\.(\d+)\.(Key|Value)$", re.IGNORECASE)
    grouped: Dict[int, Dict[str, str]] = {}
    for key, value in params.items():
        match = pattern.match(key)
        if not match:
            continue
        idx = int(match.group(1))
        part = match.group(2).lower()
        grouped.setdefault(idx, {})[part] = value
    for entry in grouped.values():
        key = entry.get("key")
        val = entry.get("value")
        if key is None or val is None:
            continue
        entries[key] = val
    return entries


def _parse_structure(params: Dict[str, str], prefix: str, shape_name: str) -> dict:
    """Parse a nested structure from EC2 Query parameters."""
    shape = _shape(shape_name)
    result: Dict[str, Any] = {}
    for member_name, member in shape.get("members", {}).items():
        location = _member_location(member_name, member)
        key = f"{prefix}{location}" if prefix else location
        member_shape = member.get("shape")
        if not member_shape:
            continue
        member_def = _shape(member_shape)
        mtype = member_def.get("type")
        if mtype == "structure":
            value = _parse_structure(params, key + ".", member_shape)
            if value:
                result[member_name] = value
        elif mtype == "list":
            value = _parse_list(params, key, member_def["member"]["shape"])
            if value:
                result[member_name] = value
        elif mtype == "map":
            key_shape = member_def["key"]["shape"]
            val_shape = member_def["value"]["shape"]
            value = _parse_map(params, key, key_shape, val_shape)
            if value:
                result[member_name] = value
        else:
            value = _parse_scalar(params, key)
            if value is not None:
                result[member_name] = value
    return result


def parse_action_input(action: str, params: Dict[str, str]) -> dict:
    """Parse query parameters for a given Action into structured input."""
    op = get_operation(action)
    if not op:
        return {}
    input_shape_name = op.get("input", {}).get("shape")
    if not input_shape_name:
        return {}
    return _parse_structure(params, "", input_shape_name)


def get_input_shape_name(action: str) -> str | None:
    """Return the input shape name for an action."""
    op = get_operation(action)
    if not op:
        return None
    return op.get("input", {}).get("shape")
