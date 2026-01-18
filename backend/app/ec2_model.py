"""Model-driven EC2 Query validation helpers."""
from __future__ import annotations

from typing import Dict, List

from .ec2_spec import get_operation, get_shapes


def required_params_for_action(action: str) -> List[str]:
    """Return required parameter names for an action."""
    op = get_operation(action)
    if not op:
        return []
    input_shape_name = op.get("input", {}).get("shape")
    if not input_shape_name:
        return []
    shape = get_shapes().get(input_shape_name, {})
    required = shape.get("required", [])
    return required


def _param_present(params: Dict[str, str], name: str) -> bool:
    """Check if a parameter (or list prefix) is present."""
    if name in params:
        return True
    prefix = f"{name}."
    return any(key.startswith(prefix) for key in params)


def _get_input_members(action: str) -> tuple[dict, dict] | None:
    """Return (input_shape, shapes) for an action."""
    op = get_operation(action)
    if not op:
        return None
    input_shape_name = op.get("input", {}).get("shape")
    if not input_shape_name:
        return None
    shapes = get_shapes()
    shape = shapes.get(input_shape_name, {})
    return shape, shapes


def validate_required_params(action: str, params: Dict[str, str]) -> List[str]:
    """Return missing required parameters for an action."""
    missing: list[str] = []
    resolved = _get_input_members(action)
    if not resolved:
        return missing
    shape, _shapes = resolved
    members = shape.get("members", {})
    for name in shape.get("required", []):
        member = members.get(name, {})
        location = member.get("locationName", name)
        if not _param_present(params, location):
            missing.append(location)
    return missing


def _validate_enum(location: str, value: str, member_shape: dict) -> str | None:
    if "enum" not in member_shape:
        return None
    if value not in member_shape["enum"]:
        return f"{location} must be one of {member_shape['enum']}"
    return None


def _validate_scalar_type(location: str, value: str, mtype: str | None) -> str | None:
    if mtype in {"integer", "long"}:
        try:
            int(value)
        except ValueError:
            return f"{location} must be an integer"
        return None
    if mtype in {"float", "double"}:
        try:
            float(value)
        except ValueError:
            return f"{location} must be a number"
        return None
    if mtype == "boolean":
        if value.lower() not in {"true", "false", "1", "0"}:
            return f"{location} must be a boolean"
    return None


def validate_params(action: str, params: Dict[str, str]) -> List[str]:
    """Validate scalar params against enum/type constraints."""
    resolved = _get_input_members(action)
    if not resolved:
        return []
    shape, shapes = resolved
    members = shape.get("members", {})
    errors: List[str] = []

    for member_name, member in members.items():
        location = member.get("locationName", member_name)
        if not _param_present(params, location):
            continue
        member_shape = shapes.get(member.get("shape", ""), {})
        mtype = member_shape.get("type")
        if mtype in {"list", "map", "structure"}:
            continue
        value = params.get(location)
        if value is None:
            continue
        enum_error = _validate_enum(location, value, member_shape)
        if enum_error:
            errors.append(enum_error)
            continue
        scalar_error = _validate_scalar_type(location, value, mtype)
        if scalar_error:
            errors.append(scalar_error)

    return errors
