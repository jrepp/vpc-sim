from __future__ import annotations

import json
import keyword
import re
from pathlib import Path
from typing import Any, Dict, List, Set

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "specs" / "ec2-2016-11-15.normal.json"
OUT_DIR = ROOT / "backend" / "app" / "generated"
OUT_FILE = OUT_DIR / "ec2_shapes.py"


def to_identifier(name: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    if not safe:
        safe = "field"
    if safe[0].isdigit():
        safe = f"_{safe}"
    if keyword.iskeyword(safe):
        safe = f"{safe}_"
    return safe


def type_for_shape(shape_name: str, shapes: Dict[str, Any]) -> str:
    shape = shapes[shape_name]
    stype = shape.get("type")
    if "enum" in shape:
        values = ", ".join(repr(v) for v in shape["enum"])
        return f"Literal[{values}]"
    if stype == "string":
        return "str"
    if stype in {"integer", "long"}:
        return "int"
    if stype in {"float", "double"}:
        return "float"
    if stype == "boolean":
        return "bool"
    if stype == "timestamp":
        return "str"
    if stype == "list":
        member = shape.get("member", {})
        mshape = member.get("shape", "str")
        return f"List[{type_for_shape(mshape, shapes)}]"
    if stype == "map":
        key = shape.get("key", {}).get("shape", "str")
        val = shape.get("value", {}).get("shape", "str")
        return f"Dict[{type_for_shape(key, shapes)}, {type_for_shape(val, shapes)}]"
    if stype == "structure":
        return shape_name
    return "str"


def collect_references(shape_name: str, shapes: Dict[str, Any], seen: Set[str]) -> None:
    if shape_name in seen:
        return
    seen.add(shape_name)
    shape = shapes[shape_name]
    stype = shape.get("type")
    if stype == "structure":
        for member in shape.get("members", {}).values():
            mshape = member.get("shape")
            if mshape:
                collect_references(mshape, shapes, seen)
    elif stype == "list":
        mshape = shape.get("member", {}).get("shape")
        if mshape:
            collect_references(mshape, shapes, seen)
    elif stype == "map":
        kshape = shape.get("key", {}).get("shape")
        vshape = shape.get("value", {}).get("shape")
        if kshape:
            collect_references(kshape, shapes, seen)
        if vshape:
            collect_references(vshape, shapes, seen)


def main() -> None:
    model = json.loads(MODEL_PATH.read_text())
    shapes: Dict[str, Any] = model["shapes"]

    referenced: Set[str] = set()
    for op in model.get("operations", {}).values():
        if "input" in op:
            collect_references(op["input"]["shape"], shapes, referenced)
        if "output" in op:
            collect_references(op["output"]["shape"], shapes, referenced)

    structure_names = [
        name
        for name in sorted(referenced)
        if shapes.get(name, {}).get("type") == "structure"
    ]

    lines: List[str] = []
    lines.append("# pylint: skip-file")
    lines.append("from __future__ import annotations")
    lines.append("")
    lines.append("from typing import Dict, List, Optional")
    lines.append("from typing import Literal")
    lines.append("from pydantic import BaseModel, Field, ConfigDict")
    lines.append("")

    for name in structure_names:
        shape = shapes[name]
        members = shape.get("members", {})
        required = set(shape.get("required", []))
        lines.append(f"class {name}(BaseModel):")
        lines.append("    model_config = ConfigDict(populate_by_name=True)")
        if not members:
            lines.append("    pass")
            lines.append("")
            continue
        for member_name, member in members.items():
            field_name = to_identifier(member_name)
            field_type = type_for_shape(member["shape"], shapes)
            optional = member_name not in required
            if optional:
                field_type = f"Optional[{field_type}]"
            alias = member.get("locationName")
            if optional:
                default = "None"
                if field_name != member_name or alias:
                    alias_value = alias or member_name
                    lines.append(
                        f"    {field_name}: {field_type} = Field(default=None, alias={alias_value!r})"
                    )
                else:
                    lines.append(f"    {field_name}: {field_type} = {default}")
            else:
                if field_name != member_name or alias:
                    alias_value = alias or member_name
                    lines.append(
                        f"    {field_name}: {field_type} = Field(..., alias={alias_value!r})"
                    )
                else:
                    lines.append(f"    {field_name}: {field_type} = Field(...)")
        lines.append("")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_DIR.joinpath("__init__.py").write_text("")
    OUT_FILE.write_text("\n".join(lines))


if __name__ == "__main__":
    main()
