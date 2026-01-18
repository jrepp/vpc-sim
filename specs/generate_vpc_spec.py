from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "specs" / "ec2-2016-11-15.normal.json"
OUT_MODEL_PATH = ROOT / "specs" / "vpc-ec2-model.json"
OUT_MD_PATH = ROOT / "specs" / "vpc-ec2-coverage.md"
OUT_REPORT_PATH = ROOT / "specs" / "vpc-ec2-coverage-report.md"
FIXTURE_DIR = ROOT / "specs" / "vpc-ec2-fixtures"

KEYWORDS = [
    "Vpc",
    "Subnet",
    "RouteTable",
    "Route",
    "InternetGateway",
    "NatGateway",
    "NetworkAcl",
    "SecurityGroup",
    "VpcPeering",
    "VpcEndpoint",
    "DhcpOptions",
    "EgressOnlyInternetGateway",
    "VpcCidrBlock",
    "Ipv6",
    "VpnGateway",
    "CustomerGateway",
    "TransitGateway",
    "FlowLogs",
    "ClassicLink",
]


def select_operations(model: Dict[str, Any]) -> Dict[str, Any]:
    ops = model.get("operations", {})
    selected = {}
    for name, op in ops.items():
        if any(k in name for k in KEYWORDS):
            selected[name] = op
    return dict(sorted(selected.items(), key=lambda x: x[0]))


def collect_shapes(model: Dict[str, Any], operations: Dict[str, Any]) -> Dict[str, Any]:
    shapes = model.get("shapes", {})
    needed: set[str] = set()
    stack: List[str] = []
    for op in operations.values():
        if "input" in op:
            stack.append(op["input"]["shape"])
        if "output" in op:
            stack.append(op["output"]["shape"])

    while stack:
        name = stack.pop()
        if name in needed:
            continue
        needed.add(name)
        shape = shapes.get(name, {})
        stype = shape.get("type")
        if stype == "structure":
            for member in shape.get("members", {}).values():
                mshape = member.get("shape")
                if mshape:
                    stack.append(mshape)
        elif stype == "list":
            member = shape.get("member", {})
            mshape = member.get("shape")
            if mshape:
                stack.append(mshape)
        elif stype == "map":
            key = shape.get("key", {}).get("shape")
            val = shape.get("value", {}).get("shape")
            if key:
                stack.append(key)
            if val:
                stack.append(val)

    return {name: shapes[name] for name in sorted(needed) if name in shapes}


def write_model(model: Dict[str, Any], operations: Dict[str, Any], shapes: Dict[str, Any]) -> None:
    out = {
        "version": model.get("version"),
        "metadata": model.get("metadata", {}),
        "operations": operations,
        "shapes": shapes,
    }
    OUT_MODEL_PATH.write_text(json.dumps(out, indent=2))


def write_coverage_md(model: Dict[str, Any], operations: Dict[str, Any]) -> None:
    shapes = model.get("shapes", {})
    lines = [
        "# EC2 VPC Management API Coverage Spec (Derived from AWS EC2 model)",
        "",
        f"Source: `{MODEL_PATH.relative_to(ROOT)}`",
        "Protocol: EC2 Query (Action + Version, XML responses).",
        "",
        "## Operations",
        "",
        "| Operation | Input Shape | Required Fields | Output Shape |",
        "| --- | --- | --- | --- |",
    ]
    for name, op in operations.items():
        input_shape = op.get("input", {}).get("shape", "")
        output_shape = op.get("output", {}).get("shape", "")
        required = []
        if input_shape:
            shape = shapes.get(input_shape, {})
            required = shape.get("required", [])
        req_str = ", ".join(required) if required else ""
        lines.append(f"| `{name}` | `{input_shape}` | {req_str} | `{output_shape}` |")
    OUT_MD_PATH.write_text("\n".join(lines))


def sample_value(shape: Dict[str, Any]) -> str:
    if "enum" in shape and shape["enum"]:
        return str(shape["enum"][0])
    stype = shape.get("type")
    if stype == "string":
        return "example"
    if stype in {"integer", "long"}:
        return "1"
    if stype in {"float", "double"}:
        return "1.0"
    if stype == "boolean":
        return "true"
    if stype == "timestamp":
        return "1970-01-01T00:00:00Z"
    return "example"


def xml_member_name(member_name: str, member: Dict[str, Any]) -> str:
    return member.get("locationName", member_name)


def render_shape(
    model: Dict[str, Any],
    shape_name: str,
    parent: ET.Element,
    member_name: str | None = None,
) -> None:
    shapes = model.get("shapes", {})
    shape = shapes.get(shape_name, {})
    stype = shape.get("type")
    node_name = member_name or shape_name
    node = ET.SubElement(parent, node_name) if member_name else parent

    if stype == "structure":
        members = shape.get("members", {})
        required = shape.get("required")
        member_names = required if required else list(members.keys())
        for name in member_names:
            member = members.get(name)
            if not member:
                continue
            mshape = member.get("shape")
            if not mshape:
                continue
            child_name = xml_member_name(name, member)
            render_shape(model, mshape, node, child_name)
    elif stype == "list":
        member = shape.get("member", {})
        mshape = member.get("shape")
        if not mshape:
            return
        item_name = member.get("locationName", "item")
        item = ET.SubElement(node, item_name)
        render_shape(model, mshape, item, None)
    elif stype == "map":
        entry_name = shape.get("locationName", "entry")
        entry = ET.SubElement(node, entry_name)
        key_shape = shape.get("key", {}).get("shape")
        val_shape = shape.get("value", {}).get("shape")
        if key_shape:
            ET.SubElement(entry, "key").text = sample_value(shapes.get(key_shape, {}))
        if val_shape:
            ET.SubElement(entry, "value").text = sample_value(shapes.get(val_shape, {}))
    else:
        node.text = sample_value(shape)


def write_fixtures(model: Dict[str, Any], operations: Dict[str, Any]) -> None:
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    ns = None
    xml_ns = model.get("metadata", {}).get("xmlNamespace")
    if isinstance(xml_ns, dict):
        ns = xml_ns.get("uri")
    for name, op in operations.items():
        output_shape = op.get("output", {}).get("shape")
        if not output_shape:
            continue
        root = ET.Element(f"{name}Response")
        if ns:
            root.attrib["xmlns"] = ns
        render_shape(model, output_shape, root, None)
        content = ET.tostring(root, encoding="utf-8", xml_declaration=True)
        (FIXTURE_DIR / f"{name}.xml").write_bytes(content)


def _extract_implemented_actions() -> List[str]:
    ec2_api_path = ROOT / "backend" / "app" / "ec2_api.py"
    if not ec2_api_path.exists():
        return []
    text = ec2_api_path.read_text()
    actions = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('"') and '":' in line:
            key = line.split('":', 1)[0].strip('"')
            actions.append(key)
    return sorted(set(actions))


def write_coverage_report(operations: Dict[str, Any]) -> None:
    all_ops = sorted(operations.keys())
    implemented = _extract_implemented_actions()
    implemented_set = set(implemented)
    missing = [op for op in all_ops if op not in implemented_set]

    lines = [
        "# VPC API Coverage Report",
        "",
        f"Total VPC-related operations: {len(all_ops)}",
        f"Implemented actions: {len(implemented)}",
        f"Missing actions: {len(missing)}",
        "",
        "## Implemented",
        "",
    ]
    for op in implemented:
        lines.append(f"- `{op}`")
    lines.extend(["", "## Missing", ""])
    for op in missing:
        lines.append(f"- `{op}`")
    OUT_REPORT_PATH.write_text("\n".join(lines))


def main() -> None:
    model = json.loads(MODEL_PATH.read_text())
    ops = select_operations(model)
    shapes = collect_shapes(model, ops)
    write_model(model, ops, shapes)
    write_coverage_md(model, ops)
    write_fixtures(model, ops)
    write_coverage_report(ops)


if __name__ == "__main__":
    main()
