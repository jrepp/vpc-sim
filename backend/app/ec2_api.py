"""EC2 Query API handlers for the VPC simulator."""
from __future__ import annotations

import ipaddress
import uuid
from typing import Dict, List
from xml.etree import ElementTree as ET

from fastapi import APIRouter, Request, Response
from pydantic import ValidationError
from sqlalchemy.orm import Session

from .db import SessionLocal
from .ec2_query import get_input_shape_name, parse_action_input
from .ec2_model import validate_params, validate_required_params
try:
    from .generated import ec2_shapes as EC2_SHAPES
except ImportError:
    EC2_SHAPES = None
from .models import (
    InternetGateway,
    Route,
    RouteTable,
    RouteTableAssociation,
    Subnet,
    Vpc,
    VpcPeeringConnection,
)

NAMESPACE = "http://ec2.amazonaws.com/doc/2016-11-15/"

router = APIRouter()


def _ns_tag(tag: str) -> str:
    """Return a namespaced XML tag."""
    return f"{{{NAMESPACE}}}{tag}"


def _xml_response(root: ET.Element) -> Response:
    """Build an XML response from a root element."""
    body = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    return Response(content=body, media_type="text/xml")


def _request_id() -> str:
    """Generate a request id."""
    return str(uuid.uuid4())


def _generate_id(prefix: str) -> str:
    """Generate a short resource id with a prefix."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _parse_params(request: Request, form: Dict[str, str] | None) -> Dict[str, str]:
    """Merge query and form parameters."""
    params: Dict[str, str] = {}
    if request.query_params:
        params.update(request.query_params)
    if form:
        params.update(form)
    return params


def _get_list_params(params: Dict[str, str], prefix: str) -> List[str]:
    """Collect numbered list parameters for a prefix."""
    values = []
    index = 1
    while True:
        key = f"{prefix}.{index}"
        if key not in params:
            break
        values.append(params[key])
        index += 1
    return values


def _vpc_to_xml(vpc: Vpc) -> ET.Element:
    """Serialize a VPC to XML."""
    item = ET.Element("item")
    ET.SubElement(item, "vpcId").text = vpc.id
    ET.SubElement(item, "state").text = vpc.state
    ET.SubElement(item, "cidrBlock").text = vpc.cidr_block
    ET.SubElement(item, "isDefault").text = "false"
    if vpc.ipv6_cidr_block:
        assoc_set = ET.SubElement(item, "ipv6CidrBlockAssociationSet")
        assoc = ET.SubElement(assoc_set, "item")
        ET.SubElement(assoc, "associationId").text = _generate_id("vpc-cidr-assoc")
        ET.SubElement(assoc, "ipv6CidrBlock").text = vpc.ipv6_cidr_block
        state_node = ET.SubElement(assoc, "ipv6CidrBlockState")
        ET.SubElement(state_node, "state").text = "associated"
    return item


def _subnet_to_xml(subnet: Subnet) -> ET.Element:
    """Serialize a subnet to XML."""
    item = ET.Element("item")
    ET.SubElement(item, "subnetId").text = subnet.id
    ET.SubElement(item, "state").text = subnet.state
    ET.SubElement(item, "vpcId").text = subnet.vpc_id
    ET.SubElement(item, "cidrBlock").text = subnet.cidr_block
    if subnet.availability_zone:
        ET.SubElement(item, "availabilityZone").text = subnet.availability_zone
    if subnet.ipv6_cidr_block:
        assoc_set = ET.SubElement(item, "ipv6CidrBlockAssociationSet")
        assoc = ET.SubElement(assoc_set, "item")
        ET.SubElement(assoc, "associationId").text = _generate_id("subnet-cidr-assoc")
        ET.SubElement(assoc, "ipv6CidrBlock").text = subnet.ipv6_cidr_block
        state_node = ET.SubElement(assoc, "ipv6CidrBlockState")
        ET.SubElement(state_node, "state").text = "associated"
    return item


def _route_to_xml(route: Route) -> ET.Element:
    """Serialize a route to XML."""
    item = ET.Element("item")
    try:
        is_ipv6 = ipaddress.ip_network(route.destination_cidr, strict=False).version == 6
    except ValueError:
        is_ipv6 = False
    if is_ipv6:
        ET.SubElement(item, "destinationIpv6CidrBlock").text = route.destination_cidr
    else:
        ET.SubElement(item, "destinationCidrBlock").text = route.destination_cidr
    ET.SubElement(item, "state").text = route.state
    if route.target_type == "igw":
        ET.SubElement(item, "gatewayId").text = route.target_id
    if route.target_type == "pcx":
        ET.SubElement(item, "vpcPeeringConnectionId").text = route.target_id
    return item


def _association_to_xml(association: RouteTableAssociation) -> ET.Element:
    """Serialize a route table association to XML."""
    item = ET.Element("item")
    ET.SubElement(item, "routeTableAssociationId").text = association.id
    ET.SubElement(item, "routeTableId").text = association.route_table_id
    ET.SubElement(item, "subnetId").text = association.subnet_id
    ET.SubElement(item, "main").text = "true" if association.main else "false"
    return item


def _route_table_to_xml(route_table: RouteTable) -> ET.Element:
    """Serialize a route table to XML."""
    item = ET.Element("item")
    ET.SubElement(item, "routeTableId").text = route_table.id
    ET.SubElement(item, "vpcId").text = route_table.vpc_id

    associations = ET.SubElement(item, "associationSet")
    for association in route_table.associations:
        associations.append(_association_to_xml(association))

    routes = ET.SubElement(item, "routeSet")
    for route in route_table.routes:
        routes.append(_route_to_xml(route))

    return item


def _igw_to_xml(igw: InternetGateway) -> ET.Element:
    """Serialize an internet gateway to XML."""
    item = ET.Element("item")
    ET.SubElement(item, "internetGatewayId").text = igw.id
    attachments = ET.SubElement(item, "attachmentSet")
    if igw.vpc_id:
        attach = ET.SubElement(attachments, "item")
        ET.SubElement(attach, "vpcId").text = igw.vpc_id
        ET.SubElement(attach, "state").text = "available"
    return item


def _peering_to_xml(peering: VpcPeeringConnection) -> ET.Element:
    """Serialize a VPC peering connection to XML."""
    item = ET.Element("item")
    ET.SubElement(item, "vpcPeeringConnectionId").text = peering.id
    ET.SubElement(item, "status").text = peering.status
    requester = ET.SubElement(item, "requesterVpcInfo")
    ET.SubElement(requester, "vpcId").text = peering.requester_vpc_id
    accepter = ET.SubElement(item, "accepterVpcInfo")
    ET.SubElement(accepter, "vpcId").text = peering.accepter_vpc_id
    return item


def _xml_error(code: str, message: str) -> Response:
    """Build an EC2 Query error response."""
    root = ET.Element(_ns_tag("Response"))
    errors = ET.SubElement(root, "Errors")
    error = ET.SubElement(errors, "Error")
    ET.SubElement(error, "Code").text = code
    ET.SubElement(error, "Message").text = message
    ET.SubElement(root, "RequestID").text = _request_id()
    return _xml_response(root)


def _validate_cidr_within(parent: str, child: str) -> bool:
    """Validate that a CIDR is within another CIDR."""
    parent_net = ipaddress.ip_network(parent, strict=False)
    child_net = ipaddress.ip_network(child, strict=False)
    if isinstance(parent_net, ipaddress.IPv4Network) and isinstance(child_net, ipaddress.IPv4Network):
        return child_net.subnet_of(parent_net)
    if isinstance(parent_net, ipaddress.IPv6Network) and isinstance(child_net, ipaddress.IPv6Network):
        return child_net.subnet_of(parent_net)
    return False


def _cidr_overlaps(existing: List[str], candidate: str) -> bool:
    """Check whether a candidate CIDR overlaps an existing set."""
    candidate_net = ipaddress.ip_network(candidate)
    for cidr in existing:
        if candidate_net.overlaps(ipaddress.ip_network(cidr)):
            return True
    return False


def _generate_ipv6_cidr() -> str:
    """Generate a pseudo-random IPv6 CIDR for the simulator."""
    hex_bits = uuid.uuid4().hex[:8]
    return f"fd00:{hex_bits[:4]}:{hex_bits[4:]}::/56"


def _validate_subnet_request(vpc: Vpc, cidr: str, ipv6_cidr: str | None) -> Response | None:
    """Validate subnet CIDRs against VPC ranges."""
    if not _validate_cidr_within(vpc.cidr_block, cidr):
        return _xml_error("InvalidSubnet.Range", "Subnet CIDR must be within VPC CIDR")
    existing = [subnet.cidr_block for subnet in vpc.subnets]
    if _cidr_overlaps(existing, cidr):
        return _xml_error("InvalidSubnet.Conflict", "Subnet CIDR overlaps existing subnet")
    if ipv6_cidr:
        if not vpc.ipv6_cidr_block:
            return _xml_error("InvalidSubnet.Range", "VPC does not have an IPv6 CIDR")
        if not _validate_cidr_within(vpc.ipv6_cidr_block, ipv6_cidr):
            return _xml_error(
                "InvalidSubnet.Range",
                "Subnet IPv6 CIDR must be within VPC IPv6 CIDR",
            )
        existing_v6 = [
            subnet.ipv6_cidr_block for subnet in vpc.subnets if subnet.ipv6_cidr_block
        ]
        if _cidr_overlaps(existing_v6, ipv6_cidr):
            return _xml_error(
                "InvalidSubnet.Conflict",
                "Subnet IPv6 CIDR overlaps existing subnet",
            )
    return None


@router.api_route("/", methods=["GET", "POST"])
async def ec2_entry(request: Request) -> Response:
    """Single EC2 Query entrypoint."""
    form = None
    if request.method == "POST":
        form_data = await request.form()
        form = {k: str(v) for k, v in form_data.items()}
    params = _parse_params(request, form)
    action = params.get("Action")
    if not action:
        return _xml_error("MissingAction", "Action parameter is required")

    with SessionLocal() as session:
        handler = _ACTIONS.get(action)
        if not handler:
            return _xml_error("InvalidAction", f"Unsupported action: {action}")
        missing = validate_required_params(action, params)
        if missing:
            return _xml_error(
                "MissingParameter",
                f"Missing required parameter(s): {', '.join(missing)}",
            )
        invalid = validate_params(action, params)
        if invalid:
            return _xml_error("InvalidParameterValue", "; ".join(invalid))

        if EC2_SHAPES:
            input_data = parse_action_input(action, params)
            model_name = get_input_shape_name(action)
            if model_name and hasattr(EC2_SHAPES, model_name):
                model = getattr(EC2_SHAPES, model_name)
                try:
                    model(**input_data)
                except ValidationError as exc:
                    return _xml_error("InvalidParameterValue", str(exc.errors()))
        return handler(session, params)


def _create_vpc(session: Session, params: Dict[str, str]) -> Response:
    """Handle CreateVpc."""
    cidr = params.get("CidrBlock")
    ipv6_cidr = params.get("Ipv6CidrBlock")
    auto_ipv6 = params.get("AmazonProvidedIpv6CidrBlock") or params.get("AssignGeneratedIpv6CidrBlock")
    if not cidr:
        return _xml_error("MissingParameter", "CidrBlock is required")
    if auto_ipv6 and not ipv6_cidr:
        ipv6_cidr = _generate_ipv6_cidr()

    vpc = Vpc(id=_generate_id("vpc"), cidr_block=cidr, ipv6_cidr_block=ipv6_cidr, state="available")
    session.add(vpc)
    session.commit()

    root = ET.Element(_ns_tag("CreateVpcResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    vpc_node = ET.SubElement(root, "vpc")
    vpc_node.append(_vpc_to_xml(vpc))
    return _xml_response(root)


def _describe_vpcs(session: Session, params: Dict[str, str]) -> Response:
    """Handle DescribeVpcs."""
    vpc_ids = _get_list_params(params, "VpcId")
    query = session.query(Vpc)
    if vpc_ids:
        query = query.filter(Vpc.id.in_(vpc_ids))
    vpcs = query.all()

    root = ET.Element(_ns_tag("DescribeVpcsResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    vpc_set = ET.SubElement(root, "vpcSet")
    for vpc in vpcs:
        vpc_set.append(_vpc_to_xml(vpc))
    return _xml_response(root)


def _delete_vpc(session: Session, params: Dict[str, str]) -> Response:
    """Handle DeleteVpc."""
    vpc_id = params.get("VpcId")
    if not vpc_id:
        return _xml_error("MissingParameter", "VpcId is required")
    vpc = session.get(Vpc, vpc_id)
    if not vpc:
        return _xml_error("InvalidVpcID.NotFound", f"Vpc {vpc_id} not found")
    if vpc.subnets:
        return _xml_error("DependencyViolation", "VPC has subnets")
    session.delete(vpc)
    session.commit()

    root = ET.Element(_ns_tag("DeleteVpcResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
    return _xml_response(root)


def _create_subnet(session: Session, params: Dict[str, str]) -> Response:
    """Handle CreateSubnet."""
    vpc_id = params.get("VpcId")
    cidr = params.get("CidrBlock")
    ipv6_cidr = params.get("Ipv6CidrBlock")
    az = params.get("AvailabilityZone")
    if not vpc_id or not cidr:
        return _xml_error("MissingParameter", "VpcId and CidrBlock are required")
    vpc = session.get(Vpc, vpc_id)
    if not vpc:
        return _xml_error("InvalidVpcID.NotFound", f"Vpc {vpc_id} not found")
    validation_error = _validate_subnet_request(vpc, cidr, ipv6_cidr)
    if validation_error:
        return validation_error

    subnet = Subnet(
        id=_generate_id("subnet"),
        vpc_id=vpc_id,
        cidr_block=cidr,
        ipv6_cidr_block=ipv6_cidr,
        availability_zone=az,
        state="available",
    )
    session.add(subnet)
    session.commit()

    root = ET.Element(_ns_tag("CreateSubnetResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    subnet_node = ET.SubElement(root, "subnet")
    subnet_node.append(_subnet_to_xml(subnet))
    return _xml_response(root)


def _describe_subnets(session: Session, params: Dict[str, str]) -> Response:
    """Handle DescribeSubnets."""
    subnet_ids = _get_list_params(params, "SubnetId")
    query = session.query(Subnet)
    if subnet_ids:
        query = query.filter(Subnet.id.in_(subnet_ids))
    subnets = query.all()

    root = ET.Element(_ns_tag("DescribeSubnetsResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    subnet_set = ET.SubElement(root, "subnetSet")
    for subnet in subnets:
        subnet_set.append(_subnet_to_xml(subnet))
    return _xml_response(root)


def _delete_subnet(session: Session, params: Dict[str, str]) -> Response:
    """Handle DeleteSubnet."""
    subnet_id = params.get("SubnetId")
    if not subnet_id:
        return _xml_error("MissingParameter", "SubnetId is required")
    subnet = session.get(Subnet, subnet_id)
    if not subnet:
        return _xml_error("InvalidSubnetID.NotFound", f"Subnet {subnet_id} not found")
    session.delete(subnet)
    session.commit()

    root = ET.Element(_ns_tag("DeleteSubnetResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
    return _xml_response(root)


def _create_route_table(session: Session, params: Dict[str, str]) -> Response:
    """Handle CreateRouteTable."""
    vpc_id = params.get("VpcId")
    if not vpc_id:
        return _xml_error("MissingParameter", "VpcId is required")
    vpc = session.get(Vpc, vpc_id)
    if not vpc:
        return _xml_error("InvalidVpcID.NotFound", f"Vpc {vpc_id} not found")

    route_table = RouteTable(id=_generate_id("rtb"), vpc_id=vpc_id)
    session.add(route_table)
    session.commit()

    root = ET.Element(_ns_tag("CreateRouteTableResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    rtb_node = ET.SubElement(root, "routeTable")
    rtb_node.append(_route_table_to_xml(route_table))
    return _xml_response(root)


def _describe_route_tables(session: Session, params: Dict[str, str]) -> Response:
    """Handle DescribeRouteTables."""
    rtb_ids = _get_list_params(params, "RouteTableId")
    query = session.query(RouteTable)
    if rtb_ids:
        query = query.filter(RouteTable.id.in_(rtb_ids))
    route_tables = query.all()

    root = ET.Element(_ns_tag("DescribeRouteTablesResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    rtb_set = ET.SubElement(root, "routeTableSet")
    for route_table in route_tables:
        rtb_set.append(_route_table_to_xml(route_table))
    return _xml_response(root)


def _associate_route_table(session: Session, params: Dict[str, str]) -> Response:
    """Handle AssociateRouteTable."""
    route_table_id = params.get("RouteTableId")
    subnet_id = params.get("SubnetId")
    if not route_table_id or not subnet_id:
        return _xml_error("MissingParameter", "RouteTableId and SubnetId are required")
    route_table = session.get(RouteTable, route_table_id)
    subnet = session.get(Subnet, subnet_id)
    if not route_table or not subnet:
        return _xml_error("InvalidRouteTableID.NotFound", "Route table or subnet not found")
    association = RouteTableAssociation(
        id=_generate_id("rtbassoc"),
        route_table_id=route_table_id,
        subnet_id=subnet_id,
        main=False,
    )
    subnet.route_table_id = route_table_id
    session.add(association)
    session.commit()

    root = ET.Element(_ns_tag("AssociateRouteTableResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "associationId").text = association.id
    return _xml_response(root)


def _create_route(session: Session, params: Dict[str, str]) -> Response:
    """Handle CreateRoute."""
    route_table_id = params.get("RouteTableId")
    destination = params.get("DestinationCidrBlock") or params.get("DestinationIpv6CidrBlock")
    gateway_id = params.get("GatewayId")
    peering_id = params.get("VpcPeeringConnectionId")
    if not route_table_id or not destination:
        return _xml_error("MissingParameter", "RouteTableId and destination CIDR are required")
    if not gateway_id and not peering_id:
        return _xml_error("MissingParameter", "GatewayId or VpcPeeringConnectionId is required")

    route_table = session.get(RouteTable, route_table_id)
    if not route_table:
        return _xml_error("InvalidRouteTableID.NotFound", f"Route table {route_table_id} not found")

    if peering_id:
        peering = session.get(VpcPeeringConnection, peering_id)
        if not peering:
            return _xml_error("InvalidVpcPeeringConnectionID.NotFound", f"Peering {peering_id} not found")
        target_type = "pcx"
        target_id = peering_id
    else:
        target_type = "igw"
        target_id = gateway_id

    route = Route(
        id=_generate_id("rt"),
        route_table_id=route_table_id,
        destination_cidr=destination,
        target_type=target_type,
        target_id=target_id,
        state="active",
    )
    session.add(route)
    session.commit()

    root = ET.Element(_ns_tag("CreateRouteResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
    return _xml_response(root)


def _create_igw(session: Session, _params: Dict[str, str]) -> Response:
    """Handle CreateInternetGateway."""
    igw = InternetGateway(id=_generate_id("igw"), vpc_id=None)
    session.add(igw)
    session.commit()

    root = ET.Element(_ns_tag("CreateInternetGatewayResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    igw_node = ET.SubElement(root, "internetGateway")
    igw_node.append(_igw_to_xml(igw))
    return _xml_response(root)


def _describe_igws(session: Session, params: Dict[str, str]) -> Response:
    """Handle DescribeInternetGateways."""
    igw_ids = _get_list_params(params, "InternetGatewayId")
    query = session.query(InternetGateway)
    if igw_ids:
        query = query.filter(InternetGateway.id.in_(igw_ids))
    igws = query.all()

    root = ET.Element(_ns_tag("DescribeInternetGatewaysResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    igw_set = ET.SubElement(root, "internetGatewaySet")
    for igw in igws:
        igw_set.append(_igw_to_xml(igw))
    return _xml_response(root)


def _attach_igw(session: Session, params: Dict[str, str]) -> Response:
    """Handle AttachInternetGateway."""
    igw_id = params.get("InternetGatewayId")
    vpc_id = params.get("VpcId")
    if not igw_id or not vpc_id:
        return _xml_error("MissingParameter", "InternetGatewayId and VpcId are required")
    igw = session.get(InternetGateway, igw_id)
    vpc = session.get(Vpc, vpc_id)
    if not igw or not vpc:
        return _xml_error("InvalidInternetGatewayID.NotFound", "IGW or VPC not found")
    igw.vpc_id = vpc_id
    session.commit()

    root = ET.Element(_ns_tag("AttachInternetGatewayResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
    return _xml_response(root)


def _create_vpc_peering_connection(session: Session, params: Dict[str, str]) -> Response:
    """Handle CreateVpcPeeringConnection."""
    requester_vpc_id = params.get("VpcId")
    accepter_vpc_id = params.get("PeerVpcId")
    if not requester_vpc_id or not accepter_vpc_id:
        return _xml_error("MissingParameter", "VpcId and PeerVpcId are required")
    requester = session.get(Vpc, requester_vpc_id)
    accepter = session.get(Vpc, accepter_vpc_id)
    if not requester or not accepter:
        return _xml_error("InvalidVpcID.NotFound", "Requester or accepter VPC not found")

    peering = VpcPeeringConnection(
        id=_generate_id("pcx"),
        requester_vpc_id=requester_vpc_id,
        accepter_vpc_id=accepter_vpc_id,
        status="active",
    )
    session.add(peering)
    session.commit()

    root = ET.Element(_ns_tag("CreateVpcPeeringConnectionResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    connection = ET.SubElement(root, "vpcPeeringConnection")
    connection.append(_peering_to_xml(peering))
    return _xml_response(root)


def _describe_vpc_peering_connections(session: Session, params: Dict[str, str]) -> Response:
    """Handle DescribeVpcPeeringConnections."""
    pcx_ids = _get_list_params(params, "VpcPeeringConnectionId")
    query = session.query(VpcPeeringConnection)
    if pcx_ids:
        query = query.filter(VpcPeeringConnection.id.in_(pcx_ids))
    connections = query.all()

    root = ET.Element(_ns_tag("DescribeVpcPeeringConnectionsResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    conn_set = ET.SubElement(root, "vpcPeeringConnectionSet")
    for connection in connections:
        conn_set.append(_peering_to_xml(connection))
    return _xml_response(root)


def _accept_vpc_peering_connection(session: Session, params: Dict[str, str]) -> Response:
    """Handle AcceptVpcPeeringConnection."""
    pcx_id = params.get("VpcPeeringConnectionId")
    if not pcx_id:
        return _xml_error("MissingParameter", "VpcPeeringConnectionId is required")
    peering = session.get(VpcPeeringConnection, pcx_id)
    if not peering:
        return _xml_error("InvalidVpcPeeringConnectionID.NotFound", f"Peering {pcx_id} not found")
    peering.status = "active"
    session.commit()

    root = ET.Element(_ns_tag("AcceptVpcPeeringConnectionResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    connection = ET.SubElement(root, "vpcPeeringConnection")
    connection.append(_peering_to_xml(peering))
    return _xml_response(root)


def _delete_vpc_peering_connection(session: Session, params: Dict[str, str]) -> Response:
    """Handle DeleteVpcPeeringConnection."""
    pcx_id = params.get("VpcPeeringConnectionId")
    if not pcx_id:
        return _xml_error("MissingParameter", "VpcPeeringConnectionId is required")
    peering = session.get(VpcPeeringConnection, pcx_id)
    if not peering:
        return _xml_error("InvalidVpcPeeringConnectionID.NotFound", f"Peering {pcx_id} not found")
    session.delete(peering)
    session.commit()

    root = ET.Element(_ns_tag("DeleteVpcPeeringConnectionResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
    return _xml_response(root)


_ACTIONS = {
    "CreateVpc": _create_vpc,
    "DescribeVpcs": _describe_vpcs,
    "DeleteVpc": _delete_vpc,
    "CreateSubnet": _create_subnet,
    "DescribeSubnets": _describe_subnets,
    "DeleteSubnet": _delete_subnet,
    "CreateRouteTable": _create_route_table,
    "DescribeRouteTables": _describe_route_tables,
    "AssociateRouteTable": _associate_route_table,
    "CreateRoute": _create_route,
    "CreateInternetGateway": _create_igw,
    "DescribeInternetGateways": _describe_igws,
    "AttachInternetGateway": _attach_igw,
    "CreateVpcPeeringConnection": _create_vpc_peering_connection,
    "DescribeVpcPeeringConnections": _describe_vpc_peering_connections,
    "AcceptVpcPeeringConnection": _accept_vpc_peering_connection,
    "DeleteVpcPeeringConnection": _delete_vpc_peering_connection,
}
