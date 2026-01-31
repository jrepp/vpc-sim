"""EC2 Query API handlers for the VPC simulator."""
# pylint: disable=too-many-lines
from __future__ import annotations

import ipaddress
import json
import os
import uuid
from typing import Dict, List
from xml.etree import ElementTree as ET

from fastapi import APIRouter, Request, Response
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import SessionLocal
from .ec2_query import get_input_shape_name, parse_action_input
from .ec2_model import validate_params, validate_required_params
from .models import (
    DhcpOptions,
    EgressOnlyInternetGateway,
    ElasticIp,
    FlowLog,
    CustomerGateway,
    InternetGateway,
    NatGateway,
    NatGatewayAddress,
    NetworkAcl,
    NetworkAclAssociation,
    NetworkAclEntry,
    Route,
    RouteTable,
    RouteTableAssociation,
    SecurityGroup,
    SecurityGroupRule,
    Subnet,
    Tag,
    Vpc,
    VpcCidrBlockAssociation,
    VpcEndpoint,
    VpcEndpointConnectionNotification,
    VpcEndpointService,
    VpcEndpointServicePermission,
    VpcPeeringConnection,
    VpnConnection,
    VpnGateway,
)
from .tracing import trace_span

EC2_SHAPES = None
if os.getenv("EC2_VALIDATE_PYDANTIC", "").lower() in {"1", "true", "yes"}:
    try:
        from .generated import ec2_shapes as EC2_SHAPES
    except ImportError:
        EC2_SHAPES = None

NAMESPACE = "http://ec2.amazonaws.com/doc/2016-11-15/"

router = APIRouter()


def _ns_tag(tag: str) -> str:
    """Return a namespaced XML tag."""
    return tag


def _xml_response(root: ET.Element) -> Response:
    """Build an XML response from a root element."""
    if "xmlns" not in root.attrib:
        root.set("xmlns", NAMESPACE)
    body = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    return Response(content=body, media_type="text/xml")


def _request_id() -> str:
    """Generate a request id."""
    return str(uuid.uuid4())


def _generate_id(prefix: str) -> str:
    """Generate a short resource id with a prefix."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _next_public_ip(session: Session) -> str:
    """Allocate a deterministic public IP from TEST-NET-2."""
    offset = session.query(ElasticIp).count()
    octet = 10 + offset % 200
    return f"198.51.100.{octet}"


def _next_private_ip(cidr_block: str) -> str:
    """Pick a stable private IP inside the subnet CIDR."""
    network = ipaddress.ip_network(cidr_block, strict=False)
    return str(network.network_address + 10)


def _seed_default_network_acl_entries(session: Session, acl: NetworkAcl, vpc: Vpc) -> None:
    """Ensure default allow/deny entries exist for a default NACL."""
    existing = session.query(NetworkAclEntry).filter_by(network_acl_id=acl.id).count()
    if existing:
        return
    rules: list[NetworkAclEntry] = []
    for egress in (False, True):
        rules.append(
            NetworkAclEntry(
                id=_generate_id("aclentry"),
                network_acl_id=acl.id,
                rule_number=100,
                protocol="-1",
                rule_action="allow",
                egress=egress,
                cidr_block="0.0.0.0/0",
                ipv6_cidr_block=None,
                from_port=None,
                to_port=None,
            )
        )
        rules.append(
            NetworkAclEntry(
                id=_generate_id("aclentry"),
                network_acl_id=acl.id,
                rule_number=32767,
                protocol="-1",
                rule_action="deny",
                egress=egress,
                cidr_block="0.0.0.0/0",
                ipv6_cidr_block=None,
                from_port=None,
                to_port=None,
            )
        )
        if vpc.ipv6_cidr_block:
            rules.append(
                NetworkAclEntry(
                    id=_generate_id("aclentry"),
                    network_acl_id=acl.id,
                    rule_number=100,
                    protocol="-1",
                    rule_action="allow",
                    egress=egress,
                    cidr_block=None,
                    ipv6_cidr_block="::/0",
                    from_port=None,
                    to_port=None,
                )
            )
            rules.append(
                NetworkAclEntry(
                    id=_generate_id("aclentry"),
                    network_acl_id=acl.id,
                    rule_number=32767,
                    protocol="-1",
                    rule_action="deny",
                    egress=egress,
                    cidr_block=None,
                    ipv6_cidr_block="::/0",
                    from_port=None,
                    to_port=None,
                )
            )
    session.add_all(rules)


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


def _get_nested_list_params(params: Dict[str, str], prefix: str, field: str) -> List[str]:
    """Collect list parameters for a nested field (e.g., Prefix.1.Field)."""
    values = []
    index = 1
    while True:
        key = f"{prefix}.{index}.{field}"
        if key not in params:
            break
        values.append(params[key])
        index += 1
    return values


def _get_filter_params(params: Dict[str, str]) -> List[dict]:
    """Collect filters in the form Filter.n.Name and Filter.n.Value.m."""
    filters: list[dict] = []
    index = 1
    while True:
        name_key = f"Filter.{index}.Name"
        if name_key not in params:
            break
        name = params[name_key]
        values: list[str] = []
        val_index = 1
        while True:
            val_key = f"Filter.{index}.Value.{val_index}"
            if val_key not in params:
                break
            values.append(params[val_key])
            val_index += 1
        if not values and f"Filter.{index}.Value" in params:
            values.append(params[f"Filter.{index}.Value"])
        filters.append({"name": name, "values": values})
        index += 1
    return filters


def _parse_tags(params: Dict[str, str]) -> List[dict]:
    """Parse Tag.n.Key/Tag.n.Value pairs."""
    tags: list[dict] = []
    index = 1
    while True:
        key = params.get(f"Tag.{index}.Key")
        value = params.get(f"Tag.{index}.Value")
        if key is None:
            break
        tags.append({"key": key, "value": value})
        index += 1
    return tags


def _parse_tag_specifications(params: Dict[str, str]) -> list[dict]:
    """Parse TagSpecification.n.ResourceType and TagSpecification.n.Tag.m pairs."""
    specs: list[dict] = []
    spec_index = 1
    while True:
        resource_type = params.get(f"TagSpecification.{spec_index}.ResourceType")
        if resource_type is None:
            break
        tags: list[dict] = []
        tag_index = 1
        while True:
            key = params.get(f"TagSpecification.{spec_index}.Tag.{tag_index}.Key")
            if key is None:
                break
            value = params.get(f"TagSpecification.{spec_index}.Tag.{tag_index}.Value")
            tags.append({"key": key, "value": value})
            tag_index += 1
        specs.append({"resource_type": resource_type, "tags": tags})
        spec_index += 1
    return specs


def _tags_for_resource(tag_specs: list[dict], resource_type: str) -> list[dict]:
    for spec in tag_specs:
        if spec["resource_type"] == resource_type:
            return spec["tags"]
    return []


def _apply_tags(session: Session, resource_id: str, tags: list[dict]) -> None:
    for tag in tags:
        existing = (
            session.query(Tag)
            .filter_by(resource_id=resource_id, key=tag["key"])
            .one_or_none()
        )
        if existing:
            existing.value = tag.get("value")
        else:
            session.add(
                Tag(
                    id=_generate_id("tag"),
                    resource_id=resource_id,
                    key=tag["key"],
                    value=tag.get("value"),
                )
            )


def _resource_type_from_id(resource_id: str) -> str:
    prefix = resource_id.split("-", 1)[0]
    return {
        "vpc": "vpc",
        "subnet": "subnet",
        "igw": "internet-gateway",
        "eipalloc": "elastic-ip",
        "nat": "natgateway",
        "vpce": "vpc-endpoint",
        "vpcesvc": "vpc-endpoint-service",
        "rtb": "route-table",
        "rtbassoc": "route-table-association",
        "pcx": "vpc-peering-connection",
        "dopt": "dhcp-options",
        "sg": "security-group",
    }.get(prefix, "unknown")


def _vpc_fields(node: ET.Element, vpc: Vpc) -> None:
    """Populate VPC XML fields on an element."""
    ET.SubElement(node, "vpcId").text = vpc.id
    ET.SubElement(node, "state").text = vpc.state
    ET.SubElement(node, "cidrBlock").text = vpc.cidr_block
    ET.SubElement(node, "isDefault").text = "false"
    ipv4_assocs = [assoc for assoc in vpc.cidr_associations if not assoc.is_ipv6]
    if ipv4_assocs:
        assoc_set = ET.SubElement(node, "cidrBlockAssociationSet")
        for assoc in ipv4_assocs:
            item = ET.SubElement(assoc_set, "item")
            ET.SubElement(item, "associationId").text = assoc.id
            ET.SubElement(item, "cidrBlock").text = assoc.cidr_block
            state_node = ET.SubElement(item, "cidrBlockState")
            ET.SubElement(state_node, "state").text = assoc.state
    ipv6_assocs = [assoc for assoc in vpc.cidr_associations if assoc.is_ipv6]
    if ipv6_assocs:
        assoc_set = ET.SubElement(node, "ipv6CidrBlockAssociationSet")
        for assoc in ipv6_assocs:
            item = ET.SubElement(assoc_set, "item")
            ET.SubElement(item, "associationId").text = assoc.id
            ET.SubElement(item, "ipv6CidrBlock").text = assoc.cidr_block
            state_node = ET.SubElement(item, "ipv6CidrBlockState")
            ET.SubElement(state_node, "state").text = assoc.state
    elif vpc.ipv6_cidr_block:
        assoc_set = ET.SubElement(node, "ipv6CidrBlockAssociationSet")
        assoc = ET.SubElement(assoc_set, "item")
        assoc_id = vpc.ipv6_association_id or _generate_id("vpc-cidr-assoc")
        ET.SubElement(assoc, "associationId").text = assoc_id
        ET.SubElement(assoc, "ipv6CidrBlock").text = vpc.ipv6_cidr_block
        state_node = ET.SubElement(assoc, "ipv6CidrBlockState")
        ET.SubElement(state_node, "state").text = "associated"
    if vpc.dhcp_options_id:
        ET.SubElement(node, "dhcpOptionsId").text = vpc.dhcp_options_id


def _vpc_to_xml(vpc: Vpc) -> ET.Element:
    """Serialize a VPC to XML item."""
    item = ET.Element("item")
    _vpc_fields(item, vpc)
    return item


def _subnet_fields(node: ET.Element, subnet: Subnet) -> None:
    """Populate subnet XML fields on an element."""
    ET.SubElement(node, "subnetId").text = subnet.id
    ET.SubElement(node, "state").text = subnet.state
    ET.SubElement(node, "vpcId").text = subnet.vpc_id
    ET.SubElement(node, "cidrBlock").text = subnet.cidr_block
    if subnet.availability_zone:
        ET.SubElement(node, "availabilityZone").text = subnet.availability_zone
    ET.SubElement(node, "assignIpv6AddressOnCreation").text = (
        "true" if subnet.assign_ipv6_address_on_creation else "false"
    )
    if subnet.ipv6_cidr_block:
        assoc_set = ET.SubElement(node, "ipv6CidrBlockAssociationSet")
        assoc = ET.SubElement(assoc_set, "item")
        assoc_id = subnet.ipv6_association_id or _generate_id("subnet-cidr-assoc")
        ET.SubElement(assoc, "associationId").text = assoc_id
        ET.SubElement(assoc, "ipv6CidrBlock").text = subnet.ipv6_cidr_block
        state_node = ET.SubElement(assoc, "ipv6CidrBlockState")
        ET.SubElement(state_node, "state").text = "associated"


def _subnet_to_xml(subnet: Subnet) -> ET.Element:
    """Serialize a subnet to XML item."""
    item = ET.Element("item")
    _subnet_fields(item, subnet)
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
    if route.target_type == "local":
        ET.SubElement(item, "gatewayId").text = "local"
    if route.target_type == "pcx":
        ET.SubElement(item, "vpcPeeringConnectionId").text = route.target_id
    return item


def _association_to_xml(association: RouteTableAssociation) -> ET.Element:
    """Serialize a route table association to XML."""
    item = ET.Element("item")
    ET.SubElement(item, "routeTableAssociationId").text = association.id
    ET.SubElement(item, "routeTableId").text = association.route_table_id
    if association.subnet_id:
        ET.SubElement(item, "subnetId").text = association.subnet_id
    ET.SubElement(item, "main").text = "true" if association.main else "false"
    return item


def _route_table_fields(node: ET.Element, route_table: RouteTable) -> None:
    """Populate route table XML fields on an element."""
    ET.SubElement(node, "routeTableId").text = route_table.id
    ET.SubElement(node, "vpcId").text = route_table.vpc_id

    associations = ET.SubElement(node, "associationSet")
    if route_table.associations:
        for association in route_table.associations:
            associations.append(_association_to_xml(association))
    else:
        item = ET.SubElement(associations, "item")
        ET.SubElement(item, "routeTableAssociationId").text = _generate_id("rtbassoc")
        ET.SubElement(item, "routeTableId").text = route_table.id
        ET.SubElement(item, "main").text = "false"

    routes = ET.SubElement(node, "routeSet")
    for route in route_table.routes:
        routes.append(_route_to_xml(route))

    ET.SubElement(node, "propagatingVgwSet")
    ET.SubElement(node, "tagSet")


def _route_table_to_xml(route_table: RouteTable) -> ET.Element:
    """Serialize a route table to XML item."""
    item = ET.Element("item")
    _route_table_fields(item, route_table)
    return item


def _igw_fields(node: ET.Element, igw: InternetGateway) -> None:
    """Populate internet gateway XML fields on an element."""
    ET.SubElement(node, "internetGatewayId").text = igw.id
    attachments = ET.SubElement(node, "attachmentSet")
    if igw.vpc_id:
        attach = ET.SubElement(attachments, "item")
        ET.SubElement(attach, "vpcId").text = igw.vpc_id
        ET.SubElement(attach, "state").text = "available"


def _igw_to_xml(igw: InternetGateway) -> ET.Element:
    """Serialize an internet gateway to XML item."""
    item = ET.Element("item")
    _igw_fields(item, igw)
    return item


def _egress_only_igw_fields(node: ET.Element, igw: EgressOnlyInternetGateway) -> None:
    ET.SubElement(node, "egressOnlyInternetGatewayId").text = igw.id
    attachments = ET.SubElement(node, "attachmentSet")
    attach = ET.SubElement(attachments, "item")
    ET.SubElement(attach, "vpcId").text = igw.vpc_id
    ET.SubElement(attach, "state").text = "attached"


def _egress_only_igw_to_xml(igw: EgressOnlyInternetGateway) -> ET.Element:
    item = ET.Element("item")
    _egress_only_igw_fields(item, igw)
    return item


def _elastic_ip_to_xml(address: ElasticIp) -> ET.Element:
    item = ET.Element("item")
    ET.SubElement(item, "allocationId").text = address.id
    ET.SubElement(item, "publicIp").text = address.public_ip
    ET.SubElement(item, "domain").text = address.domain
    return item


def _nat_gateway_address_to_xml(address: NatGatewayAddress) -> ET.Element:
    item = ET.Element("item")
    ET.SubElement(item, "allocationId").text = address.allocation_id
    ET.SubElement(item, "publicIp").text = address.public_ip
    ET.SubElement(item, "privateIp").text = address.private_ip
    return item


def _nat_gateway_fields(
    node: ET.Element, nat_gateway: NatGateway, addresses: List[NatGatewayAddress]
) -> None:
    ET.SubElement(node, "natGatewayId").text = nat_gateway.id
    ET.SubElement(node, "subnetId").text = nat_gateway.subnet_id
    ET.SubElement(node, "vpcId").text = nat_gateway.vpc_id
    ET.SubElement(node, "state").text = nat_gateway.state
    ET.SubElement(node, "createTime").text = nat_gateway.created_at.isoformat()
    addr_set = ET.SubElement(node, "natGatewayAddressSet")
    for address in addresses:
        addr_set.append(_nat_gateway_address_to_xml(address))


def _nat_gateway_to_xml(nat_gateway: NatGateway, addresses: List[NatGatewayAddress]) -> ET.Element:
    item = ET.Element("item")
    _nat_gateway_fields(item, nat_gateway, addresses)
    return item


def _vpc_endpoint_fields(node: ET.Element, endpoint: VpcEndpoint) -> None:
    ET.SubElement(node, "vpcEndpointId").text = endpoint.id
    ET.SubElement(node, "vpcId").text = endpoint.vpc_id
    ET.SubElement(node, "serviceName").text = endpoint.service_name
    ET.SubElement(node, "vpcEndpointType").text = endpoint.vpc_endpoint_type
    ET.SubElement(node, "state").text = endpoint.state
    route_set = ET.SubElement(node, "routeTableIdSet")
    for route_id in json.loads(endpoint.route_table_ids_json):
        ET.SubElement(route_set, "item").text = route_id
    subnet_set = ET.SubElement(node, "subnetIdSet")
    for subnet_id in json.loads(endpoint.subnet_ids_json):
        ET.SubElement(subnet_set, "item").text = subnet_id
    group_set = ET.SubElement(node, "groupSet")
    for group_id in json.loads(endpoint.security_group_ids_json):
        entry = ET.SubElement(group_set, "item")
        ET.SubElement(entry, "groupId").text = group_id


def _vpc_endpoint_to_xml(endpoint: VpcEndpoint) -> ET.Element:
    item = ET.Element("item")
    _vpc_endpoint_fields(item, endpoint)
    return item


def _flow_log_to_xml(flow_log: FlowLog) -> ET.Element:
    item = ET.Element("item")
    ET.SubElement(item, "flowLogId").text = flow_log.id
    ET.SubElement(item, "resourceId").text = flow_log.resource_id
    ET.SubElement(item, "resourceType").text = flow_log.resource_type
    ET.SubElement(item, "trafficType").text = flow_log.traffic_type
    ET.SubElement(item, "logDestinationType").text = flow_log.log_destination_type
    ET.SubElement(item, "logDestination").text = flow_log.log_destination
    ET.SubElement(item, "flowLogStatus").text = flow_log.status
    ET.SubElement(item, "creationTime").text = flow_log.created_at.isoformat()
    return item


def _customer_gateway_fields(node: ET.Element, gateway: CustomerGateway) -> None:
    ET.SubElement(node, "customerGatewayId").text = gateway.id
    ET.SubElement(node, "bgpAsn").text = gateway.bgp_asn
    ET.SubElement(node, "ipAddress").text = gateway.ip_address
    ET.SubElement(node, "type").text = gateway.gateway_type
    ET.SubElement(node, "state").text = gateway.state


def _customer_gateway_to_xml(gateway: CustomerGateway) -> ET.Element:
    item = ET.Element("item")
    _customer_gateway_fields(item, gateway)
    return item


def _vpn_gateway_fields(node: ET.Element, gateway: VpnGateway) -> None:
    ET.SubElement(node, "vpnGatewayId").text = gateway.id
    ET.SubElement(node, "type").text = gateway.gateway_type
    ET.SubElement(node, "state").text = gateway.state
    attachments = ET.SubElement(node, "attachments")
    if gateway.vpc_id:
        attachment = ET.SubElement(attachments, "item")
        ET.SubElement(attachment, "vpcId").text = gateway.vpc_id
        ET.SubElement(attachment, "state").text = "attached"


def _vpn_gateway_to_xml(gateway: VpnGateway) -> ET.Element:
    item = ET.Element("item")
    _vpn_gateway_fields(item, gateway)
    return item


def _vpn_connection_fields(node: ET.Element, connection: VpnConnection) -> None:
    ET.SubElement(node, "vpnConnectionId").text = connection.id
    ET.SubElement(node, "customerGatewayId").text = connection.customer_gateway_id
    ET.SubElement(node, "vpnGatewayId").text = connection.vpn_gateway_id
    ET.SubElement(node, "type").text = connection.connection_type
    ET.SubElement(node, "state").text = connection.state


def _vpn_connection_to_xml(connection: VpnConnection) -> ET.Element:
    item = ET.Element("item")
    _vpn_connection_fields(item, connection)
    return item


def _endpoint_service_fields(node: ET.Element, service: VpcEndpointService) -> None:
    ET.SubElement(node, "serviceId").text = service.id
    ET.SubElement(node, "serviceName").text = service.service_name
    ET.SubElement(node, "serviceState").text = service.state
    ET.SubElement(node, "acceptanceRequired").text = "true" if service.acceptance_required else "false"
    service_types = ET.SubElement(node, "serviceType")
    type_item = ET.SubElement(service_types, "item")
    ET.SubElement(type_item, "serviceType").text = "Interface"
    supported_ip_types = ET.SubElement(node, "supportedIpAddressTypeSet")
    ET.SubElement(supported_ip_types, "item").text = "ipv4"
    ET.SubElement(node, "managesVpcEndpoints").text = "false"
    nlb_set = ET.SubElement(node, "networkLoadBalancerArns")
    for arn in json.loads(service.network_load_balancer_arns_json):
        ET.SubElement(nlb_set, "item").text = arn
    gwlb_set = ET.SubElement(node, "gatewayLoadBalancerArns")
    for arn in json.loads(service.gateway_load_balancer_arns_json):
        ET.SubElement(gwlb_set, "item").text = arn


def _endpoint_service_to_xml(service: VpcEndpointService) -> ET.Element:
    item = ET.Element("item")
    _endpoint_service_fields(item, service)
    return item


def _connection_notification_fields(node: ET.Element, notification: VpcEndpointConnectionNotification) -> None:
    ET.SubElement(node, "connectionNotificationId").text = notification.id
    if notification.service_id:
        ET.SubElement(node, "serviceId").text = notification.service_id
    if notification.vpc_endpoint_id:
        ET.SubElement(node, "vpcEndpointId").text = notification.vpc_endpoint_id
    ET.SubElement(node, "connectionNotificationArn").text = notification.connection_notification_arn
    ET.SubElement(node, "connectionNotificationType").text = notification.connection_notification_type
    ET.SubElement(node, "connectionNotificationState").text = notification.connection_notification_state
    event_set = ET.SubElement(node, "connectionEvents")
    for event in json.loads(notification.connection_events_json):
        ET.SubElement(event_set, "item").text = event


def _connection_notification_to_xml(notification: VpcEndpointConnectionNotification) -> ET.Element:
    item = ET.Element("item")
    _connection_notification_fields(item, notification)
    return item


def _peering_fields(node: ET.Element, peering: VpcPeeringConnection) -> None:
    """Populate peering XML fields on an element."""
    ET.SubElement(node, "vpcPeeringConnectionId").text = peering.id
    status = ET.SubElement(node, "status")
    ET.SubElement(status, "code").text = peering.status
    ET.SubElement(status, "message").text = peering.status.replace("-", " ").title()
    requester = ET.SubElement(node, "requesterVpcInfo")
    ET.SubElement(requester, "vpcId").text = peering.requester_vpc_id
    accepter = ET.SubElement(node, "accepterVpcInfo")
    ET.SubElement(accepter, "vpcId").text = peering.accepter_vpc_id


def _peering_to_xml(peering: VpcPeeringConnection) -> ET.Element:
    """Serialize a VPC peering connection to XML item."""
    item = ET.Element("item")
    _peering_fields(item, peering)
    return item


def _dhcp_options_fields(node: ET.Element, options: DhcpOptions) -> None:
    ET.SubElement(node, "dhcpOptionsId").text = options.id
    config_set = ET.SubElement(node, "dhcpConfigurationSet")
    try:
        configs = json.loads(options.configurations_json)
    except json.JSONDecodeError:
        configs = []
    for config in configs:
        entry = ET.SubElement(config_set, "item")
        ET.SubElement(entry, "key").text = config.get("key")
        values = ET.SubElement(entry, "valueSet")
        for value in config.get("values", []):
            value_item = ET.SubElement(values, "item")
            ET.SubElement(value_item, "value").text = value


def _dhcp_options_to_xml(options: DhcpOptions) -> ET.Element:
    item = ET.Element("item")
    _dhcp_options_fields(item, options)
    return item


def _network_acl_entry_to_xml(entry: NetworkAclEntry) -> ET.Element:
    item = ET.Element("item")
    ET.SubElement(item, "ruleNumber").text = str(entry.rule_number)
    ET.SubElement(item, "protocol").text = entry.protocol
    ET.SubElement(item, "ruleAction").text = entry.rule_action
    ET.SubElement(item, "egress").text = "true" if entry.egress else "false"
    if entry.cidr_block:
        ET.SubElement(item, "cidrBlock").text = entry.cidr_block
    if entry.ipv6_cidr_block:
        ET.SubElement(item, "ipv6CidrBlock").text = entry.ipv6_cidr_block
    if entry.from_port is not None or entry.to_port is not None:
        port_range = ET.SubElement(item, "portRange")
        if entry.from_port is not None:
            ET.SubElement(port_range, "from").text = str(entry.from_port)
        if entry.to_port is not None:
            ET.SubElement(port_range, "to").text = str(entry.to_port)
    return item


def _network_acl_association_to_xml(association: NetworkAclAssociation) -> ET.Element:
    item = ET.Element("item")
    ET.SubElement(item, "networkAclAssociationId").text = association.id
    ET.SubElement(item, "networkAclId").text = association.network_acl_id
    ET.SubElement(item, "subnetId").text = association.subnet_id
    return item


def _network_acl_fields(node: ET.Element, acl: NetworkAcl) -> None:
    ET.SubElement(node, "networkAclId").text = acl.id
    ET.SubElement(node, "vpcId").text = acl.vpc_id
    ET.SubElement(node, "isDefault").text = "true" if acl.is_default else "false"

    entry_set = ET.SubElement(node, "entrySet")
    for entry in acl.entries:
        entry_set.append(_network_acl_entry_to_xml(entry))

    assoc_set = ET.SubElement(node, "associationSet")
    for association in acl.associations:
        assoc_set.append(_network_acl_association_to_xml(association))


def _network_acl_to_xml(acl: NetworkAcl) -> ET.Element:
    item = ET.Element("item")
    _network_acl_fields(item, acl)
    return item


def _security_group_to_xml(group: SecurityGroup) -> ET.Element:
    item = ET.Element("item")
    ET.SubElement(item, "groupId").text = group.id
    ET.SubElement(item, "groupName").text = group.name
    ET.SubElement(item, "groupDescription").text = group.description
    ET.SubElement(item, "vpcId").text = group.vpc_id

    ingress = ET.SubElement(item, "ipPermissions")
    egress = ET.SubElement(item, "ipPermissionsEgress")
    for rule in group.rules:
        perm = _rule_to_permission_xml(rule)
        if rule.direction == "ingress":
            ingress.append(perm)
        else:
            egress.append(perm)
    return item


def _rule_to_permission_xml(rule: SecurityGroupRule) -> ET.Element:
    perm = ET.Element("item")
    ET.SubElement(perm, "ipProtocol").text = rule.protocol
    if rule.from_port is not None:
        ET.SubElement(perm, "fromPort").text = str(rule.from_port)
    if rule.to_port is not None:
        ET.SubElement(perm, "toPort").text = str(rule.to_port)
    if rule.cidr_ipv4:
        ranges = ET.SubElement(perm, "ipRanges")
        entry = ET.SubElement(ranges, "item")
        ET.SubElement(entry, "cidrIp").text = rule.cidr_ipv4
    if rule.cidr_ipv6:
        ranges = ET.SubElement(perm, "ipv6Ranges")
        entry = ET.SubElement(ranges, "item")
        ET.SubElement(entry, "cidrIpv6").text = rule.cidr_ipv6
    if rule.source_group_id:
        pairs = ET.SubElement(perm, "userIdGroupPairs")
        entry = ET.SubElement(pairs, "item")
        ET.SubElement(entry, "groupId").text = rule.source_group_id
    return perm


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


def _parse_dhcp_configurations(params: Dict[str, str]) -> list[dict]:
    configs = []
    index = 1
    while True:
        key = params.get(f"DhcpConfiguration.{index}.Key")
        if not key:
            break
        values = _get_list_params(params, f"DhcpConfiguration.{index}.Value")
        configs.append({"key": key, "values": values})
        index += 1
    return configs


def _parse_ip_permissions(params: Dict[str, str], prefix: str) -> list[dict]:
    permissions = []
    index = 1
    while True:
        base = f"{prefix}.{index}"
        proto = params.get(f"{base}.IpProtocol")
        if not proto:
            break
        from_port = params.get(f"{base}.FromPort")
        to_port = params.get(f"{base}.ToPort")
        ipv4_ranges = _get_nested_list_params(params, f"{base}.IpRanges", "CidrIp")
        ipv6_ranges = _get_nested_list_params(params, f"{base}.Ipv6Ranges", "CidrIpv6")
        group_pairs = _get_nested_list_params(params, f"{base}.UserIdGroupPairs", "GroupId")
        permissions.append(
            {
                "protocol": proto,
                "from_port": from_port,
                "to_port": to_port,
                "ipv4_ranges": ipv4_ranges,
                "ipv6_ranges": ipv6_ranges,
                "group_pairs": group_pairs,
            }
        )
        index += 1
    return permissions


@router.api_route("/", methods=["GET", "POST"])
async def ec2_entry(request: Request) -> Response:
    """Single EC2 Query entrypoint."""
    form = None
    with trace_span("ec2.parse_request"):
        if request.method == "POST":
            form_data = await request.form()
            form = {k: str(v) for k, v in form_data.items()}
    with trace_span("ec2.parse_params"):
        params = _parse_params(request, form)
    action = params.get("Action")
    if not action:
        return _xml_error("MissingAction", "Action parameter is required")

    if os.getenv("EC2_TRACE", "").lower() in {"1", "true", "yes"}:
        print(f"EC2_TRACE action={action} params={params}")

    with SessionLocal() as session:
        handler = _ACTIONS.get(action)
        if not handler:
            return _xml_error("InvalidAction", f"Unsupported action: {action}")
        with trace_span("ec2.validate_required"):
            missing = validate_required_params(action, params)
        if missing:
            return _xml_error(
                "MissingParameter",
                f"Missing required parameter(s): {', '.join(missing)}",
            )
        with trace_span("ec2.validate_params"):
            invalid = validate_params(action, params)
        if invalid:
            return _xml_error("InvalidParameterValue", "; ".join(invalid))

        if EC2_SHAPES:
            with trace_span("ec2.parse_shape_input"):
                input_data = parse_action_input(action, params)
                model_name = get_input_shape_name(action)
            if model_name and hasattr(EC2_SHAPES, model_name):
                model = getattr(EC2_SHAPES, model_name)
                try:
                    with trace_span("ec2.validate_shape"):
                        model(**input_data)
                except ValidationError as exc:
                    return _xml_error("InvalidParameterValue", str(exc.errors()))
        with trace_span(f"ec2.action.{action}"):
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

    tag_specs = _parse_tag_specifications(params)

    vpc = Vpc(
        id=_generate_id("vpc"),
        cidr_block=cidr,
        ipv6_cidr_block=ipv6_cidr,
        ipv6_association_id=_generate_id("vpc-cidr-assoc") if ipv6_cidr else None,
        state="available",
        enable_dns_support=True,
        enable_dns_hostnames=False,
        enable_network_address_usage_metrics=False,
    )
    session.add(vpc)
    session.add(
        VpcCidrBlockAssociation(
            id=_generate_id("vpc-cidr-assoc"),
            vpc_id=vpc.id,
            cidr_block=cidr,
            is_ipv6=False,
        )
    )
    if ipv6_cidr:
        session.add(
            VpcCidrBlockAssociation(
                id=vpc.ipv6_association_id or _generate_id("vpc-cidr-assoc"),
                vpc_id=vpc.id,
                cidr_block=ipv6_cidr,
                is_ipv6=True,
            )
        )
    default_acl = NetworkAcl(
        id=_generate_id("acl"),
        vpc_id=vpc.id,
        is_default=True,
    )
    session.add(default_acl)
    _seed_default_network_acl_entries(session, default_acl, vpc)
    default_route_table = RouteTable(id=_generate_id("rtb"), vpc_id=vpc.id)
    session.add(default_route_table)
    session.add(
        Route(
            id=_generate_id("rt"),
            route_table_id=default_route_table.id,
            destination_cidr=vpc.cidr_block,
            target_type="local",
            target_id="local",
            state="active",
        )
    )
    if ipv6_cidr:
        session.add(
            Route(
                id=_generate_id("rt"),
                route_table_id=default_route_table.id,
                destination_cidr=ipv6_cidr,
                target_type="local",
                target_id="local",
                state="active",
            )
        )
    session.add(
        RouteTableAssociation(
            id=_generate_id("rtbassoc"),
            route_table_id=default_route_table.id,
            subnet_id=None,
            main=True,
        )
    )
    default_group = SecurityGroup(
        id=_generate_id("sg"),
        name="default",
        description="default VPC security group",
        vpc_id=vpc.id,
    )
    session.add(default_group)
    session.add_all(
        [
            SecurityGroupRule(
                id=_generate_id("sgr"),
                security_group_id=default_group.id,
                direction="egress",
                protocol="-1",
                from_port=None,
                to_port=None,
                cidr_ipv4="0.0.0.0/0",
                cidr_ipv6=None,
                source_group_id=None,
                description=None,
            ),
            SecurityGroupRule(
                id=_generate_id("sgr"),
                security_group_id=default_group.id,
                direction="egress",
                protocol="-1",
                from_port=None,
                to_port=None,
                cidr_ipv4=None,
                cidr_ipv6="::/0",
                source_group_id=None,
                description=None,
            ),
            SecurityGroupRule(
                id=_generate_id("sgr"),
                security_group_id=default_group.id,
                direction="ingress",
                protocol="-1",
                from_port=None,
                to_port=None,
                cidr_ipv4=None,
                cidr_ipv6=None,
                source_group_id=default_group.id,
                description=None,
            ),
        ]
    )
    _apply_tags(session, vpc.id, _tags_for_resource(tag_specs, "vpc"))
    session.commit()

    root = ET.Element(_ns_tag("CreateVpcResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    vpc_node = ET.SubElement(root, "vpc")
    _vpc_fields(vpc_node, vpc)
    return _xml_response(root)


def _describe_vpcs(session: Session, params: Dict[str, str]) -> Response:
    """Handle DescribeVpcs."""
    vpc_ids = _get_list_params(params, "VpcId")
    query = session.query(Vpc)
    if vpc_ids:
        query = query.filter(Vpc.id.in_(vpc_ids))
    for flt in _get_filter_params(params):
        name = flt.get("name")
        values = flt.get("values", [])
        if not values:
            continue
        if name == "cidr-block-association.association-id":
            assoc_ids = select(VpcCidrBlockAssociation.vpc_id).where(
                VpcCidrBlockAssociation.id.in_(values),
                VpcCidrBlockAssociation.is_ipv6.is_(False),
            )
            query = query.filter(Vpc.id.in_(assoc_ids))
        elif name == "ipv6-cidr-block-association.association-id":
            assoc_ids = select(VpcCidrBlockAssociation.vpc_id).where(
                VpcCidrBlockAssociation.id.in_(values),
                VpcCidrBlockAssociation.is_ipv6.is_(True),
            )
            query = query.filter(Vpc.id.in_(assoc_ids))
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


def _associate_vpc_cidr_block(session: Session, params: Dict[str, str]) -> Response:
    """Handle AssociateVpcCidrBlock."""
    vpc_id = params.get("VpcId")
    if not vpc_id:
        return _xml_error("MissingParameter", "VpcId is required")
    vpc = session.get(Vpc, vpc_id)
    if not vpc:
        return _xml_error("InvalidVpcID.NotFound", f"Vpc {vpc_id} not found")

    ipv6_cidr = params.get("Ipv6CidrBlock")
    auto_ipv6 = params.get("AmazonProvidedIpv6CidrBlock")
    cidr_block = params.get("CidrBlock")
    if auto_ipv6 and not ipv6_cidr:
        ipv6_cidr = _generate_ipv6_cidr()
    if not cidr_block and not ipv6_cidr:
        return _xml_error("MissingParameter", "CidrBlock or Ipv6CidrBlock is required")

    assoc_id = _generate_id("vpc-cidr-assoc")
    if ipv6_cidr:
        session.add(
            VpcCidrBlockAssociation(
                id=assoc_id,
                vpc_id=vpc_id,
                cidr_block=ipv6_cidr,
                is_ipv6=True,
            )
        )
    else:
        session.add(
            VpcCidrBlockAssociation(
                id=assoc_id,
                vpc_id=vpc_id,
                cidr_block=cidr_block,
                is_ipv6=False,
            )
        )
    session.commit()

    root = ET.Element(_ns_tag("AssociateVpcCidrBlockResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "vpcId").text = vpc_id
    if ipv6_cidr:
        assoc = ET.SubElement(root, "ipv6CidrBlockAssociation")
        ET.SubElement(assoc, "associationId").text = assoc_id
        ET.SubElement(assoc, "ipv6CidrBlock").text = ipv6_cidr
        state_node = ET.SubElement(assoc, "ipv6CidrBlockState")
        ET.SubElement(state_node, "state").text = "associated"
    else:
        assoc = ET.SubElement(root, "cidrBlockAssociation")
        ET.SubElement(assoc, "associationId").text = assoc_id
        ET.SubElement(assoc, "cidrBlock").text = cidr_block
        state_node = ET.SubElement(assoc, "cidrBlockState")
        ET.SubElement(state_node, "state").text = "associated"
    return _xml_response(root)


def _disassociate_vpc_cidr_block(session: Session, params: Dict[str, str]) -> Response:
    """Handle DisassociateVpcCidrBlock."""
    assoc_id = params.get("AssociationId")
    if not assoc_id:
        return _xml_error("MissingParameter", "AssociationId is required")
    assoc = session.get(VpcCidrBlockAssociation, assoc_id)
    if not assoc:
        return _xml_error("InvalidVpcCidrBlockAssociationID.NotFound", f"{assoc_id} not found")
    session.delete(assoc)
    session.commit()

    root = ET.Element(_ns_tag("DisassociateVpcCidrBlockResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
    return _xml_response(root)


def _describe_vpc_attribute(session: Session, params: Dict[str, str]) -> Response:
    vpc_id = params.get("VpcId")
    attribute = params.get("Attribute")
    if not vpc_id or not attribute:
        return _xml_error("MissingParameter", "VpcId and Attribute are required")
    vpc = session.get(Vpc, vpc_id)
    if not vpc:
        return _xml_error("InvalidVpcID.NotFound", f"Vpc {vpc_id} not found")

    value: str | None = None
    if attribute == "enableDnsSupport":
        value = "true" if vpc.enable_dns_support else "false"
    elif attribute == "enableDnsHostnames":
        value = "true" if vpc.enable_dns_hostnames else "false"
    elif attribute == "enableNetworkAddressUsageMetrics":
        value = "true" if vpc.enable_network_address_usage_metrics else "false"
    else:
        return _xml_error("InvalidParameterValue", f"Unsupported attribute: {attribute}")

    root = ET.Element(_ns_tag("DescribeVpcAttributeResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "vpcId").text = vpc.id
    attr_node = ET.SubElement(root, attribute)
    ET.SubElement(attr_node, "value").text = value
    return _xml_response(root)


def _modify_vpc_attribute(session: Session, params: Dict[str, str]) -> Response:
    vpc_id = params.get("VpcId")
    if not vpc_id:
        return _xml_error("MissingParameter", "VpcId is required")
    vpc = session.get(Vpc, vpc_id)
    if not vpc:
        return _xml_error("InvalidVpcID.NotFound", f"Vpc {vpc_id} not found")

    dns_support = params.get("EnableDnsSupport.Value") or params.get("EnableDnsSupport")
    dns_hostnames = params.get("EnableDnsHostnames.Value") or params.get("EnableDnsHostnames")
    network_usage = params.get("EnableNetworkAddressUsageMetrics.Value") or params.get(
        "EnableNetworkAddressUsageMetrics"
    )

    if dns_support is None and dns_hostnames is None and network_usage is None:
        return _xml_error(
            "MissingParameter",
            "EnableDnsSupport, EnableDnsHostnames, or EnableNetworkAddressUsageMetrics is required",
        )

    if dns_support is not None:
        vpc.enable_dns_support = dns_support.lower() in {"true", "1", "yes"}
    if dns_hostnames is not None:
        vpc.enable_dns_hostnames = dns_hostnames.lower() in {"true", "1", "yes"}
    if network_usage is not None:
        vpc.enable_network_address_usage_metrics = network_usage.lower() in {"true", "1", "yes"}
    session.commit()

    root = ET.Element(_ns_tag("ModifyVpcAttributeResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
    return _xml_response(root)


def _create_subnet(session: Session, params: Dict[str, str]) -> Response:  # pylint: disable=too-many-locals
    """Handle CreateSubnet."""
    vpc_id = params.get("VpcId")
    cidr = params.get("CidrBlock")
    ipv6_cidr = params.get("Ipv6CidrBlock")
    az = params.get("AvailabilityZone")
    assign_ipv6 = params.get("AssignIpv6AddressOnCreation") or params.get(
        "AssignIpv6AddressOnCreation.Value"
    )
    if not vpc_id or not cidr:
        return _xml_error("MissingParameter", "VpcId and CidrBlock are required")
    vpc = session.get(Vpc, vpc_id)
    if not vpc:
        return _xml_error("InvalidVpcID.NotFound", f"Vpc {vpc_id} not found")
    validation_error = _validate_subnet_request(vpc, cidr, ipv6_cidr)
    if validation_error:
        return validation_error

    tag_specs = _parse_tag_specifications(params)
    subnet = Subnet(
        id=_generate_id("subnet"),
        vpc_id=vpc_id,
        cidr_block=cidr,
        ipv6_cidr_block=ipv6_cidr,
        ipv6_association_id=_generate_id("subnet-cidr-assoc") if ipv6_cidr else None,
        availability_zone=az,
        state="available",
        assign_ipv6_address_on_creation=(
            assign_ipv6.lower() in {"true", "1", "yes"} if assign_ipv6 is not None else False
        ),
    )
    session.add(subnet)
    default_acl = (
        session.query(NetworkAcl)
        .filter_by(vpc_id=vpc_id, is_default=True)
        .one_or_none()
    )
    if not default_acl:
        default_acl = NetworkAcl(
            id=_generate_id("acl"),
            vpc_id=vpc_id,
            is_default=True,
        )
        session.add(default_acl)
        _seed_default_network_acl_entries(session, default_acl, vpc)
    association = NetworkAclAssociation(
        id=_generate_id("aclassoc"),
        network_acl_id=default_acl.id,
        subnet_id=subnet.id,
    )
    session.add(association)
    main_assoc = (
        session.query(RouteTableAssociation)
        .join(RouteTable)
        .filter(RouteTable.vpc_id == vpc_id, RouteTableAssociation.main.is_(True))
        .one_or_none()
    )
    if main_assoc:
        subnet.route_table_id = main_assoc.route_table_id
        session.add(
            RouteTableAssociation(
                id=_generate_id("rtbassoc"),
                route_table_id=main_assoc.route_table_id,
                subnet_id=subnet.id,
                main=False,
            )
        )
    _apply_tags(session, subnet.id, _tags_for_resource(tag_specs, "subnet"))
    session.commit()

    root = ET.Element(_ns_tag("CreateSubnetResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    subnet_node = ET.SubElement(root, "subnet")
    _subnet_fields(subnet_node, subnet)
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


def _create_network_acl(session: Session, params: Dict[str, str]) -> Response:
    """Handle CreateNetworkAcl."""
    vpc_id = params.get("VpcId")
    if not vpc_id:
        return _xml_error("MissingParameter", "VpcId is required")
    vpc = session.get(Vpc, vpc_id)
    if not vpc:
        return _xml_error("InvalidVpcID.NotFound", f"Vpc {vpc_id} not found")

    tag_specs = _parse_tag_specifications(params)
    acl = NetworkAcl(id=_generate_id("acl"), vpc_id=vpc_id, is_default=False)
    session.add(acl)
    _apply_tags(session, acl.id, _tags_for_resource(tag_specs, "network-acl"))
    session.commit()

    root = ET.Element(_ns_tag("CreateNetworkAclResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    acl_node = ET.SubElement(root, "networkAcl")
    _network_acl_fields(acl_node, acl)
    return _xml_response(root)


def _describe_network_acls(session: Session, params: Dict[str, str]) -> Response:
    """Handle DescribeNetworkAcls."""
    acl_ids = _get_list_params(params, "NetworkAclId")
    query = session.query(NetworkAcl)
    if acl_ids:
        query = query.filter(NetworkAcl.id.in_(acl_ids))

    for flt in _get_filter_params(params):
        values = flt.get("values", [])
        if not values:
            continue
        name = flt.get("name")
        if name == "vpc-id":
            query = query.filter(NetworkAcl.vpc_id.in_(values))
        elif name == "default":
            bool_values = {v.lower() for v in values}
            if "true" in bool_values:
                query = query.filter_by(is_default=True)
            elif "false" in bool_values:
                query = query.filter_by(is_default=False)
        elif name == "association.subnet-id":
            query = query.join(NetworkAclAssociation).filter(
                NetworkAclAssociation.subnet_id.in_(values)
            )
        elif name in {"association.network-acl-association-id", "association.association-id"}:
            query = query.join(NetworkAclAssociation).filter(
                NetworkAclAssociation.id.in_(values)
            )
        elif name == "network-acl-id":
            query = query.filter(NetworkAcl.id.in_(values))

    acls = query.all()

    root = ET.Element(_ns_tag("DescribeNetworkAclsResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    acl_set = ET.SubElement(root, "networkAclSet")
    for acl in acls:
        acl_set.append(_network_acl_to_xml(acl))
    return _xml_response(root)


def _delete_network_acl(session: Session, params: Dict[str, str]) -> Response:
    """Handle DeleteNetworkAcl."""
    acl_id = params.get("NetworkAclId")
    if not acl_id:
        return _xml_error("MissingParameter", "NetworkAclId is required")
    acl = session.get(NetworkAcl, acl_id)
    if not acl:
        return _xml_error("InvalidNetworkAclID.NotFound", f"NetworkAcl {acl_id} not found")
    if acl.associations:
        return _xml_error("DependencyViolation", "Network ACL has associations")
    session.delete(acl)
    session.commit()

    root = ET.Element(_ns_tag("DeleteNetworkAclResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
    return _xml_response(root)


def _create_network_acl_entry(  # pylint: disable=too-many-locals
    session: Session, params: Dict[str, str]
) -> Response:
    """Handle CreateNetworkAclEntry."""
    acl_id = params.get("NetworkAclId")
    rule_number = params.get("RuleNumber")
    protocol = params.get("Protocol")
    rule_action = params.get("RuleAction")
    egress = params.get("Egress")
    cidr_block = params.get("CidrBlock")
    ipv6_cidr_block = params.get("Ipv6CidrBlock")
    from_port = params.get("PortRange.From")
    to_port = params.get("PortRange.To")

    if not acl_id or rule_number is None or protocol is None or rule_action is None:
        return _xml_error(
            "MissingParameter",
            "NetworkAclId, RuleNumber, Protocol, and RuleAction are required",
        )
    acl = session.get(NetworkAcl, acl_id)
    if not acl:
        return _xml_error("InvalidNetworkAclID.NotFound", f"NetworkAcl {acl_id} not found")

    egress_flag = str(egress).lower() in {"true", "1", "yes"} if egress is not None else False
    rule_num = int(rule_number)
    existing = (
        session.query(NetworkAclEntry)
        .filter_by(network_acl_id=acl_id, rule_number=rule_num, egress=egress_flag)
        .one_or_none()
    )
    if existing:
        session.delete(existing)
        session.flush()

    entry = NetworkAclEntry(
        id=_generate_id("aclentry"),
        network_acl_id=acl_id,
        egress=egress_flag,
        rule_number=rule_num,
        protocol=protocol,
        rule_action=rule_action,
        cidr_block=cidr_block,
        ipv6_cidr_block=ipv6_cidr_block,
        from_port=int(from_port) if from_port is not None else None,
        to_port=int(to_port) if to_port is not None else None,
    )
    session.add(entry)
    session.commit()

    root = ET.Element(_ns_tag("CreateNetworkAclEntryResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
    return _xml_response(root)


def _replace_network_acl_entry(  # pylint: disable=too-many-locals
    session: Session, params: Dict[str, str]
) -> Response:
    """Handle ReplaceNetworkAclEntry."""
    acl_id = params.get("NetworkAclId")
    rule_number = params.get("RuleNumber")
    protocol = params.get("Protocol")
    rule_action = params.get("RuleAction")
    egress = params.get("Egress")
    cidr_block = params.get("CidrBlock")
    ipv6_cidr_block = params.get("Ipv6CidrBlock")
    from_port = params.get("PortRange.From")
    to_port = params.get("PortRange.To")

    if not acl_id or rule_number is None or protocol is None or rule_action is None:
        return _xml_error(
            "MissingParameter",
            "NetworkAclId, RuleNumber, Protocol, and RuleAction are required",
        )
    acl = session.get(NetworkAcl, acl_id)
    if not acl:
        return _xml_error("InvalidNetworkAclID.NotFound", f"NetworkAcl {acl_id} not found")

    egress_flag = str(egress).lower() in {"true", "1", "yes"} if egress is not None else False
    rule_num = int(rule_number)
    existing = (
        session.query(NetworkAclEntry)
        .filter_by(network_acl_id=acl_id, rule_number=rule_num, egress=egress_flag)
        .one_or_none()
    )
    if existing:
        session.delete(existing)
        session.flush()

    entry = NetworkAclEntry(
        id=_generate_id("aclentry"),
        network_acl_id=acl_id,
        egress=egress_flag,
        rule_number=rule_num,
        protocol=protocol,
        rule_action=rule_action,
        cidr_block=cidr_block,
        ipv6_cidr_block=ipv6_cidr_block,
        from_port=int(from_port) if from_port is not None else None,
        to_port=int(to_port) if to_port is not None else None,
    )
    session.add(entry)
    session.commit()

    root = ET.Element(_ns_tag("ReplaceNetworkAclEntryResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
    return _xml_response(root)


def _delete_network_acl_entry(session: Session, params: Dict[str, str]) -> Response:
    """Handle DeleteNetworkAclEntry."""
    acl_id = params.get("NetworkAclId")
    rule_number = params.get("RuleNumber")
    egress = params.get("Egress")
    if not acl_id or rule_number is None:
        return _xml_error("MissingParameter", "NetworkAclId and RuleNumber are required")
    egress_flag = str(egress).lower() in {"true", "1", "yes"} if egress is not None else False
    entry = (
        session.query(NetworkAclEntry)
        .filter_by(network_acl_id=acl_id, rule_number=int(rule_number), egress=egress_flag)
        .one_or_none()
    )
    if not entry:
        return _xml_error("InvalidNetworkAclEntry.NotFound", "Network ACL entry not found")
    session.delete(entry)
    session.commit()

    root = ET.Element(_ns_tag("DeleteNetworkAclEntryResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
    return _xml_response(root)


def _replace_network_acl_association(session: Session, params: Dict[str, str]) -> Response:
    """Handle ReplaceNetworkAclAssociation."""
    assoc_id = params.get("AssociationId")
    acl_id = params.get("NetworkAclId")
    if not assoc_id or not acl_id:
        return _xml_error("MissingParameter", "AssociationId and NetworkAclId are required")
    association = session.get(NetworkAclAssociation, assoc_id)
    if not association:
        return _xml_error("InvalidAssociationID.NotFound", f"Association {assoc_id} not found")
    acl = session.get(NetworkAcl, acl_id)
    if not acl:
        return _xml_error("InvalidNetworkAclID.NotFound", f"NetworkAcl {acl_id} not found")

    subnet_id = association.subnet_id
    session.delete(association)
    new_assoc = NetworkAclAssociation(
        id=_generate_id("aclassoc"),
        network_acl_id=acl_id,
        subnet_id=subnet_id,
    )
    session.add(new_assoc)
    session.commit()

    root = ET.Element(_ns_tag("ReplaceNetworkAclAssociationResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "newAssociationId").text = new_assoc.id
    return _xml_response(root)


def _describe_subnet_attribute(session: Session, params: Dict[str, str]) -> Response:
    subnet_id = params.get("SubnetId")
    attribute = params.get("Attribute")
    if not subnet_id or not attribute:
        return _xml_error("MissingParameter", "SubnetId and Attribute are required")
    subnet = session.get(Subnet, subnet_id)
    if not subnet:
        return _xml_error("InvalidSubnetID.NotFound", f"Subnet {subnet_id} not found")

    if attribute != "assignIpv6AddressOnCreation":
        return _xml_error("InvalidParameterValue", f"Unsupported attribute: {attribute}")

    root = ET.Element(_ns_tag("DescribeSubnetAttributeResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "subnetId").text = subnet.id
    attr_node = ET.SubElement(root, "assignIpv6AddressOnCreation")
    ET.SubElement(attr_node, "value").text = (
        "true" if subnet.assign_ipv6_address_on_creation else "false"
    )
    return _xml_response(root)


def _modify_subnet_attribute(session: Session, params: Dict[str, str]) -> Response:
    subnet_id = params.get("SubnetId")
    if not subnet_id:
        return _xml_error("MissingParameter", "SubnetId is required")
    subnet = session.get(Subnet, subnet_id)
    if not subnet:
        return _xml_error("InvalidSubnetID.NotFound", f"Subnet {subnet_id} not found")

    assign_ipv6 = params.get("AssignIpv6AddressOnCreation.Value") or params.get(
        "AssignIpv6AddressOnCreation"
    )
    if assign_ipv6 is None:
        return _xml_error("MissingParameter", "AssignIpv6AddressOnCreation is required")

    subnet.assign_ipv6_address_on_creation = assign_ipv6.lower() in {"true", "1", "yes"}
    session.commit()

    root = ET.Element(_ns_tag("ModifySubnetAttributeResponse"))
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

    tag_specs = _parse_tag_specifications(params)
    route_table = RouteTable(id=_generate_id("rtb"), vpc_id=vpc_id)
    local_routes = [
        Route(
            id=_generate_id("rt"),
            route_table_id=route_table.id,
            destination_cidr=vpc.cidr_block,
            target_type="local",
            target_id="local",
            state="active",
        )
    ]
    if vpc.ipv6_cidr_block:
        local_routes.append(
            Route(
                id=_generate_id("rt"),
                route_table_id=route_table.id,
                destination_cidr=vpc.ipv6_cidr_block,
                target_type="local",
                target_id="local",
                state="active",
            )
        )
    session.add(route_table)
    session.add_all(local_routes)
    _apply_tags(session, route_table.id, _tags_for_resource(tag_specs, "route-table"))
    session.commit()

    root = ET.Element(_ns_tag("CreateRouteTableResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    rtb_node = ET.SubElement(root, "routeTable")
    _route_table_fields(rtb_node, route_table)
    return _xml_response(root)


def _describe_route_tables(session: Session, params: Dict[str, str]) -> Response:
    """Handle DescribeRouteTables."""
    rtb_ids = _get_list_params(params, "RouteTableId")
    query = session.query(RouteTable)
    if rtb_ids:
        query = query.filter(RouteTable.id.in_(rtb_ids))
    for flt in _get_filter_params(params):
        name = flt.get("name")
        values = flt.get("values", [])
        if not values:
            continue
        if name == "vpc-id":
            query = query.filter(RouteTable.vpc_id.in_(values))
        elif name == "association.main":
            bool_values = {v.lower() for v in values}
            if "true" in bool_values:
                query = query.join(RouteTableAssociation).filter(RouteTableAssociation.main.is_(True))
            elif "false" in bool_values:
                query = query.join(RouteTableAssociation).filter(RouteTableAssociation.main.is_(False))
        elif name in {"association.route-table-association-id", "association-id"}:
            query = query.join(RouteTableAssociation).filter(
                RouteTableAssociation.id.in_(values)
            )
        elif name == "association.subnet-id":
            query = query.join(RouteTableAssociation).filter(
                RouteTableAssociation.subnet_id.in_(values)
            )
    route_tables = query.all()

    root = ET.Element(_ns_tag("DescribeRouteTablesResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    rtb_set = ET.SubElement(root, "routeTableSet")
    for route_table in route_tables:
        rtb_set.append(_route_table_to_xml(route_table))
    return _xml_response(root)


def _delete_route_table(session: Session, params: Dict[str, str]) -> Response:
    """Handle DeleteRouteTable."""
    route_table_id = params.get("RouteTableId")
    if not route_table_id:
        return _xml_error("MissingParameter", "RouteTableId is required")
    route_table = session.get(RouteTable, route_table_id)
    if not route_table:
        return _xml_error("InvalidRouteTableID.NotFound", f"Route table {route_table_id} not found")
    if route_table.associations:
        return _xml_error("DependencyViolation", "Route table has associations")
    session.delete(route_table)
    session.commit()

    root = ET.Element(_ns_tag("DeleteRouteTableResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
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


def _disassociate_route_table(session: Session, params: Dict[str, str]) -> Response:
    """Handle DisassociateRouteTable."""
    assoc_id = params.get("AssociationId")
    if not assoc_id:
        return _xml_error("MissingParameter", "AssociationId is required")
    association = session.get(RouteTableAssociation, assoc_id)
    if not association:
        return _xml_error("InvalidAssociationID.NotFound", f"Association {assoc_id} not found")
    subnet = association.subnet
    if subnet and subnet.route_table_id == association.route_table_id:
        subnet.route_table_id = None
    session.delete(association)
    session.commit()

    root = ET.Element(_ns_tag("DisassociateRouteTableResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
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


def _delete_route(session: Session, params: Dict[str, str]) -> Response:
    """Handle DeleteRoute."""
    route_table_id = params.get("RouteTableId")
    destination = params.get("DestinationCidrBlock") or params.get("DestinationIpv6CidrBlock")
    if not route_table_id or not destination:
        return _xml_error("MissingParameter", "RouteTableId and destination CIDR are required")

    route = (
        session.query(Route)
        .filter_by(route_table_id=route_table_id, destination_cidr=destination)
        .filter(Route.target_type != "local")
        .one_or_none()
    )
    if not route:
        return _xml_error("InvalidRoute.NotFound", "Route not found")
    session.delete(route)
    session.commit()

    root = ET.Element(_ns_tag("DeleteRouteResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
    return _xml_response(root)


def _create_igw(session: Session, params: Dict[str, str]) -> Response:
    """Handle CreateInternetGateway."""
    tag_specs = _parse_tag_specifications(params)
    igw = InternetGateway(id=_generate_id("igw"), vpc_id=None)
    session.add(igw)
    _apply_tags(session, igw.id, _tags_for_resource(tag_specs, "internet-gateway"))
    session.commit()

    root = ET.Element(_ns_tag("CreateInternetGatewayResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    igw_node = ET.SubElement(root, "internetGateway")
    _igw_fields(igw_node, igw)
    return _xml_response(root)


def _create_egress_only_igw(session: Session, params: Dict[str, str]) -> Response:
    """Handle CreateEgressOnlyInternetGateway."""
    vpc_id = params.get("VpcId")
    if not vpc_id:
        return _xml_error("MissingParameter", "VpcId is required")
    vpc = session.get(Vpc, vpc_id)
    if not vpc:
        return _xml_error("InvalidVpcID.NotFound", f"Vpc {vpc_id} not found")
    tag_specs = _parse_tag_specifications(params)
    igw = EgressOnlyInternetGateway(id=_generate_id("eigw"), vpc_id=vpc_id)
    session.add(igw)
    _apply_tags(session, igw.id, _tags_for_resource(tag_specs, "egress-only-internet-gateway"))
    session.commit()

    root = ET.Element(_ns_tag("CreateEgressOnlyInternetGatewayResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    node = ET.SubElement(root, "egressOnlyInternetGateway")
    _egress_only_igw_fields(node, igw)
    return _xml_response(root)


def _describe_egress_only_igws(session: Session, params: Dict[str, str]) -> Response:
    """Handle DescribeEgressOnlyInternetGateways."""
    igw_ids = _get_list_params(params, "EgressOnlyInternetGatewayId")
    query = session.query(EgressOnlyInternetGateway)
    if igw_ids:
        query = query.filter(EgressOnlyInternetGateway.id.in_(igw_ids))
    for flt in _get_filter_params(params):
        values = flt.get("values", [])
        if not values:
            continue
        name = flt.get("name")
        if name == "vpc-id":
            query = query.filter(EgressOnlyInternetGateway.vpc_id.in_(values))
        elif name == "egress-only-internet-gateway-id":
            query = query.filter(EgressOnlyInternetGateway.id.in_(values))
    igws = query.all()

    root = ET.Element(_ns_tag("DescribeEgressOnlyInternetGatewaysResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    igw_set = ET.SubElement(root, "egressOnlyInternetGatewaySet")
    for igw in igws:
        igw_set.append(_egress_only_igw_to_xml(igw))
    return _xml_response(root)


def _delete_egress_only_igw(session: Session, params: Dict[str, str]) -> Response:
    """Handle DeleteEgressOnlyInternetGateway."""
    igw_id = params.get("EgressOnlyInternetGatewayId")
    if not igw_id:
        return _xml_error("MissingParameter", "EgressOnlyInternetGatewayId is required")
    igw = session.get(EgressOnlyInternetGateway, igw_id)
    if not igw:
        return _xml_error(
            "InvalidEgressOnlyInternetGatewayId.NotFound",
            f"Egress-only internet gateway {igw_id} not found",
        )
    session.delete(igw)
    session.commit()

    root = ET.Element(_ns_tag("DeleteEgressOnlyInternetGatewayResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
    return _xml_response(root)


def _allocate_address(session: Session, params: Dict[str, str]) -> Response:
    """Handle AllocateAddress."""
    domain = params.get("Domain", "vpc")
    tag_specs = _parse_tag_specifications(params)
    public_ip = _next_public_ip(session)
    allocation_id = _generate_id("eipalloc")
    address = ElasticIp(id=allocation_id, public_ip=public_ip, domain=domain)
    session.add(address)
    _apply_tags(session, allocation_id, _tags_for_resource(tag_specs, "elastic-ip"))
    session.commit()

    root = ET.Element(_ns_tag("AllocateAddressResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "publicIp").text = public_ip
    ET.SubElement(root, "allocationId").text = allocation_id
    ET.SubElement(root, "domain").text = domain
    return _xml_response(root)


def _describe_addresses(session: Session, params: Dict[str, str]) -> Response:
    """Handle DescribeAddresses."""
    allocation_ids = _get_list_params(params, "AllocationId")
    public_ips = _get_list_params(params, "PublicIp")
    query = session.query(ElasticIp)
    if allocation_ids:
        query = query.filter(ElasticIp.id.in_(allocation_ids))
    if public_ips:
        query = query.filter(ElasticIp.public_ip.in_(public_ips))
    addresses = query.all()

    root = ET.Element(_ns_tag("DescribeAddressesResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    addr_set = ET.SubElement(root, "addressesSet")
    for address in addresses:
        addr_set.append(_elastic_ip_to_xml(address))
    return _xml_response(root)


def _release_address(session: Session, params: Dict[str, str]) -> Response:
    """Handle ReleaseAddress."""
    allocation_id = params.get("AllocationId")
    public_ip = params.get("PublicIp")
    query = session.query(ElasticIp)
    if allocation_id:
        query = query.filter(ElasticIp.id == allocation_id)
    elif public_ip:
        query = query.filter(ElasticIp.public_ip == public_ip)
    else:
        return _xml_error("MissingParameter", "AllocationId or PublicIp is required")
    address = query.one_or_none()
    if not address:
        return _xml_error("InvalidAllocationID.NotFound", "Elastic IP not found")
    session.delete(address)
    session.commit()

    root = ET.Element(_ns_tag("ReleaseAddressResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
    return _xml_response(root)


def _create_nat_gateway(session: Session, params: Dict[str, str]) -> Response:
    """Handle CreateNatGateway."""
    subnet_id = params.get("SubnetId")
    allocation_id = params.get("AllocationId")
    if not subnet_id or not allocation_id:
        return _xml_error("MissingParameter", "SubnetId and AllocationId are required")
    subnet = session.get(Subnet, subnet_id)
    if not subnet:
        return _xml_error("InvalidSubnetID.NotFound", f"Subnet {subnet_id} not found")
    allocation = session.get(ElasticIp, allocation_id)
    if not allocation:
        return _xml_error("InvalidAllocationID.NotFound", f"Allocation {allocation_id} not found")

    tag_specs = _parse_tag_specifications(params)
    nat_gateway = NatGateway(
        id=_generate_id("nat"),
        subnet_id=subnet_id,
        vpc_id=subnet.vpc_id,
        state="available",
    )
    session.add(nat_gateway)
    address = NatGatewayAddress(
        id=_generate_id("nat-addr"),
        nat_gateway_id=nat_gateway.id,
        allocation_id=allocation.id,
        public_ip=allocation.public_ip,
        private_ip=_next_private_ip(subnet.cidr_block),
    )
    session.add(address)
    _apply_tags(session, nat_gateway.id, _tags_for_resource(tag_specs, "natgateway"))
    session.commit()

    root = ET.Element(_ns_tag("CreateNatGatewayResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    nat_node = ET.SubElement(root, "natGateway")
    _nat_gateway_fields(nat_node, nat_gateway, [address])
    return _xml_response(root)


def _describe_nat_gateways(session: Session, params: Dict[str, str]) -> Response:
    """Handle DescribeNatGateways."""
    nat_ids = _get_list_params(params, "NatGatewayId")
    query = session.query(NatGateway)
    if nat_ids:
        query = query.filter(NatGateway.id.in_(nat_ids))
    for flt in _get_filter_params(params):
        name = flt.get("name")
        values = flt.get("values", [])
        if not values:
            continue
        if name == "subnet-id":
            query = query.filter(NatGateway.subnet_id.in_(values))
        elif name == "vpc-id":
            query = query.filter(NatGateway.vpc_id.in_(values))
        elif name == "state":
            query = query.filter(NatGateway.state.in_(values))
    nat_gateways = query.all()

    root = ET.Element(_ns_tag("DescribeNatGatewaysResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    nat_set = ET.SubElement(root, "natGatewaySet")
    for nat_gateway in nat_gateways:
        addresses = (
            session.query(NatGatewayAddress)
            .filter_by(nat_gateway_id=nat_gateway.id)
            .all()
        )
        nat_set.append(_nat_gateway_to_xml(nat_gateway, addresses))
    return _xml_response(root)


def _delete_nat_gateway(session: Session, params: Dict[str, str]) -> Response:
    """Handle DeleteNatGateway."""
    nat_id = params.get("NatGatewayId")
    if not nat_id:
        return _xml_error("MissingParameter", "NatGatewayId is required")
    nat_gateway = session.get(NatGateway, nat_id)
    if not nat_gateway:
        return _xml_error("InvalidNatGatewayID.NotFound", f"NatGateway {nat_id} not found")
    nat_gateway.state = "deleted"
    session.commit()

    root = ET.Element(_ns_tag("DeleteNatGatewayResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "natGatewayId").text = nat_gateway.id
    return _xml_response(root)


def _create_vpc_endpoint(session: Session, params: Dict[str, str]) -> Response:
    """Handle CreateVpcEndpoint."""
    vpc_id = params.get("VpcId")
    service_name = params.get("ServiceName")
    if not vpc_id or not service_name:
        return _xml_error("MissingParameter", "VpcId and ServiceName are required")
    vpc = session.get(Vpc, vpc_id)
    if not vpc:
        return _xml_error("InvalidVpcID.NotFound", f"Vpc {vpc_id} not found")
    endpoint_type = params.get("VpcEndpointType", "Gateway")
    route_table_ids = _get_list_params(params, "RouteTableId")
    subnet_ids = _get_list_params(params, "SubnetId")
    security_group_ids = _get_list_params(params, "SecurityGroupId")
    tag_specs = _parse_tag_specifications(params)
    endpoint = VpcEndpoint(
        id=_generate_id("vpce"),
        vpc_id=vpc_id,
        service_name=service_name,
        vpc_endpoint_type=endpoint_type,
        state="available",
        route_table_ids_json=json.dumps(route_table_ids),
        subnet_ids_json=json.dumps(subnet_ids),
        security_group_ids_json=json.dumps(security_group_ids),
    )
    session.add(endpoint)
    _apply_tags(session, endpoint.id, _tags_for_resource(tag_specs, "vpc-endpoint"))
    session.commit()

    root = ET.Element(_ns_tag("CreateVpcEndpointResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    endpoint_node = ET.SubElement(root, "vpcEndpoint")
    _vpc_endpoint_fields(endpoint_node, endpoint)
    return _xml_response(root)


def _modify_vpc_endpoint(session: Session, params: Dict[str, str]) -> Response:
    """Handle ModifyVpcEndpoint."""
    endpoint_id = params.get("VpcEndpointId")
    if not endpoint_id:
        return _xml_error("MissingParameter", "VpcEndpointId is required")
    endpoint = session.get(VpcEndpoint, endpoint_id)
    if not endpoint:
        return _xml_error("InvalidVpcEndpointId.NotFound", f"VpcEndpoint {endpoint_id} not found")

    route_table_ids = set(json.loads(endpoint.route_table_ids_json))
    subnet_ids = set(json.loads(endpoint.subnet_ids_json))
    security_group_ids = set(json.loads(endpoint.security_group_ids_json))

    route_table_ids.update(_get_list_params(params, "AddRouteTableId"))
    route_table_ids.difference_update(_get_list_params(params, "RemoveRouteTableId"))
    subnet_ids.update(_get_list_params(params, "AddSubnetId"))
    subnet_ids.difference_update(_get_list_params(params, "RemoveSubnetId"))
    security_group_ids.update(_get_list_params(params, "AddSecurityGroupId"))
    security_group_ids.difference_update(_get_list_params(params, "RemoveSecurityGroupId"))

    endpoint.route_table_ids_json = json.dumps(sorted(route_table_ids))
    endpoint.subnet_ids_json = json.dumps(sorted(subnet_ids))
    endpoint.security_group_ids_json = json.dumps(sorted(security_group_ids))
    session.commit()

    root = ET.Element(_ns_tag("ModifyVpcEndpointResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
    return _xml_response(root)


def _describe_vpc_endpoints(session: Session, params: Dict[str, str]) -> Response:
    """Handle DescribeVpcEndpoints."""
    endpoint_ids = _get_list_params(params, "VpcEndpointId")
    query = session.query(VpcEndpoint)
    if endpoint_ids:
        query = query.filter(VpcEndpoint.id.in_(endpoint_ids))
    for flt in _get_filter_params(params):
        name = flt.get("name")
        values = flt.get("values", [])
        if not values:
            continue
        if name == "vpc-id":
            query = query.filter(VpcEndpoint.vpc_id.in_(values))
        elif name == "service-name":
            query = query.filter(VpcEndpoint.service_name.in_(values))
        elif name == "vpc-endpoint-type":
            query = query.filter(VpcEndpoint.vpc_endpoint_type.in_(values))
        elif name == "state":
            query = query.filter(VpcEndpoint.state.in_(values))
    endpoints = query.all()

    root = ET.Element(_ns_tag("DescribeVpcEndpointsResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    endpoint_set = ET.SubElement(root, "vpcEndpointSet")
    for endpoint in endpoints:
        endpoint_set.append(_vpc_endpoint_to_xml(endpoint))
    return _xml_response(root)


def _delete_vpc_endpoints(session: Session, params: Dict[str, str]) -> Response:
    """Handle DeleteVpcEndpoints."""
    endpoint_ids = _get_list_params(params, "VpcEndpointId")
    if not endpoint_ids:
        return _xml_error("MissingParameter", "VpcEndpointId is required")
    for endpoint_id in endpoint_ids:
        endpoint = session.get(VpcEndpoint, endpoint_id)
        if endpoint:
            session.delete(endpoint)
    session.commit()

    root = ET.Element(_ns_tag("DeleteVpcEndpointsResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    success_set = ET.SubElement(root, "unsuccessful")
    if not endpoint_ids:
        ET.SubElement(success_set, "item")
    return _xml_response(root)


def _create_flow_logs(session: Session, params: Dict[str, str]) -> Response:
    """Handle CreateFlowLogs."""
    resource_ids = _get_list_params(params, "ResourceId")
    resource_type = params.get("ResourceType")
    traffic_type = params.get("TrafficType")
    log_destination_type = params.get("LogDestinationType", "cloud-watch-logs")
    log_destination = params.get("LogDestination", "arn:aws:logs:::log-group")
    if not resource_ids or not resource_type or not traffic_type:
        return _xml_error("MissingParameter", "ResourceId, ResourceType, and TrafficType are required")

    tag_specs = _parse_tag_specifications(params)
    flow_log_ids: list[str] = []
    for resource_id in resource_ids:
        flow_log = FlowLog(
            id=_generate_id("fl"),
            resource_id=resource_id,
            resource_type=resource_type,
            traffic_type=traffic_type,
            log_destination_type=log_destination_type,
            log_destination=log_destination,
            status="ACTIVE",
        )
        session.add(flow_log)
        _apply_tags(session, flow_log.id, _tags_for_resource(tag_specs, "vpc-flow-log"))
        flow_log_ids.append(flow_log.id)
    session.commit()

    root = ET.Element(_ns_tag("CreateFlowLogsResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    id_set = ET.SubElement(root, "flowLogIdSet")
    for flow_log_id in flow_log_ids:
        ET.SubElement(id_set, "item").text = flow_log_id
    ET.SubElement(root, "unsuccessful")
    return _xml_response(root)


def _describe_flow_logs(session: Session, params: Dict[str, str]) -> Response:
    """Handle DescribeFlowLogs."""
    flow_log_ids = _get_list_params(params, "FlowLogId")
    query = session.query(FlowLog)
    if flow_log_ids:
        query = query.filter(FlowLog.id.in_(flow_log_ids))
    for flt in _get_filter_params(params):
        name = flt.get("name")
        values = flt.get("values", [])
        if not values:
            continue
        if name == "resource-id":
            query = query.filter(FlowLog.resource_id.in_(values))
        elif name == "resource-type":
            query = query.filter(FlowLog.resource_type.in_(values))
    flow_logs = query.all()

    root = ET.Element(_ns_tag("DescribeFlowLogsResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    flow_set = ET.SubElement(root, "flowLogSet")
    for flow_log in flow_logs:
        flow_set.append(_flow_log_to_xml(flow_log))
    return _xml_response(root)


def _delete_flow_logs(session: Session, params: Dict[str, str]) -> Response:
    """Handle DeleteFlowLogs."""
    flow_log_ids = _get_list_params(params, "FlowLogId")
    if not flow_log_ids:
        return _xml_error("MissingParameter", "FlowLogId is required")
    for flow_log_id in flow_log_ids:
        flow_log = session.get(FlowLog, flow_log_id)
        if flow_log:
            session.delete(flow_log)
    session.commit()

    root = ET.Element(_ns_tag("DeleteFlowLogsResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "unsuccessful")
    return _xml_response(root)


def _create_customer_gateway(session: Session, params: Dict[str, str]) -> Response:
    """Handle CreateCustomerGateway."""
    bgp_asn = params.get("BgpAsn")
    ip_address = params.get("IpAddress")
    gw_type = params.get("Type")
    if not bgp_asn or not ip_address or not gw_type:
        return _xml_error("MissingParameter", "BgpAsn, IpAddress, and Type are required")
    tag_specs = _parse_tag_specifications(params)
    gateway = CustomerGateway(
        id=_generate_id("cgw"),
        bgp_asn=bgp_asn,
        ip_address=ip_address,
        gateway_type=gw_type,
    )
    session.add(gateway)
    _apply_tags(session, gateway.id, _tags_for_resource(tag_specs, "customer-gateway"))
    session.commit()

    root = ET.Element(_ns_tag("CreateCustomerGatewayResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    node = ET.SubElement(root, "customerGateway")
    _customer_gateway_fields(node, gateway)
    return _xml_response(root)


def _describe_customer_gateways(session: Session, params: Dict[str, str]) -> Response:
    """Handle DescribeCustomerGateways."""
    gateway_ids = _get_list_params(params, "CustomerGatewayId")
    query = session.query(CustomerGateway)
    if gateway_ids:
        query = query.filter(CustomerGateway.id.in_(gateway_ids))
    gateways = query.all()

    root = ET.Element(_ns_tag("DescribeCustomerGatewaysResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    gateway_set = ET.SubElement(root, "customerGatewaySet")
    for gateway in gateways:
        gateway_set.append(_customer_gateway_to_xml(gateway))
    return _xml_response(root)


def _delete_customer_gateway(session: Session, params: Dict[str, str]) -> Response:
    """Handle DeleteCustomerGateway."""
    gateway_id = params.get("CustomerGatewayId")
    if not gateway_id:
        return _xml_error("MissingParameter", "CustomerGatewayId is required")
    gateway = session.get(CustomerGateway, gateway_id)
    if not gateway:
        return _xml_error("InvalidCustomerGatewayID.NotFound", f"{gateway_id} not found")
    session.delete(gateway)
    session.commit()

    root = ET.Element(_ns_tag("DeleteCustomerGatewayResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
    return _xml_response(root)


def _create_vpn_gateway(session: Session, params: Dict[str, str]) -> Response:
    """Handle CreateVpnGateway."""
    gw_type = params.get("Type")
    if not gw_type:
        return _xml_error("MissingParameter", "Type is required")
    tag_specs = _parse_tag_specifications(params)
    gateway = VpnGateway(id=_generate_id("vgw"), gateway_type=gw_type)
    session.add(gateway)
    _apply_tags(session, gateway.id, _tags_for_resource(tag_specs, "vpn-gateway"))
    session.commit()

    root = ET.Element(_ns_tag("CreateVpnGatewayResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    node = ET.SubElement(root, "vpnGateway")
    _vpn_gateway_fields(node, gateway)
    return _xml_response(root)


def _describe_vpn_gateways(session: Session, params: Dict[str, str]) -> Response:
    """Handle DescribeVpnGateways."""
    gateway_ids = _get_list_params(params, "VpnGatewayId")
    query = session.query(VpnGateway)
    if gateway_ids:
        query = query.filter(VpnGateway.id.in_(gateway_ids))
    gateways = query.all()

    root = ET.Element(_ns_tag("DescribeVpnGatewaysResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    gateway_set = ET.SubElement(root, "vpnGatewaySet")
    for gateway in gateways:
        gateway_set.append(_vpn_gateway_to_xml(gateway))
    return _xml_response(root)


def _attach_vpn_gateway(session: Session, params: Dict[str, str]) -> Response:
    """Handle AttachVpnGateway."""
    gateway_id = params.get("VpnGatewayId")
    vpc_id = params.get("VpcId")
    if not gateway_id or not vpc_id:
        return _xml_error("MissingParameter", "VpnGatewayId and VpcId are required")
    gateway = session.get(VpnGateway, gateway_id)
    vpc = session.get(Vpc, vpc_id)
    if not gateway or not vpc:
        return _xml_error("InvalidVpnGatewayID.NotFound", "VPN gateway or VPC not found")
    gateway.vpc_id = vpc_id
    session.commit()

    root = ET.Element(_ns_tag("AttachVpnGatewayResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    attachment = ET.SubElement(root, "attachment")
    ET.SubElement(attachment, "vpcId").text = vpc_id
    ET.SubElement(attachment, "state").text = "attached"
    return _xml_response(root)


def _detach_vpn_gateway(session: Session, params: Dict[str, str]) -> Response:
    """Handle DetachVpnGateway."""
    gateway_id = params.get("VpnGatewayId")
    vpc_id = params.get("VpcId")
    if not gateway_id or not vpc_id:
        return _xml_error("MissingParameter", "VpnGatewayId and VpcId are required")
    gateway = session.get(VpnGateway, gateway_id)
    if not gateway:
        return _xml_error("InvalidVpnGatewayID.NotFound", f"{gateway_id} not found")
    gateway.vpc_id = None
    session.commit()

    root = ET.Element(_ns_tag("DetachVpnGatewayResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
    return _xml_response(root)


def _delete_vpn_gateway(session: Session, params: Dict[str, str]) -> Response:
    """Handle DeleteVpnGateway."""
    gateway_id = params.get("VpnGatewayId")
    if not gateway_id:
        return _xml_error("MissingParameter", "VpnGatewayId is required")
    gateway = session.get(VpnGateway, gateway_id)
    if not gateway:
        return _xml_error("InvalidVpnGatewayID.NotFound", f"{gateway_id} not found")
    if gateway.vpc_id:
        return _xml_error("DependencyViolation", "VPN gateway is attached to a VPC")
    session.delete(gateway)
    session.commit()

    root = ET.Element(_ns_tag("DeleteVpnGatewayResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
    return _xml_response(root)


def _create_vpn_connection(session: Session, params: Dict[str, str]) -> Response:
    """Handle CreateVpnConnection."""
    customer_gateway_id = params.get("CustomerGatewayId")
    vpn_gateway_id = params.get("VpnGatewayId")
    conn_type = params.get("Type")
    if not customer_gateway_id or not vpn_gateway_id or not conn_type:
        return _xml_error("MissingParameter", "CustomerGatewayId, VpnGatewayId, and Type are required")
    customer_gateway = session.get(CustomerGateway, customer_gateway_id)
    vpn_gateway = session.get(VpnGateway, vpn_gateway_id)
    if not customer_gateway or not vpn_gateway:
        return _xml_error("InvalidCustomerGatewayID.NotFound", "Customer or VPN gateway not found")
    tag_specs = _parse_tag_specifications(params)
    connection = VpnConnection(
        id=_generate_id("vpn"),
        customer_gateway_id=customer_gateway_id,
        vpn_gateway_id=vpn_gateway_id,
        connection_type=conn_type,
    )
    session.add(connection)
    _apply_tags(session, connection.id, _tags_for_resource(tag_specs, "vpn-connection"))
    session.commit()

    root = ET.Element(_ns_tag("CreateVpnConnectionResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    node = ET.SubElement(root, "vpnConnection")
    _vpn_connection_fields(node, connection)
    return _xml_response(root)


def _describe_vpn_connections(session: Session, params: Dict[str, str]) -> Response:
    """Handle DescribeVpnConnections."""
    connection_ids = _get_list_params(params, "VpnConnectionId")
    query = session.query(VpnConnection)
    if connection_ids:
        query = query.filter(VpnConnection.id.in_(connection_ids))
    connections = query.all()

    root = ET.Element(_ns_tag("DescribeVpnConnectionsResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    conn_set = ET.SubElement(root, "vpnConnectionSet")
    for connection in connections:
        conn_set.append(_vpn_connection_to_xml(connection))
    return _xml_response(root)


def _delete_vpn_connection(session: Session, params: Dict[str, str]) -> Response:
    """Handle DeleteVpnConnection."""
    connection_id = params.get("VpnConnectionId")
    if not connection_id:
        return _xml_error("MissingParameter", "VpnConnectionId is required")
    connection = session.get(VpnConnection, connection_id)
    if not connection:
        return _xml_error("InvalidVpnConnectionID.NotFound", f"{connection_id} not found")
    session.delete(connection)
    session.commit()

    root = ET.Element(_ns_tag("DeleteVpnConnectionResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
    return _xml_response(root)


def _create_vpc_endpoint_service_configuration(session: Session, params: Dict[str, str]) -> Response:
    """Handle CreateVpcEndpointServiceConfiguration."""
    acceptance_required = params.get("AcceptanceRequired", "false").lower() in {"true", "1", "yes"}
    nlb_arns = _get_list_params(params, "NetworkLoadBalancerArn")
    gwlb_arns = _get_list_params(params, "GatewayLoadBalancerArn")
    if not nlb_arns and not gwlb_arns:
        return _xml_error("MissingParameter", "NetworkLoadBalancerArn or GatewayLoadBalancerArn is required")
    tag_specs = _parse_tag_specifications(params)
    service_id = _generate_id("vpcesvc")
    service_name = f"com.amazonaws.vpce.us-east-1.{service_id}"
    service = VpcEndpointService(
        id=service_id,
        service_name=service_name,
        acceptance_required=acceptance_required,
        state="Available",
        network_load_balancer_arns_json=json.dumps(nlb_arns),
        gateway_load_balancer_arns_json=json.dumps(gwlb_arns),
    )
    session.add(service)
    _apply_tags(session, service.id, _tags_for_resource(tag_specs, "vpc-endpoint-service"))
    session.commit()

    root = ET.Element(_ns_tag("CreateVpcEndpointServiceConfigurationResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    node = ET.SubElement(root, "serviceConfiguration")
    _endpoint_service_fields(node, service)
    return _xml_response(root)


def _describe_vpc_endpoint_service_configurations(session: Session, params: Dict[str, str]) -> Response:
    """Handle DescribeVpcEndpointServiceConfigurations."""
    service_ids = _get_list_params(params, "ServiceId")
    query = session.query(VpcEndpointService)
    if service_ids:
        query = query.filter(VpcEndpointService.id.in_(service_ids))
    services = query.all()

    root = ET.Element(_ns_tag("DescribeVpcEndpointServiceConfigurationsResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    config_set = ET.SubElement(root, "serviceConfigurationSet")
    for service in services:
        config_set.append(_endpoint_service_to_xml(service))
    return _xml_response(root)


def _modify_vpc_endpoint_service_configuration(session: Session, params: Dict[str, str]) -> Response:
    """Handle ModifyVpcEndpointServiceConfiguration."""
    service_id = params.get("ServiceId")
    if not service_id:
        return _xml_error("MissingParameter", "ServiceId is required")
    service = session.get(VpcEndpointService, service_id)
    if not service:
        return _xml_error("InvalidVpcEndpointServiceId.NotFound", f"{service_id} not found")
    if "AcceptanceRequired" in params:
        service.acceptance_required = params.get("AcceptanceRequired", "false").lower() in {"true", "1", "yes"}
    session.commit()

    root = ET.Element(_ns_tag("ModifyVpcEndpointServiceConfigurationResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    node = ET.SubElement(root, "serviceConfiguration")
    _endpoint_service_fields(node, service)
    return _xml_response(root)


def _delete_vpc_endpoint_service_configurations(session: Session, params: Dict[str, str]) -> Response:
    """Handle DeleteVpcEndpointServiceConfigurations."""
    service_ids = _get_list_params(params, "ServiceId")
    if not service_ids:
        return _xml_error("MissingParameter", "ServiceId is required")
    for service_id in service_ids:
        service = session.get(VpcEndpointService, service_id)
        if service:
            session.query(VpcEndpointServicePermission).filter_by(service_id=service_id).delete()
            session.delete(service)
    session.commit()

    root = ET.Element(_ns_tag("DeleteVpcEndpointServiceConfigurationsResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    return _xml_response(root)


def _describe_vpc_endpoint_service_permissions(session: Session, params: Dict[str, str]) -> Response:
    """Handle DescribeVpcEndpointServicePermissions."""
    service_id = params.get("ServiceId")
    if not service_id:
        return _xml_error("MissingParameter", "ServiceId is required")
    permissions = session.query(VpcEndpointServicePermission).filter_by(service_id=service_id).all()

    root = ET.Element(_ns_tag("DescribeVpcEndpointServicePermissionsResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    principal_set = ET.SubElement(root, "allowedPrincipals")
    for permission in permissions:
        item = ET.SubElement(principal_set, "item")
        ET.SubElement(item, "principal").text = permission.principal
        ET.SubElement(item, "principalType").text = "Account"
        ET.SubElement(item, "servicePermissionId").text = permission.id
        ET.SubElement(item, "serviceId").text = permission.service_id
    return _xml_response(root)


def _modify_vpc_endpoint_service_permissions(session: Session, params: Dict[str, str]) -> Response:
    """Handle ModifyVpcEndpointServicePermissions."""
    service_id = params.get("ServiceId")
    if not service_id:
        return _xml_error("MissingParameter", "ServiceId is required")
    service = session.get(VpcEndpointService, service_id)
    if not service:
        return _xml_error("InvalidVpcEndpointServiceId.NotFound", f"{service_id} not found")

    add_principals = _get_list_params(params, "AddAllowedPrincipal")
    add_principals += _get_list_params(params, "AddAllowedPrincipals")
    remove_principals = _get_list_params(params, "RemoveAllowedPrincipal")
    remove_principals += _get_list_params(params, "RemoveAllowedPrincipals")
    for principal in add_principals:
        existing = (
            session.query(VpcEndpointServicePermission)
            .filter_by(service_id=service_id, principal=principal)
            .one_or_none()
        )
        if not existing:
            session.add(
                VpcEndpointServicePermission(
                    id=_generate_id("vpceperm"),
                    service_id=service_id,
                    principal=principal,
                )
            )
    if remove_principals:
        session.query(VpcEndpointServicePermission).filter(
            VpcEndpointServicePermission.service_id == service_id,
            VpcEndpointServicePermission.principal.in_(remove_principals),
        ).delete(synchronize_session=False)
    session.commit()

    root = ET.Element(_ns_tag("ModifyVpcEndpointServicePermissionsResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    return _xml_response(root)


def _describe_vpc_endpoint_services(session: Session, _params: Dict[str, str]) -> Response:
    """Handle DescribeVpcEndpointServices."""
    services = session.query(VpcEndpointService).all()
    root = ET.Element(_ns_tag("DescribeVpcEndpointServicesResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    service_names = ET.SubElement(root, "serviceNames")
    service_details = ET.SubElement(root, "serviceDetails")
    for service in services:
        ET.SubElement(service_names, "item").text = service.service_name
        service_details.append(_endpoint_service_to_xml(service))
    return _xml_response(root)


def _create_vpc_endpoint_connection_notification(session: Session, params: Dict[str, str]) -> Response:
    """Handle CreateVpcEndpointConnectionNotification."""
    service_id = params.get("ServiceId")
    vpc_endpoint_id = params.get("VpcEndpointId")
    arn = params.get("ConnectionNotificationArn")
    events = _get_list_params(params, "ConnectionEvents")
    if not arn or not events:
        return _xml_error("MissingParameter", "ConnectionNotificationArn and ConnectionEvents are required")
    if not service_id and not vpc_endpoint_id:
        return _xml_error("MissingParameter", "ServiceId or VpcEndpointId is required")
    tag_specs = _parse_tag_specifications(params)
    notification = VpcEndpointConnectionNotification(
        id=_generate_id("vpce-notify"),
        service_id=service_id,
        vpc_endpoint_id=vpc_endpoint_id,
        connection_notification_arn=arn,
        connection_notification_type="Topic",
        connection_notification_state="Enabled",
        connection_events_json=json.dumps(events),
    )
    session.add(notification)
    _apply_tags(
        session,
        notification.id,
        _tags_for_resource(tag_specs, "vpc-endpoint-connection-notification"),
    )
    session.commit()

    root = ET.Element(_ns_tag("CreateVpcEndpointConnectionNotificationResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    node = ET.SubElement(root, "connectionNotification")
    _connection_notification_fields(node, notification)
    return _xml_response(root)


def _describe_vpc_endpoint_connection_notifications(session: Session, params: Dict[str, str]) -> Response:
    """Handle DescribeVpcEndpointConnectionNotifications."""
    notification_ids = _get_list_params(params, "ConnectionNotificationId")
    query = session.query(VpcEndpointConnectionNotification)
    if notification_ids:
        query = query.filter(VpcEndpointConnectionNotification.id.in_(notification_ids))
    notifications = query.all()

    root = ET.Element(_ns_tag("DescribeVpcEndpointConnectionNotificationsResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    notif_set = ET.SubElement(root, "connectionNotificationSet")
    for notification in notifications:
        notif_set.append(_connection_notification_to_xml(notification))
    return _xml_response(root)


def _modify_vpc_endpoint_connection_notification(session: Session, params: Dict[str, str]) -> Response:
    """Handle ModifyVpcEndpointConnectionNotification."""
    notification_id = params.get("ConnectionNotificationId")
    if not notification_id:
        return _xml_error("MissingParameter", "ConnectionNotificationId is required")
    notification = session.get(VpcEndpointConnectionNotification, notification_id)
    if not notification:
        return _xml_error("InvalidVpcEndpointConnectionNotificationID.NotFound", f"{notification_id} not found")
    if "ConnectionNotificationArn" in params:
        notification.connection_notification_arn = params["ConnectionNotificationArn"]
    if "ConnectionNotificationState" in params:
        notification.connection_notification_state = params["ConnectionNotificationState"]
    session.commit()

    root = ET.Element(_ns_tag("ModifyVpcEndpointConnectionNotificationResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    node = ET.SubElement(root, "connectionNotification")
    _connection_notification_fields(node, notification)
    return _xml_response(root)


def _delete_vpc_endpoint_connection_notifications(session: Session, params: Dict[str, str]) -> Response:
    """Handle DeleteVpcEndpointConnectionNotifications."""
    notification_ids = _get_list_params(params, "ConnectionNotificationId")
    if not notification_ids:
        return _xml_error("MissingParameter", "ConnectionNotificationId is required")
    for notification_id in notification_ids:
        notification = session.get(VpcEndpointConnectionNotification, notification_id)
        if notification:
            session.delete(notification)
    session.commit()

    root = ET.Element(_ns_tag("DeleteVpcEndpointConnectionNotificationsResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "unsuccessful")
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


def _detach_igw(session: Session, params: Dict[str, str]) -> Response:
    """Handle DetachInternetGateway."""
    igw_id = params.get("InternetGatewayId")
    vpc_id = params.get("VpcId")
    if not igw_id or not vpc_id:
        return _xml_error("MissingParameter", "InternetGatewayId and VpcId are required")
    igw = session.get(InternetGateway, igw_id)
    if not igw:
        return _xml_error("InvalidInternetGatewayID.NotFound", f"IGW {igw_id} not found")
    if igw.vpc_id != vpc_id:
        return _xml_error("Gateway.NotAttached", "Internet gateway is not attached to the VPC")
    igw.vpc_id = None
    session.commit()

    root = ET.Element(_ns_tag("DetachInternetGatewayResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
    return _xml_response(root)


def _delete_igw(session: Session, params: Dict[str, str]) -> Response:
    """Handle DeleteInternetGateway."""
    igw_id = params.get("InternetGatewayId")
    if not igw_id:
        return _xml_error("MissingParameter", "InternetGatewayId is required")
    igw = session.get(InternetGateway, igw_id)
    if not igw:
        return _xml_error("InvalidInternetGatewayID.NotFound", f"IGW {igw_id} not found")
    if igw.vpc_id:
        return _xml_error("DependencyViolation", "Internet gateway is attached to a VPC")
    session.delete(igw)
    session.commit()

    root = ET.Element(_ns_tag("DeleteInternetGatewayResponse"))
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

    tag_specs = _parse_tag_specifications(params)
    peering = VpcPeeringConnection(
        id=_generate_id("pcx"),
        requester_vpc_id=requester_vpc_id,
        accepter_vpc_id=accepter_vpc_id,
        status="active",
    )
    session.add(peering)
    _apply_tags(session, peering.id, _tags_for_resource(tag_specs, "vpc-peering-connection"))
    session.commit()

    root = ET.Element(_ns_tag("CreateVpcPeeringConnectionResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    connection = ET.SubElement(root, "vpcPeeringConnection")
    _peering_fields(connection, peering)
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
    _peering_fields(connection, peering)
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


def _create_dhcp_options(session: Session, params: Dict[str, str]) -> Response:
    configs = _parse_dhcp_configurations(params)
    tag_specs = _parse_tag_specifications(params)
    options = DhcpOptions(
        id=_generate_id("dopt"),
        configurations_json=json.dumps(configs),
    )
    session.add(options)
    _apply_tags(session, options.id, _tags_for_resource(tag_specs, "dhcp-options"))
    session.commit()

    root = ET.Element(_ns_tag("CreateDhcpOptionsResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    node = ET.SubElement(root, "dhcpOptions")
    _dhcp_options_fields(node, options)
    return _xml_response(root)


def _describe_dhcp_options(session: Session, params: Dict[str, str]) -> Response:
    dopt_ids = _get_list_params(params, "DhcpOptionsId")
    query = session.query(DhcpOptions)
    if dopt_ids:
        query = query.filter(DhcpOptions.id.in_(dopt_ids))
    options = query.all()

    root = ET.Element(_ns_tag("DescribeDhcpOptionsResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    dopt_set = ET.SubElement(root, "dhcpOptionsSet")
    for option in options:
        dopt_set.append(_dhcp_options_to_xml(option))
    return _xml_response(root)


def _delete_dhcp_options(session: Session, params: Dict[str, str]) -> Response:
    dopt_id = params.get("DhcpOptionsId")
    if not dopt_id:
        return _xml_error("MissingParameter", "DhcpOptionsId is required")
    options = session.get(DhcpOptions, dopt_id)
    if not options:
        return _xml_error("InvalidDhcpOptionID.NotFound", f"DhcpOptions {dopt_id} not found")
    if options.vpcs:
        return _xml_error("DependencyViolation", "DHCP options are associated with VPCs")
    session.delete(options)
    session.commit()

    root = ET.Element(_ns_tag("DeleteDhcpOptionsResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
    return _xml_response(root)


def _associate_dhcp_options(session: Session, params: Dict[str, str]) -> Response:
    dopt_id = params.get("DhcpOptionsId")
    vpc_id = params.get("VpcId")
    if not dopt_id or not vpc_id:
        return _xml_error("MissingParameter", "DhcpOptionsId and VpcId are required")
    options = session.get(DhcpOptions, dopt_id)
    vpc = session.get(Vpc, vpc_id)
    if not options or not vpc:
        return _xml_error("InvalidDhcpOptionID.NotFound", "DHCP options or VPC not found")
    vpc.dhcp_options_id = dopt_id
    session.commit()

    root = ET.Element(_ns_tag("AssociateDhcpOptionsResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
    return _xml_response(root)


def _create_security_group(session: Session, params: Dict[str, str]) -> Response:
    name = params.get("GroupName")
    description = params.get("GroupDescription")
    vpc_id = params.get("VpcId")
    if not name or not description or not vpc_id:
        return _xml_error("MissingParameter", "GroupName, GroupDescription, and VpcId are required")
    vpc = session.get(Vpc, vpc_id)
    if not vpc:
        return _xml_error("InvalidVpcID.NotFound", f"Vpc {vpc_id} not found")

    tag_specs = _parse_tag_specifications(params)
    group = SecurityGroup(
        id=_generate_id("sg"),
        name=name,
        description=description,
        vpc_id=vpc_id,
    )
    session.add(group)
    _apply_tags(session, group.id, _tags_for_resource(tag_specs, "security-group"))
    session.commit()

    root = ET.Element(_ns_tag("CreateSecurityGroupResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "groupId").text = group.id
    return _xml_response(root)


def _describe_security_groups(session: Session, params: Dict[str, str]) -> Response:
    group_ids = _get_list_params(params, "GroupId")
    query = session.query(SecurityGroup)
    if group_ids:
        query = query.filter(SecurityGroup.id.in_(group_ids))
    for flt in _get_filter_params(params):
        name = flt.get("name")
        values = flt.get("values", [])
        if not values:
            continue
        if name == "group-name":
            query = query.filter(SecurityGroup.name.in_(values))
        elif name == "vpc-id":
            query = query.filter(SecurityGroup.vpc_id.in_(values))
        elif name == "group-id":
            query = query.filter(SecurityGroup.id.in_(values))
    groups = query.all()

    root = ET.Element(_ns_tag("DescribeSecurityGroupsResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    group_set = ET.SubElement(root, "securityGroupInfo")
    for group in groups:
        group_set.append(_security_group_to_xml(group))
    return _xml_response(root)


def _delete_security_group(session: Session, params: Dict[str, str]) -> Response:
    group_id = params.get("GroupId")
    if not group_id:
        return _xml_error("MissingParameter", "GroupId is required")
    group = session.get(SecurityGroup, group_id)
    if not group:
        return _xml_error("InvalidGroup.NotFound", f"Security group {group_id} not found")
    session.delete(group)
    session.commit()

    root = ET.Element(_ns_tag("DeleteSecurityGroupResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
    return _xml_response(root)


def _apply_security_group_rules(
    session: Session,
    group_id: str,
    permissions: list[dict],
    direction: str,
) -> None:
    for perm in permissions:
        protocol = perm["protocol"]
        from_port = perm["from_port"]
        to_port = perm["to_port"]

        if perm["ipv4_ranges"]:
            for cidr in perm["ipv4_ranges"]:
                session.add(
                    SecurityGroupRule(
                        id=_generate_id("sgr"),
                        security_group_id=group_id,
                        direction=direction,
                        protocol=protocol,
                        from_port=from_port,
                        to_port=to_port,
                        cidr_ipv4=cidr,
                    )
                )
        if perm["ipv6_ranges"]:
            for cidr in perm["ipv6_ranges"]:
                session.add(
                    SecurityGroupRule(
                        id=_generate_id("sgr"),
                        security_group_id=group_id,
                        direction=direction,
                        protocol=protocol,
                        from_port=from_port,
                        to_port=to_port,
                        cidr_ipv6=cidr,
                    )
                )
        if perm["group_pairs"]:
            for group in perm["group_pairs"]:
                session.add(
                    SecurityGroupRule(
                        id=_generate_id("sgr"),
                        security_group_id=group_id,
                        direction=direction,
                        protocol=protocol,
                        from_port=from_port,
                        to_port=to_port,
                        source_group_id=group,
                    )
                )


def _authorize_security_group_ingress(session: Session, params: Dict[str, str]) -> Response:
    group_id = params.get("GroupId")
    if not group_id:
        return _xml_error("MissingParameter", "GroupId is required")
    group = session.get(SecurityGroup, group_id)
    if not group:
        return _xml_error("InvalidGroup.NotFound", f"Security group {group_id} not found")
    permissions = _parse_ip_permissions(params, "IpPermissions")
    _apply_security_group_rules(session, group_id, permissions, "ingress")
    session.commit()

    root = ET.Element(_ns_tag("AuthorizeSecurityGroupIngressResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
    return _xml_response(root)


def _authorize_security_group_egress(session: Session, params: Dict[str, str]) -> Response:
    group_id = params.get("GroupId")
    if not group_id:
        return _xml_error("MissingParameter", "GroupId is required")
    group = session.get(SecurityGroup, group_id)
    if not group:
        return _xml_error("InvalidGroup.NotFound", f"Security group {group_id} not found")
    permissions = _parse_ip_permissions(params, "IpPermissions")
    _apply_security_group_rules(session, group_id, permissions, "egress")
    session.commit()

    root = ET.Element(_ns_tag("AuthorizeSecurityGroupEgressResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
    return _xml_response(root)


def _revoke_security_group_rules(
    session: Session,
    group_id: str,
    permissions: list[dict],
    direction: str,
) -> None:
    for perm in permissions:
        protocol = perm["protocol"]
        from_port = perm["from_port"]
        to_port = perm["to_port"]
        if perm["ipv4_ranges"]:
            for cidr in perm["ipv4_ranges"]:
                session.query(SecurityGroupRule).filter_by(
                    security_group_id=group_id,
                    direction=direction,
                    protocol=protocol,
                    from_port=from_port,
                    to_port=to_port,
                    cidr_ipv4=cidr,
                ).delete()
        if perm["ipv6_ranges"]:
            for cidr in perm["ipv6_ranges"]:
                session.query(SecurityGroupRule).filter_by(
                    security_group_id=group_id,
                    direction=direction,
                    protocol=protocol,
                    from_port=from_port,
                    to_port=to_port,
                    cidr_ipv6=cidr,
                ).delete()
        if perm["group_pairs"]:
            for group in perm["group_pairs"]:
                session.query(SecurityGroupRule).filter_by(
                    security_group_id=group_id,
                    direction=direction,
                    protocol=protocol,
                    from_port=from_port,
                    to_port=to_port,
                    source_group_id=group,
                ).delete()


def _revoke_security_group_ingress(session: Session, params: Dict[str, str]) -> Response:
    group_id = params.get("GroupId")
    if not group_id:
        return _xml_error("MissingParameter", "GroupId is required")
    group = session.get(SecurityGroup, group_id)
    if not group:
        return _xml_error("InvalidGroup.NotFound", f"Security group {group_id} not found")
    permissions = _parse_ip_permissions(params, "IpPermissions")
    _revoke_security_group_rules(session, group_id, permissions, "ingress")
    session.commit()

    root = ET.Element(_ns_tag("RevokeSecurityGroupIngressResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
    return _xml_response(root)


def _revoke_security_group_egress(session: Session, params: Dict[str, str]) -> Response:
    group_id = params.get("GroupId")
    if not group_id:
        return _xml_error("MissingParameter", "GroupId is required")
    group = session.get(SecurityGroup, group_id)
    if not group:
        return _xml_error("InvalidGroup.NotFound", f"Security group {group_id} not found")
    permissions = _parse_ip_permissions(params, "IpPermissions")
    _revoke_security_group_rules(session, group_id, permissions, "egress")
    session.commit()

    root = ET.Element(_ns_tag("RevokeSecurityGroupEgressResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
    return _xml_response(root)


def _create_tags(session: Session, params: Dict[str, str]) -> Response:
    resource_ids = _get_list_params(params, "ResourceId")
    tags = _parse_tags(params)
    if not resource_ids or not tags:
        return _xml_error("MissingParameter", "ResourceId and Tag are required")

    for resource_id in resource_ids:
        for tag in tags:
            existing = (
                session.query(Tag)
                .filter_by(resource_id=resource_id, key=tag["key"])
                .one_or_none()
            )
            if existing:
                existing.value = tag.get("value")
            else:
                session.add(
                    Tag(
                        id=_generate_id("tag"),
                        resource_id=resource_id,
                        key=tag["key"],
                        value=tag.get("value"),
                    )
                )
    session.commit()

    root = ET.Element(_ns_tag("CreateTagsResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
    return _xml_response(root)


def _delete_tags(session: Session, params: Dict[str, str]) -> Response:
    resource_ids = _get_list_params(params, "ResourceId")
    tags = _parse_tags(params)
    if not resource_ids or not tags:
        return _xml_error("MissingParameter", "ResourceId and Tag are required")

    for resource_id in resource_ids:
        for tag in tags:
            query = session.query(Tag).filter_by(resource_id=resource_id, key=tag["key"])
            value = tag.get("value")
            if value is not None:
                query = query.filter_by(value=value)
            for existing in query.all():
                session.delete(existing)
    session.commit()

    root = ET.Element(_ns_tag("DeleteTagsResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    ET.SubElement(root, "return").text = "true"
    return _xml_response(root)


def _describe_tags(session: Session, params: Dict[str, str]) -> Response:
    filters = _get_filter_params(params)
    query = session.query(Tag)
    for flt in filters:
        values = flt.get("values", [])
        if not values:
            continue
        name = flt.get("name")
        if name == "resource-id":
            query = query.filter(Tag.resource_id.in_(values))
        elif name == "key":
            query = query.filter(Tag.key.in_(values))
        elif name == "value":
            query = query.filter(Tag.value.in_(values))
    tags = query.all()

    root = ET.Element(_ns_tag("DescribeTagsResponse"))
    ET.SubElement(root, "requestId").text = _request_id()
    tag_set = ET.SubElement(root, "tagSet")
    for tag in tags:
        item = ET.SubElement(tag_set, "item")
        ET.SubElement(item, "resourceId").text = tag.resource_id
        resource_type = _resource_type_from_id(tag.resource_id)
        if resource_type != "unknown":
            ET.SubElement(item, "resourceType").text = resource_type
        ET.SubElement(item, "key").text = tag.key
        if tag.value is not None:
            ET.SubElement(item, "value").text = tag.value
    return _xml_response(root)


_ACTIONS = {
    "CreateVpc": _create_vpc,
    "DescribeVpcs": _describe_vpcs,
    "DeleteVpc": _delete_vpc,
    "AssociateVpcCidrBlock": _associate_vpc_cidr_block,
    "DisassociateVpcCidrBlock": _disassociate_vpc_cidr_block,
    "DescribeVpcAttribute": _describe_vpc_attribute,
    "ModifyVpcAttribute": _modify_vpc_attribute,
    "CreateSubnet": _create_subnet,
    "DescribeSubnets": _describe_subnets,
    "DeleteSubnet": _delete_subnet,
    "DescribeSubnetAttribute": _describe_subnet_attribute,
    "ModifySubnetAttribute": _modify_subnet_attribute,
    "CreateNetworkAcl": _create_network_acl,
    "DescribeNetworkAcls": _describe_network_acls,
    "DeleteNetworkAcl": _delete_network_acl,
    "CreateNetworkAclEntry": _create_network_acl_entry,
    "DeleteNetworkAclEntry": _delete_network_acl_entry,
    "ReplaceNetworkAclEntry": _replace_network_acl_entry,
    "ReplaceNetworkAclAssociation": _replace_network_acl_association,
    "CreateRouteTable": _create_route_table,
    "DescribeRouteTables": _describe_route_tables,
    "DeleteRouteTable": _delete_route_table,
    "AssociateRouteTable": _associate_route_table,
    "DisassociateRouteTable": _disassociate_route_table,
    "CreateRoute": _create_route,
    "DeleteRoute": _delete_route,
    "CreateInternetGateway": _create_igw,
    "CreateEgressOnlyInternetGateway": _create_egress_only_igw,
    "DescribeInternetGateways": _describe_igws,
    "DescribeEgressOnlyInternetGateways": _describe_egress_only_igws,
    "AttachInternetGateway": _attach_igw,
    "DetachInternetGateway": _detach_igw,
    "DeleteInternetGateway": _delete_igw,
    "DeleteEgressOnlyInternetGateway": _delete_egress_only_igw,
    "AllocateAddress": _allocate_address,
    "DescribeAddresses": _describe_addresses,
    "ReleaseAddress": _release_address,
    "CreateNatGateway": _create_nat_gateway,
    "DescribeNatGateways": _describe_nat_gateways,
    "DeleteNatGateway": _delete_nat_gateway,
    "CreateVpcEndpoint": _create_vpc_endpoint,
    "DescribeVpcEndpoints": _describe_vpc_endpoints,
    "ModifyVpcEndpoint": _modify_vpc_endpoint,
    "DeleteVpcEndpoints": _delete_vpc_endpoints,
    "CreateFlowLogs": _create_flow_logs,
    "DescribeFlowLogs": _describe_flow_logs,
    "DeleteFlowLogs": _delete_flow_logs,
    "CreateVpcEndpointServiceConfiguration": _create_vpc_endpoint_service_configuration,
    "DescribeVpcEndpointServiceConfigurations": _describe_vpc_endpoint_service_configurations,
    "ModifyVpcEndpointServiceConfiguration": _modify_vpc_endpoint_service_configuration,
    "DeleteVpcEndpointServiceConfigurations": _delete_vpc_endpoint_service_configurations,
    "DescribeVpcEndpointServicePermissions": _describe_vpc_endpoint_service_permissions,
    "ModifyVpcEndpointServicePermissions": _modify_vpc_endpoint_service_permissions,
    "DescribeVpcEndpointServices": _describe_vpc_endpoint_services,
    "CreateVpcEndpointConnectionNotification": _create_vpc_endpoint_connection_notification,
    "DescribeVpcEndpointConnectionNotifications": _describe_vpc_endpoint_connection_notifications,
    "ModifyVpcEndpointConnectionNotification": _modify_vpc_endpoint_connection_notification,
    "DeleteVpcEndpointConnectionNotifications": _delete_vpc_endpoint_connection_notifications,
    "CreateCustomerGateway": _create_customer_gateway,
    "DescribeCustomerGateways": _describe_customer_gateways,
    "DeleteCustomerGateway": _delete_customer_gateway,
    "CreateVpnGateway": _create_vpn_gateway,
    "DescribeVpnGateways": _describe_vpn_gateways,
    "AttachVpnGateway": _attach_vpn_gateway,
    "DetachVpnGateway": _detach_vpn_gateway,
    "DeleteVpnGateway": _delete_vpn_gateway,
    "CreateVpnConnection": _create_vpn_connection,
    "DescribeVpnConnections": _describe_vpn_connections,
    "DeleteVpnConnection": _delete_vpn_connection,
    "CreateVpcPeeringConnection": _create_vpc_peering_connection,
    "DescribeVpcPeeringConnections": _describe_vpc_peering_connections,
    "AcceptVpcPeeringConnection": _accept_vpc_peering_connection,
    "DeleteVpcPeeringConnection": _delete_vpc_peering_connection,
    "CreateDhcpOptions": _create_dhcp_options,
    "DescribeDhcpOptions": _describe_dhcp_options,
    "DeleteDhcpOptions": _delete_dhcp_options,
    "AssociateDhcpOptions": _associate_dhcp_options,
    "CreateSecurityGroup": _create_security_group,
    "DescribeSecurityGroups": _describe_security_groups,
    "DeleteSecurityGroup": _delete_security_group,
    "AuthorizeSecurityGroupIngress": _authorize_security_group_ingress,
    "AuthorizeSecurityGroupEgress": _authorize_security_group_egress,
    "RevokeSecurityGroupIngress": _revoke_security_group_ingress,
    "RevokeSecurityGroupEgress": _revoke_security_group_egress,
    "CreateTags": _create_tags,
    "DeleteTags": _delete_tags,
    "DescribeTags": _describe_tags,
}
