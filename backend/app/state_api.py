"""State reporting endpoints."""
from __future__ import annotations

import json

from fastapi import APIRouter

from .db import SessionLocal
from .models import (
    Base,
    DhcpOptions,
    EgressOnlyInternetGateway,
    ElasticIp,
    FlowLog,
    CustomerGateway,
    InternetGateway,
    NatGateway,
    NatGatewayAddress,
    NetworkAcl,
    RouteTable,
    SecurityGroup,
    Subnet,
    Tag,
    Vpc,
    VpcEndpoint,
    VpcEndpointConnectionNotification,
    VpcEndpointService,
    VpcEndpointServicePermission,
    VpcPeeringConnection,
    VpnConnection,
    VpnGateway,
)
from .serializers import route_summary

router = APIRouter(prefix="/state")


@router.get("")
def get_state(tag: str | None = None) -> dict:
    """Return the current simulator state."""
    with SessionLocal() as session:
        tagged_ids: set[str] | None = None
        if tag:
            tagged_ids = {
                row[0]
                for row in session.query(Tag.resource_id)
                .filter(Tag.key == "TestNamespace", Tag.value == tag)
                .all()
            }

        def _filter(
            items: list[dict], id_key: str = "id", extra_keys: tuple[str, ...] = ()
        ) -> list[dict]:
            if tagged_ids is None:
                return items
            scoped: list[dict] = []
            for item in items:
                if item.get(id_key) in tagged_ids:
                    scoped.append(item)
                    continue
                for key in extra_keys:
                    if item.get(key) in tagged_ids:
                        scoped.append(item)
                        break
            return scoped

        vpcs = session.query(Vpc).all()
        subnets = session.query(Subnet).all()
        route_tables = session.query(RouteTable).all()
        igws = session.query(InternetGateway).all()
        elastic_ips = session.query(ElasticIp).all()
        nat_gateways = session.query(NatGateway).all()
        nat_gateway_addresses = session.query(NatGatewayAddress).all()
        vpc_endpoints = session.query(VpcEndpoint).all()
        flow_logs = session.query(FlowLog).all()
        customer_gateways = session.query(CustomerGateway).all()
        vpn_gateways = session.query(VpnGateway).all()
        vpn_connections = session.query(VpnConnection).all()
        endpoint_services = session.query(VpcEndpointService).all()
        endpoint_permissions = session.query(VpcEndpointServicePermission).all()
        endpoint_notifications = session.query(VpcEndpointConnectionNotification).all()
        peerings = session.query(VpcPeeringConnection).all()
        dhcp_options = session.query(DhcpOptions).all()
        security_groups = session.query(SecurityGroup).all()
        network_acls = session.query(NetworkAcl).all()
        egress_only_igws = session.query(EgressOnlyInternetGateway).all()

        return {
            "vpcs": _filter(
                [
                    {
                        "id": vpc.id,
                        "cidr_block": vpc.cidr_block,
                        "ipv6_cidr_block": vpc.ipv6_cidr_block,
                        "dhcp_options_id": vpc.dhcp_options_id,
                        "state": vpc.state,
                    }
                    for vpc in vpcs
                ]
            ),
            "subnets": _filter(
                [
                    {
                        "id": subnet.id,
                        "vpc_id": subnet.vpc_id,
                        "cidr_block": subnet.cidr_block,
                        "ipv6_cidr_block": subnet.ipv6_cidr_block,
                        "availability_zone": subnet.availability_zone,
                        "state": subnet.state,
                        "route_table_id": subnet.route_table_id,
                    }
                    for subnet in subnets
                ],
                extra_keys=("vpc_id",),
            ),
            "route_tables": _filter(
                [
                    {
                        "id": route_table.id,
                        "vpc_id": route_table.vpc_id,
                        "routes": [
                            route_summary(route) for route in route_table.routes
                        ],
                    }
                    for route_table in route_tables
                ],
                extra_keys=("vpc_id",),
            ),
            "internet_gateways": _filter(
                [{"id": igw.id, "vpc_id": igw.vpc_id} for igw in igws],
                extra_keys=("vpc_id",),
            ),
            "elastic_ips": _filter(
                [
                    {
                        "id": address.id,
                        "public_ip": address.public_ip,
                        "domain": address.domain,
                    }
                    for address in elastic_ips
                ]
            ),
            "nat_gateways": _filter(
                [
                    {
                        "id": gateway.id,
                        "subnet_id": gateway.subnet_id,
                        "vpc_id": gateway.vpc_id,
                        "state": gateway.state,
                        "addresses": [
                            {
                                "allocation_id": addr.allocation_id,
                                "public_ip": addr.public_ip,
                                "private_ip": addr.private_ip,
                            }
                            for addr in nat_gateway_addresses
                            if addr.nat_gateway_id == gateway.id
                        ],
                    }
                    for gateway in nat_gateways
                ],
                extra_keys=("vpc_id", "subnet_id"),
            ),
            "vpc_endpoints": _filter(
                [
                    {
                        "id": endpoint.id,
                        "vpc_id": endpoint.vpc_id,
                        "service_name": endpoint.service_name,
                        "vpc_endpoint_type": endpoint.vpc_endpoint_type,
                        "state": endpoint.state,
                    }
                    for endpoint in vpc_endpoints
                ],
                extra_keys=("vpc_id",),
            ),
            "flow_logs": _filter(
                [
                    {
                        "id": flow_log.id,
                        "resource_id": flow_log.resource_id,
                        "resource_type": flow_log.resource_type,
                        "traffic_type": flow_log.traffic_type,
                        "log_destination_type": flow_log.log_destination_type,
                        "log_destination": flow_log.log_destination,
                        "status": flow_log.status,
                    }
                    for flow_log in flow_logs
                ],
                extra_keys=("resource_id",),
            ),
            "vpc_endpoint_services": _filter(
                [
                    {
                        "id": service.id,
                        "service_name": service.service_name,
                        "acceptance_required": service.acceptance_required,
                        "state": service.state,
                        "network_load_balancer_arns": json.loads(
                            service.network_load_balancer_arns_json
                        ),
                        "gateway_load_balancer_arns": json.loads(
                            service.gateway_load_balancer_arns_json
                        ),
                        "allowed_principals": [
                            permission.principal
                            for permission in endpoint_permissions
                            if permission.service_id == service.id
                        ],
                    }
                    for service in endpoint_services
                ]
            ),
            "vpc_endpoint_connection_notifications": _filter(
                [
                    {
                        "id": notification.id,
                        "service_id": notification.service_id,
                        "vpc_endpoint_id": notification.vpc_endpoint_id,
                        "connection_notification_arn": notification.connection_notification_arn,
                        "connection_notification_type": notification.connection_notification_type,
                        "connection_notification_state": notification.connection_notification_state,
                        "connection_events": json.loads(
                            notification.connection_events_json
                        ),
                    }
                    for notification in endpoint_notifications
                ],
                extra_keys=("service_id", "vpc_endpoint_id"),
            ),
            "customer_gateways": _filter(
                [
                    {
                        "id": gateway.id,
                        "bgp_asn": gateway.bgp_asn,
                        "ip_address": gateway.ip_address,
                        "type": gateway.gateway_type,
                        "state": gateway.state,
                    }
                    for gateway in customer_gateways
                ]
            ),
            "vpn_gateways": _filter(
                [
                    {
                        "id": gateway.id,
                        "type": gateway.gateway_type,
                        "vpc_id": gateway.vpc_id,
                        "state": gateway.state,
                    }
                    for gateway in vpn_gateways
                ]
            ),
            "vpn_connections": _filter(
                [
                    {
                        "id": connection.id,
                        "customer_gateway_id": connection.customer_gateway_id,
                        "vpn_gateway_id": connection.vpn_gateway_id,
                        "type": connection.connection_type,
                        "state": connection.state,
                    }
                    for connection in vpn_connections
                ]
            ),
            "dhcp_options": _filter([{"id": options.id} for options in dhcp_options]),
            "security_groups": _filter(
                [
                    {
                        "id": group.id,
                        "name": group.name,
                        "description": group.description,
                        "vpc_id": group.vpc_id,
                        "rules": [
                            {
                                "id": rule.id,
                                "direction": rule.direction,
                                "protocol": rule.protocol,
                                "from_port": rule.from_port,
                                "to_port": rule.to_port,
                                "cidr_ipv4": rule.cidr_ipv4,
                                "cidr_ipv6": rule.cidr_ipv6,
                                "source_group_id": rule.source_group_id,
                                "description": rule.description,
                            }
                            for rule in group.rules
                        ],
                    }
                    for group in security_groups
                ],
                extra_keys=("vpc_id",),
            ),
            "vpc_peerings": _filter(
                [
                    {
                        "id": peering.id,
                        "requester_vpc_id": peering.requester_vpc_id,
                        "accepter_vpc_id": peering.accepter_vpc_id,
                        "status": peering.status,
                    }
                    for peering in peerings
                ],
                extra_keys=("requester_vpc_id", "accepter_vpc_id"),
            ),
            "network_acls": _filter(
                [
                    {
                        "id": acl.id,
                        "vpc_id": acl.vpc_id,
                        "is_default": acl.is_default,
                        "entries": [
                            {
                                "id": entry.id,
                                "egress": entry.egress,
                                "rule_number": entry.rule_number,
                                "protocol": entry.protocol,
                                "rule_action": entry.rule_action,
                                "cidr_block": entry.cidr_block,
                                "ipv6_cidr_block": entry.ipv6_cidr_block,
                                "from_port": entry.from_port,
                                "to_port": entry.to_port,
                            }
                            for entry in acl.entries
                        ],
                        "associations": [
                            {
                                "id": assoc.id,
                                "subnet_id": assoc.subnet_id,
                            }
                            for assoc in acl.associations
                        ],
                    }
                    for acl in network_acls
                ],
                extra_keys=("vpc_id",),
            ),
            "egress_only_internet_gateways": _filter(
                [{"id": igw.id, "vpc_id": igw.vpc_id} for igw in egress_only_igws],
                extra_keys=("vpc_id",),
            ),
        }


@router.post("/reset")
def reset_state() -> dict:
    """Clear all simulator state."""
    with SessionLocal() as session:
        for table in reversed(Base.metadata.sorted_tables):
            session.execute(table.delete())
        session.commit()
    return {"status": "ok"}
