"""Connectivity validation for simulated VPC routing."""
from __future__ import annotations

import ipaddress
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .db import SessionLocal
from .models import Route, RouteTable, RouteTableAssociation, Subnet, Vpc, VpcPeeringConnection
from .serializers import route_summary
from .tracing import trace_span

router = APIRouter(prefix="/validate")


class ConnectivityRequest(BaseModel):
    """Connectivity check request payload."""

    source_subnet_id: Optional[str] = None
    source_vpc_id: Optional[str] = None
    destination_cidr: str = Field(..., description="CIDR block to test reachability")


def _resolve_source(session: Session, payload: ConnectivityRequest) -> tuple[Subnet | None, Vpc]:
    """Resolve the source subnet/VPC from the request."""
    if payload.source_subnet_id:
        subnet = session.get(Subnet, payload.source_subnet_id)
        if not subnet:
            raise HTTPException(status_code=404, detail="Subnet not found")
        vpc = session.get(Vpc, subnet.vpc_id)
        if not vpc:
            raise HTTPException(status_code=404, detail="VPC not found")
        return subnet, vpc

    vpc = session.get(Vpc, payload.source_vpc_id)
    if not vpc:
        raise HTTPException(status_code=404, detail="VPC not found")
    return None, vpc


def _resolve_route_table(session: Session, subnet: Subnet | None) -> RouteTable | None:
    """Resolve the route table associated with a subnet."""
    if subnet and subnet.route_table_id:
        return session.get(RouteTable, subnet.route_table_id)
    if subnet:
        association = (
            session.query(RouteTableAssociation)
            .join(RouteTable)
            .filter(RouteTable.vpc_id == subnet.vpc_id, RouteTableAssociation.main.is_(True))
            .one_or_none()
        )
        if association:
            return session.get(RouteTable, association.route_table_id)
    return None


def _route_matches(dest_net: ipaddress._BaseNetwork, route_net: ipaddress._BaseNetwork) -> bool:
    """Return whether a route matches the destination network."""
    if dest_net.version != route_net.version:
        return False
    if isinstance(dest_net, ipaddress.IPv4Network) and isinstance(route_net, ipaddress.IPv4Network):
        return dest_net.subnet_of(route_net) or dest_net.overlaps(route_net)
    if isinstance(dest_net, ipaddress.IPv6Network) and isinstance(route_net, ipaddress.IPv6Network):
        return dest_net.subnet_of(route_net) or dest_net.overlaps(route_net)
    return False


def _find_best_route(route_table: RouteTable, destination_cidr: str) -> Route | None:
    """Find the most specific matching route for a destination."""
    dest_net = ipaddress.ip_network(destination_cidr, strict=False)
    best_route = None
    best_prefix = -1
    for route in route_table.routes:
        route_net = ipaddress.ip_network(route.destination_cidr, strict=False)
        if _route_matches(dest_net, route_net) and route_net.prefixlen > best_prefix:
            best_route = route
            best_prefix = route_net.prefixlen
    return best_route


def _validate_peering(
    session: Session,
    route_table: RouteTable,
    matched_route: Route,
    destination_cidr: str,
) -> tuple[bool, list[str]]:
    """Validate reachability across a peering connection."""
    warnings: list[str] = []
    reachable = False
    peering = session.get(VpcPeeringConnection, matched_route.target_id)
    if not peering or peering.status != "active":
        warnings.append("Peering connection not active")
        return reachable, warnings

    peer_vpc_id = None
    if route_table.vpc_id == peering.requester_vpc_id:
        peer_vpc_id = peering.accepter_vpc_id
    elif route_table.vpc_id == peering.accepter_vpc_id:
        peer_vpc_id = peering.requester_vpc_id
    if not peer_vpc_id:
        warnings.append("Route table VPC not part of peering connection")
        return reachable, warnings

    peer_vpc = session.get(Vpc, peer_vpc_id)
    if not peer_vpc:
        warnings.append("Peer VPC not found")
        return reachable, warnings

    dest_net = ipaddress.ip_network(destination_cidr, strict=False)
    if dest_net.version == 6:
        if not peer_vpc.ipv6_cidr_block:
            warnings.append("Peer VPC has no IPv6 CIDR")
            return reachable, warnings
        peer_net = ipaddress.ip_network(peer_vpc.ipv6_cidr_block, strict=False)
        if isinstance(peer_net, ipaddress.IPv6Network) and dest_net.subnet_of(peer_net):
            reachable = True
        else:
            warnings.append("Destination not within peer IPv6 CIDR")
        return reachable, warnings

    peer_net = ipaddress.ip_network(peer_vpc.cidr_block, strict=False)
    if isinstance(peer_net, ipaddress.IPv4Network) and dest_net.subnet_of(peer_net):
        reachable = True
    else:
        warnings.append("Destination not within peer IPv4 CIDR")
    return reachable, warnings


@router.post("/connectivity")
def validate_connectivity(payload: ConnectivityRequest) -> dict:
    """Validate reachability from a subnet/VPC to a destination CIDR."""
    if not payload.source_subnet_id and not payload.source_vpc_id:
        raise HTTPException(status_code=400, detail="source_subnet_id or source_vpc_id is required")

    with trace_span("validate.connectivity"):
        with SessionLocal() as session:
            with trace_span("validate.resolve_source"):
                subnet, vpc = _resolve_source(session, payload)
            with trace_span("validate.resolve_route_table"):
                route_table = _resolve_route_table(session, subnet)
            with trace_span("validate.match_route"):
                matched_route = (
                    _find_best_route(route_table, payload.destination_cidr) if route_table else None
                )
            result = {
                "source": {
                    "subnet_id": subnet.id if subnet else None,
                    "vpc_id": vpc.id if vpc else None,
                },
                "destination_cidr": payload.destination_cidr,
                "route_table_id": route_table.id if route_table else None,
                "matched_route": None,
                "reachable": False,
                "warnings": [],
            }

            if not route_table:
                result["warnings"].append("No route table associated with subnet")
            elif not matched_route:
                result["warnings"].append("No matching route found")
            else:
                result["matched_route"] = route_summary(matched_route)
                if matched_route.target_type == "igw":
                    result["reachable"] = True
                    if not vpc:
                        result["warnings"].append("VPC not resolved for IGW validation")
                elif matched_route.target_type == "pcx":
                    with trace_span("validate.peering"):
                        reachable, warnings = _validate_peering(
                            session, route_table, matched_route, payload.destination_cidr
                        )
                    result["reachable"] = reachable
                    result["warnings"].extend(warnings)
                else:
                    result["warnings"].append("Target type not supported for reachability")

            return result
