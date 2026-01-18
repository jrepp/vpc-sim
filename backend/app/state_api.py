"""State reporting endpoints."""
from __future__ import annotations

from fastapi import APIRouter

from .db import SessionLocal
from .models import InternetGateway, RouteTable, Subnet, Vpc, VpcPeeringConnection
from .serializers import route_summary

router = APIRouter(prefix="/state")


@router.get("")
def get_state() -> dict:
    """Return the current simulator state."""
    with SessionLocal() as session:
        vpcs = session.query(Vpc).all()
        subnets = session.query(Subnet).all()
        route_tables = session.query(RouteTable).all()
        igws = session.query(InternetGateway).all()
        peerings = session.query(VpcPeeringConnection).all()

        return {
            "vpcs": [
                {
                    "id": vpc.id,
                    "cidr_block": vpc.cidr_block,
                    "ipv6_cidr_block": vpc.ipv6_cidr_block,
                    "state": vpc.state,
                }
                for vpc in vpcs
            ],
            "subnets": [
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
            "route_tables": [
                {
                    "id": route_table.id,
                    "vpc_id": route_table.vpc_id,
                    "routes": [route_summary(route) for route in route_table.routes],
                }
                for route_table in route_tables
            ],
            "internet_gateways": [
                {"id": igw.id, "vpc_id": igw.vpc_id} for igw in igws
            ],
            "vpc_peerings": [
                {
                    "id": peering.id,
                    "requester_vpc_id": peering.requester_vpc_id,
                    "accepter_vpc_id": peering.accepter_vpc_id,
                    "status": peering.status,
                }
                for peering in peerings
            ],
        }
