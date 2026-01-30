from __future__ import annotations

import pytest

VPC_RESOURCES = [
    "aws_vpc",
    "aws_subnet",
    "aws_internet_gateway",
    "aws_route_table",
    "aws_route",
    "aws_route_table_association",
    "aws_vpc_peering_connection",
    "aws_security_group",
    "aws_network_acl",
    "aws_network_acl_rule",
    "aws_network_acl_association",
    "aws_nat_gateway",
    "aws_eip",
    "aws_vpc_endpoint",
    "aws_vpc_endpoint_service",
    "aws_vpc_endpoint_service_allowed_principal",
    "aws_vpc_endpoint_connection_notification",
    "aws_vpc_dhcp_options",
    "aws_vpc_dhcp_options_association",
    "aws_egress_only_internet_gateway",
    "aws_vpc_ipv4_cidr_block_association",
    "aws_vpc_ipv6_cidr_block_association",
    "aws_subnet_cidr_reservation",
    "aws_default_vpc",
    "aws_default_subnet",
    "aws_default_route_table",
    "aws_default_network_acl",
    "aws_default_security_group",
    "aws_flow_log",
]

IMPLEMENTED = {
    "aws_vpc",
    "aws_subnet",
    "aws_internet_gateway",
    "aws_route_table",
    "aws_route",
    "aws_route_table_association",
    "aws_vpc_peering_connection",
    "aws_vpc_dhcp_options",
    "aws_vpc_dhcp_options_association",
    "aws_security_group",
}


@pytest.mark.parametrize("resource", VPC_RESOURCES)
def test_ladder_inventory(resource: str) -> None:
    if resource in IMPLEMENTED:
        assert True
    else:
        pytest.xfail(f"{resource} not implemented in simulator yet")
