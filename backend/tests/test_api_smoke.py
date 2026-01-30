from __future__ import annotations

import requests


def _ec2_query(base_url: str, params: dict) -> requests.Response:
    return requests.post(f"{base_url}/", data=params, timeout=5)


def test_vpc_subnet_route_table_igw_flow(sim_server: dict) -> None:
    base_url = sim_server["base_url"]

    vpc_resp = _ec2_query(base_url, {"Action": "CreateVpc", "CidrBlock": "10.0.0.0/16"})
    assert vpc_resp.status_code == 200
    vpc_id = _extract_tag(vpc_resp.text, "vpcId")

    subnet_resp = _ec2_query(
        base_url,
        {"Action": "CreateSubnet", "VpcId": vpc_id, "CidrBlock": "10.0.1.0/24"},
    )
    assert subnet_resp.status_code == 200
    subnet_id = _extract_tag(subnet_resp.text, "subnetId")

    rtb_resp = _ec2_query(base_url, {"Action": "CreateRouteTable", "VpcId": vpc_id})
    assert rtb_resp.status_code == 200
    rtb_id = _extract_tag(rtb_resp.text, "routeTableId")

    assoc_resp = _ec2_query(
        base_url,
        {"Action": "AssociateRouteTable", "RouteTableId": rtb_id, "SubnetId": subnet_id},
    )
    assert assoc_resp.status_code == 200

    igw_resp = _ec2_query(base_url, {"Action": "CreateInternetGateway"})
    assert igw_resp.status_code == 200
    igw_id = _extract_tag(igw_resp.text, "internetGatewayId")

    attach_resp = _ec2_query(
        base_url, {"Action": "AttachInternetGateway", "InternetGatewayId": igw_id, "VpcId": vpc_id}
    )
    assert attach_resp.status_code == 200

    route_resp = _ec2_query(
        base_url,
        {
            "Action": "CreateRoute",
            "RouteTableId": rtb_id,
            "DestinationCidrBlock": "0.0.0.0/0",
            "GatewayId": igw_id,
        },
    )
    assert route_resp.status_code == 200

    state = requests.get(f"{base_url}/state", timeout=5).json()
    assert any(vpc["id"] == vpc_id for vpc in state["vpcs"])
    assert any(subnet["id"] == subnet_id for subnet in state["subnets"])
    assert any(table["id"] == rtb_id for table in state["route_tables"])


def test_vpc_peering_ipv6_route(sim_server: dict) -> None:
    base_url = sim_server["base_url"]

    vpc_a = _ec2_query(
        base_url,
        {"Action": "CreateVpc", "CidrBlock": "10.10.0.0/16", "AmazonProvidedIpv6CidrBlock": "true"},
    )
    vpc_b = _ec2_query(
        base_url,
        {"Action": "CreateVpc", "CidrBlock": "10.20.0.0/16", "AmazonProvidedIpv6CidrBlock": "true"},
    )
    vpc_a_id = _extract_tag(vpc_a.text, "vpcId")
    vpc_b_id = _extract_tag(vpc_b.text, "vpcId")
    vpc_b_ipv6 = _extract_tag(vpc_b.text, "ipv6CidrBlock")

    rtb_resp = _ec2_query(base_url, {"Action": "CreateRouteTable", "VpcId": vpc_a_id})
    rtb_id = _extract_tag(rtb_resp.text, "routeTableId")

    pcx_resp = _ec2_query(
        base_url,
        {"Action": "CreateVpcPeeringConnection", "VpcId": vpc_a_id, "PeerVpcId": vpc_b_id},
    )
    pcx_id = _extract_tag(pcx_resp.text, "vpcPeeringConnectionId")

    route_resp = _ec2_query(
        base_url,
        {
            "Action": "CreateRoute",
            "RouteTableId": rtb_id,
            "DestinationIpv6CidrBlock": vpc_b_ipv6,
            "VpcPeeringConnectionId": pcx_id,
        },
    )
    assert route_resp.status_code == 200


def _extract_tag(xml_text: str, tag: str) -> str:
    start = xml_text.find(f"<{tag}>")
    if start == -1:
        raise AssertionError(f"Missing tag {tag} in XML: {xml_text}")
    start += len(tag) + 2
    end = xml_text.find(f"</{tag}>", start)
    if end == -1:
        raise AssertionError(f"Missing closing tag {tag} in XML: {xml_text}")
    return xml_text[start:end]
