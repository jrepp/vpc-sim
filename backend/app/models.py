"""SQLAlchemy models for the VPC simulator."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Declarative base for ORM models."""


class Vpc(Base):
    """VPC record with IPv4/IPv6 CIDRs and relationships."""
    __tablename__ = "vpcs"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    cidr_block: Mapped[str] = mapped_column(String, nullable=False)
    ipv6_cidr_block: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    ipv6_association_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    state: Mapped[str] = mapped_column(String, nullable=False, default="Available")
    enable_dns_support: Mapped[bool] = mapped_column(Boolean, default=True)
    enable_dns_hostnames: Mapped[bool] = mapped_column(Boolean, default=False)
    enable_network_address_usage_metrics: Mapped[bool] = mapped_column(Boolean, default=False)

    dhcp_options_id: Mapped[Optional[str]] = mapped_column(
        String, ForeignKey("dhcp_options.id"), nullable=True
    )

    subnets: Mapped[List["Subnet"]] = relationship(
        "Subnet", back_populates="vpc", cascade="all, delete-orphan"
    )
    route_tables: Mapped[List["RouteTable"]] = relationship(
        "RouteTable", back_populates="vpc", cascade="all, delete-orphan"
    )
    igws: Mapped[List["InternetGateway"]] = relationship("InternetGateway", back_populates="vpc")
    dhcp_options: Mapped[Optional["DhcpOptions"]] = relationship(
        "DhcpOptions", back_populates="vpcs"
    )
    peering_requester: Mapped[List["VpcPeeringConnection"]] = relationship(
        "VpcPeeringConnection",
        back_populates="requester_vpc",
        foreign_keys="VpcPeeringConnection.requester_vpc_id",
    )
    peering_accepter: Mapped[List["VpcPeeringConnection"]] = relationship(
        "VpcPeeringConnection",
        back_populates="accepter_vpc",
        foreign_keys="VpcPeeringConnection.accepter_vpc_id",
    )
    cidr_associations: Mapped[List["VpcCidrBlockAssociation"]] = relationship(
        "VpcCidrBlockAssociation",
        back_populates="vpc",
        cascade="all, delete-orphan",
    )


class Subnet(Base):
    """Subnet record with IPv4/IPv6 CIDRs and route association."""
    __tablename__ = "subnets"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    vpc_id: Mapped[str] = mapped_column(String, ForeignKey("vpcs.id"), nullable=False)
    cidr_block: Mapped[str] = mapped_column(String, nullable=False)
    ipv6_cidr_block: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    ipv6_association_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    availability_zone: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    state: Mapped[str] = mapped_column(String, nullable=False, default="available")
    assign_ipv6_address_on_creation: Mapped[bool] = mapped_column(Boolean, default=False)

    route_table_id: Mapped[Optional[str]] = mapped_column(
        String, ForeignKey("route_tables.id"), nullable=True
    )

    vpc: Mapped["Vpc"] = relationship("Vpc", back_populates="subnets")
    route_table: Mapped[Optional["RouteTable"]] = relationship("RouteTable", back_populates="subnets")
    associations: Mapped[List["RouteTableAssociation"]] = relationship(
        "RouteTableAssociation", back_populates="subnet", cascade="all, delete-orphan"
    )


class RouteTable(Base):
    """Route table holding routes and associations."""
    __tablename__ = "route_tables"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    vpc_id: Mapped[str] = mapped_column(String, ForeignKey("vpcs.id"), nullable=False)

    vpc: Mapped["Vpc"] = relationship("Vpc", back_populates="route_tables")
    routes: Mapped[List["Route"]] = relationship(
        "Route", back_populates="route_table", cascade="all, delete-orphan"
    )
    associations: Mapped[List["RouteTableAssociation"]] = relationship(
        "RouteTableAssociation", back_populates="route_table", cascade="all, delete-orphan"
    )
    subnets: Mapped[List["Subnet"]] = relationship("Subnet", back_populates="route_table")


class Route(Base):
    """Route entry for IPv4 or IPv6 destinations."""
    __tablename__ = "routes"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    route_table_id: Mapped[str] = mapped_column(String, ForeignKey("route_tables.id"), nullable=False)
    destination_cidr: Mapped[str] = mapped_column(String, nullable=False)
    target_type: Mapped[str] = mapped_column(String, nullable=False)
    target_id: Mapped[str] = mapped_column(String, nullable=False)
    state: Mapped[str] = mapped_column(String, nullable=False, default="active")

    route_table: Mapped["RouteTable"] = relationship("RouteTable", back_populates="routes")


class RouteTableAssociation(Base):
    """Associates a subnet to a route table."""
    __tablename__ = "route_table_associations"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    route_table_id: Mapped[str] = mapped_column(String, ForeignKey("route_tables.id"), nullable=False)
    subnet_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("subnets.id"), nullable=True)
    main: Mapped[bool] = mapped_column(Boolean, default=False)

    route_table: Mapped["RouteTable"] = relationship("RouteTable", back_populates="associations")
    subnet: Mapped[Optional["Subnet"]] = relationship("Subnet", back_populates="associations")


class InternetGateway(Base):
    """Internet gateway attached to a VPC."""
    __tablename__ = "internet_gateways"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    vpc_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("vpcs.id"), nullable=True)

    vpc: Mapped[Optional["Vpc"]] = relationship("Vpc", back_populates="igws")


class VpcPeeringConnection(Base):
    """Peering connection between two VPCs."""
    __tablename__ = "vpc_peering_connections"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    requester_vpc_id: Mapped[str] = mapped_column(String, ForeignKey("vpcs.id"), nullable=False)
    accepter_vpc_id: Mapped[str] = mapped_column(String, ForeignKey("vpcs.id"), nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="active")

    requester_vpc: Mapped["Vpc"] = relationship(
        "Vpc",
        foreign_keys=[requester_vpc_id],
        back_populates="peering_requester",
    )
    accepter_vpc: Mapped["Vpc"] = relationship(
        "Vpc",
        foreign_keys=[accepter_vpc_id],
        back_populates="peering_accepter",
    )


class VpcCidrBlockAssociation(Base):
    """Additional CIDR associations for a VPC."""
    __tablename__ = "vpc_cidr_block_associations"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    vpc_id: Mapped[str] = mapped_column(String, ForeignKey("vpcs.id"), nullable=False)
    cidr_block: Mapped[str] = mapped_column(String, nullable=False)
    is_ipv6: Mapped[bool] = mapped_column(Boolean, default=False)
    state: Mapped[str] = mapped_column(String, nullable=False, default="associated")

    vpc: Mapped["Vpc"] = relationship("Vpc", back_populates="cidr_associations")


class DhcpOptions(Base):
    """DHCP options set."""

    __tablename__ = "dhcp_options"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    configurations_json: Mapped[str] = mapped_column(String, nullable=False, default="[]")

    vpcs: Mapped[List["Vpc"]] = relationship("Vpc", back_populates="dhcp_options")


class SecurityGroup(Base):
    """Security group attached to a VPC."""

    __tablename__ = "security_groups"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=False)
    vpc_id: Mapped[str] = mapped_column(String, ForeignKey("vpcs.id"), nullable=False)

    vpc: Mapped["Vpc"] = relationship("Vpc")
    rules: Mapped[List["SecurityGroupRule"]] = relationship(
        "SecurityGroupRule", back_populates="security_group", cascade="all, delete-orphan"
    )


class SecurityGroupRule(Base):
    """Security group ingress/egress rule."""

    __tablename__ = "security_group_rules"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    security_group_id: Mapped[str] = mapped_column(
        String, ForeignKey("security_groups.id"), nullable=False
    )
    direction: Mapped[str] = mapped_column(String, nullable=False)
    protocol: Mapped[str] = mapped_column(String, nullable=False)
    from_port: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    to_port: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    cidr_ipv4: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    cidr_ipv6: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    source_group_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    description: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    security_group: Mapped["SecurityGroup"] = relationship("SecurityGroup", back_populates="rules")


class Tag(Base):
    """Tag attached to an EC2 resource."""

    __tablename__ = "tags"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    resource_id: Mapped[str] = mapped_column(String, nullable=False)
    key: Mapped[str] = mapped_column(String, nullable=False)
    value: Mapped[Optional[str]] = mapped_column(String, nullable=True)


class NetworkAcl(Base):
    """Network ACL attached to a VPC."""

    __tablename__ = "network_acls"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    vpc_id: Mapped[str] = mapped_column(String, ForeignKey("vpcs.id"), nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)

    vpc: Mapped["Vpc"] = relationship("Vpc")
    entries: Mapped[List["NetworkAclEntry"]] = relationship(
        "NetworkAclEntry", back_populates="network_acl", cascade="all, delete-orphan"
    )
    associations: Mapped[List["NetworkAclAssociation"]] = relationship(
        "NetworkAclAssociation", back_populates="network_acl", cascade="all, delete-orphan"
    )


class NetworkAclEntry(Base):
    """Network ACL entry."""

    __tablename__ = "network_acl_entries"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    network_acl_id: Mapped[str] = mapped_column(
        String, ForeignKey("network_acls.id"), nullable=False
    )
    egress: Mapped[bool] = mapped_column(Boolean, default=False)
    rule_number: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String, nullable=False)
    rule_action: Mapped[str] = mapped_column(String, nullable=False)
    cidr_block: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    ipv6_cidr_block: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    from_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    to_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    network_acl: Mapped["NetworkAcl"] = relationship("NetworkAcl", back_populates="entries")


class NetworkAclAssociation(Base):
    """Network ACL association to a subnet."""

    __tablename__ = "network_acl_associations"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    network_acl_id: Mapped[str] = mapped_column(
        String, ForeignKey("network_acls.id"), nullable=False
    )
    subnet_id: Mapped[str] = mapped_column(String, ForeignKey("subnets.id"), nullable=False)

    network_acl: Mapped["NetworkAcl"] = relationship("NetworkAcl", back_populates="associations")
    subnet: Mapped["Subnet"] = relationship("Subnet")


class EgressOnlyInternetGateway(Base):
    """Egress-only internet gateway attached to a VPC."""

    __tablename__ = "egress_only_internet_gateways"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    vpc_id: Mapped[str] = mapped_column(String, ForeignKey("vpcs.id"), nullable=False)

    vpc: Mapped["Vpc"] = relationship("Vpc")


class ElasticIp(Base):
    """Elastic IP allocation."""
    __tablename__ = "elastic_ips"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    public_ip: Mapped[str] = mapped_column(String, nullable=False)
    domain: Mapped[str] = mapped_column(String, nullable=False, default="vpc")


class NatGateway(Base):
    """NAT gateway."""
    __tablename__ = "nat_gateways"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    subnet_id: Mapped[str] = mapped_column(String, ForeignKey("subnets.id"), nullable=False)
    vpc_id: Mapped[str] = mapped_column(String, ForeignKey("vpcs.id"), nullable=False)
    state: Mapped[str] = mapped_column(String, nullable=False, default="available")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    subnet: Mapped["Subnet"] = relationship("Subnet")


class NatGatewayAddress(Base):
    """NAT gateway address allocation."""
    __tablename__ = "nat_gateway_addresses"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    nat_gateway_id: Mapped[str] = mapped_column(String, ForeignKey("nat_gateways.id"), nullable=False)
    allocation_id: Mapped[str] = mapped_column(String, ForeignKey("elastic_ips.id"), nullable=False)
    public_ip: Mapped[str] = mapped_column(String, nullable=False)
    private_ip: Mapped[str] = mapped_column(String, nullable=False)

    nat_gateway: Mapped["NatGateway"] = relationship("NatGateway")
    allocation: Mapped["ElasticIp"] = relationship("ElasticIp")


class VpcEndpoint(Base):
    """VPC endpoint."""
    __tablename__ = "vpc_endpoints"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    vpc_id: Mapped[str] = mapped_column(String, ForeignKey("vpcs.id"), nullable=False)
    service_name: Mapped[str] = mapped_column(String, nullable=False)
    vpc_endpoint_type: Mapped[str] = mapped_column(String, nullable=False, default="Gateway")
    state: Mapped[str] = mapped_column(String, nullable=False, default="available")
    route_table_ids_json: Mapped[str] = mapped_column(String, nullable=False, default="[]")
    subnet_ids_json: Mapped[str] = mapped_column(String, nullable=False, default="[]")
    security_group_ids_json: Mapped[str] = mapped_column(String, nullable=False, default="[]")

    vpc: Mapped["Vpc"] = relationship("Vpc")


class FlowLog(Base):
    """VPC flow log."""
    __tablename__ = "flow_logs"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    resource_id: Mapped[str] = mapped_column(String, nullable=False)
    resource_type: Mapped[str] = mapped_column(String, nullable=False)
    traffic_type: Mapped[str] = mapped_column(String, nullable=False)
    log_destination_type: Mapped[str] = mapped_column(String, nullable=False)
    log_destination: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="ACTIVE")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class CustomerGateway(Base):
    """Customer gateway."""
    __tablename__ = "customer_gateways"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    bgp_asn: Mapped[str] = mapped_column(String, nullable=False)
    ip_address: Mapped[str] = mapped_column(String, nullable=False)
    gateway_type: Mapped[str] = mapped_column(String, nullable=False)
    state: Mapped[str] = mapped_column(String, nullable=False, default="available")


class VpnGateway(Base):
    """VPN gateway."""
    __tablename__ = "vpn_gateways"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    gateway_type: Mapped[str] = mapped_column(String, nullable=False)
    vpc_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("vpcs.id"), nullable=True)
    state: Mapped[str] = mapped_column(String, nullable=False, default="available")

    vpc: Mapped[Optional["Vpc"]] = relationship("Vpc")


class VpnConnection(Base):
    """VPN connection."""
    __tablename__ = "vpn_connections"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    customer_gateway_id: Mapped[str] = mapped_column(String, ForeignKey("customer_gateways.id"), nullable=False)
    vpn_gateway_id: Mapped[str] = mapped_column(String, ForeignKey("vpn_gateways.id"), nullable=False)
    connection_type: Mapped[str] = mapped_column(String, nullable=False)
    state: Mapped[str] = mapped_column(String, nullable=False, default="available")

    customer_gateway: Mapped["CustomerGateway"] = relationship("CustomerGateway")
    vpn_gateway: Mapped["VpnGateway"] = relationship("VpnGateway")


class VpcEndpointService(Base):
    """VPC endpoint service configuration."""
    __tablename__ = "vpc_endpoint_services"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    service_name: Mapped[str] = mapped_column(String, nullable=False)
    acceptance_required: Mapped[bool] = mapped_column(Boolean, default=False)
    state: Mapped[str] = mapped_column(String, nullable=False, default="available")
    network_load_balancer_arns_json: Mapped[str] = mapped_column(String, nullable=False, default="[]")
    gateway_load_balancer_arns_json: Mapped[str] = mapped_column(String, nullable=False, default="[]")


class VpcEndpointServicePermission(Base):
    """Allowed principal for a VPC endpoint service."""
    __tablename__ = "vpc_endpoint_service_permissions"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    service_id: Mapped[str] = mapped_column(
        String, ForeignKey("vpc_endpoint_services.id"), nullable=False
    )
    principal: Mapped[str] = mapped_column(String, nullable=False)

    service: Mapped["VpcEndpointService"] = relationship("VpcEndpointService")


class VpcEndpointConnectionNotification(Base):
    """VPC endpoint connection notification."""
    __tablename__ = "vpc_endpoint_connection_notifications"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    service_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    vpc_endpoint_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    connection_notification_arn: Mapped[str] = mapped_column(String, nullable=False)
    connection_notification_type: Mapped[str] = mapped_column(String, nullable=False, default="Topic")
    connection_notification_state: Mapped[str] = mapped_column(String, nullable=False, default="Enabled")
    connection_events_json: Mapped[str] = mapped_column(String, nullable=False, default="[]")


class ApiTrace(Base):
    """Request trace entry."""

    __tablename__ = "api_traces"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    method: Mapped[str] = mapped_column(String, nullable=False)
    path: Mapped[str] = mapped_column(String, nullable=False)
    action: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    namespace: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    duration_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    spans: Mapped[List["ApiSpan"]] = relationship(
        "ApiSpan", back_populates="trace", cascade="all, delete-orphan"
    )


class ApiSpan(Base):
    """Nested span recorded under a trace."""

    __tablename__ = "api_spans"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    trace_id: Mapped[str] = mapped_column(String, ForeignKey("api_traces.id"), nullable=False)
    parent_span_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    duration_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    trace: Mapped["ApiTrace"] = relationship("ApiTrace", back_populates="spans")
