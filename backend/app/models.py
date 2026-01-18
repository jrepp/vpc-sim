"""SQLAlchemy models for the VPC simulator."""
from __future__ import annotations

from typing import List, Optional

from sqlalchemy import Boolean, ForeignKey, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Declarative base for ORM models."""


class Vpc(Base):
    """VPC record with IPv4/IPv6 CIDRs and relationships."""
    __tablename__ = "vpcs"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    cidr_block: Mapped[str] = mapped_column(String, nullable=False)
    ipv6_cidr_block: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    state: Mapped[str] = mapped_column(String, nullable=False, default="available")

    subnets: Mapped[List["Subnet"]] = relationship(
        "Subnet", back_populates="vpc", cascade="all, delete-orphan"
    )
    route_tables: Mapped[List["RouteTable"]] = relationship(
        "RouteTable", back_populates="vpc", cascade="all, delete-orphan"
    )
    igws: Mapped[List["InternetGateway"]] = relationship("InternetGateway", back_populates="vpc")
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


class Subnet(Base):
    """Subnet record with IPv4/IPv6 CIDRs and route association."""
    __tablename__ = "subnets"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    vpc_id: Mapped[str] = mapped_column(String, ForeignKey("vpcs.id"), nullable=False)
    cidr_block: Mapped[str] = mapped_column(String, nullable=False)
    ipv6_cidr_block: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    availability_zone: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    state: Mapped[str] = mapped_column(String, nullable=False, default="available")

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
    subnet_id: Mapped[str] = mapped_column(String, ForeignKey("subnets.id"), nullable=False)
    main: Mapped[bool] = mapped_column(Boolean, default=False)

    route_table: Mapped["RouteTable"] = relationship("RouteTable", back_populates="associations")
    subnet: Mapped["Subnet"] = relationship("Subnet", back_populates="associations")


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
