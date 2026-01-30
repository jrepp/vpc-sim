variable "name_prefix" {
  type    = string
  default = "test"
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  default_tags {
    tags = {
      TestNamespace = var.name_prefix
    }
  }

  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  skip_requesting_account_id  = true

  endpoints {
    ec2 = "http://127.0.0.1:8731"
  }
}

resource "aws_vpc" "admin" {
  cidr_block                     = "10.30.0.0/16"
  assign_generated_ipv6_cidr_block = true
  tags = {
    Name = "admin-vpc"
    Role = "admin"
  }
}

resource "aws_vpc" "data" {
  cidr_block                     = "10.40.0.0/16"
  assign_generated_ipv6_cidr_block = true
  tags = {
    Name = "data-vpc"
    Role = "data"
  }
}

resource "aws_vpc" "agent" {
  cidr_block                     = "10.50.0.0/16"
  assign_generated_ipv6_cidr_block = true
  tags = {
    Name = "agent-vpc"
    Role = "agent"
  }
}

resource "aws_subnet" "admin" {
  vpc_id                          = aws_vpc.admin.id
  cidr_block                      = "10.30.1.0/24"
  ipv6_cidr_block                 = cidrsubnet(aws_vpc.admin.ipv6_cidr_block, 8, 0)
  assign_ipv6_address_on_creation = true
}

resource "aws_subnet" "data" {
  vpc_id                          = aws_vpc.data.id
  cidr_block                      = "10.40.1.0/24"
  ipv6_cidr_block                 = cidrsubnet(aws_vpc.data.ipv6_cidr_block, 8, 0)
  assign_ipv6_address_on_creation = true
}

resource "aws_subnet" "agent" {
  vpc_id                          = aws_vpc.agent.id
  cidr_block                      = "10.50.1.0/24"
  ipv6_cidr_block                 = cidrsubnet(aws_vpc.agent.ipv6_cidr_block, 8, 0)
  assign_ipv6_address_on_creation = true
}

resource "aws_internet_gateway" "admin" {
  vpc_id = aws_vpc.admin.id
}

resource "aws_internet_gateway" "data" {
  vpc_id = aws_vpc.data.id
}

resource "aws_internet_gateway" "agent" {
  vpc_id = aws_vpc.agent.id
}

resource "aws_route_table" "admin" {
  vpc_id = aws_vpc.admin.id
}

resource "aws_route_table" "data" {
  vpc_id = aws_vpc.data.id
}

resource "aws_route_table" "agent" {
  vpc_id = aws_vpc.agent.id
}

resource "aws_route" "admin_igw_ipv4" {
  route_table_id         = aws_route_table.admin.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.admin.id
}

resource "aws_route" "data_igw_ipv4" {
  route_table_id         = aws_route_table.data.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.data.id
}

resource "aws_route" "agent_igw_ipv4" {
  route_table_id         = aws_route_table.agent.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.agent.id
}

resource "aws_vpc_peering_connection" "admin_data" {
  vpc_id      = aws_vpc.admin.id
  peer_vpc_id = aws_vpc.data.id
  auto_accept = true
}

resource "aws_vpc_peering_connection" "admin_agent" {
  vpc_id      = aws_vpc.admin.id
  peer_vpc_id = aws_vpc.agent.id
  auto_accept = true
}

resource "aws_route" "admin_to_data_ipv6" {
  route_table_id              = aws_route_table.admin.id
  destination_ipv6_cidr_block = aws_vpc.data.ipv6_cidr_block
  vpc_peering_connection_id   = aws_vpc_peering_connection.admin_data.id
}

resource "aws_route" "data_to_admin_ipv6" {
  route_table_id              = aws_route_table.data.id
  destination_ipv6_cidr_block = aws_vpc.admin.ipv6_cidr_block
  vpc_peering_connection_id   = aws_vpc_peering_connection.admin_data.id
}

resource "aws_route" "admin_to_agent_ipv6" {
  route_table_id              = aws_route_table.admin.id
  destination_ipv6_cidr_block = aws_vpc.agent.ipv6_cidr_block
  vpc_peering_connection_id   = aws_vpc_peering_connection.admin_agent.id
}

resource "aws_route" "agent_to_admin_ipv6" {
  route_table_id              = aws_route_table.agent.id
  destination_ipv6_cidr_block = aws_vpc.admin.ipv6_cidr_block
  vpc_peering_connection_id   = aws_vpc_peering_connection.admin_agent.id
}

resource "aws_route_table_association" "admin" {
  route_table_id = aws_route_table.admin.id
  subnet_id      = aws_subnet.admin.id
}

resource "aws_route_table_association" "data" {
  route_table_id = aws_route_table.data.id
  subnet_id      = aws_subnet.data.id
}

resource "aws_route_table_association" "agent" {
  route_table_id = aws_route_table.agent.id
  subnet_id      = aws_subnet.agent.id
}
