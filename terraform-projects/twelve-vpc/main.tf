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

locals {
  admins = ["admin-1", "admin-2"]
  datas  = ["data-1", "data-2", "data-3"]
  agents = ["agent-1", "agent-2", "agent-3", "agent-4", "agent-5", "agent-6", "agent-7"]

  vpc_names = concat(local.admins, local.datas, local.agents)
  vpc_index = { for idx, name in local.vpc_names : name => idx }

  peering_pairs = flatten([
    for admin in local.admins : [
      for peer in concat(local.datas, local.agents) : {
        key       = "${admin}-${peer}"
        requester = admin
        accepter  = peer
      }
    ]
  ])
}

resource "aws_vpc" "vpcs" {
  for_each = toset(local.vpc_names)

  cidr_block                     = cidrsubnet("10.0.0.0/8", 8, local.vpc_index[each.key])
  assign_generated_ipv6_cidr_block = true

  tags = {
    Name = each.key
    Role = split("-", each.key)[0]
  }
}

resource "aws_subnet" "subnets" {
  for_each = aws_vpc.vpcs

  vpc_id                          = each.value.id
  cidr_block                      = cidrsubnet(each.value.cidr_block, 8, 1)
  ipv6_cidr_block                 = cidrsubnet(each.value.ipv6_cidr_block, 8, 0)
  assign_ipv6_address_on_creation = true
}

resource "aws_internet_gateway" "igws" {
  for_each = aws_vpc.vpcs
  vpc_id   = each.value.id
}

resource "aws_route_table" "rtbs" {
  for_each = aws_vpc.vpcs
  vpc_id   = each.value.id
}

resource "aws_route" "igw_ipv4" {
  for_each = aws_route_table.rtbs

  route_table_id         = each.value.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igws[each.key].id
}

resource "aws_route_table_association" "assoc" {
  for_each = aws_subnet.subnets

  route_table_id = aws_route_table.rtbs[each.key].id
  subnet_id      = each.value.id
}

resource "aws_vpc_peering_connection" "admin_peer" {
  for_each = { for pair in local.peering_pairs : pair.key => pair }

  vpc_id      = aws_vpc.vpcs[each.value.requester].id
  peer_vpc_id = aws_vpc.vpcs[each.value.accepter].id
  auto_accept = true
}

resource "aws_route" "admin_to_peer_ipv6" {
  for_each = aws_vpc_peering_connection.admin_peer

  route_table_id              = aws_route_table.rtbs[each.value.requester].id
  destination_ipv6_cidr_block = aws_vpc.vpcs[each.value.accepter].ipv6_cidr_block
  vpc_peering_connection_id   = each.value.id
}

resource "aws_route" "peer_to_admin_ipv6" {
  for_each = aws_vpc_peering_connection.admin_peer

  route_table_id              = aws_route_table.rtbs[each.value.accepter].id
  destination_ipv6_cidr_block = aws_vpc.vpcs[each.value.requester].ipv6_cidr_block
  vpc_peering_connection_id   = each.value.id
}
