variable "name_prefix" {
  type    = string
  default = "test"
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  default_tags {
    tags = {
      TestNamespace = var.name_prefix
    }
  }

  access_key                  = "test"
  secret_key                  = "test"
  region                      = "us-east-1"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  endpoints {
    ec2 = "http://127.0.0.1:8731"
  }
}

resource "aws_vpc" "requester" {
  cidr_block                       = "10.70.0.0/16"
  assign_generated_ipv6_cidr_block = true
  enable_dns_hostnames             = true
  enable_dns_support               = true
  tags = {
    Name = "pcx-requester"
  }
}

resource "aws_vpc" "accepter" {
  cidr_block                       = "10.71.0.0/16"
  assign_generated_ipv6_cidr_block = true
  enable_dns_hostnames             = true
  enable_dns_support               = true
  tags = {
    Name = "pcx-accepter"
  }
}

resource "aws_vpc_peering_connection" "main" {
  vpc_id        = aws_vpc.requester.id
  peer_vpc_id   = aws_vpc.accepter.id
  auto_accept  = true
  tags = {
    Name = "pcx-main"
  }
}
