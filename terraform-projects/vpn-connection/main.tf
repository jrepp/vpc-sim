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

resource "aws_vpc" "main" {
  cidr_block                       = "10.99.0.0/16"
  assign_generated_ipv6_cidr_block = true
  enable_dns_hostnames             = true
  enable_dns_support               = true
  tags = {
    Name = "vpn-conn-vpc"
  }
}

resource "aws_vpn_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "vpn-gw"
  }
}

resource "aws_customer_gateway" "main" {
  bgp_asn    = 65001
  ip_address = "198.51.100.11"
  type       = "ipsec.1"
  tags = {
    Name = "cgw-main"
  }
}

resource "aws_vpn_connection" "main" {
  customer_gateway_id = aws_customer_gateway.main.id
  vpn_gateway_id      = aws_vpn_gateway.main.id
  type                = "ipsec.1"
  tags = {
    Name = "vpn-connection"
  }
}
