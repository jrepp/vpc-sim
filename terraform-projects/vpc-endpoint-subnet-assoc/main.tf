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
  cidr_block                       = "10.92.0.0/16"
  assign_generated_ipv6_cidr_block = true
  enable_dns_hostnames             = true
  enable_dns_support               = true
  tags = {
    Name = "vpce-subnet-vpc"
  }
}

resource "aws_subnet" "a" {
  vpc_id                          = aws_vpc.main.id
  cidr_block                      = "10.92.1.0/24"
  ipv6_cidr_block                 = cidrsubnet(aws_vpc.main.ipv6_cidr_block, 8, 1)
  assign_ipv6_address_on_creation = true
  availability_zone               = "us-east-1a"
  tags = {
    Name = "vpce-subnet-a"
  }
}

resource "aws_subnet" "b" {
  vpc_id                          = aws_vpc.main.id
  cidr_block                      = "10.92.2.0/24"
  ipv6_cidr_block                 = cidrsubnet(aws_vpc.main.ipv6_cidr_block, 8, 2)
  assign_ipv6_address_on_creation = true
  availability_zone               = "us-east-1b"
  tags = {
    Name = "vpce-subnet-b"
  }
}

resource "aws_security_group" "main" {
  name        = "vpce-sg"
  description = "VPC endpoint SG"
  vpc_id      = aws_vpc.main.id
}

resource "aws_vpc_endpoint" "iface" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.us-east-1.ec2"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.a.id]
  security_group_ids  = [aws_security_group.main.id]
  private_dns_enabled = false
  tags = {
    Name = "vpce-iface"
  }
}

resource "aws_vpc_endpoint_subnet_association" "b" {
  vpc_endpoint_id = aws_vpc_endpoint.iface.id
  subnet_id       = aws_subnet.b.id
}
