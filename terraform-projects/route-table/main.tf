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
  cidr_block                       = "10.60.0.0/16"
  assign_generated_ipv6_cidr_block = true
  enable_dns_hostnames             = true
  enable_dns_support               = true
  tags = {
    Name = "rtb-vpc"
  }
}

resource "aws_subnet" "main" {
  vpc_id                          = aws_vpc.main.id
  cidr_block                      = "10.60.1.0/24"
  ipv6_cidr_block                 = cidrsubnet(aws_vpc.main.ipv6_cidr_block, 8, 1)
  assign_ipv6_address_on_creation = true
  availability_zone               = "us-east-1a"
  tags = {
    Name = "rtb-subnet"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "rtb-igw"
  }
}

resource "aws_route_table" "main" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "rtb-main"
  }
}

resource "aws_route" "igw_ipv4" {
  route_table_id         = aws_route_table.main.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
}

resource "aws_route_table_association" "subnet" {
  route_table_id = aws_route_table.main.id
  subnet_id      = aws_subnet.main.id
}
