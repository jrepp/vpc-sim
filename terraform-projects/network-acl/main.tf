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

resource "aws_vpc" "main" {
  cidr_block = "10.80.0.0/16"

  tags = {
    Name = "nacl-vpc"
  }
}

resource "aws_subnet" "main" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.80.1.0/24"

  tags = {
    Name = "nacl-subnet"
  }
}

resource "aws_network_acl" "main" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = [aws_subnet.main.id]

  egress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "10.80.0.0/16"
    from_port  = 0
    to_port    = 65535
  }

  tags = {
    Name = "nacl-main"
  }
}
