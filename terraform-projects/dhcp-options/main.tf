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
  cidr_block                     = "10.60.0.0/16"
  assign_generated_ipv6_cidr_block = true

  tags = {
    Name = "dhcp-vpc"
  }
}

resource "aws_vpc_dhcp_options" "main" {
  domain_name          = "example.internal"
  domain_name_servers  = ["10.60.0.2", "10.60.0.3"]
  ntp_servers          = ["10.60.0.4"]
  netbios_name_servers = ["10.60.0.5"]
  netbios_node_type    = 2

  tags = {
    Name = "dhcp-options"
  }
}

resource "aws_vpc_dhcp_options_association" "main" {
  vpc_id          = aws_vpc.main.id
  dhcp_options_id = aws_vpc_dhcp_options.main.id
}
