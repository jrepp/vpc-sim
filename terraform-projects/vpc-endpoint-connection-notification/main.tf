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

resource "aws_vpc_endpoint_service" "main" {
  acceptance_required     = false
  network_load_balancer_arns = [
    "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/fake/abcdef1234567890",
  ]
}

resource "aws_vpc_endpoint_connection_notification" "main" {
  vpc_endpoint_service_id   = aws_vpc_endpoint_service.main.id
  connection_notification_arn  = "arn:aws:sns:us-east-1:123456789012:vpce-notify"
  connection_events           = ["Accept", "Reject"]
}
