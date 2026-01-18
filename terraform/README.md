# Terraform Projects

Run a Terraform project against the local VPC simulator.

```bash
./run.sh /path/to/project
```

The Terraform project should configure the AWS provider to use the simulator endpoint:

```hcl
provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  skip_requesting_account_id  = true

  endpoints {
    ec2 = "http://127.0.0.1:8000"
  }
}
```

Override host/port if needed:

```bash
SIM_HOST=127.0.0.1 SIM_PORT=8001 ./run.sh /path/to/project
```
