# VPC Sim

Local AWS VPC simulation with a FastAPI backend, SQLite state, and a Svelte UI.
The EC2 Query API subset is implemented so the Terraform AWS provider can target it.

## Run (single server)

```bash
just app
```

This builds the frontend and serves it from the FastAPI app at `http://localhost:8731`.

## Dev (hot reload)

```bash
just dev
```

Backend runs on `http://localhost:8731` and Vite runs on `http://localhost:5179` with HMR.

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cd ../frontend
npm install
npm run build
cd ../backend
uvicorn app.main:app --reload --port 8731
```

## Terraform AWS provider

Point the AWS provider at the local endpoint:

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
    ec2 = "http://localhost:8731"
  }
}
```

## Terraform runner (self-hosted)

The UI can run `terraform init`, `plan`, and `apply` against the simulator.
Drop project folders under `terraform-projects/` (or set `TERRAFORM_PROFILES_DIR`).

Requirements:
- `terraform` installed and on your `PATH`
- provider configured to use the local endpoint above

Optional overrides:
- `SIM_BASE_URL` to control the endpoint used by the runner
- `TERRAFORM_PROFILES_DIR` to point at a different profile directory

Included profiles (under `terraform-projects/`):
- `single-vpc`
- `double-vpc`
- `triple-vpc`
- `twelve-vpc` (2 admin, 3 data, 7 agent VPCs with IPv6 peering routes)

## Connectivity validation

Use the UI or call the JSON endpoint directly:

```bash
curl -X POST http://localhost:8731/validate/connectivity \
  -H 'Content-Type: application/json' \
  -d '{"source_subnet_id":"subnet-12345678","destination_cidr":"0.0.0.0/0"}'
```

## Frontend dev server (optional)

```bash
cd frontend
npm install
VITE_API_BASE=http://localhost:8731 npm run dev -- --port 5179 --strictPort
```

## MVP resource coverage

- VPCs
- Subnets
- Route tables + routes
- Internet gateways

More EC2 actions can be added in `backend/app/ec2_api.py` and will show up in the UI via `backend/app/state_api.py`.
