# VPC Testing Ladder

This ladder grows from fast API checks to full Terraform lifecycle tests.

## Rungs

1. **Spec validation**
   - Driven by the EC2 service model in `specs/`.
   - Ensures required params, enums, and basic scalar types.

2. **API smoke tests**
   - `pytest backend/tests/test_api_smoke.py`
   - Verifies EC2 Query flows for VPC, subnet, IGW, route table, routes, and peering.

3. **Terraform lifecycle**
   - `pytest backend/tests/test_terraform_lifecycle.py`
   - Full `init/plan/apply/destroy` against the simulator for `single-vpc`.
   - Uses testcontainers to run the simulator on an isolated port.

4. **Resource ladder inventory**
   - `pytest backend/tests/test_ladder_manifest.py`
   - Tracks all VPC-related Terraform resources and marks unimplemented ones as xfail.

## Running

```
just backend-dev-tools
cd backend
.venv/bin/pytest -q
```

Terraform tests require the `terraform` binary on your PATH.
