from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest
import requests


def _terraform_available() -> bool:
    return shutil.which("terraform") is not None


def _copy_project(tmp_path: Path, name: str) -> Path:
    src = Path(__file__).resolve().parents[2] / "terraform-projects" / name
    dst = tmp_path / name
    shutil.copytree(src, dst)
    return dst


def _run_terraform(
    cmd: list[str],
    cwd: Path,
    env: dict,
    label: str,
    log_path: Path | None = None,
    timing_log: Path | None = None,
    timeout_seconds: int = 180,
) -> None:
    start = time.perf_counter()
    if timing_log:
        timing_log.parent.mkdir(parents=True, exist_ok=True)
        with timing_log.open("a", encoding="utf-8") as handle:
            handle.write(f"{label} start\n")
    if log_path:
        env = env.copy()
        env["TF_LOG"] = "TRACE"
        env["TF_LOG_PATH"] = str(log_path)
    try:
        result = subprocess.run(
            cmd,
            cwd=str(cwd),
            env=env,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        duration = time.perf_counter() - start
        if timing_log:
            with timing_log.open("a", encoding="utf-8") as handle:
                handle.write(f"{label} timeout after {duration:.2f}s\n")
        raise AssertionError(f"{label} timed out after {duration:.2f}s") from exc
    duration = time.perf_counter() - start
    print(f"{label} took {duration:.2f}s")
    if timing_log:
        with timing_log.open("a", encoding="utf-8") as handle:
            handle.write(f"{label} complete in {duration:.2f}s\n")
    assert result.returncode == 0, result.stderr


def _configure_provider_installation(project_dir: Path, env: dict) -> None:
    env.pop("TF_CLI_CONFIG_FILE", None)


def _terraform_env() -> dict:
    env = os.environ.copy()
    env["AWS_ACCESS_KEY_ID"] = "test"
    env["AWS_SECRET_ACCESS_KEY"] = "test"
    env["AWS_DEFAULT_REGION"] = "us-east-1"
    env["AWS_REGION"] = "us-east-1"
    env["AWS_RETRY_MODE"] = "standard"
    env["AWS_MAX_ATTEMPTS"] = "2"
    env["AWS_EC2_METADATA_DISABLED"] = "true"
    env["TF_IN_AUTOMATION"] = "1"
    env["TF_INPUT"] = "0"
    worker = os.getenv("PYTEST_XDIST_WORKER", "main")
    plugin_cache = Path.home() / ".terraform.d" / f"plugin-cache-{worker}"
    plugin_cache.mkdir(parents=True, exist_ok=True)
    env["TF_PLUGIN_CACHE_DIR"] = str(plugin_cache)
    env["TF_REGISTRY_CLIENT_TIMEOUT"] = "30"
    env["TF_HTTP_TIMEOUT"] = "30"
    env["TF_CLI_ARGS_plan"] = "-refresh=false"
    env["TF_CLI_ARGS_apply"] = "-refresh=false -parallelism=20"
    env["TF_CLI_ARGS_destroy"] = "-refresh=false -parallelism=20"
    env["EC2_TRACE"] = "true"
    return env


@pytest.mark.skipif(not _terraform_available(), reason="terraform binary not found")
def test_terraform_single_vpc_lifecycle(sim_container_clean: dict, tmp_path: Path, test_namespace: str) -> None:
    base_url = sim_container_clean["base_url"]
    project_dir = _copy_project(tmp_path, "single-vpc")
    _rewrite_endpoint(project_dir, base_url)

    env = _terraform_env()
    env["TF_VAR_name_prefix"] = test_namespace
    _configure_provider_installation(project_dir, env)
    timing_log = project_dir / "tf-timing.log"

    _run_terraform(["terraform", "init", "-input=false"], project_dir, env, "terraform init", timing_log=timing_log)
    _run_terraform(
        ["terraform", "plan", "-input=false", "-out=tfplan"],
        project_dir,
        env,
        "terraform plan",
        timing_log=timing_log,
    )
    _run_terraform(
        ["terraform", "apply", "-input=false", "-auto-approve", "tfplan"],
        project_dir,
        env,
        "terraform apply",
        log_path=project_dir / "tf-apply-trace.log",
        timing_log=timing_log,
    )

    state = requests.get(f"{base_url}/state?tag={test_namespace}", timeout=5).json()
    assert len(state["vpcs"]) >= 1
    assert len(state["subnets"]) >= 1

    _run_terraform(
        ["terraform", "destroy", "-input=false", "-auto-approve"],
        project_dir,
        env,
        "terraform destroy",
        log_path=project_dir / "tf-destroy-trace.log",
        timing_log=timing_log,
    )


@pytest.mark.skipif(not _terraform_available(), reason="terraform binary not found")
def test_terraform_dhcp_options(sim_container_clean: dict, tmp_path: Path, test_namespace: str) -> None:
    base_url = sim_container_clean["base_url"]
    project_dir = _copy_project(tmp_path, "dhcp-options")
    _rewrite_endpoint(project_dir, base_url)

    env = _terraform_env()
    env["TF_VAR_name_prefix"] = test_namespace
    _configure_provider_installation(project_dir, env)
    timing_log = project_dir / "tf-timing.log"

    _run_terraform(["terraform", "init", "-input=false"], project_dir, env, "terraform init", timing_log=timing_log)
    _run_terraform(
        ["terraform", "plan", "-input=false", "-out=tfplan"],
        project_dir,
        env,
        "terraform plan",
        timing_log=timing_log,
    )
    _run_terraform(
        ["terraform", "apply", "-input=false", "-auto-approve", "tfplan"],
        project_dir,
        env,
        "terraform apply",
        log_path=project_dir / "tf-apply-trace.log",
        timing_log=timing_log,
    )

    state = requests.get(f"{base_url}/state?tag={test_namespace}", timeout=5).json()
    assert len(state["dhcp_options"]) >= 1

    _run_terraform(
        ["terraform", "destroy", "-input=false", "-auto-approve"],
        project_dir,
        env,
        "terraform destroy",
        log_path=project_dir / "tf-destroy-trace.log",
        timing_log=timing_log,
    )


@pytest.mark.skipif(not _terraform_available(), reason="terraform binary not found")
def test_terraform_security_group(sim_container_clean: dict, tmp_path: Path, test_namespace: str) -> None:
    base_url = sim_container_clean["base_url"]
    project_dir = _copy_project(tmp_path, "security-group")
    _rewrite_endpoint(project_dir, base_url)

    env = _terraform_env()
    env["TF_VAR_name_prefix"] = test_namespace
    _configure_provider_installation(project_dir, env)
    timing_log = project_dir / "tf-timing.log"

    _run_terraform(["terraform", "init", "-input=false"], project_dir, env, "terraform init", timing_log=timing_log)
    _run_terraform(
        ["terraform", "plan", "-input=false", "-out=tfplan"],
        project_dir,
        env,
        "terraform plan",
        timing_log=timing_log,
    )
    _run_terraform(
        ["terraform", "apply", "-input=false", "-auto-approve", "tfplan"],
        project_dir,
        env,
        "terraform apply",
        log_path=project_dir / "tf-apply-trace.log",
        timing_log=timing_log,
    )

    state = requests.get(f"{base_url}/state?tag={test_namespace}", timeout=5).json()
    assert len(state["security_groups"]) >= 1

    _run_terraform(
        ["terraform", "destroy", "-input=false", "-auto-approve"],
        project_dir,
        env,
        "terraform destroy",
        log_path=project_dir / "tf-destroy-trace.log",
        timing_log=timing_log,
    )


@pytest.mark.skipif(not _terraform_available(), reason="terraform binary not found")
def test_terraform_network_acl(sim_container_clean: dict, tmp_path: Path, test_namespace: str) -> None:
    base_url = sim_container_clean["base_url"]
    project_dir = _copy_project(tmp_path, "network-acl")
    _rewrite_endpoint(project_dir, base_url)

    env = _terraform_env()
    env["TF_VAR_name_prefix"] = test_namespace
    _configure_provider_installation(project_dir, env)
    timing_log = project_dir / "tf-timing.log"

    _run_terraform(["terraform", "init", "-input=false"], project_dir, env, "terraform init", timing_log=timing_log)
    _run_terraform(
        ["terraform", "plan", "-input=false", "-out=tfplan"],
        project_dir,
        env,
        "terraform plan",
        timing_log=timing_log,
    )
    _run_terraform(
        ["terraform", "apply", "-input=false", "-auto-approve", "tfplan"],
        project_dir,
        env,
        "terraform apply",
        log_path=project_dir / "tf-apply-trace.log",
        timing_log=timing_log,
    )

    state = requests.get(f"{base_url}/state?tag={test_namespace}", timeout=5).json()
    assert len(state["network_acls"]) >= 1

    _run_terraform(
        ["terraform", "destroy", "-input=false", "-auto-approve"],
        project_dir,
        env,
        "terraform destroy",
        log_path=project_dir / "tf-destroy-trace.log",
        timing_log=timing_log,
    )


@pytest.mark.skipif(not _terraform_available(), reason="terraform binary not found")
def test_terraform_network_acl_rule(sim_container_clean: dict, tmp_path: Path, test_namespace: str) -> None:
    base_url = sim_container_clean["base_url"]
    project_dir = _copy_project(tmp_path, "network-acl-rule")
    _rewrite_endpoint(project_dir, base_url)

    env = _terraform_env()
    env["TF_VAR_name_prefix"] = test_namespace
    _configure_provider_installation(project_dir, env)
    timing_log = project_dir / "tf-timing.log"

    _run_terraform(["terraform", "init", "-input=false"], project_dir, env, "terraform init", timing_log=timing_log)
    _run_terraform(
        ["terraform", "plan", "-input=false", "-out=tfplan"],
        project_dir,
        env,
        "terraform plan",
        timing_log=timing_log,
    )
    _run_terraform(
        ["terraform", "apply", "-input=false", "-auto-approve", "tfplan"],
        project_dir,
        env,
        "terraform apply",
        log_path=project_dir / "tf-apply-trace.log",
        timing_log=timing_log,
    )

    state = requests.get(f"{base_url}/state?tag={test_namespace}", timeout=5).json()
    assert len(state["network_acls"]) >= 1

    _run_terraform(
        ["terraform", "destroy", "-input=false", "-auto-approve"],
        project_dir,
        env,
        "terraform destroy",
        log_path=project_dir / "tf-destroy-trace.log",
        timing_log=timing_log,
    )


@pytest.mark.skipif(not _terraform_available(), reason="terraform binary not found")
def test_terraform_egress_only_igw(sim_container_clean: dict, tmp_path: Path, test_namespace: str) -> None:
    base_url = sim_container_clean["base_url"]
    project_dir = _copy_project(tmp_path, "egress-only-igw")
    _rewrite_endpoint(project_dir, base_url)

    env = _terraform_env()
    env["TF_VAR_name_prefix"] = test_namespace
    _configure_provider_installation(project_dir, env)
    timing_log = project_dir / "tf-timing.log"

    _run_terraform(["terraform", "init", "-input=false"], project_dir, env, "terraform init", timing_log=timing_log)
    _run_terraform(
        ["terraform", "plan", "-input=false", "-out=tfplan"],
        project_dir,
        env,
        "terraform plan",
        timing_log=timing_log,
    )
    _run_terraform(
        ["terraform", "apply", "-input=false", "-auto-approve", "tfplan"],
        project_dir,
        env,
        "terraform apply",
        log_path=project_dir / "tf-apply-trace.log",
        timing_log=timing_log,
    )

    state = requests.get(f"{base_url}/state?tag={test_namespace}", timeout=5).json()
    assert len(state["egress_only_internet_gateways"]) >= 1

    _run_terraform(
        ["terraform", "destroy", "-input=false", "-auto-approve"],
        project_dir,
        env,
        "terraform destroy",
        log_path=project_dir / "tf-destroy-trace.log",
        timing_log=timing_log,
    )


@pytest.mark.skipif(not _terraform_available(), reason="terraform binary not found")
def test_terraform_internet_gateway(sim_container_clean: dict, tmp_path: Path, test_namespace: str) -> None:
    base_url = sim_container_clean["base_url"]
    project_dir = _copy_project(tmp_path, "internet-gateway")
    _rewrite_endpoint(project_dir, base_url)

    env = _terraform_env()
    env["TF_VAR_name_prefix"] = test_namespace
    _configure_provider_installation(project_dir, env)
    timing_log = project_dir / "tf-timing.log"

    _run_terraform(["terraform", "init", "-input=false"], project_dir, env, "terraform init", timing_log=timing_log)
    _run_terraform(
        ["terraform", "plan", "-input=false", "-out=tfplan"],
        project_dir,
        env,
        "terraform plan",
        timing_log=timing_log,
    )
    _run_terraform(
        ["terraform", "apply", "-input=false", "-auto-approve", "tfplan"],
        project_dir,
        env,
        "terraform apply",
        log_path=project_dir / "tf-apply-trace.log",
        timing_log=timing_log,
    )

    state = requests.get(f"{base_url}/state?tag={test_namespace}", timeout=5).json()
    assert len(state["internet_gateways"]) >= 1

    _run_terraform(
        ["terraform", "destroy", "-input=false", "-auto-approve"],
        project_dir,
        env,
        "terraform destroy",
        log_path=project_dir / "tf-destroy-trace.log",
        timing_log=timing_log,
    )


@pytest.mark.skipif(not _terraform_available(), reason="terraform binary not found")
def test_terraform_route_table(sim_container_clean: dict, tmp_path: Path, test_namespace: str) -> None:
    base_url = sim_container_clean["base_url"]
    project_dir = _copy_project(tmp_path, "route-table")
    _rewrite_endpoint(project_dir, base_url)

    env = _terraform_env()
    env["TF_VAR_name_prefix"] = test_namespace
    _configure_provider_installation(project_dir, env)
    timing_log = project_dir / "tf-timing.log"

    _run_terraform(["terraform", "init", "-input=false"], project_dir, env, "terraform init", timing_log=timing_log)
    _run_terraform(
        ["terraform", "plan", "-input=false", "-out=tfplan"],
        project_dir,
        env,
        "terraform plan",
        timing_log=timing_log,
    )
    _run_terraform(
        ["terraform", "apply", "-input=false", "-auto-approve", "tfplan"],
        project_dir,
        env,
        "terraform apply",
        log_path=project_dir / "tf-apply-trace.log",
        timing_log=timing_log,
    )

    state = requests.get(f"{base_url}/state?tag={test_namespace}", timeout=5).json()
    assert len(state["route_tables"]) >= 1
    assert any(table["routes"] for table in state["route_tables"])
    assert any(subnet["route_table_id"] for subnet in state["subnets"])

    _run_terraform(
        ["terraform", "destroy", "-input=false", "-auto-approve"],
        project_dir,
        env,
        "terraform destroy",
        log_path=project_dir / "tf-destroy-trace.log",
        timing_log=timing_log,
    )


@pytest.mark.skipif(not _terraform_available(), reason="terraform binary not found")
def test_terraform_vpc_peering(sim_container_clean: dict, tmp_path: Path, test_namespace: str) -> None:
    base_url = sim_container_clean["base_url"]
    project_dir = _copy_project(tmp_path, "vpc-peering")
    _rewrite_endpoint(project_dir, base_url)

    env = _terraform_env()
    env["TF_VAR_name_prefix"] = test_namespace
    _configure_provider_installation(project_dir, env)
    timing_log = project_dir / "tf-timing.log"

    _run_terraform(["terraform", "init", "-input=false"], project_dir, env, "terraform init", timing_log=timing_log)
    _run_terraform(
        ["terraform", "plan", "-input=false", "-out=tfplan"],
        project_dir,
        env,
        "terraform plan",
        timing_log=timing_log,
    )
    _run_terraform(
        ["terraform", "apply", "-input=false", "-auto-approve", "tfplan"],
        project_dir,
        env,
        "terraform apply",
        log_path=project_dir / "tf-apply-trace.log",
        timing_log=timing_log,
    )

    state = requests.get(f"{base_url}/state?tag={test_namespace}", timeout=5).json()
    assert len(state["vpc_peerings"]) >= 1

    _run_terraform(
        ["terraform", "destroy", "-input=false", "-auto-approve"],
        project_dir,
        env,
        "terraform destroy",
        log_path=project_dir / "tf-destroy-trace.log",
        timing_log=timing_log,
    )


@pytest.mark.skipif(not _terraform_available(), reason="terraform binary not found")
def test_terraform_nat_gateway(sim_container_clean: dict, tmp_path: Path, test_namespace: str) -> None:
    base_url = sim_container_clean["base_url"]
    project_dir = _copy_project(tmp_path, "nat-gateway")
    _rewrite_endpoint(project_dir, base_url)

    env = _terraform_env()
    env["TF_VAR_name_prefix"] = test_namespace
    _configure_provider_installation(project_dir, env)
    timing_log = project_dir / "tf-timing.log"

    _run_terraform(["terraform", "init", "-input=false"], project_dir, env, "terraform init", timing_log=timing_log)
    _run_terraform(
        ["terraform", "plan", "-input=false", "-out=tfplan"],
        project_dir,
        env,
        "terraform plan",
        timing_log=timing_log,
    )
    _run_terraform(
        ["terraform", "apply", "-input=false", "-auto-approve", "tfplan"],
        project_dir,
        env,
        "terraform apply",
        log_path=project_dir / "tf-apply-trace.log",
        timing_log=timing_log,
    )

    state = requests.get(f"{base_url}/state?tag={test_namespace}", timeout=5).json()
    assert len(state["elastic_ips"]) >= 1
    assert len(state["nat_gateways"]) >= 1

    _run_terraform(
        ["terraform", "destroy", "-input=false", "-auto-approve"],
        project_dir,
        env,
        "terraform destroy",
        log_path=project_dir / "tf-destroy-trace.log",
        timing_log=timing_log,
    )


@pytest.mark.skipif(not _terraform_available(), reason="terraform binary not found")
def test_terraform_vpc_endpoint(sim_container_clean: dict, tmp_path: Path, test_namespace: str) -> None:
    base_url = sim_container_clean["base_url"]
    project_dir = _copy_project(tmp_path, "vpc-endpoint")
    _rewrite_endpoint(project_dir, base_url)

    env = _terraform_env()
    env["TF_VAR_name_prefix"] = test_namespace
    _configure_provider_installation(project_dir, env)
    timing_log = project_dir / "tf-timing.log"

    _run_terraform(["terraform", "init", "-input=false"], project_dir, env, "terraform init", timing_log=timing_log)
    _run_terraform(
        ["terraform", "plan", "-input=false", "-out=tfplan"],
        project_dir,
        env,
        "terraform plan",
        timing_log=timing_log,
    )
    _run_terraform(
        ["terraform", "apply", "-input=false", "-auto-approve", "tfplan"],
        project_dir,
        env,
        "terraform apply",
        log_path=project_dir / "tf-apply-trace.log",
        timing_log=timing_log,
    )

    state = requests.get(f"{base_url}/state?tag={test_namespace}", timeout=5).json()
    assert len(state["vpc_endpoints"]) >= 1

    _run_terraform(
        ["terraform", "destroy", "-input=false", "-auto-approve"],
        project_dir,
        env,
        "terraform destroy",
        log_path=project_dir / "tf-destroy-trace.log",
        timing_log=timing_log,
    )


@pytest.mark.skipif(not _terraform_available(), reason="terraform binary not found")
def test_terraform_vpc_endpoint_route_table_association(
    sim_container_clean: dict, tmp_path: Path, test_namespace: str) -> None:
    base_url = sim_container_clean["base_url"]
    project_dir = _copy_project(tmp_path, "vpc-endpoint-rt-assoc")
    _rewrite_endpoint(project_dir, base_url)

    env = _terraform_env()
    env["TF_VAR_name_prefix"] = test_namespace
    _configure_provider_installation(project_dir, env)
    timing_log = project_dir / "tf-timing.log"

    _run_terraform(["terraform", "init", "-input=false"], project_dir, env, "terraform init", timing_log=timing_log)
    _run_terraform(
        ["terraform", "plan", "-input=false", "-out=tfplan"],
        project_dir,
        env,
        "terraform plan",
        timing_log=timing_log,
    )
    _run_terraform(
        ["terraform", "apply", "-input=false", "-auto-approve", "tfplan"],
        project_dir,
        env,
        "terraform apply",
        log_path=project_dir / "tf-apply-trace.log",
        timing_log=timing_log,
    )

    state = requests.get(f"{base_url}/state?tag={test_namespace}", timeout=5).json()
    assert len(state["vpc_endpoints"]) >= 1

    _run_terraform(
        ["terraform", "destroy", "-input=false", "-auto-approve"],
        project_dir,
        env,
        "terraform destroy",
        log_path=project_dir / "tf-destroy-trace.log",
        timing_log=timing_log,
    )


@pytest.mark.skipif(not _terraform_available(), reason="terraform binary not found")
def test_terraform_vpc_endpoint_subnet_association(
    sim_container_clean: dict, tmp_path: Path, test_namespace: str) -> None:
    base_url = sim_container_clean["base_url"]
    project_dir = _copy_project(tmp_path, "vpc-endpoint-subnet-assoc")
    _rewrite_endpoint(project_dir, base_url)

    env = _terraform_env()
    env["TF_VAR_name_prefix"] = test_namespace
    _configure_provider_installation(project_dir, env)
    timing_log = project_dir / "tf-timing.log"

    _run_terraform(["terraform", "init", "-input=false"], project_dir, env, "terraform init", timing_log=timing_log)
    _run_terraform(
        ["terraform", "plan", "-input=false", "-out=tfplan"],
        project_dir,
        env,
        "terraform plan",
        timing_log=timing_log,
    )
    _run_terraform(
        ["terraform", "apply", "-input=false", "-auto-approve", "tfplan"],
        project_dir,
        env,
        "terraform apply",
        log_path=project_dir / "tf-apply-trace.log",
        timing_log=timing_log,
    )

    state = requests.get(f"{base_url}/state?tag={test_namespace}", timeout=5).json()
    assert len(state["vpc_endpoints"]) >= 1

    _run_terraform(
        ["terraform", "destroy", "-input=false", "-auto-approve"],
        project_dir,
        env,
        "terraform destroy",
        log_path=project_dir / "tf-destroy-trace.log",
        timing_log=timing_log,
    )


@pytest.mark.skipif(not _terraform_available(), reason="terraform binary not found")
def test_terraform_vpc_endpoint_security_group_association(
    sim_container_clean: dict, tmp_path: Path, test_namespace: str) -> None:
    base_url = sim_container_clean["base_url"]
    project_dir = _copy_project(tmp_path, "vpc-endpoint-sg-assoc")
    _rewrite_endpoint(project_dir, base_url)

    env = _terraform_env()
    env["TF_VAR_name_prefix"] = test_namespace
    _configure_provider_installation(project_dir, env)
    timing_log = project_dir / "tf-timing.log"

    _run_terraform(["terraform", "init", "-input=false"], project_dir, env, "terraform init", timing_log=timing_log)
    _run_terraform(
        ["terraform", "plan", "-input=false", "-out=tfplan"],
        project_dir,
        env,
        "terraform plan",
        timing_log=timing_log,
    )
    _run_terraform(
        ["terraform", "apply", "-input=false", "-auto-approve", "tfplan"],
        project_dir,
        env,
        "terraform apply",
        log_path=project_dir / "tf-apply-trace.log",
        timing_log=timing_log,
    )

    state = requests.get(f"{base_url}/state?tag={test_namespace}", timeout=5).json()
    assert len(state["vpc_endpoints"]) >= 1

    _run_terraform(
        ["terraform", "destroy", "-input=false", "-auto-approve"],
        project_dir,
        env,
        "terraform destroy",
        log_path=project_dir / "tf-destroy-trace.log",
        timing_log=timing_log,
    )


@pytest.mark.skipif(not _terraform_available(), reason="terraform binary not found")
def test_terraform_vpc_ipv4_cidr_association(sim_container_clean: dict, tmp_path: Path, test_namespace: str) -> None:
    base_url = sim_container_clean["base_url"]
    project_dir = _copy_project(tmp_path, "vpc-cidr-assoc-ipv4")
    _rewrite_endpoint(project_dir, base_url)

    env = _terraform_env()
    env["TF_VAR_name_prefix"] = test_namespace
    _configure_provider_installation(project_dir, env)
    timing_log = project_dir / "tf-timing.log"

    _run_terraform(["terraform", "init", "-input=false"], project_dir, env, "terraform init", timing_log=timing_log)
    _run_terraform(
        ["terraform", "plan", "-input=false", "-out=tfplan"],
        project_dir,
        env,
        "terraform plan",
        timing_log=timing_log,
    )
    _run_terraform(
        ["terraform", "apply", "-input=false", "-auto-approve", "tfplan"],
        project_dir,
        env,
        "terraform apply",
        log_path=project_dir / "tf-apply-trace.log",
        timing_log=timing_log,
    )

    state = requests.get(f"{base_url}/state?tag={test_namespace}", timeout=5).json()
    assert len(state["vpcs"]) >= 1

    _run_terraform(
        ["terraform", "destroy", "-input=false", "-auto-approve"],
        project_dir,
        env,
        "terraform destroy",
        log_path=project_dir / "tf-destroy-trace.log",
        timing_log=timing_log,
    )


@pytest.mark.skipif(not _terraform_available(), reason="terraform binary not found")
def test_terraform_vpc_ipv6_cidr_association(sim_container_clean: dict, tmp_path: Path, test_namespace: str) -> None:
    base_url = sim_container_clean["base_url"]
    project_dir = _copy_project(tmp_path, "vpc-cidr-assoc-ipv6")
    _rewrite_endpoint(project_dir, base_url)

    env = _terraform_env()
    env["TF_VAR_name_prefix"] = test_namespace
    _configure_provider_installation(project_dir, env)
    timing_log = project_dir / "tf-timing.log"

    _run_terraform(["terraform", "init", "-input=false"], project_dir, env, "terraform init", timing_log=timing_log)
    _run_terraform(
        ["terraform", "plan", "-input=false", "-out=tfplan"],
        project_dir,
        env,
        "terraform plan",
        timing_log=timing_log,
    )
    _run_terraform(
        ["terraform", "apply", "-input=false", "-auto-approve", "tfplan"],
        project_dir,
        env,
        "terraform apply",
        log_path=project_dir / "tf-apply-trace.log",
        timing_log=timing_log,
    )

    state = requests.get(f"{base_url}/state?tag={test_namespace}", timeout=5).json()
    assert len(state["vpcs"]) >= 1

    _run_terraform(
        ["terraform", "destroy", "-input=false", "-auto-approve"],
        project_dir,
        env,
        "terraform destroy",
        log_path=project_dir / "tf-destroy-trace.log",
        timing_log=timing_log,
    )


@pytest.mark.skipif(not _terraform_available(), reason="terraform binary not found")
def test_terraform_vpc_flow_log(sim_container_clean: dict, tmp_path: Path, test_namespace: str) -> None:
    base_url = sim_container_clean["base_url"]
    project_dir = _copy_project(tmp_path, "vpc-flow-log")
    _rewrite_endpoint(project_dir, base_url)

    env = _terraform_env()
    env["TF_VAR_name_prefix"] = test_namespace
    _configure_provider_installation(project_dir, env)
    timing_log = project_dir / "tf-timing.log"

    _run_terraform(["terraform", "init", "-input=false"], project_dir, env, "terraform init", timing_log=timing_log)
    _run_terraform(
        ["terraform", "plan", "-input=false", "-out=tfplan"],
        project_dir,
        env,
        "terraform plan",
        timing_log=timing_log,
    )
    _run_terraform(
        ["terraform", "apply", "-input=false", "-auto-approve", "tfplan"],
        project_dir,
        env,
        "terraform apply",
        log_path=project_dir / "tf-apply-trace.log",
        timing_log=timing_log,
    )

    state = requests.get(f"{base_url}/state?tag={test_namespace}", timeout=5).json()
    assert len(state["flow_logs"]) >= 1

    _run_terraform(
        ["terraform", "destroy", "-input=false", "-auto-approve"],
        project_dir,
        env,
        "terraform destroy",
        log_path=project_dir / "tf-destroy-trace.log",
        timing_log=timing_log,
    )


@pytest.mark.skipif(not _terraform_available(), reason="terraform binary not found")
def test_terraform_customer_gateway(sim_container_clean: dict, tmp_path: Path, test_namespace: str) -> None:
    base_url = sim_container_clean["base_url"]
    project_dir = _copy_project(tmp_path, "customer-gateway")
    _rewrite_endpoint(project_dir, base_url)

    env = _terraform_env()
    env["TF_VAR_name_prefix"] = test_namespace
    _configure_provider_installation(project_dir, env)
    timing_log = project_dir / "tf-timing.log"

    _run_terraform(["terraform", "init", "-input=false"], project_dir, env, "terraform init", timing_log=timing_log)
    _run_terraform(
        ["terraform", "plan", "-input=false", "-out=tfplan"],
        project_dir,
        env,
        "terraform plan",
        timing_log=timing_log,
    )
    _run_terraform(
        ["terraform", "apply", "-input=false", "-auto-approve", "tfplan"],
        project_dir,
        env,
        "terraform apply",
        log_path=project_dir / "tf-apply-trace.log",
        timing_log=timing_log,
    )

    state = requests.get(f"{base_url}/state?tag={test_namespace}", timeout=5).json()
    assert len(state["customer_gateways"]) >= 1

    _run_terraform(
        ["terraform", "destroy", "-input=false", "-auto-approve"],
        project_dir,
        env,
        "terraform destroy",
        log_path=project_dir / "tf-destroy-trace.log",
        timing_log=timing_log,
    )


@pytest.mark.skipif(not _terraform_available(), reason="terraform binary not found")
def test_terraform_vpn_gateway(sim_container_clean: dict, tmp_path: Path, test_namespace: str) -> None:
    base_url = sim_container_clean["base_url"]
    project_dir = _copy_project(tmp_path, "vpn-gateway")
    _rewrite_endpoint(project_dir, base_url)

    env = _terraform_env()
    env["TF_VAR_name_prefix"] = test_namespace
    _configure_provider_installation(project_dir, env)
    timing_log = project_dir / "tf-timing.log"

    _run_terraform(["terraform", "init", "-input=false"], project_dir, env, "terraform init", timing_log=timing_log)
    _run_terraform(
        ["terraform", "plan", "-input=false", "-out=tfplan"],
        project_dir,
        env,
        "terraform plan",
        timing_log=timing_log,
    )
    _run_terraform(
        ["terraform", "apply", "-input=false", "-auto-approve", "tfplan"],
        project_dir,
        env,
        "terraform apply",
        log_path=project_dir / "tf-apply-trace.log",
        timing_log=timing_log,
    )

    state = requests.get(f"{base_url}/state?tag={test_namespace}", timeout=5).json()
    assert len(state["vpn_gateways"]) >= 1

    _run_terraform(
        ["terraform", "destroy", "-input=false", "-auto-approve"],
        project_dir,
        env,
        "terraform destroy",
        log_path=project_dir / "tf-destroy-trace.log",
        timing_log=timing_log,
    )


@pytest.mark.skipif(not _terraform_available(), reason="terraform binary not found")
def test_terraform_vpn_connection(sim_container_clean: dict, tmp_path: Path, test_namespace: str) -> None:
    base_url = sim_container_clean["base_url"]
    project_dir = _copy_project(tmp_path, "vpn-connection")
    _rewrite_endpoint(project_dir, base_url)

    env = _terraform_env()
    env["TF_VAR_name_prefix"] = test_namespace
    _configure_provider_installation(project_dir, env)
    timing_log = project_dir / "tf-timing.log"

    _run_terraform(["terraform", "init", "-input=false"], project_dir, env, "terraform init", timing_log=timing_log)
    _run_terraform(
        ["terraform", "plan", "-input=false", "-out=tfplan"],
        project_dir,
        env,
        "terraform plan",
        timing_log=timing_log,
    )
    _run_terraform(
        ["terraform", "apply", "-input=false", "-auto-approve", "tfplan"],
        project_dir,
        env,
        "terraform apply",
        log_path=project_dir / "tf-apply-trace.log",
        timing_log=timing_log,
    )

    state = requests.get(f"{base_url}/state?tag={test_namespace}", timeout=5).json()
    assert len(state["vpn_connections"]) >= 1

    _run_terraform(
        ["terraform", "destroy", "-input=false", "-auto-approve"],
        project_dir,
        env,
        "terraform destroy",
        log_path=project_dir / "tf-destroy-trace.log",
        timing_log=timing_log,
    )


@pytest.mark.skipif(not _terraform_available(), reason="terraform binary not found")
def test_terraform_vpn_gateway_attachment(sim_container_clean: dict, tmp_path: Path, test_namespace: str) -> None:
    base_url = sim_container_clean["base_url"]
    project_dir = _copy_project(tmp_path, "vpn-gateway-attachment")
    _rewrite_endpoint(project_dir, base_url)

    env = _terraform_env()
    env["TF_VAR_name_prefix"] = test_namespace
    _configure_provider_installation(project_dir, env)
    timing_log = project_dir / "tf-timing.log"

    _run_terraform(["terraform", "init", "-input=false"], project_dir, env, "terraform init", timing_log=timing_log)
    _run_terraform(
        ["terraform", "plan", "-input=false", "-out=tfplan"],
        project_dir,
        env,
        "terraform plan",
        timing_log=timing_log,
    )
    _run_terraform(
        ["terraform", "apply", "-input=false", "-auto-approve", "tfplan"],
        project_dir,
        env,
        "terraform apply",
        log_path=project_dir / "tf-apply-trace.log",
        timing_log=timing_log,
    )

    state = requests.get(f"{base_url}/state?tag={test_namespace}", timeout=5).json()
    assert len(state["vpn_gateways"]) >= 1

    _run_terraform(
        ["terraform", "destroy", "-input=false", "-auto-approve"],
        project_dir,
        env,
        "terraform destroy",
        log_path=project_dir / "tf-destroy-trace.log",
        timing_log=timing_log,
    )


@pytest.mark.skipif(not _terraform_available(), reason="terraform binary not found")
def test_terraform_vpc_endpoint_service(sim_container_clean: dict, tmp_path: Path, test_namespace: str) -> None:
    base_url = sim_container_clean["base_url"]
    project_dir = _copy_project(tmp_path, "vpc-endpoint-service")
    _rewrite_endpoint(project_dir, base_url)

    env = _terraform_env()
    env["TF_VAR_name_prefix"] = test_namespace
    _configure_provider_installation(project_dir, env)
    timing_log = project_dir / "tf-timing.log"

    _run_terraform(["terraform", "init", "-input=false"], project_dir, env, "terraform init", timing_log=timing_log)
    _run_terraform(
        ["terraform", "plan", "-input=false", "-out=tfplan"],
        project_dir,
        env,
        "terraform plan",
        timing_log=timing_log,
    )
    _run_terraform(
        ["terraform", "apply", "-input=false", "-auto-approve", "tfplan"],
        project_dir,
        env,
        "terraform apply",
        log_path=project_dir / "tf-apply-trace.log",
        timing_log=timing_log,
    )

    state = requests.get(f"{base_url}/state?tag={test_namespace}", timeout=5).json()
    assert len(state["vpc_endpoint_services"]) >= 1
    assert any(service["allowed_principals"] for service in state["vpc_endpoint_services"])

    _run_terraform(
        ["terraform", "destroy", "-input=false", "-auto-approve"],
        project_dir,
        env,
        "terraform destroy",
        log_path=project_dir / "tf-destroy-trace.log",
        timing_log=timing_log,
    )


@pytest.mark.skipif(not _terraform_available(), reason="terraform binary not found")
def test_terraform_vpc_endpoint_connection_notification(
    sim_container_clean: dict, tmp_path: Path, test_namespace: str) -> None:
    base_url = sim_container_clean["base_url"]
    project_dir = _copy_project(tmp_path, "vpc-endpoint-connection-notification")
    _rewrite_endpoint(project_dir, base_url)

    env = _terraform_env()
    env["TF_VAR_name_prefix"] = test_namespace
    _configure_provider_installation(project_dir, env)
    timing_log = project_dir / "tf-timing.log"

    _run_terraform(["terraform", "init", "-input=false"], project_dir, env, "terraform init", timing_log=timing_log)
    _run_terraform(
        ["terraform", "plan", "-input=false", "-out=tfplan"],
        project_dir,
        env,
        "terraform plan",
        timing_log=timing_log,
    )
    _run_terraform(
        ["terraform", "apply", "-input=false", "-auto-approve", "tfplan"],
        project_dir,
        env,
        "terraform apply",
        log_path=project_dir / "tf-apply-trace.log",
        timing_log=timing_log,
    )

    state = requests.get(f"{base_url}/state?tag={test_namespace}", timeout=5).json()
    assert len(state["vpc_endpoint_connection_notifications"]) >= 1

    _run_terraform(
        ["terraform", "destroy", "-input=false", "-auto-approve"],
        project_dir,
        env,
        "terraform destroy",
        log_path=project_dir / "tf-destroy-trace.log",
        timing_log=timing_log,
    )


@pytest.mark.skipif(not _terraform_available(), reason="terraform binary not found")
def test_terraform_default_security_group(sim_container_clean: dict, tmp_path: Path, test_namespace: str) -> None:
    base_url = sim_container_clean["base_url"]
    project_dir = _copy_project(tmp_path, "default-security-group")
    _rewrite_endpoint(project_dir, base_url)

    env = _terraform_env()
    env["TF_VAR_name_prefix"] = test_namespace
    _configure_provider_installation(project_dir, env)
    timing_log = project_dir / "tf-timing.log"

    _run_terraform(["terraform", "init", "-input=false"], project_dir, env, "terraform init", timing_log=timing_log)
    _run_terraform(
        ["terraform", "plan", "-input=false", "-out=tfplan"],
        project_dir,
        env,
        "terraform plan",
        timing_log=timing_log,
    )
    _run_terraform(
        ["terraform", "apply", "-input=false", "-auto-approve", "tfplan"],
        project_dir,
        env,
        "terraform apply",
        log_path=project_dir / "tf-apply-trace.log",
        timing_log=timing_log,
    )

    state = requests.get(f"{base_url}/state?tag={test_namespace}", timeout=5).json()
    assert len(state["security_groups"]) >= 1

    _run_terraform(
        ["terraform", "destroy", "-input=false", "-auto-approve"],
        project_dir,
        env,
        "terraform destroy",
        log_path=project_dir / "tf-destroy-trace.log",
        timing_log=timing_log,
    )


@pytest.mark.skipif(not _terraform_available(), reason="terraform binary not found")
def test_terraform_default_route_table(sim_container_clean: dict, tmp_path: Path, test_namespace: str) -> None:
    base_url = sim_container_clean["base_url"]
    project_dir = _copy_project(tmp_path, "default-route-table")
    _rewrite_endpoint(project_dir, base_url)

    env = _terraform_env()
    env["TF_VAR_name_prefix"] = test_namespace
    _configure_provider_installation(project_dir, env)
    timing_log = project_dir / "tf-timing.log"

    _run_terraform(["terraform", "init", "-input=false"], project_dir, env, "terraform init", timing_log=timing_log)
    _run_terraform(
        ["terraform", "plan", "-input=false", "-out=tfplan"],
        project_dir,
        env,
        "terraform plan",
        timing_log=timing_log,
    )
    _run_terraform(
        ["terraform", "apply", "-input=false", "-auto-approve", "tfplan"],
        project_dir,
        env,
        "terraform apply",
        log_path=project_dir / "tf-apply-trace.log",
        timing_log=timing_log,
    )

    state = requests.get(f"{base_url}/state?tag={test_namespace}", timeout=5).json()
    assert len(state["route_tables"]) >= 1

    _run_terraform(
        ["terraform", "destroy", "-input=false", "-auto-approve"],
        project_dir,
        env,
        "terraform destroy",
        log_path=project_dir / "tf-destroy-trace.log",
        timing_log=timing_log,
    )


@pytest.mark.skipif(not _terraform_available(), reason="terraform binary not found")
def test_terraform_default_network_acl(sim_container_clean: dict, tmp_path: Path, test_namespace: str) -> None:
    base_url = sim_container_clean["base_url"]
    project_dir = _copy_project(tmp_path, "default-network-acl")
    _rewrite_endpoint(project_dir, base_url)

    env = _terraform_env()
    env["TF_VAR_name_prefix"] = test_namespace
    _configure_provider_installation(project_dir, env)
    timing_log = project_dir / "tf-timing.log"

    _run_terraform(["terraform", "init", "-input=false"], project_dir, env, "terraform init", timing_log=timing_log)
    _run_terraform(
        ["terraform", "plan", "-input=false", "-out=tfplan"],
        project_dir,
        env,
        "terraform plan",
        timing_log=timing_log,
    )
    _run_terraform(
        ["terraform", "apply", "-input=false", "-auto-approve", "tfplan"],
        project_dir,
        env,
        "terraform apply",
        log_path=project_dir / "tf-apply-trace.log",
        timing_log=timing_log,
    )

    state = requests.get(f"{base_url}/state?tag={test_namespace}", timeout=5).json()
    assert len(state["network_acls"]) >= 1

    _run_terraform(
        ["terraform", "destroy", "-input=false", "-auto-approve"],
        project_dir,
        env,
        "terraform destroy",
        log_path=project_dir / "tf-destroy-trace.log",
        timing_log=timing_log,
    )


def _rewrite_endpoint(project_dir: Path, base_url: str) -> None:
    tf_file = project_dir / "main.tf"
    contents = tf_file.read_text()
    contents = contents.replace("http://127.0.0.1:8731", base_url)
    tf_file.write_text(contents)
