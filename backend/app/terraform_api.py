"""Terraform runner endpoints."""
from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Iterator, List

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

router = APIRouter(prefix="/terraform")

ROOT_DIR = Path(__file__).resolve().parents[2]
PROFILES_DIR = Path(
    os.getenv("TERRAFORM_PROFILES_DIR", str(ROOT_DIR / "terraform-projects"))
)
RUN_LOCK = threading.Lock()


class TerraformRunRequest(BaseModel):
    """Payload to run Terraform for a selected profile."""

    profile: str = Field(..., description="Profile name under terraform-projects")
    step: str = Field("all", description="init, plan, apply, or all")


def _discover_profiles() -> List[Path]:
    """Return terraform profiles that contain .tf files."""
    if not PROFILES_DIR.exists():
        return []
    profiles = []
    for entry in PROFILES_DIR.iterdir():
        if not entry.is_dir() or entry.name.startswith("."):
            continue
        if any(entry.rglob("*.tf")):
            profiles.append(entry)
    return sorted(profiles, key=lambda p: p.name)


def _base_env(base_url: str) -> Dict[str, str]:
    """Build environment vars for Terraform runs."""
    env = os.environ.copy()
    env.setdefault("AWS_ACCESS_KEY_ID", "test")
    env.setdefault("AWS_SECRET_ACCESS_KEY", "test")
    env.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    env.setdefault("AWS_REGION", "us-east-1")
    env.setdefault("TF_IN_AUTOMATION", "1")
    env.setdefault("TF_INPUT", "0")
    env["AWS_ENDPOINT_URL"] = base_url
    env["AWS_ENDPOINT_URL_EC2"] = base_url
    return env


def _run_command(cmd: List[str], cwd: Path, env: Dict[str, str]) -> Dict[str, str | int]:
    """Run a command and capture stdout/stderr."""
    result = subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    output = ""
    if result.stdout:
        output += result.stdout
    if result.stderr:
        if output:
            output += "\n"
        output += result.stderr
    return {"exit_code": result.returncode, "output": output.strip()}


@router.get("/profiles")
def list_profiles() -> Dict[str, List[str]]:
    """List available Terraform profiles."""
    profiles = _discover_profiles()
    return {"profiles": [profile.name for profile in profiles]}


@contextmanager
def _acquire_runner_lock() -> Iterator[None]:
    """Acquire the runner lock or raise a busy error."""
    if not RUN_LOCK.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="Terraform runner is busy")
    try:
        yield
    finally:
        RUN_LOCK.release()


@router.post("/run")
def run_terraform(payload: TerraformRunRequest, request: Request) -> Dict[str, object]:
    """Run Terraform against a profile with init/plan/apply steps."""
    if not shutil.which("terraform"):
        raise HTTPException(status_code=500, detail="terraform binary not found in PATH")

    profiles = {profile.name: profile for profile in _discover_profiles()}
    profile_dir = profiles.get(payload.profile)
    if not profile_dir:
        raise HTTPException(status_code=404, detail="Terraform profile not found")

    step = payload.step.lower()
    if step not in {"init", "plan", "apply", "all"}:
        raise HTTPException(status_code=400, detail="Invalid step")

    with _acquire_runner_lock():
        base_url = os.getenv("SIM_BASE_URL") or str(request.base_url).rstrip("/")
        env = _base_env(base_url)

        steps: List[Dict[str, object]] = []
        commands = []
        if step in {"init", "all"}:
            commands.append(("init", ["terraform", "init", "-input=false"]))
        if step in {"plan", "all"}:
            commands.append(
                ("plan", ["terraform", "plan", "-input=false", "-out=tfplan"])
            )
        if step in {"apply", "all"}:
            commands.append(
                (
                    "apply",
                    ["terraform", "apply", "-input=false", "-auto-approve", "tfplan"],
                )
            )

        start = time.time()
        success = True
        for name, cmd in commands:
            result = _run_command(cmd, profile_dir, env)
            steps.append({"step": name, **result})
            if result["exit_code"] != 0:
                success = False
                break

        return {
            "profile": payload.profile,
            "success": success,
            "duration_ms": int((time.time() - start) * 1000),
            "steps": steps,
        }
