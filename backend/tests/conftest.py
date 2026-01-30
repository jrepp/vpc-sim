from __future__ import annotations

import os
import socket
import subprocess
import time
import uuid
from pathlib import Path

import pytest
import requests

def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="session")
def sim_server(tmp_path_factory: pytest.TempPathFactory) -> dict:
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    db_path = tmp_path_factory.mktemp("db") / "test.db"
    env = os.environ.copy()
    env["DATABASE_URL"] = f"sqlite:///{db_path}"
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])

    proc = subprocess.Popen(
        [
            str(Path(__file__).resolve().parents[1] / ".venv" / "bin" / "uvicorn"),
            "app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=str(Path(__file__).resolve().parents[1]),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    ready = False
    for _ in range(40):
        try:
            if requests.get(f"{base_url}/health", timeout=0.5).status_code == 200:
                ready = True
                break
        except requests.RequestException:
            time.sleep(0.25)

    if not ready:
        proc.terminate()
        output = proc.stdout.read() if proc.stdout else ""
        raise RuntimeError(f"Simulator failed to start.\n{output}")

    yield {"base_url": base_url, "port": port}

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture(scope="session")
def sim_container(sim_server: dict) -> dict:
    return sim_server


@pytest.fixture(scope="function")
def sim_container_clean(sim_container: dict) -> dict:
    try:
        requests.post(f"{sim_container['base_url']}/state/reset", timeout=5)
    except requests.RequestException as exc:
        pytest.fail(f"Failed to reset simulator state: {exc}")
    return sim_container


@pytest.fixture(scope="function")
def test_namespace() -> str:
    return uuid.uuid4().hex[:8]


def pytest_report_header() -> list[str]:
    return [
        "E2E ladder: requires terraform binary for terraform tests.",
    ]
