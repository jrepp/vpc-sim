#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $(basename "$0") /path/to/terraform/project" >&2
  exit 1
fi

project_path="$1"
if [[ ! -d "$project_path" ]]; then
  echo "Project path not found: $project_path" >&2
  exit 1
fi

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
backend_dir="$root_dir/backend"
venv_dir="$backend_dir/.venv"
log_file="$root_dir/terraform-projects/simulator.log"

host="${SIM_HOST:-127.0.0.1}"
port="${SIM_PORT:-8000}"
health_url="http://${host}:${port}/health"

if ! command -v python >/dev/null 2>&1; then
  echo "python is required" >&2
  exit 1
fi

if ! command -v terraform >/dev/null 2>&1; then
  echo "terraform is required" >&2
  exit 1
fi

if [[ ! -d "$venv_dir" ]]; then
  python -m venv "$venv_dir"
fi

"$venv_dir/bin/pip" install -r "$backend_dir/requirements.txt" >/dev/null

"$venv_dir/bin/uvicorn" app.main:app --host "$host" --port "$port" --log-level info \
  >"$log_file" 2>&1 &
SIM_PID=$!

cleanup() {
  kill "$SIM_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ready=0
for _ in {1..30}; do
  if curl -fsS "$health_url" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.5
done

if [[ $ready -ne 1 ]]; then
  echo "Simulator did not start; check $log_file" >&2
  exit 1
fi

echo "Simulator running at ${health_url}"

pushd "$project_path" >/dev/null
terraform init -input=false
terraform plan -input=false -out=tfplan
terraform apply -input=false -auto-approve tfplan
popd >/dev/null
