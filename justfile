set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

backend_dir := "backend"
frontend_dir := "frontend"
terraform_dir := "terraform"
backend_port := "8731"
frontend_port := "5179"

@backend-build:
	cd {{backend_dir}} && if [[ ! -d .venv ]]; then python -m venv .venv; fi
	cd {{backend_dir}} && .venv/bin/pip install -r requirements.txt >/dev/null

@backend-dev-tools:
	cd {{backend_dir}} && if [[ ! -d .venv ]]; then python -m venv .venv; fi
	cd {{backend_dir}} && .venv/bin/pip install -r requirements.txt >/dev/null
	cd {{backend_dir}} && .venv/bin/pip install -r requirements-dev.txt >/dev/null

@backend:
	just backend-build
	cd {{backend_dir}} && .venv/bin/uvicorn app.main:app --reload --port {{backend_port}}

@backend-dev:
	just backend-build
	cd {{backend_dir}} && .venv/bin/uvicorn app.main:app --reload --port {{backend_port}}

@frontend:
	cd {{frontend_dir}} && npm install
	cd {{frontend_dir}} && npm run dev

@frontend-dev:
	cd {{frontend_dir}} && npm install
	cd {{frontend_dir}} && VITE_API_BASE=http://localhost:{{backend_port}} npm run dev -- --port {{frontend_port}} --strictPort

@frontend-build:
	cd {{frontend_dir}} && npm install
	cd {{frontend_dir}} && npm run build

@tf-run project:
	just backend-build
	{{terraform_dir}}/run.sh {{project}}

@spec-gen:
	python specs/generate_vpc_spec.py

@spec-pydantic:
	python specs/generate_pydantic_models.py

@spec-all:
	just spec-gen
	just spec-pydantic

@lint:
	just backend-dev-tools
	cd {{backend_dir}} && .venv/bin/pyright
	cd {{backend_dir}} && .venv/bin/pylint --ignore=generated app
	cd {{backend_dir}} && .venv/bin/pycodestyle --exclude=generated app

@lint-frontend:
	cd {{frontend_dir}} && npm install
	cd {{frontend_dir}} && npm run lint

@lint-all:
	just lint
	just lint-frontend

@test:
	just backend-dev-tools
	cd {{backend_dir}} && .venv/bin/pytest -n auto -vv -ra -s --durations=15 --durations-min=0.1

@test-backend:
	just test

@pre-commit-install:
	just backend-dev-tools
	{{backend_dir}}/.venv/bin/pre-commit install

@app:
	just frontend-build
	just backend

@dev:
	just stop-dev
	just backend-dev & just frontend-dev

@stop-dev:
	@backend_pids=$(lsof -nP -iTCP:{{backend_port}} -sTCP:LISTEN -t 2>/dev/null || true); \
	if [ -n "$backend_pids" ]; then kill $backend_pids; fi
	@frontend_pids=$(lsof -nP -iTCP:{{frontend_port}} -sTCP:LISTEN -t 2>/dev/null || true); \
	if [ -n "$frontend_pids" ]; then kill $frontend_pids; fi
