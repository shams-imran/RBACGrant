.PHONY: run dev backend frontend test catalog docker clean

VENV := .venv
PY := $(VENV)/bin/python

$(VENV)/bin/activate:
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install -U pip
	$(VENV)/bin/pip install -e "backend[dev]"

frontend/node_modules:
	cd frontend && npm ci --no-audit --no-fund || npm install --no-audit --no-fund

frontend: frontend/node_modules
	cd frontend && npm run build

catalog: $(VENV)/bin/activate
	cd backend && ../$(PY) -m app.catalog.generate --builtin

# One command: build the frontend, generate the catalog, start the server.
run: $(VENV)/bin/activate frontend catalog
	cd backend && ../$(PY) -m app.main

dev: $(VENV)/bin/activate
	cd backend && RBAC_UI_AUTH_MODE=none ../$(PY) -m app.main &
	cd frontend && npm run dev

test: $(VENV)/bin/activate
	cd backend && ../$(PY) -m pytest tests/ -q
	cd frontend && npx tsc -b

docker:
	docker build -t rbacgrant:latest .

clean:
	rm -rf $(VENV) frontend/dist frontend/node_modules backend/.pytest_cache
