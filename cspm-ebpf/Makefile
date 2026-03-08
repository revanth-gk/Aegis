# ╔══════════════════════════════════════════════════════════════╗
# ║               Sentinel-Core — Makefile                      ║
# ║  One-command orchestration for the eBPF security pipeline   ║
# ╚══════════════════════════════════════════════════════════════╝

.PHONY: help up down demo logs test forwarder install port-forward clean dashboard-api dashboard docker-up docker-down

SHELL := /bin/bash

# ── Defaults ──────────────────────────────────────────────────────
CLUSTER_NAME ?= sentinel-core
VENV_DIR     ?= .venv
PYTHON       ?= python3

help: ## Show this help
	@echo "Sentinel-Core — Makefile Targets"
	@echo "════════════════════════════════"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ── Infrastructure ────────────────────────────────────────────────

up: ## Create Kind cluster + install Tetragon + apply policies
	@chmod +x scripts/*.sh
	@bash scripts/setup-cluster.sh

down: ## Delete the Kind cluster
	@bash scripts/teardown.sh

port-forward: ## Port-forward Tetragon gRPC to localhost:54321
	kubectl -n kube-system port-forward svc/tetragon 54321:54321 &

# ── Python Environment ───────────────────────────────────────────

install: ## Install Python dependencies into a virtualenv
	$(PYTHON) -m venv $(VENV_DIR)
	$(VENV_DIR)/bin/pip install --upgrade pip
	$(VENV_DIR)/bin/pip install -r requirements.txt
	$(VENV_DIR)/bin/pip install -r forwarder/requirements.txt
	@echo "✅ Run 'source $(VENV_DIR)/bin/activate' to activate the virtualenv."

# ── Event Forwarder ───────────────────────────────────────────────

forwarder: ## Start the event forwarder (live tetra mode)
	$(VENV_DIR)/bin/python -m forwarder.main

forwarder-offline: ## Start the forwarder in offline mode (sample data)
	$(VENV_DIR)/bin/python -m forwarder.main --file fixtures/sample-tetragon-raw.jsonl

# ── Demo ──────────────────────────────────────────────────────────

demo: ## Run the attack simulation demo
	@bash scripts/run-demo.sh

# ── Testing ───────────────────────────────────────────────────────

test: ## Run unit tests
	$(VENV_DIR)/bin/python -m pytest forwarder/tests/ -v --tb=short

test-quick: ## Run tests without virtualenv (uses system python)
	$(PYTHON) -m pytest forwarder/tests/ -v --tb=short

# ── Logs ──────────────────────────────────────────────────────────

logs: ## Tail Tetragon pod logs
	kubectl -n kube-system logs -l app.kubernetes.io/name=tetragon -f --tail=50

logs-events: ## Stream raw Tetragon events via tetra CLI
	tetra getevents -o compact --server-address localhost:54321

# ── Cleanup ───────────────────────────────────────────────────────

clean: ## Remove virtualenv and cached files
	rm -rf $(VENV_DIR) __pycache__ forwarder/__pycache__ forwarder/tests/__pycache__
	rm -rf .pytest_cache forwarder/.pytest_cache
	find . -name "*.pyc" -delete

# ── Dashboard API ─────────────────────────────────────────────────

dashboard-api: ## Start the Dashboard API server (port 8080)
	$(VENV_DIR)/bin/python dashboard_api.py

# ── Frontend Dashboard ────────────────────────────────────────────

dashboard: ## Start the Vite frontend dev server (port 5173)
	cd dashboard && npm run dev

# ── Docker Compose ────────────────────────────────────────────────

docker-up: ## Start all services via Docker Compose
	docker compose up --build -d
	@echo "✅ Services running:"
	@echo "  Dashboard API:   http://localhost:8080"
	@echo "  Forwarder API:   http://localhost:8081"
	@echo "  Orchestrator:    http://localhost:8000"
	@echo "  Redis:           localhost:6379"
	@echo "  ChromaDB:        http://localhost:8100"

docker-down: ## Stop all Docker Compose services
	docker compose down

# ── Full Stack (Local Dev) ────────────────────────────────────────

run-all: ## Start Redis + Forwarder + Dashboard API + Frontend (local dev)
	@echo "Starting Sentinel-Core full stack..."
	@echo "Ensure Redis is running on port 6379"
	@echo "Starting Forwarder API (port 8081)..."
	$(VENV_DIR)/bin/python live_backend.py &
	@sleep 2
	@echo "Starting Dashboard API (port 8080)..."
	$(VENV_DIR)/bin/python dashboard_api.py &
	@sleep 2
	@echo "Starting Frontend (port 5173)..."
	cd dashboard && npm run dev &
	@echo "✅ All services started"
	@echo "  Frontend:        http://localhost:5173"
	@echo "  Dashboard API:   http://localhost:8080"
	@echo "  Forwarder API:   http://localhost:8081"
