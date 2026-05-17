# Agentic AI Industry Use Cases - Build & Deploy Orchestration
SHELL := /bin/bash
.DEFAULT_GOAL := help

ifeq ($(OS),Windows_NT)
    VENV := .venv/Scripts
    PYTHON := $(VENV)/python
    PIP := $(VENV)/pip
else
    VENV := .venv
    PYTHON := $(VENV)/bin/python
    PIP := $(VENV)/bin/pip
endif

# ============================================================
# Setup
# ============================================================

.PHONY: setup
setup: venv install-deps ## Full project setup

.PHONY: venv
venv: ## Create Python virtual environment
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip

.PHONY: install-deps
install-deps: ## Install all Python dependencies
	$(PIP) install -e '.[dev]'

# ============================================================
# Finance Trading Assistant
# ============================================================

.PHONY: run-finance
run-finance: ## Run Finance Trading agent locally
	cd apps/finance-trading && $(PYTHON) agent/app.py

.PHONY: build-finance-frontend
build-finance-frontend: ## Build Finance Trading React frontend
	cd apps/finance-trading/frontend && npm install && npm run build

.PHONY: dev-finance-frontend
dev-finance-frontend: ## Run Finance Trading frontend dev server
	cd apps/finance-trading/frontend && npm install && npm run dev

# ============================================================
# All Industry Apps
# ============================================================

.PHONY: run-insurance
run-insurance: ## Run Insurance Claims agent locally
	cd apps/insurance-claims && $(PYTHON) agent/app.py

.PHONY: run-retail
run-retail: ## Run Retail Inventory agent locally
	cd apps/retail-inventory && $(PYTHON) agent/app.py

.PHONY: run-healthcare
run-healthcare: ## Run Healthcare Medical agent locally
	cd apps/healthcare-medical && $(PYTHON) agent/app.py

.PHONY: run-manufacturing
run-manufacturing: ## Run Manufacturing Maintenance agent locally
	cd apps/manufacturing-maintenance && $(PYTHON) agent/app.py

.PHONY: run-realestate
run-realestate: ## Run Real Estate Valuation agent locally
	cd apps/real-estate-valuation && $(PYTHON) agent/app.py

# ============================================================
# CDK Infrastructure
# ============================================================

.PHONY: cdk-synth
cdk-synth: ## Synthesize CDK CloudFormation templates
	cd infra/cdk && cdk synth

.PHONY: cdk-deploy-shared
cdk-deploy-shared: ## Deploy shared infrastructure (VPC, WAF, KMS)
	cd infra/cdk && cdk deploy SharedInfra

.PHONY: cdk-deploy-finance
cdk-deploy-finance: ## Deploy Finance Trading infrastructure
	cd infra/cdk && cdk deploy FinanceTrading

.PHONY: cdk-deploy-all
cdk-deploy-all: ## Deploy all CDK stacks
	cd infra/cdk && cdk deploy --all

# ============================================================
# Quality & Testing
# ============================================================

.PHONY: test
test: ## Run all tests
	$(PYTHON) -m pytest tests/ -v

.PHONY: lint
lint: ## Run linters
	$(PYTHON) -m ruff check .
	$(PYTHON) -m black --check .

.PHONY: format
format: ## Auto-format code
	$(PYTHON) -m black .
	$(PYTHON) -m ruff check --fix .

.PHONY: typecheck
typecheck: ## Run type checking with mypy
	$(PYTHON) -m mypy packages/ --ignore-missing-imports

.PHONY: lock
lock: ## Generate requirements.txt from current environment
	$(PIP) freeze > requirements.txt

# ============================================================
# Docker
# ============================================================

.PHONY: docker-build-finance
docker-build-finance: ## Build Finance Trading Docker image
	docker build -t agenticai-finance-trading -f apps/finance-trading/agent/Dockerfile .

.PHONY: docker-run-finance
docker-run-finance: ## Run Finance Trading in Docker
	docker run -p 8080:8080 -e AWS_REGION=us-west-2 agenticai-finance-trading

.PHONY: docker-build-all
docker-build-all: ## Build Docker images for all agents
	docker build -t agenticai-finance-trading -f apps/finance-trading/agent/Dockerfile .
	docker build -t agenticai-insurance-claims -f apps/insurance-claims/agent/Dockerfile .
	docker build -t agenticai-retail-inventory -f apps/retail-inventory/agent/Dockerfile .
	docker build -t agenticai-healthcare-medical -f apps/healthcare-medical/agent/Dockerfile .
	docker build -t agenticai-manufacturing-maintenance -f apps/manufacturing-maintenance/agent/Dockerfile .
	docker build -t agenticai-real-estate-valuation -f apps/real-estate-valuation/agent/Dockerfile .

# ============================================================
# Help
# ============================================================

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
