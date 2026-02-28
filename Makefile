# Agentic AI Industry Use Cases - Build & Deploy Orchestration
SHELL := /bin/bash
.DEFAULT_GOAL := help

VENV := .venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

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
	$(PIP) install strands-agents strands-agents-tools 'bedrock-agentcore[strands-agents]'
	$(PIP) install boto3 pydantic pydantic-settings numpy scipy pandas
	$(PIP) install aws-cdk-lib constructs
	$(PIP) install pytest pytest-asyncio black ruff mypy

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

# ============================================================
# Docker
# ============================================================

.PHONY: docker-build-finance
docker-build-finance: ## Build Finance Trading Docker image
	docker build -t agenticai-finance-trading -f apps/finance-trading/agent/Dockerfile .

.PHONY: docker-run-finance
docker-run-finance: ## Run Finance Trading in Docker
	docker run -p 8080:8080 -e AWS_REGION=us-west-2 agenticai-finance-trading

# ============================================================
# Help
# ============================================================

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
