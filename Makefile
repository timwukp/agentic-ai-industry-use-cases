# Agentic AI Industry Use Cases — AgentCore Harness build & deploy
SHELL := /bin/bash
.DEFAULT_GOAL := help

VENV    := .venv
PYTHON  := $(VENV)/bin/python
PIP     := $(VENV)/bin/pip
CDK     := node_modules/.bin/cdk
export JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION := 1

# ============================================================
# Setup
# ============================================================

.PHONY: setup
setup: ## Create venv, install python deps + CDK CLI
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -e '.[dev,infra]'
	npm install --no-save aws-cdk@latest

# ============================================================
# Test
# ============================================================

.PHONY: test
test: ## Unit + infra tests (python + web)
	$(PYTHON) -m pytest tests/unit tests/infra -q
	$(MAKE) test-web

# Node runs the .ts test directly via native type stripping (>=22.6), so the web
# app gains no test runner or transpiler for this. Wired into `test` because a
# suite nothing invokes is a suite that rots.
.PHONY: test-web
test-web: ## Front-end unit tests (node:test, no extra deps)
	node --test tests/unit/*.test.ts

.PHONY: lint
lint: ## Ruff lint on tools/ deploy/ infra/
	$(PYTHON) -m ruff check tools deploy infra tests

# ============================================================
# Deploy (flagship: finance). Steps are idempotent.
# ============================================================

.PHONY: deploy-finance
deploy-finance: ## Full end-to-end deploy: CDK -> seed -> gateway -> harness -> smoke
	$(PYTHON) deploy/deploy.py --industry finance

.PHONY: deploy-step
deploy-step: ## Run one step: make deploy-step STEP=gateway
	$(PYTHON) deploy/deploy.py --industry finance --only $(STEP)

# Live check, not covered by `make test`: the unit tests read the templates, and
# the failure worth catching is the LIVE config drifting away from them. Reads
# tool-result events rather than the agent's prose, because an agent cut off from
# its tools writes confident text with invented numbers.
.PHONY: verify-harnesses
verify-harnesses: ## Assert every deployed harness can reach its gateway tools
	$(PYTHON) deploy/verify_harness.py

.PHONY: deploy-web
deploy-web: ## Build PWA + deploy WebStack + sync assets
	cd web && npm install && npm run build
	cd infra/cdk && PATH="$(PWD)/$(VENV)/bin:$$PATH" ../../$(CDK) deploy AgenticWeb --require-approval never --outputs-file ../../deploy/outputs/web-outputs.json
	$(PYTHON) deploy/publish_web.py

# ============================================================
# Local dev
# ============================================================

.PHONY: dev-web
dev-web: ## Run the PWA dev server
	cd web && npm run dev

.PHONY: synth
synth: ## cdk synth all stacks
	cd infra/cdk && PATH="$(PWD)/$(VENV)/bin:$$PATH" ../../$(CDK) synth -q

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-18s\033[0m %s\n", $$1, $$2}'
