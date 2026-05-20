# TraceTree Unified Monorepo Makefile

PYTHON = python3
PIP = pip3
NPM = npm
ORCHESTRATOR_DIR = orchestrator
FRONTEND_DIR = frontend

.PHONY: all install build start dev clean help

all: install build

help:
	@echo "TraceTree Unified Monorepo Management"
	@echo "-------------------------------------"
	@echo "make install  - Install all dependencies (Python, Orchestrator, Frontend)"
	@echo "make build    - Build Orchestrator and Frontend"
	@echo "make start    - Start Orchestrator and Frontend in production mode"
	@echo "make dev      - Start Orchestrator and Frontend in development mode"
	@echo "make clean    - Remove build artifacts and node_modules"

install:
	@echo "Installing Python telemetry dependencies..."
	$(PIP) install -e .
	@echo "Installing Orchestrator dependencies..."
	cd $(ORCHESTRATOR_DIR) && $(NPM) install
	@echo "Installing Frontend dependencies..."
	cd $(FRONTEND_DIR) && $(NPM) install

build:
	@echo "Building Orchestrator..."
	cd $(ORCHESTRATOR_DIR) && $(NPM) run build
	@echo "Building Frontend..."
	cd $(FRONTEND_DIR) && $(NPM) run build

start:
	@echo "Starting TraceTree Stack..."
	(cd $(ORCHESTRATOR_DIR) && $(NPM) start) & \
	(cd $(FRONTEND_DIR) && $(NPM) start) & \
	wait

dev:
	@echo "Starting TraceTree Stack in DEV mode..."
	(cd $(ORCHESTRATOR_DIR) && $(NPM) run dev) & \
	(cd $(FRONTEND_DIR) && $(NPM) run dev) & \
	wait

clean:
	@echo "Cleaning artifacts..."
	find . -type d -name "__pycache__" -exec rm -rf {} +
	rm -rf $(ORCHESTRATOR_DIR)/dist
	rm -rf $(ORCHESTRATOR_DIR)/node_modules
	rm -rf $(FRONTEND_DIR)/.next
	rm -rf $(FRONTEND_DIR)/node_modules
	rm -rf *.egg-info
