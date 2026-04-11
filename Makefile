.PHONY: build test lint clean embed-engine

VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo "dev")
GO_DIR := go
PY_DIR := python
BIN_DIR := bin
PYTHON ?= python3
EMBED_DIR := $(GO_DIR)/internal/embedded/engine

# embed-engine copies the Python engine files into the Go embed directory.
# This must run before go build to bundle the Python engine into the binary.
embed-engine:
	@echo "→ Bundling Python engine for embedding..."
	@rm -rf $(EMBED_DIR)
	@mkdir -p $(EMBED_DIR)/analyzers $(EMBED_DIR)/rules
	@cp $(PY_DIR)/engine.py $(EMBED_DIR)/
	@cp $(PY_DIR)/requirements.txt $(EMBED_DIR)/
	@cp $(PY_DIR)/analyzers/__init__.py $(EMBED_DIR)/analyzers/
	@cp $(PY_DIR)/analyzers/ast_analyzer.py $(EMBED_DIR)/analyzers/
	@cp $(PY_DIR)/analyzers/deps.py $(EMBED_DIR)/analyzers/
	@cp $(PY_DIR)/analyzers/secrets.py $(EMBED_DIR)/analyzers/
	@cp $(PY_DIR)/analyzers/semgrep_runner.py $(EMBED_DIR)/analyzers/
	@cp $(PY_DIR)/analyzers/spec_parser.py $(EMBED_DIR)/analyzers/
	@cp $(PY_DIR)/rules/auth.yaml $(EMBED_DIR)/rules/
	@cp $(PY_DIR)/rules/injection.yaml $(EMBED_DIR)/rules/
	@cp $(PY_DIR)/rules/secrets.yaml $(EMBED_DIR)/rules/
	@echo "✓ Python engine bundled into $(EMBED_DIR)/"

build: embed-engine
	@echo "→ Building Go binary..."
	cd $(GO_DIR) && go build -ldflags="-s -w -X main.Version=$(VERSION)" \
		-o ../$(BIN_DIR)/fendix ./cmd/fendix/
	@echo "✓ Built: $(BIN_DIR)/fendix"

test: test-go test-python

test-go:
	@echo "→ Running Go tests..."
	cd $(GO_DIR) && go test -race ./...

test-python:
	@echo "→ Running Python tests..."
	cd $(PY_DIR) && $(PYTHON) -m pytest tests/ -v

lint: lint-go lint-python

lint-go:
	@echo "→ Checking Go formatting..."
	@test -z "$$(cd $(GO_DIR) && gofmt -l .)" || \
		(echo "gofmt: files need formatting:" && cd $(GO_DIR) && gofmt -l . && exit 1)
	cd $(GO_DIR) && go vet ./...

lint-python:
	@echo "→ Checking Python formatting..."
	@if command -v ruff >/dev/null 2>&1; then \
		cd $(PY_DIR) && ruff check .; \
	else \
		echo "ruff not installed, skipping"; \
	fi
	@if command -v black >/dev/null 2>&1; then \
		cd $(PY_DIR) && black --check .; \
	else \
		echo "black not installed, skipping"; \
	fi

clean:
	rm -rf $(BIN_DIR)/
	cd $(GO_DIR) && go clean
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	@# Clean embedded engine (restore placeholder)
	rm -rf $(EMBED_DIR)
	mkdir -p $(EMBED_DIR)
	echo "# Fendix Python Engine (populated at build time)" > $(EMBED_DIR)/.gitkeep
