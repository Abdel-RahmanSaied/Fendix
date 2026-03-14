.PHONY: build test lint clean

VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo "dev")
GO_DIR := go
PY_DIR := python
BIN_DIR := bin
PYTHON ?= python3

build:
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
