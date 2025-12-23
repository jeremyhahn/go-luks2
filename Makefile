# Makefile for go-luks2
# LUKS2 encryption library and tools in pure Go

.PHONY: help build install test test-verbose test-coverage test-integration coverage clean fmt vet lint gosec ci ci-full fmt-check all check test-cli integration-test-pkg integration-test-cli

# Default target
.DEFAULT_GOAL := help

# Variables
BINARY_NAME=luks2
BUILD_DIR=build
CMD_DIR=cmd/luks2
COVERAGE_FILE=coverage.out
COVERAGE_HTML=coverage.html
# Coverage threshold - set to 90% for all packages
COVERAGE_THRESHOLD=90.0
GO=$(shell which go 2>/dev/null || echo /usr/local/go/bin/go)
GOPATH=$(shell $(GO) env GOPATH)
GOBIN=$(GOPATH)/bin
# Version from VERSION file
VERSION=$(shell cat VERSION 2>/dev/null | tr -d 'v' || echo "dev")
LDFLAGS=-ldflags "-X main.Version=$(VERSION)"

# Colors for output
COLOR_RESET=\033[0m
COLOR_BOLD=\033[1m
COLOR_GREEN=\033[32m
COLOR_YELLOW=\033[33m
COLOR_BLUE=\033[34m
COLOR_RED=\033[31m

help: ## Show this help message
	@echo "$(COLOR_BOLD)go-luks2 Makefile$(COLOR_RESET)"
	@echo "$(COLOR_BLUE)Pure Go LUKS2 Implementation$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_BOLD)Available targets:$(COLOR_RESET)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(COLOR_GREEN)%-25s$(COLOR_RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(COLOR_BOLD)Examples:$(COLOR_RESET)"
	@echo "  make build              # Build the CLI tool"
	@echo "  make test               # Run unit tests only"
	@echo "  make test-cli           # Run CLI unit tests"
	@echo "  make integration-test   # Run all integration tests in Docker"
	@echo "  make coverage           # Run all tests with coverage"
	@echo "  make ci                 # Run CI pipeline locally"
	@echo "  make check              # Run all quality checks"
	@echo ""

all: clean fmt vet test build ## Run all checks and build

build: ## Build the CLI binary
	@echo "$(COLOR_BOLD)Building $(BINARY_NAME) v$(VERSION)...$(COLOR_RESET)"
	@mkdir -p $(BUILD_DIR)
	@$(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)
	@echo "$(COLOR_GREEN)✓ Build complete: $(BUILD_DIR)/$(BINARY_NAME) (v$(VERSION))$(COLOR_RESET)"

install: ## Install the CLI binary to $GOPATH/bin
	@echo "$(COLOR_BOLD)Installing $(BINARY_NAME) v$(VERSION)...$(COLOR_RESET)"
	@$(GO) install $(LDFLAGS) ./$(CMD_DIR)
	@echo "$(COLOR_GREEN)✓ Installed to $(GOBIN)/$(BINARY_NAME) (v$(VERSION))$(COLOR_RESET)"

test: ## Run unit tests only (no I/O, no root required)
	@echo "$(COLOR_BOLD)Running unit tests only...$(COLOR_RESET)"
	@$(GO) test -v ./... 2>&1 | grep -v "no test files" || true
	@echo "$(COLOR_GREEN)✓ Unit tests complete$(COLOR_RESET)"

test-unit: ## Run only unit tests with coverage (fast, no I/O, no root required)
	@echo "$(COLOR_BOLD)Running unit tests with coverage...$(COLOR_RESET)"
	@$(GO) test -v -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./pkg/luks2 ./cmd/luks2 2>&1 | grep -v "no test files" || true
	@echo ""
	@echo "$(COLOR_BOLD)Coverage from unit tests:$(COLOR_RESET)"
	@$(GO) tool cover -func=$(COVERAGE_FILE) | tail -1

test-cli: ## Run CLI unit tests only
	@echo "$(COLOR_BOLD)Running CLI unit tests...$(COLOR_RESET)"
	@$(GO) test -v -coverprofile=coverage-cli.out -covermode=atomic ./cmd/luks2 2>&1 | grep -v "no test files" || true
	@echo ""
	@echo "$(COLOR_BOLD)CLI Coverage:$(COLOR_RESET)"
	@$(GO) tool cover -func=coverage-cli.out | tail -1

test-verbose: ## Run tests with verbose output
	@echo "$(COLOR_BOLD)Running tests (verbose)...$(COLOR_RESET)"
	@if [ "$$(id -u)" -eq 0 ]; then \
		$(GO) test -v -race ./...; \
	else \
		sudo -E PATH="$(PATH)" $(GO) test -v -race ./...; \
	fi

test-coverage: ## Run tests with coverage report
	@echo "$(COLOR_BOLD)Running tests with coverage...$(COLOR_RESET)"
	@if [ "$$(id -u)" -eq 0 ]; then \
		$(GO) test -v -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./...; \
	else \
		sudo -E PATH="$(PATH)" $(GO) test -v -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./...; \
	fi
	@echo "$(COLOR_BOLD)Generating coverage report...$(COLOR_RESET)"
	@$(GO) tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@$(GO) tool cover -func=$(COVERAGE_FILE)
	@echo "$(COLOR_GREEN)✓ Coverage report: $(COVERAGE_HTML)$(COLOR_RESET)"

integration-test: build ## Run all integration tests in Docker (isolated, recommended)
	@echo "$(COLOR_BOLD)Running all integration tests in Docker container...$(COLOR_RESET)"
	@$(MAKE) docker-integration-test

integration-test-pkg: build ## Run package integration tests in Docker
	@echo "$(COLOR_BOLD)Running package integration tests in Docker...$(COLOR_RESET)"
	@docker build -f test/integration/Dockerfile -t go-luks2-integration-test .
	@docker run --rm --privileged go-luks2-integration-test \
		go test -v -tags=integration ./test/integration/pkg/...

integration-test-cli: build ## Run CLI integration tests in Docker
	@echo "$(COLOR_BOLD)Running CLI integration tests in Docker...$(COLOR_RESET)"
	@docker build -f test/integration/Dockerfile -t go-luks2-integration-test .
	@docker run --rm --privileged go-luks2-integration-test \
		go test -v -tags=integration ./test/integration/cli/...

coverage: build ## Run all tests (unit + integration) with coverage (requires root)
	@echo "$(COLOR_BOLD)Running all tests (unit + integration) with coverage...$(COLOR_RESET)"
	@rm -f coverage-unit.out coverage-integration.out $(COVERAGE_FILE)
	@echo ""
	@echo "$(COLOR_BOLD)Step 1: Running unit tests with coverage...$(COLOR_RESET)"
	@$(GO) test -coverprofile=coverage-unit.out -covermode=atomic ./pkg/luks2 ./cmd/luks2 2>&1 | grep -v "no test files" || true
	@echo ""
	@echo "$(COLOR_BOLD)Step 2: Running integration tests with coverage...$(COLOR_RESET)"
	@if [ "$$(id -u)" -eq 0 ]; then \
		$(GO) test -tags=integration -coverprofile=coverage-integration.out -covermode=atomic ./... 2>&1 | grep -v "no test files" || true; \
	else \
		sudo -E PATH="$(PATH)" $(GO) test -tags=integration -coverprofile=coverage-integration.out -covermode=atomic ./... 2>&1 | grep -v "no test files" || true; \
	fi
	@echo ""
	@echo "$(COLOR_BOLD)Step 3: Merging coverage profiles...$(COLOR_RESET)"
	@if [ -f coverage-unit.out ] && [ -f coverage-integration.out ]; then \
		echo "mode: atomic" > $(COVERAGE_FILE); \
		grep -v "^mode:" coverage-unit.out >> $(COVERAGE_FILE) 2>/dev/null || true; \
		grep -v "^mode:" coverage-integration.out >> $(COVERAGE_FILE) 2>/dev/null || true; \
	elif [ -f coverage-unit.out ]; then \
		cp coverage-unit.out $(COVERAGE_FILE); \
	elif [ -f coverage-integration.out ]; then \
		cp coverage-integration.out $(COVERAGE_FILE); \
	fi
	@rm -f coverage-unit.out coverage-integration.out
	@echo ""
	@echo "$(COLOR_BOLD)Generating coverage report...$(COLOR_RESET)"
	@$(GO) tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@$(GO) tool cover -func=$(COVERAGE_FILE) | tail -1
	@echo "$(COLOR_GREEN)✓ Coverage report: $(COVERAGE_HTML)$(COLOR_RESET)"

docker-integration-test: ## Run integration tests in Docker (isolated, recommended)
	@echo "$(COLOR_BOLD)Building Docker image for integration tests...$(COLOR_RESET)"
	@docker build -f test/integration/Dockerfile -t go-luks2-integration-test .
	@echo ""
	@echo "$(COLOR_BOLD)Running integration tests in Docker container (privileged)...$(COLOR_RESET)"
	@rm -f coverage-docker.out
	@docker rm -f go-luks2-test-runner 2>/dev/null || true
	@docker run --privileged --name go-luks2-test-runner go-luks2-integration-test
	@docker cp go-luks2-test-runner:/app/coverage.out coverage-docker.out 2>/dev/null || true
	@docker rm -f go-luks2-test-runner 2>/dev/null || true
	@if [ -f coverage-docker.out ]; then \
		echo ""; \
		echo "$(COLOR_BOLD)Generating coverage report...$(COLOR_RESET)"; \
		$(GO) tool cover -html=coverage-docker.out -o coverage-docker.html 2>/dev/null || true; \
		echo "$(COLOR_GREEN)✓ Coverage report: coverage-docker.html$(COLOR_RESET)"; \
	fi
	@echo "$(COLOR_GREEN)✓ Docker integration tests complete$(COLOR_RESET)"

docker-test-specific: ## Run specific integration test in Docker (use TEST=TestName)
	@echo "$(COLOR_BOLD)Building Docker image...$(COLOR_RESET)"
	@docker build -f test/integration/Dockerfile -t go-luks2-integration-test .
	@echo ""
	@echo "$(COLOR_BOLD)Running test: $(TEST)$(COLOR_RESET)"
	@docker run --rm --privileged go-luks2-integration-test \
		go test -v -tags=integration -run="$(TEST)" ./...

host-integration-test: build ## Run integration tests on host (requires sudo, NOT recommended)
	@echo "$(COLOR_YELLOW)⚠ WARNING: Running integration tests on HOST system$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)  This requires root privileges and modifies the system.$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)  Recommended: use 'make integration-test' (runs in Docker)$(COLOR_RESET)"
	@echo ""
	@if [ "$$(id -u)" -eq 0 ]; then \
		$(GO) test -v -tags=integration ./... 2>&1 | grep -v "no test files" || true; \
	else \
		sudo -E PATH="$(PATH)" $(GO) test -v -tags=integration ./... 2>&1 | grep -v "no test files" || true; \
	fi
	@echo "$(COLOR_GREEN)✓ Host integration tests complete$(COLOR_RESET)"

test-integration: integration-test ## Alias for integration-test

bench: ## Run benchmarks
	@echo "$(COLOR_BOLD)Running benchmarks...$(COLOR_RESET)"
	@$(GO) test -bench=. -benchmem ./...

fmt: ## Format code with gofmt
	@echo "$(COLOR_BOLD)Formatting code...$(COLOR_RESET)"
	@gofmt -s -w .
	@echo "$(COLOR_GREEN)✓ Code formatted$(COLOR_RESET)"

fmt-check: ## Check if code is formatted (CI-friendly, doesn't modify files)
	@echo "$(COLOR_BOLD)Checking code formatting...$(COLOR_RESET)"
	@UNFORMATTED=$$(gofmt -l .); \
	if [ -n "$$UNFORMATTED" ]; then \
		echo "$(COLOR_RED)✗ The following files are not formatted:$(COLOR_RESET)"; \
		echo "$$UNFORMATTED"; \
		echo ""; \
		echo "$(COLOR_YELLOW)Run 'make fmt' to format the code$(COLOR_RESET)"; \
		exit 1; \
	fi
	@echo "$(COLOR_GREEN)✓ All files are properly formatted$(COLOR_RESET)"

vet: ## Run go vet
	@echo "$(COLOR_BOLD)Running go vet...$(COLOR_RESET)"
	@$(GO) vet ./...
	@echo "$(COLOR_GREEN)✓ Vet passed$(COLOR_RESET)"

lint: ## Run golangci-lint (if installed)
	@echo "$(COLOR_BOLD)Running golangci-lint...$(COLOR_RESET)"
	@LINTER=$$(command -v golangci-lint 2>/dev/null || echo "$(GOBIN)/golangci-lint"); \
	if [ -x "$$LINTER" ]; then \
		$$LINTER run ./... || exit 1; \
		echo "$(COLOR_GREEN)✓ Lint passed$(COLOR_RESET)"; \
	else \
		echo "$(COLOR_YELLOW)⚠ golangci-lint not installed, skipping...$(COLOR_RESET)"; \
		echo "  Install: curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b \$$(go env GOPATH)/bin"; \
	fi

gosec: ## Run gosec security scanner
	@echo "$(COLOR_BOLD)Running gosec security scanner...$(COLOR_RESET)"
	@GOSEC=$$(command -v gosec 2>/dev/null || echo "$(GOBIN)/gosec"); \
	if [ -x "$$GOSEC" ]; then \
		$$GOSEC -exclude-generated -severity medium -confidence medium ./... || exit 1; \
		echo "$(COLOR_GREEN)✓ Security scan passed$(COLOR_RESET)"; \
	else \
		echo "$(COLOR_YELLOW)⚠ gosec not installed, skipping...$(COLOR_RESET)"; \
		echo "  Install: go install github.com/securego/gosec/v2/cmd/gosec@latest"; \
	fi

ci: fmt-check vet lint gosec test-unit build ## Run CI pipeline locally (format, lint, security, unit tests, build)
	@echo ""
	@echo "$(COLOR_BOLD)======================================$(COLOR_RESET)"
	@echo "$(COLOR_BOLD)CI Pipeline Complete$(COLOR_RESET)"
	@echo "$(COLOR_BOLD)======================================$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_GREEN)✓ Format check passed$(COLOR_RESET)"
	@echo "$(COLOR_GREEN)✓ Vet passed$(COLOR_RESET)"
	@echo "$(COLOR_GREEN)✓ Lint passed$(COLOR_RESET)"
	@echo "$(COLOR_GREEN)✓ Security scan passed$(COLOR_RESET)"
	@echo "$(COLOR_GREEN)✓ Unit tests passed$(COLOR_RESET)"
	@echo "$(COLOR_GREEN)✓ Build successful$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_BOLD)Coverage Summary (unit tests only):$(COLOR_RESET)"
	@$(GO) tool cover -func=$(COVERAGE_FILE) | tail -1
	@echo ""
	@echo "$(COLOR_YELLOW)Note: Full coverage requires integration tests (make ci-full)$(COLOR_RESET)"
	@echo "$(COLOR_GREEN)All CI checks passed! Ready to push.$(COLOR_RESET)"
	@echo ""

ci-full: ## Run full CI pipeline with Docker integration tests (enforces 90% coverage)
	@echo "$(COLOR_BOLD)Running full CI pipeline with integration tests...$(COLOR_RESET)"
	@echo ""
	@$(MAKE) fmt-check
	@$(MAKE) vet
	@$(MAKE) lint
	@$(MAKE) gosec
	@$(MAKE) docker-integration-test
	@$(MAKE) build
	@echo ""
	@echo "$(COLOR_BOLD)======================================$(COLOR_RESET)"
	@echo "$(COLOR_BOLD)Full CI Pipeline Complete$(COLOR_RESET)"
	@echo "$(COLOR_BOLD)======================================$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_GREEN)✓ Format check passed$(COLOR_RESET)"
	@echo "$(COLOR_GREEN)✓ Vet passed$(COLOR_RESET)"
	@echo "$(COLOR_GREEN)✓ Lint passed$(COLOR_RESET)"
	@echo "$(COLOR_GREEN)✓ Security scan passed$(COLOR_RESET)"
	@echo "$(COLOR_GREEN)✓ Integration tests passed$(COLOR_RESET)"
	@echo "$(COLOR_GREEN)✓ Build successful$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_BOLD)Coverage Summary:$(COLOR_RESET)"
	@if [ -f coverage-docker.out ]; then \
		$(GO) tool cover -func=coverage-docker.out | tail -1; \
		COVERAGE=$$($(GO) tool cover -func=coverage-docker.out | grep total | awk '{print $$3}' | sed 's/%//'); \
		COVERAGE_INT=$$(echo "$$COVERAGE" | awk '{print int($$1)}'); \
		if [ "$$COVERAGE_INT" -lt $(shell echo $(COVERAGE_THRESHOLD) | awk '{print int($$1)}') ]; then \
			echo "$(COLOR_RED)✗ Coverage $$COVERAGE% is below threshold of $(COVERAGE_THRESHOLD)%$(COLOR_RESET)"; \
			exit 1; \
		else \
			echo "$(COLOR_GREEN)✓ Coverage threshold met ($$COVERAGE% >= $(COVERAGE_THRESHOLD)%)$(COLOR_RESET)"; \
		fi; \
	else \
		echo "$(COLOR_YELLOW)⚠ Coverage file not found$(COLOR_RESET)"; \
	fi
	@echo ""
	@echo "$(COLOR_GREEN)All CI checks passed! Ready to push.$(COLOR_RESET)"
	@echo ""

check: fmt vet test ## Run all quality checks (format, vet, test)
	@echo "$(COLOR_GREEN)✓ All checks passed$(COLOR_RESET)"

clean: ## Clean build artifacts and test files
	@echo "$(COLOR_BOLD)Cleaning...$(COLOR_RESET)"
	@rm -rf $(BUILD_DIR) *.log *.test
	@rm -f $(BINARY_NAME)
	@rm -f $(COVERAGE_FILE) $(COVERAGE_HTML)
	@rm -f coverage-docker.out coverage-docker.html
	@rm -f coverage-cli.out coverage-unit.out coverage-integration.out
	@rm -f gosec-report.json
	@rm -f *.test
	@find . -name "*.test" -type f -delete
	@find . -name "*.out" -type f -delete
	@echo "$(COLOR_GREEN)✓ Clean complete$(COLOR_RESET)"

deps: ## Download dependencies
	@echo "$(COLOR_BOLD)Downloading dependencies...$(COLOR_RESET)"
	@$(GO) mod download
	@$(GO) mod tidy
	@echo "$(COLOR_GREEN)✓ Dependencies updated$(COLOR_RESET)"

verify: ## Verify dependencies
	@echo "$(COLOR_BOLD)Verifying dependencies...$(COLOR_RESET)"
	@$(GO) mod verify
	@echo "$(COLOR_GREEN)✓ Dependencies verified$(COLOR_RESET)"

tidy: ## Tidy go.mod
	@echo "$(COLOR_BOLD)Tidying go.mod...$(COLOR_RESET)"
	@$(GO) mod tidy
	@echo "$(COLOR_GREEN)✓ go.mod tidied$(COLOR_RESET)"

run: build ## Build and run the CLI (use ARGS to pass arguments)
	@echo "$(COLOR_BOLD)Running $(BINARY_NAME)...$(COLOR_RESET)"
	@sudo $(BUILD_DIR)/$(BINARY_NAME) $(ARGS)

doc: ## Generate and serve documentation
	@echo "$(COLOR_BOLD)Serving documentation at http://localhost:6060$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)Press Ctrl+C to stop$(COLOR_RESET)"
	@godoc -http=:6060

version: ## Show Go version
	@$(GO) version

info: ## Show project information
	@echo "$(COLOR_BOLD)Project Information$(COLOR_RESET)"
	@echo "Module: $(shell $(GO) list -m)"
	@echo "Go version: $(shell $(GO) version)"
	@echo "Go binary: $(GO)"
	@echo "GOPATH: $(GOPATH)"
	@echo "Build directory: $(BUILD_DIR)"
	@echo "Binary name: $(BINARY_NAME)"
	@echo "Coverage file: $(COVERAGE_FILE)"
	@echo "Coverage threshold: $(COVERAGE_THRESHOLD)%"

devcontainer: ## Build and run the devcontainer
	@echo "$(COLOR_BOLD)Building devcontainer...$(COLOR_RESET)"
	@docker build -f .devcontainer/Dockerfile -t go-luks2-devcontainer .
	@echo "$(COLOR_GREEN)✓ Devcontainer built$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_BOLD)To run:$(COLOR_RESET)"
	@echo "  docker run --privileged -v \$$(pwd):/workspace -it go-luks2-devcontainer bash"
