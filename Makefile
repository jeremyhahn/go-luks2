# Makefile for go-luks2
# LUKS2 encryption library and tools in pure Go

.PHONY: help build install test test-verbose test-coverage test-integration coverage clean fmt vet lint gosec govulncheck trivy-fs security ci ci-full fmt-check all check test-cli integration-test-pkg integration-test-cli docker-build-integration no-global-device-cleanup test-require-tool test-calibration no-internal-disclosure test-guards seccomp-diff integration-lock

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
# Version stamped into the binary, read from the VERSION file.
#
# Named BUILD_VERSION, not VERSION, and that is not cosmetic (#19). The release
# target takes the version as `make release-alpha VERSION=vX.Y.Z-alpha` and
# refuses to guess. A make variable also called VERSION SHADOWS that argument:
# measured on adoption, `make release-alpha` with no argument sailed past the
# "state the version explicitly" guard — REL_VERSION was never empty, it held
# this line's text — and died one guard later on a grammar error naming
# `$(shell cat VERSION ...)`. The guard written to give the clearest message
# was unreachable, which is the failure mode a fail-closed recipe is supposed
# not to have. Renaming the build variable frees the argument name.
BUILD_VERSION=$(shell cat VERSION 2>/dev/null | tr -d 'v' || echo "dev")
LDFLAGS=-ldflags "-X main.Version=$(BUILD_VERSION)"

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
	@echo "$(COLOR_BOLD)Building $(BINARY_NAME) v$(BUILD_VERSION)...$(COLOR_RESET)"
	@mkdir -p $(BUILD_DIR)
	@$(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)
	@echo "$(COLOR_GREEN)✓ Build complete: $(BUILD_DIR)/$(BINARY_NAME) (v$(BUILD_VERSION))$(COLOR_RESET)"

install: ## Install the CLI binary to $GOPATH/bin
	@echo "$(COLOR_BOLD)Installing $(BINARY_NAME) v$(BUILD_VERSION)...$(COLOR_RESET)"
	@$(GO) install $(LDFLAGS) ./$(CMD_DIR)
	@echo "$(COLOR_GREEN)✓ Installed to $(GOBIN)/$(BINARY_NAME) (v$(BUILD_VERSION))$(COLOR_RESET)"

# WHICH `|| true` IS A DEFECT, AND WHICH IS NOT (#97).
#
# `|| true` is not the defect by itself. The defect is `|| true` on a command
# WHOSE FAILURE IS THE SIGNAL YOU CAME FOR. Apply it per site rather than
# sweeping, because a sweep produces a rule nobody can apply to the next case:
#
#   go test          the failure IS the result           -> never suppress
#   a repo guard     the failure IS the result           -> never suppress
#   grep on an       exit 1 means "no lines matched",
#   optional file    which is not an error               -> suppressing is fine
#   docker rm -f     removing something already absent
#   of a container   is the goal state, not a failure    -> suppressing is fine
#
# So `|| true` survives deliberately below on the coverage-profile merges and
# on the docker container teardown, and it is gone from every `go test`. If you
# are adding one, the question is not "is this noisy" but "would I want to know
# if this failed".
#
# The `2>&1 | grep -v "no test files" || true` this used to end in made the
# target INCAPABLE OF FAILING, twice over: in a pipeline the exit status is
# grep's, so go test's failure was already lost, and `|| true` then discarded
# whatever was left. `make check` depends on this target, so a red suite
# reported green. The filter was also filtering nothing — every package `./...`
# returns under the default tag set has test files.
test: ## Run unit tests only (no I/O, no root required)
	@echo "$(COLOR_BOLD)Running unit tests only...$(COLOR_RESET)"
	@$(GO) test -v ./...
	@echo "$(COLOR_GREEN)✓ Unit tests complete$(COLOR_RESET)"

# The package list here is the same enumeration CI races, and it is ASSERTED
# against `go list ./...` before the tests run (#34): a third package added
# later would otherwise be raced by neither, silently. What this covers is the
# DEFAULT tag set only — integration-tagged code is not race-checked anywhere;
# the reasoning and the measurement that would change that are recorded at the
# race legs in .github/workflows/ci.yml, and the coverage statement is in
# README.md under Testing.
test-unit: ## Run only unit tests with coverage and the race detector (fast, no I/O, no root required)
	@./scripts/race-packages.sh ./pkg/luks2 ./cmd/luks2 ./test/harness ./test/harness/cmd/luks2-testreap
	@echo "$(COLOR_BOLD)Running unit tests with coverage...$(COLOR_RESET)"
	@$(GO) test -v -race -timeout 30m -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./pkg/luks2 ./cmd/luks2 ./test/harness ./test/harness/cmd/luks2-testreap
	@echo ""
	@echo "$(COLOR_BOLD)Coverage from unit tests:$(COLOR_RESET)"
	@$(GO) tool cover -func=$(COVERAGE_FILE) | tail -1

# The PBKDF2 calibration tests, deliberately WITHOUT -race.
#
# This is not a duplicate of test-unit and must not be folded into it. The
# defect these tests exist for (#52) is INVISIBLE under -race, and that is
# measured, not assumed: the old implementation gated its extrapolation on
# `elapsed.Milliseconds() > 0`, and race instrumentation slows the probe past
# 1ms, so the gate passes, the extrapolation runs, and the broken code returns a
# plausible, correctly-scaling iteration count. In an ordinary build the same
# code returns a hardcoded 100000 -- 25-100x under the requested work factor --
# on every pbkdf2 volume it formats.
#
# CI runs ./pkg/luks2 under -race only, which is how a critical weakening of
# every pbkdf2 keyslot survived five merges and three releases of green suites.
# The uninstrumented build is the one that ships; something has to run these
# assertions in it.
#
# No `|| true`: a calibration failure must fail the build. That used to be a
# distinction from test-unit; #86 removed the swallow there, so it is now simply
# the house rule rather than an exception to one.
CALIBRATION_TESTS := TestBenchmarkPBKDF2|TestCalibratePBKDF2|TestPBKDF2IterationFloor|TestScalePBKDF2Iterations|TestCreateKDFPBKDF2

test-calibration: ## Run the PBKDF2 calibration tests without -race (the mode the defect lives in)
	@echo "$(COLOR_BOLD)Running PBKDF2 calibration tests (no -race)...$(COLOR_RESET)"
	@$(GO) test -count=1 -timeout 10m -run '$(CALIBRATION_TESTS)' ./pkg/luks2
	@echo "$(COLOR_GREEN)✓ Calibration tests passed$(COLOR_RESET)"

test-cli: ## Run CLI unit tests only
	@echo "$(COLOR_BOLD)Running CLI unit tests...$(COLOR_RESET)"
	@$(GO) test -v -coverprofile=coverage-cli.out -covermode=atomic ./cmd/luks2
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

# ---- per-invocation docker names (#105) ----
#
# Docker names and image tags are unique PER HOST, not per invocation. Two
# concurrent `make integration-test` runs -- or one alongside a CI job, which
# shares the same daemon -- used the constant name `go-luks2-test-runner` and
# the constant tag `go-luks2-integration-test`, and collided two ways:
#
#   `docker rm -f` sends SIGKILL, so the second invocation's pre-run cleanup
#   killed the first one's RUNNING container mid-suite, exit 137. Reproduced
#   deterministically on one host with the old sequence: job A exit=137, job B
#   exit=0. The killed container took every loop device and device-mapper
#   mapping it held with it, because SIGKILL cannot be caught.
#
#   A shared image TAG is resolved at `docker run` time, so the second
#   invocation's build moved the tag between the first's build and its run --
#   and the first tested the second's tree. Measured. That failure is GREEN.
#
# ITEST_ID is computed ONCE (`?=` then flattened with `:=`) and exported, so
# every target in one invocation, including recursive `$(MAKE)` calls, agrees
# on the name while two invocations never do.
ITEST_ID ?= $(shell date +%s)-$(shell od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
ITEST_ID := $(ITEST_ID)
export ITEST_ID
ITEST_IMAGE := go-luks2-integration-test:$(ITEST_ID)
ITEST_CONTAINER := go-luks2-test-runner-$(ITEST_ID)

# Builds the integration image, handing the private-module credentials over as
# a BuildKit secret.
#
# go.mod pins github.com/jeremyhahn/go-enclave, whose module PATH says
# github.com while it is served from a private module host, so a bare
# `docker build` cannot resolve it: the container inherits none of this shell's
# git configuration.
#
# The staging file is written to a mktemp path OUTSIDE the build context, mode
# 0600, and removed on every exit path -- the Dockerfile ends with `COPY . .`,
# so a credentials file inside the tree would be baked into a layer.
#
# With no credentials in the environment the file is left empty and the build
# still runs: the Dockerfile's mount is optional, and modules then resolve from
# whatever proxy this machine can reach. That is the same shape CI uses on
# github.com. The four variables are git's standard GIT_CONFIG_* override set
# plus GOPRIVATE; export them to build against a private module host.
docker-build-integration:
	@set -eu; \
	umask 077; \
	stage="$$(mktemp -t gomodauth.XXXXXX)"; \
	trap 'rm -f "$$stage"' EXIT INT TERM; \
	if [ -n "$${GIT_CONFIG_KEY_0:-}" ]; then \
		{ \
			printf 'export GOPRIVATE=%s\n' "$${GOPRIVATE:-}"; \
			printf 'export GIT_CONFIG_COUNT=%s\n' "$${GIT_CONFIG_COUNT:-}"; \
			printf 'export GIT_CONFIG_KEY_0=%s\n' "$${GIT_CONFIG_KEY_0}"; \
			printf 'export GIT_CONFIG_VALUE_0=%s\n' "$${GIT_CONFIG_VALUE_0:-}"; \
		} > "$$stage"; \
		echo "$(COLOR_BOLD)Staged private module credentials for the image build$(COLOR_RESET)"; \
	else \
		echo "$(COLOR_BOLD)No private module credentials in the environment; resolving from the configured proxy$(COLOR_RESET)"; \
	fi; \
	DOCKER_BUILDKIT=1 docker build \
		--secret id=gomodauth,src="$$stage" \
		-f test/integration/Dockerfile \
		-t $(ITEST_IMAGE) .

integration-test: build ## Run all integration tests in Docker (isolated, recommended)
	@echo "$(COLOR_BOLD)Running all integration tests in Docker container...$(COLOR_RESET)"
	@$(MAKE) docker-integration-test

integration-test-pkg: build ## Run package integration tests in Docker
	@echo "$(COLOR_BOLD)Running package integration tests in Docker...$(COLOR_RESET)"
	@$(MAKE) docker-build-integration
	@# One shell with a trap: the per-invocation image tag is never reused, so
	@# if this target simply exits -- and it aborts on a failing suite -- the
	@# image is orphaned on the host forever.
	@set -eu; \
	trap 'docker image rm -f $(ITEST_IMAGE) >/dev/null 2>&1 || true' EXIT INT TERM; \
	flock "$(ITEST_LOCK)" \
	  env IMAGE="$(ITEST_IMAGE)" TEST_STATE_DIR="$(TEST_STATE_DIR)" \
	    $(INTEGRATION_DOCKER_RUN) --rm -- \
		go test -v -tags=integration ./test/integration/pkg/...

integration-test-cli: build ## Run CLI integration tests in Docker
	@echo "$(COLOR_BOLD)Running CLI integration tests in Docker...$(COLOR_RESET)"
	@$(MAKE) docker-build-integration
	@# One shell with a trap: the per-invocation image tag is never reused, so
	@# if this target simply exits -- and it aborts on a failing suite -- the
	@# image is orphaned on the host forever.
	@set -eu; \
	trap 'docker image rm -f $(ITEST_IMAGE) >/dev/null 2>&1 || true' EXIT INT TERM; \
	flock "$(ITEST_LOCK)" \
	  env IMAGE="$(ITEST_IMAGE)" TEST_STATE_DIR="$(TEST_STATE_DIR)" \
	    $(INTEGRATION_DOCKER_RUN) --rm -- \
		go test -v -tags=integration ./test/integration/cli/...

coverage: build ## Run all tests (unit + integration) with coverage (requires root)
	@echo "$(COLOR_BOLD)Running all tests (unit + integration) with coverage...$(COLOR_RESET)"
	@rm -f coverage-unit.out coverage-integration.out $(COVERAGE_FILE)
	@echo ""
	@echo "$(COLOR_BOLD)Step 1: Running unit tests with coverage...$(COLOR_RESET)"
	@$(GO) test -coverprofile=coverage-unit.out -covermode=atomic ./pkg/luks2 ./cmd/luks2 ./test/harness ./test/harness/cmd/luks2-testreap
	@echo ""
	@echo "$(COLOR_BOLD)Step 2: Running integration tests with coverage...$(COLOR_RESET)"
	@if [ "$$(id -u)" -eq 0 ]; then \
		flock "$(ITEST_LOCK)" $(GO) test -tags=integration -coverprofile=coverage-integration.out -covermode=atomic ./...; \
	else \
		flock "$(ITEST_LOCK)" sudo -E PATH="$(PATH)" $(GO) test -tags=integration -coverprofile=coverage-integration.out -covermode=atomic ./...; \
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
	@$(MAKE) docker-build-integration
	@echo ""
	@echo "$(COLOR_BOLD)Running integration tests in Docker container...$(COLOR_RESET)"
	@rm -f coverage-docker.out
	@# ONE shell with a trap, deliberately. Each recipe line is its own shell,
	@# so when the suite failed the following lines never ran: the container was
	@# left behind and the NEXT invocation's `docker rm -f` collected it -- the
	@# line that did the killing. The trap removes this invocation's container
	@# on every exit path, including failure, and by a name no other invocation
	@# can hold. There is no pre-run delete: with a unique name there is nothing
	@# of ours to clear, and a delete by any broader name is the race itself.
	@set -eu; \
	trap 'docker rm -f $(ITEST_CONTAINER) >/dev/null 2>&1 || true; \
	      docker image rm -f $(ITEST_IMAGE) >/dev/null 2>&1 || true' EXIT INT TERM; \
	rc=0; flock "$(ITEST_LOCK)" \
	  env IMAGE="$(ITEST_IMAGE)" TEST_STATE_DIR="$(TEST_STATE_DIR)" \
	    $(INTEGRATION_DOCKER_RUN) --name $(ITEST_CONTAINER) -- || rc=$$?; \
	if docker container inspect $(ITEST_CONTAINER) >/dev/null 2>&1; then \
		docker cp $(ITEST_CONTAINER):/app/coverage.out coverage-docker.out || \
			echo "$(COLOR_YELLOW)container exists but /app/coverage.out could not be copied$(COLOR_RESET)"; \
	fi; \
	exit $$rc
	@if [ -f coverage-docker.out ]; then \
		echo ""; \
		echo "$(COLOR_BOLD)Generating coverage report...$(COLOR_RESET)"; \
		$(GO) tool cover -html=coverage-docker.out -o coverage-docker.html 2>/dev/null || true; \
		echo "$(COLOR_GREEN)✓ Coverage report: coverage-docker.html$(COLOR_RESET)"; \
	fi
	@echo "$(COLOR_GREEN)✓ Docker integration tests complete$(COLOR_RESET)"

# TEST_STATE_DIR holds the run ledgers and is bind-mounted into the integration
# container. It lives on the HOST on purpose: the suite writes host dm mappings
# and loop devices, records each before creating it, and the next run removes
# what was recorded (#96). A record kept inside the container dies with the run
# whose state needs removing.
#
# Never clean this directory as a matter of routine. A ledger left behind means
# a run died, and deleting it discards the only record of what that run put on
# this machine.
#
# It is deliberately NOT created here. The reaper runs as root and acts on
# whatever the ledgers name, so the directory is part of the trust boundary and
# the harness refuses one owned by another user or writable by group or other.
# Docker creates a missing bind-mount source as root:root, which is what the
# harness accepts; `make host-integration-test` runs under sudo, so the harness
# creates it as root itself.
TEST_STATE_DIR ?= /var/tmp/go-luks2-test-state

# Every target that starts the integration container goes through this script,
# and none of them spells out a privilege flag. There used to be four `docker
# run --privileged` lines here and a fifth in the CI workflow; five copies of a
# security-critical invocation is how one of them quietly grows a flag the
# others do not have. The script carries the capabilities, the seccomp profile
# and the device scoping, with the measurement behind each one written beside
# it (#80).
INTEGRATION_DOCKER_RUN := test/integration/docker-run.sh

# test/integration/seccomp.json is Docker's own default profile with one block
# appended, and the value of that arrangement is entirely in being able to
# prove it. This target fetches the upstream profile through the Go module
# proxy -- so the checksum database vouches for it -- and prints the
# difference, which should be the two _comment blocks and the three syscall
# names and nothing else.
#
# The version is the one the LOCAL dockerd links, which the recipe reads out of
# the binary rather than trusting this variable; a mismatch is reported, not
# silently diffed against the wrong upstream.
SECCOMP_PROFILE := test/integration/seccomp.json
SECCOMP_UPSTREAM := github.com/moby/profiles/seccomp
SECCOMP_UPSTREAM_VERSION := v0.1.0

seccomp-diff: ## Diff the integration seccomp profile against Docker's default
	@linked=$$($(GO) version -m "$$(command -v dockerd)" 2>/dev/null \
		| awk '$$1 == "dep" && $$2 == "$(SECCOMP_UPSTREAM)" { print $$3 }'); \
	if [ -z "$$linked" ]; then \
		echo "$(COLOR_YELLOW)No dockerd on this host, or it carries no build info;$(COLOR_RESET)"; \
		echo "$(COLOR_YELLOW)diffing against the recorded $(SECCOMP_UPSTREAM_VERSION) instead.$(COLOR_RESET)"; \
	elif [ "$$linked" != "$(SECCOMP_UPSTREAM_VERSION)" ]; then \
		echo "$(COLOR_YELLOW)The local dockerd links $(SECCOMP_UPSTREAM) $$linked,$(COLOR_RESET)"; \
		echo "$(COLOR_YELLOW)not the $(SECCOMP_UPSTREAM_VERSION) this profile was taken from. The$(COLOR_RESET)"; \
		echo "$(COLOR_YELLOW)diff below is against $(SECCOMP_UPSTREAM_VERSION); rebase the profile if$(COLOR_RESET)"; \
		echo "$(COLOR_YELLOW)upstream has moved.$(COLOR_RESET)"; \
	fi; \
	dir=$$($(GO) mod download -json $(SECCOMP_UPSTREAM)@$(SECCOMP_UPSTREAM_VERSION) \
		| sed -n 's/.*"Dir": "\(.*\)".*/\1/p'); \
	if [ -z "$$dir" ]; then \
		echo "$(COLOR_RED)Could not fetch $(SECCOMP_UPSTREAM)@$(SECCOMP_UPSTREAM_VERSION)$(COLOR_RESET)"; \
		exit 1; \
	fi; \
	echo "$(COLOR_BOLD)Upstream: $$dir/default.json$(COLOR_RESET)"; \
	sha256sum "$$dir/default.json"; \
	echo ""; \
	diff -u "$$dir/default.json" $(SECCOMP_PROFILE) || true

# ITEST_LOCK serializes the PRIVILEGED suite across every job on this host.
#
# Per-invocation container and image names stop two jobs killing each other, but
# they do NOT isolate the loop-device pool, which is HOST-GLOBAL: a suite holds
# about five devices and the host provides eight, so two overlapping suites can
# need ten and one fails for a reason unrelated to the code under test. Unique
# names removed a collision and exposed a contention.
#
# NOT inside TEST_STATE_DIR. That directory is validated by the harness
# (test/harness/statedir.go checks its owner) because its ledgers authorize host
# device removal; a user-created directory is deliberately REFUSED, and a
# root-created 0755 one cannot be written by the invoking user. Either way a lock
# placed there breaks the suite or weakens the trust check. The lock lives beside
# it instead, on a path the runner user can create.
ITEST_LOCK ?= /var/tmp/go-luks2-itest-loopdev.lock


docker-test-specific: ## Run specific integration test in Docker (use TEST=TestName)
	@echo "$(COLOR_BOLD)Building Docker image...$(COLOR_RESET)"
	@$(MAKE) docker-build-integration
	@echo ""
	@echo "$(COLOR_BOLD)Running test: $(TEST)$(COLOR_RESET)"
	@# One shell with a trap: the per-invocation image tag is never reused, so
	@# if this target simply exits -- and it aborts on a failing suite -- the
	@# image is orphaned on the host forever.
	@set -eu; \
	trap 'docker image rm -f $(ITEST_IMAGE) >/dev/null 2>&1 || true' EXIT INT TERM; \
	flock "$(ITEST_LOCK)" \
	  env IMAGE="$(ITEST_IMAGE)" TEST_STATE_DIR="$(TEST_STATE_DIR)" \
	    $(INTEGRATION_DOCKER_RUN) --rm -- \
		go test -v -tags=integration -run="$(TEST)" ./...

host-integration-test: build ## Run integration tests on host (requires sudo, NOT recommended)
	@echo "$(COLOR_YELLOW)⚠ WARNING: Running integration tests on HOST system$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)  This requires root privileges and modifies the system.$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)  Recommended: use 'make integration-test' (runs in Docker)$(COLOR_RESET)"
	@echo ""
	@if [ "$$(id -u)" -eq 0 ]; then \
		flock "$(ITEST_LOCK)" $(GO) test -v -tags=integration ./...; \
	else \
		flock "$(ITEST_LOCK)" sudo -E PATH="$(PATH)" $(GO) test -v -tags=integration ./...; \
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

# vet compiles EVERY supported build-tag configuration, not just the default
# one (#43). The tag list is derived from the //go:build lines in the tree by
# scripts/build-tags.sh — see that file for why it is derived rather than
# written down, and for why non-linux is deliberately not a configuration.
#
# This is the same command CI runs, so the local check and the gate cannot
# diverge; `make ci` and `make check` both depend on this target, which is what
# catches a tag/symbol mismatch before a push rather than at the far end of the
# pipeline.
# REGRESSION GUARD (#17). A standing written rule against adding a second
# `losetup -D` call site already existed; there were then four. A doc-only rule
# was demonstrably not enough, so this is a check that runs.
no-global-device-cleanup: ## Refuse ownership-blind device teardown (losetup -D, dmsetup remove_all)
	@./scripts/no-global-device-cleanup.sh

# REGRESSION GUARD (#105). A fixed container name is the SIGKILL vector: two
# jobs on one runner share it, `docker rm -f` sends SIGKILL, and one job's
# teardown kills the other's running container mid-suite. `--self-test` feeds
# the guard input it must reject AND input it must not, because running it
# against a clean tree proves only that it can say yes.
integration-lock: ## Refuse a privileged integration entry point that skips the host lock
	@./scripts/integration-lock-guard.sh
	@./scripts/integration-lock-guard.sh --self-test

# PUBLIC-MIRROR GUARD (#20). This repository is mirrored publicly and releases
# publish a tree byte-identical to the internal tag, so every tracked file is a
# published file. #20 asserts a WHOLE-TREE property, and a whole-tree property
# stops holding the moment anything merges beneath it — it cannot be maintained
# by remembering to re-run a grep, so it fails a build instead.
no-internal-disclosure: ## Refuse internal infrastructure detail in a publicly mirrored repo
	@./scripts/no-internal-disclosure.sh

# Behavioural tests for both guards above. Running a guard against the current
# clean tree proves only that it can say yes; it proves nothing about the thing
# the guard is for, and a guard that has stopped detecting looks exactly like a
# clean repository. Every review round on these two found a fail-open path that
# a green clean-tree run reported as fine -- including one introduced BY a fix
# for an earlier finding. Each is a case in here now.
test-guards: ## Test the disclosure and device-teardown guards against fixtures
	@./scripts/guards-test.sh

# Six defects in one branch (#96) were one idea: "I could not find out" rendered
# as "it is fine". Review found each of them, at one per round, and only because
# the reviewer happened to look there. This is the same check, mechanically, on
# every run -- and it is self-testing, because a guard that cannot say both yes
# and no is the defect it exists to catch, one level up.
no-error-collapse: ## Refuse an error collapsed into a benign answer (self-tests itself first)
	@./scripts/error-collapse-guard.sh --self-test
	@./scripts/error-collapse-guard.sh

# The CI version gate's own tests. Run locally as well as in CI, because the
# comparison they cover shipped failing open once already: a substring test
# accepted v11.7.0 for a v1.7.0 pin. `--mutate` loosens the comparison back to
# that substring in a copy and asserts the near-miss cases go red, so the suite
# cannot quietly stop testing the property it names.
test-require-tool: ## Test the pinned-version gate (add MUTATE=1 to verify the tests themselves)
	@./scripts/require-tool-test.sh $(if $(MUTATE),--mutate,)

vet: ## Run go vet under every supported build-tag configuration
	@echo "$(COLOR_BOLD)Running go vet (every build-tag configuration)...$(COLOR_RESET)"
	@./scripts/build-tags.sh
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

# ---- the mandatory security-analysis suite ----
#
# `make security` IS the contract: CI runs this same target, so a finding here
# is the finding that blocks a merge, and there is no second set of flags in a
# workflow file that can drift away from this one. The suite is gosec,
# govulncheck, `go mod verify` and `trivy fs`, all blocking.
#
# gosec deliberately runs with NO -exclude rules. The findings this repository
# carries are suppressed at the exact line that produces them, each with a
# written reason (`#nosec G115 - max 4095` on the dev_t masks in unlock.go,
# `#nosec G204` on the fixed-argv blkid call in filesystem.go). A blanket
# -exclude would hide the next occurrence of the same rule somewhere it is not
# justified; a line annotation cannot.
#
# The tools are not installed by these targets: a make target must not mutate
# the developer's machine. A missing tool prints how to get it and the target
# skips; CI provides all four, so the gate is real where it matters.

# CI passes GOSEC_EXTRA="-fmt=sarif -out=gosec.sarif" so the SARIF it uploads
# to code scanning comes from the same flags a developer runs, not a second
# set that can drift.
GOSEC_EXTRA ?=

# THE WORKER-POOL BOUND, and why it is not noise (#22).
#
# gosec sizes its worker pool from runtime.NumCPU(). It ignores GOMAXPROCS and
# it ignores cgroup CPU limits, so inside a container capped at a fraction of
# the machine it still spawns one worker per HOST core and grows the heap until
# the cgroup kills it.
#
# An OOM kill exits 137, and a non-zero exit from gosec READS AS A SECURITY
# FINDING. Unbounded, a memory failure therefore presents as the security gate
# failing, and the next person spends their afternoon auditing code that was
# never the problem. That misreading — not the memory itself — is what this
# bound is defending against.
#
# The reason lives HERE, at the definition, because it previously lived only in
# the commit message that added the flag, which is not a place anyone opens
# while editing a Makefile. A constraint whose rationale is invisible reads as
# noise, and noise gets tidied away: removal of this exact flag has been
# proposed or staged three times across sibling repositories. Stating the
# mechanism rather than "do not remove" is deliberate — a bare prohibition
# invites someone to test it, and the mechanism is what survives.
GOSEC_CONCURRENCY ?= 4

gosec: ## Run gosec security scanner
	@echo "$(COLOR_BOLD)Running gosec security scanner...$(COLOR_RESET)"
	@GOSEC=$$(command -v gosec 2>/dev/null || echo "$(GOBIN)/gosec"); \
	if [ -x "$$GOSEC" ]; then \
		$$GOSEC -concurrency $(GOSEC_CONCURRENCY) -exclude-generated -severity medium -confidence medium $(GOSEC_EXTRA) ./... || exit 1; \
		echo "$(COLOR_GREEN)✓ Security scan passed$(COLOR_RESET)"; \
	else \
		echo "$(COLOR_YELLOW)⚠ gosec not installed, skipping...$(COLOR_RESET)"; \
		echo "  Install: go install -ldflags \"-X main.Version=$(GOSEC_VERSION)\" github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)"; \
		echo "  (pinned, and the -ldflags are REQUIRED: gosec reads its version"; \
		echo "   from ldflags, not the module path, so @$(GOSEC_VERSION) alone still"; \
		echo "   self-reports 'dev' and its findings cannot be attributed — #21)"; \
	fi

# TOOL PINS, shared with .github/workflows/ci.yml, which asserts that the
# binary it got self-reports these exact versions and refuses to scan otherwise
# (#21). An unpinned scanner self-updates underneath you: a new rule fires on
# code untouched for months, reddens whichever pull request runs next, accuses
# innocent work, and leaves nobody able to reproduce the previous green.
#
# gosec is the reason the pin alone is not the fix. It reads its version string
# from ldflags rather than from the module path, so `go install ...@v2.29.0`
# still produces a binary that says `dev` — which is exactly what `make
# security` used to print, and why its results could not be attributed to any
# scanner version. The install hints below carry the -X flag for that reason.
#
# These are also the versions baked into the CI runner image. Bumping one is a
# deliberate change, one issue per bump, made here and in the image together.
GOSEC_VERSION ?= v2.29.0
GOVULNCHECK_VERSION ?= v1.7.0

govulncheck: ## Run govulncheck (known vulns in stdlib and the dependency call graph)
	@echo "$(COLOR_BOLD)Running govulncheck...$(COLOR_RESET)"
	@GOVULN=$$(command -v govulncheck 2>/dev/null || echo "$(GOBIN)/govulncheck"); \
	if [ -x "$$GOVULN" ]; then \
		$$GOVULN ./... || exit 1; \
		echo "$(COLOR_GREEN)✓ govulncheck passed$(COLOR_RESET)"; \
	else \
		echo "$(COLOR_YELLOW)⚠ govulncheck not installed, skipping...$(COLOR_RESET)"; \
		echo "  Install: go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)"; \
	fi

trivy-fs: ## Scan the working tree with trivy (dependency CVEs and leaked secrets)
	@echo "$(COLOR_BOLD)Running trivy filesystem scan...$(COLOR_RESET)"
	@if command -v trivy >/dev/null 2>&1; then \
		trivy fs --scanners vuln,secret --severity CRITICAL,HIGH --exit-code 1 . || exit 1; \
		echo "$(COLOR_GREEN)✓ Trivy scan passed$(COLOR_RESET)"; \
	else \
		echo "$(COLOR_YELLOW)⚠ trivy not installed, skipping filesystem scan$(COLOR_RESET)"; \
		echo "  Install: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin"; \
		echo "  CI installs trivy unconditionally, so this scan still gates every push."; \
	fi

security: gosec govulncheck verify trivy-fs ## Run the full §8 security suite (gosec, govulncheck, go mod verify, trivy fs)
	@echo "$(COLOR_GREEN)✓ Security suite complete$(COLOR_RESET)"

ci: fmt-check vet integration-lock no-global-device-cleanup no-internal-disclosure no-error-collapse test-require-tool test-guards lint security test-unit test-calibration build ## Run CI pipeline locally (format, lint, security suite, unit tests, build)
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
	@$(MAKE) integration-lock
	@$(MAKE) no-global-device-cleanup
	@$(MAKE) no-internal-disclosure
	@$(MAKE) test-require-tool
	@$(MAKE) test-guards
	@$(MAKE) lint
	@$(MAKE) security
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
	@echo "$(COLOR_GREEN)✓ Security suite passed$(COLOR_RESET)"
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

check: fmt vet integration-lock no-global-device-cleanup no-internal-disclosure test-require-tool test-guards test ## Run all quality checks (format, vet, guards, test)
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
	@echo "  IMAGE=go-luks2-devcontainer $(INTEGRATION_DOCKER_RUN) \\"
	@echo "      --rm -it -v \$$(pwd):/workspace -- bash"
	@echo ""
	@echo "$(COLOR_YELLOW)  It used to say --privileged here. Going through the script gets the$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)  same scoped capabilities, seccomp profile and device access the$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)  integration suite runs under, so a shell you debug in behaves like$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)  the suite instead of like a machine with no restrictions (#80).$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_YELLOW)  Note: .devcontainer/devcontainer.json still carries --privileged and$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)  a bind mount of the host /dev, so opening this repo through the VS$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)  Code devcontainer is NOT the same thing. Tracked separately: a$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)  devcontainer.json cannot read the dm major out of /proc/devices, and$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)  a hard-coded one is wrong on the next machine.$(COLOR_RESET)"

# Builds never resolve through a workspace: cross-repository modules come from
# published TAGS, never from wherever a sibling repo happens to be checked out.
# Immunizes against a stray go.work file changing what gets built.
export GOWORK=off

# ---- dependency-resolution targets (2026-08-13 cutover) ----
# deps-latest runs before compiling in a consumer repo; release-alpha publishes
# this repo's next -alpha tag.
#
# SUBMODULE_TAGS is GONE with the old recipe (#19). It existed to tag nested
# modules in lockstep with the root, and it was always empty here: `find . -name
# go.mod` returns exactly one file, the root. An empty knob for a case this
# repository does not have is a thing to maintain and to misread, not a
# feature. A repo that grows a nested module adds its lockstep check back as a
# PREREQUISITE of release-alpha, where a failure aborts before the tag exists.
# deps-latest picks the highest tag INCLUDING -alpha prereleases — bare
# 'go get @latest' ignores prereleases and would downgrade to legacy v0.0.0.

# ---- release identity (#19) ----
#
# AGENT_GIT is the signing/identity wrapper every git WRITE below goes through.
# NO DEFAULT PATH IS BAKED IN, deliberately, and this is the one place this
# recipe diverges from the shared template: a hardcoded path publishes a login
# name, a private repository's name and a machine's directory layout from a
# repository that is mirrored publicly (#20). It resolves from PATH, or you set
# it; either way the guard below fails CLOSED before VERSION is written, so an
# unset AGENT_GIT can never produce an unsigned release.
AGENT_GIT ?= $(shell command -v agent-git.sh 2>/dev/null)

# The LITERAL repo name — never $(notdir $(CURDIR)). Deriving it from the
# directory derives the signing IDENTITY from the checkout, so a worktree or a
# CI workspace named anything else signs the release as the wrong agent
# (measured 2026-08-26: a directory named `mk` signed as `agent-mk`). Releases
# here are cut from git worktrees, whose directory names are chosen for the task
# rather than to match the repo, so that failure is not hypothetical.
REPO_NAME ?= go-luks2

# MEASURED for this repository on 2026-08-31: `git remote -v` shows exactly one
# remote, named `dev`. The shared template defaults this to `origin` on the
# grounds that no fleet repo has a `dev` remote — that claim does not hold
# here, which is precisely why it is a VARIABLE and not a constant. Overridable
# for a checkout that names its remote differently.
RELEASE_REMOTE ?= dev

# ---- release-alpha (template v2.3.5) ----
#
# Replaces a recipe that failed only when you looked at it. The old one:
#   1. auto-incremented PATCH only, so an API addition shipped labeled a bugfix
#      — and the version is the only signal a pinning consumer gets;
#   2. created LIGHTWEIGHT, UNSIGNED tags as whatever local git identity
#      happened to be configured, rather than this repo's agent principal;
#   3. `git push dev HEAD --tags` pushed EVERY local tag, not the one just cut;
#   4. `|| true` swallowed a failed VERSION commit and tagged anyway, producing
#      a tag whose VERSION file disagreed with its own name;
#   5. stamped no CHANGELOG.
# Failure 2 is the one that bites immediately: `main` requires signed commits,
# so the unsigned commit is REJECTED at push — after the tag already exists
# locally. Two releases had to be cut by hand because of it.
#
# The contract now:
#   - The version is EXPLICIT: `make release-alpha VERSION=v0.2.0-alpha`. No
#     auto-increment; whoever cuts the release decides patch/minor/major and
#     says so. The recipe refuses to guess.
#   - Every git write goes through AGENT_GIT (identity + SSH signing); the tag
#     is ANNOTATED and signed, not lightweight.
#   - Pushes ONLY the release commit and the named tag, atomically. Never --tags.
#   - Cut from `main` ONLY — `push <remote> HEAD` publishes whatever branch is
#     checked out, and this repo is developed on issue branches.
#   - Fail-closed end to end: no `|| true`. Every guard aborts BEFORE the tag
#     exists, because a published tag is immutable and cannot be retracted.
#   - The remote duplicate-tag check reads the EXIT CODE rather than negating
#     the command. `git ls-remote --exit-code` answers three things: 0 = the tag
#     exists, 2 = it does not, anything else (128 on an unreachable or
#     unauthenticated remote) = THE QUESTION WAS NEVER ANSWERED. Under `!` that
#     third case reads as "tag absent" and the check fails OPEN.
#   - The CHANGELOG guard matches the UNPREFIXED heading LITERALLY, anchored at
#     column 1, via an index-based awk predicate. A regex would treat the dots
#     of a version as wildcards and admit headings the release workflow does
#     not; a pre-flight check that is not identical to the thing it clears for
#     is not a check.
#   - Error messages are SINGLE-quoted where they carry no variable.
#     A double-quoted `echo` is a live command-substitution context, and error
#     strings are exactly what people edit casually — a backtick added there
#     runs at the moment a release is already failing.
#
# v2.3.3 SECURITY: every settable Make variable crosses into the recipe ONCE,
# via a target-specific export, and the body references only shell parameters
# ($$REL_*). Before that, $(VERSION) was expanded into recipe TEXT before the
# grammar guard ran, so `make release-alpha 'VERSION=v0.0.0-alpha`cmd`'`
# executed the backtick at the first guard line. Quoting is no boundary against
# a value that becomes recipe source. `$(value VERSION)` also stops the double
# evaluation the export would otherwise add.
# ADOPTER CHECK: `grep -P '(?<!\$)\$\((?!\()'` over the recipe BODY must be
# empty — no $(...) carrying a settable value below the export lines.
# KNOWN LIMIT, stated so nobody over-trusts this: a $(shell ...) FUNCTION typed
# into a `make VAR=...` command line runs during make's own variable expansion
# whether or not any rule names the variable. That is a property of invoking
# make, not of this recipe, and this recipe cannot close it.

.PHONY: release-alpha deps-latest

release-alpha: export REL_VERSION   := $(value VERSION)
release-alpha: export REL_REMOTE    := $(RELEASE_REMOTE)
release-alpha: export REL_REPO      := $(REPO_NAME)
release-alpha: export REL_AGENT_GIT := $(AGENT_GIT)
release-alpha:
	@test -n "$$REL_VERSION" || { echo 'ERROR: state the version explicitly: make release-alpha VERSION=vX.Y.Z-alpha (you decide patch/minor/major — the recipe refuses to guess)'; exit 1; }
	@printf '%s' "$$REL_VERSION" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-alpha$$' || { echo "ERROR: VERSION is not of the form vX.Y.Z-alpha (no leading zeroes): $$REL_VERSION"; exit 1; }
	@test "$$(git rev-parse --abbrev-ref HEAD)" = main || { echo "ERROR: releases are cut from main; you are on $$(git rev-parse --abbrev-ref HEAD). 'push $$REL_REMOTE HEAD' would publish this branch."; exit 1; }
	@test -n "$$REL_REPO" || { echo 'ERROR: REPO_NAME is empty — set it to the literal repo name, never $$(notdir $$(CURDIR))'; exit 1; }
	@test -x "$$REL_AGENT_GIT" || { echo 'ERROR: AGENT_GIT does not point at an executable agent-git.sh. Every git write below signs through it, and a bad path must fail HERE rather than at the first signed write, with a tag already cut. No default path is baked in (#20): put agent-git.sh on PATH, or run: make release-alpha AGENT_GIT=/path/to/agent-git.sh VERSION=vX.Y.Z-alpha'; exit 1; }
	@test -n "$$REL_REMOTE" || { echo 'ERROR: RELEASE_REMOTE is empty — set it to the git remote that serves this module'; exit 1; }
	@git remote get-url "$$REL_REMOTE" >/dev/null 2>&1 || { echo "ERROR: no git remote named $$REL_REMOTE. Set RELEASE_REMOTE; the duplicate-tag check below cannot answer against a remote that does not resolve"; exit 1; }
	@! git rev-parse -q --verify "refs/tags/$$REL_VERSION" >/dev/null || { echo "ERROR: tag $$REL_VERSION already exists locally"; exit 1; }
	@rc=0; git ls-remote --exit-code --tags "$$REL_REMOTE" "refs/tags/$$REL_VERSION" >/dev/null 2>&1 || rc=$$?; \
	case "$$rc" in \
	  0) echo "ERROR: tag $$REL_VERSION already exists on $$REL_REMOTE (a local check alone would miss this and fail the push AFTER committing VERSION)"; exit 1 ;; \
	  2) : ;; \
	  *) echo "ERROR: could not reach $$REL_REMOTE to check whether tag $$REL_VERSION exists. Refusing to continue: an unreachable remote is not an absent tag"; exit 1 ;; \
	esac
	@test -z "$$(git status --porcelain)" || { echo 'ERROR: working tree not clean'; exit 1; }
	@ver="## [$${REL_VERSION#v}]"; awk -v ver="$$ver" 'index($$0, ver) == 1 { f = 1 } END { exit f ? 0 : 1 }' CHANGELOG.md || { echo "ERROR: CHANGELOG.md has no \"$$ver\" section heading. Matched LITERALLY and anchored at the line start — an unanchored prose mention does not count, and neither does a near-miss heading"; exit 1; }
	@printf '%s\n' "$${REL_VERSION#v}" > VERSION
	"$$REL_AGENT_GIT" "$$REL_REPO" add VERSION
	"$$REL_AGENT_GIT" "$$REL_REPO" commit -m "chore(release): $$REL_VERSION"
	"$$REL_AGENT_GIT" "$$REL_REPO" tag -a "$$REL_VERSION" -m "$$REL_VERSION"
	"$$REL_AGENT_GIT" "$$REL_REPO" push --atomic "$$REL_REMOTE" HEAD "refs/tags/$$REL_VERSION"
	@echo "Released $$REL_VERSION (signed, annotated, single tag pushed)"

deps-latest:
	@GOWORK=off sh -c ' \
	SELF=$$(go list -m); \
	for m in $$(go list -m -f "{{if not .Indirect}}{{.Path}}{{end}}" all 2>/dev/null | grep "^github.com/jeremyhahn/" | grep -vx "$$SELF"); do \
	  case "$$(go list -m -f "{{if .Replace}}{{.Replace.Path}}{{end}}" "$$m" 2>/dev/null)" in .*|/*) continue;; esac; \
	  V=$$(go list -m -versions "$$m" 2>/dev/null | tr " " "\n" | tail -1); \
	  if [ -n "$$V" ] && [ "$$V" != "$$m" ]; then go get "$$m@$$V" || exit 1; fi; \
	done; go mod tidy'
