# Makefile for go-luks2
# LUKS2 encryption library and tools in pure Go

.PHONY: api-dump api-diff coverage-gate coverage-combined changelog-assemble help build build-linux vet-32bit install test test-verbose test-coverage test-integration coverage coverage-report clean fmt vet lint gosec govulncheck vuln trivy-fs trivy-install trivy-sarif trivy-misconfig security ci ci-full fmt-check all check test-cli docker-run-bin releasability integration-test-cli docker-build-integration docker-prune-itest print-itest-label test-calibration test-unit-norace seccomp-diff proto test-pkg docker-build docker-run deps-check toolchain-image docker-build-toolchain toolchain-run ci-toolchain-run ci-reap-stacks

# Default target
.DEFAULT_GOAL := help

# Variables
BINARY_NAME=luks2
BUILD_DIR=build
CMD_DIR=cmd/luks2
COVERAGE_FILE=coverage.out
COVERAGE_HTML=coverage.html
# The image `docker-build`/`docker-run` build and run: the CLI alone, from
# build/docker/cli, for someone who wants the tool without a devcontainer or
# the integration suite's test dependencies.
CLI_IMAGE ?= go-luks2-cli

# ---- the coverage gate (#141) ----
#
# COVERAGE_THRESHOLD is the bar testing-guidelines.md sets for EVERY package
# (project-scaffold.md 6). COVERAGE_FLOORS holds one floor per package per
# tier, and test/tools/covergate compares each package against its own floor in
# integer arithmetic -- never the aggregate, and never a rounded percentage.
# The gate also refuses a floors file that leaves a package unmeasured, names
# one that no longer exists, or holds a package to the target in no tier, so a
# floor cannot be lowered past the target without the gate saying so.
COVERAGE_THRESHOLD=90
COVERAGE_FLOORS=coverage-floors.txt
COVERAGE_GATE=$(GO) run ./test/tools/covergate -floors $(COVERAGE_FLOORS) -target $(COVERAGE_THRESHOLD)

# The unit tier's profiles, one per leg of test-unit. They are handed to the
# gate SEPARATELY rather than concatenated first: a leg that wrote no profile
# is an unreadable input and fails the gate, where the old `grep ... || true`
# merge dropped it and the total went UP. coverage.out is the merged copy kept
# for the HTML report and the CI artifact; nothing gates on it.
COVERAGE_LEG_PKG=coverage-pkg.out
COVERAGE_LEG_REST=coverage-rest.out
COVERAGE_UNIT_LEGS=$(COVERAGE_LEG_PKG) $(COVERAGE_LEG_REST)

# The combined tier, measured INSIDE the devcontainer (coverage-combined). The
# packages listed here have statements that only a real kernel executes --
# loop devices, device-mapper, mount(2), mkfs on a mapped device, dmsetup and
# losetup -- so their floor of record is the union of their unit profile and
# the integration suite's, which instruments them through -coverpkg.
COVERAGE_COMBINED_PKGS=./pkg/luks2 ./pkg/dmcrypt ./pkg/loop ./pkg/filesystem ./test/internal/harness ./internal/dm ./internal/keyring
COVERAGE_COMBINED_COVERPKG=./pkg/luks2,./pkg/dmcrypt,./pkg/loop,./pkg/filesystem,./test/internal/harness,./internal/dm,./internal/keyring
COVERAGE_COMBINED_UNIT=coverage-combined-unit.out
COVERAGE_INTEGRATION=coverage-integration.out

# ---- the unit-suite runtime budget (#92) ----
#
# Two numbers, and ci.yml reads both through `make test-unit` rather than
# restating them, so the workflow and a developer's run cannot drift apart:
#
#   UNIT_TEST_TIMEOUT  the CEILING: `go test -timeout`. A hang guard with
#                      headroom, and the only one of the two that fails a run.
#                      It used to be 300s, and a loaded runner killed healthy
#                      runs at exactly 5m0s (owner ruling on #92, 2026-09-28).
#   UNIT_TEST_TARGET   the BUDGET, in seconds, for `go test -race ./pkg/luks2`
#                      on the CI runner (p95 <= 240s). test-unit prints the
#                      measured time against it on every run, so drift is
#                      visible long before the ceiling is.
UNIT_TEST_TIMEOUT ?= 10m
UNIT_TEST_TARGET ?= 240
# Extra `go test` flags for the unit legs; CI passes -v.
UNIT_TEST_FLAGS ?=
# The race detector for the unit legs (#341). `-race` by default, which is the
# full tier's Race job and the run UNIT_TEST_TARGET budgets; test-unit-norace
# empties it for the PR tier's unit legs in CI's image job. Same legs, same
# profiles, same coverage gate -- only the instrumentation differs.
UNIT_TEST_RACE ?= -race
UNIT_TEST_MODE = $(if $(strip $(UNIT_TEST_RACE)),under -race,without -race)

# Simple expansion (:=), not recursive (=), and that is load-bearing (#205).
# GNU make 4.4 exports environment-origin variables into $(shell ...). GOPATH is
# in the environment on the build workers, so a recursive GO had to expand the
# redefined GOPATH first, whose own $(GO) was still empty there: the command
# became `env GOPATH`, and env printed "can't execute 'GOPATH'" to stderr on
# every make invocation. Harmless to the build, but it landed as the first line
# of every failing verification's output and got diagnosed as the failure twice.
# Evaluating both once, in order, keeps the `which` fallback that `sudo make`
# relies on while leaving nothing for a later GOPATH expansion to re-enter.
# GOPATH is asked only of a go that exists: a CI job container that only hands
# a target to the toolchain image has none, and make printed "No such file or
# directory" for the fallback on every such step.
GO := $(shell which go 2>/dev/null || echo /usr/local/go/bin/go)
GOPATH := $(if $(wildcard $(GO)),$(shell $(GO) env GOPATH))
GOBIN=$(GOPATH)/bin
# Version stamped into the binary, read from the VERSION file.
#
# Named BUILD_VERSION, not VERSION, and that is not cosmetic (#19). The release
# targets take the version as `make release-candidate VERSION=vX.Y.Z-rc.N` or
# `make release VERSION=vX.Y.Z` and refuse to guess; `make release-alpha` derives
# it when VERSION is omitted and accepts `VERSION=vX.Y.Z-alpha` as an override.
# A make variable also called VERSION SHADOWS that argument: measured on
# adoption, `make release-alpha` with no argument sailed past the "state the
# version explicitly" guard — REL_VERSION was never empty, it held this line's
# text — and died one guard later on a grammar error naming
# `$(shell cat VERSION ...)`. The guard written to give the clearest message
# was unreachable, which is the failure mode a fail-closed recipe is supposed
# not to have. Renaming the build variable frees the argument name, and it is
# what lets release-alpha tell "VERSION omitted" from "VERSION set" at all.
BUILD_VERSION=$(shell cat VERSION 2>/dev/null | tr -d 'v' || echo "dev")
LDFLAGS=-ldflags "-X main.version=$(BUILD_VERSION)"

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
	@echo "  make test-kdf           # Unit tests for one package by name (PKG_NAMES)"
	@echo "  make coverage-kdf       # Coverage for one package by name"
	@echo "  make bench-kdf          # Benchmarks for one package by name"
	@echo "  make integration-test-luks2  # Integration tests for one package by name"
	@echo ""

all: clean fmt vet test build ## Run all checks and build

build: ## Build the CLI binary
	@echo "$(COLOR_BOLD)Building $(BINARY_NAME) v$(BUILD_VERSION)...$(COLOR_RESET)"
	@mkdir -p $(BUILD_DIR)
	@$(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)
	@echo "$(COLOR_GREEN)✓ Build complete: $(BUILD_DIR)/$(BINARY_NAME) (v$(BUILD_VERSION))$(COLOR_RESET)"
	@echo "$(COLOR_BOLD)Cross-compiling pkg/luks2 and pkg/keyprovider for darwin (both must build off Linux)...$(COLOR_RESET)"
	@GOOS=darwin GOARCH=amd64 $(GO) build ./pkg/luks2 ./pkg/keyprovider
	@GOOS=darwin GOARCH=arm64 $(GO) build ./pkg/luks2 ./pkg/keyprovider
	@echo "$(COLOR_GREEN)✓ darwin/amd64 and darwin/arm64 build$(COLOR_RESET)"

# The CLI for the 64-bit Linux targets, as CI's binaries artifact:
# luks-linux-<arch> at the checkout root, with -trimpath so no build path is
# embedded -- the way release.yml builds the binaries it publishes.
LINUX_ARCHES := amd64 arm64

build-linux: ## Build the CLI for linux/amd64 and linux/arm64 (luks-linux-<arch>, -trimpath)
	@set -e; for arch in $(LINUX_ARCHES); do \
		echo "$(COLOR_BOLD)Building luks-linux-$$arch...$(COLOR_RESET)"; \
		GOOS=linux GOARCH=$$arch $(GO) build -trimpath -o luks-linux-$$arch ./$(CMD_DIR); \
	done
	@echo "$(COLOR_GREEN)✓ luks-linux-amd64 and luks-linux-arm64 built$(COLOR_RESET)"

# 32-BIT TARGETS, COMPILE ONLY. Every other build here is 64-bit, so nothing
# compiled for a platform where `int` is 32 bits -- and a guard added in #112
# to bound a uint32 conversion did not build on 386 or arm, while building fine
# on amd64. The PACKAGES are what matter, not just the CLI: the defect was in
# pkg/luks2.
#
# `go vet`, NOT `go build`, and that distinction is the target. go build does
# not compile TEST files, so the first version of this check was structurally
# unable to see the next four defects of the class, all in tests. vet
# type-checks them without running them; the suite cannot run on a foreign
# architecture anyway, and running it under emulation would test qemu as much
# as the code. vet reports ONE error per package, so fixing a site reveals the
# next: re-run after each fix rather than assuming the first message is the
# whole list.
VET_32BIT_ARCHES := 386 arm

vet-32bit: ## go vet every package for linux/386 and linux/arm (32-bit int; compiles the tests)
	@set -e; for arch in $(VET_32BIT_ARCHES); do \
		echo "$(COLOR_BOLD)Vetting linux/$$arch (32-bit int, compiles tests)...$(COLOR_RESET)"; \
		GOOS=linux GOARCH=$$arch $(GO) vet ./...; \
	done
	@echo "$(COLOR_GREEN)✓ linux/386 and linux/arm vet clean$(COLOR_RESET)"

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
# So `|| true` survives deliberately below on the docker container teardown, and
# it is gone from every `go test`. It is gone from the coverage-profile merges
# too, which this table once listed as safe: a missing profile there is not "no
# lines matched", it is a package whose coverage nobody measured, and dropping
# it made the reported total go UP (#141). If you
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

# THE UNIT TIER, raced, in two legs: ./pkg/luks2 on its own, because its
# runtime is the one #92 budgets and it is timed here, then every other package
# `go list ./...` reports -- so a package added later is raced and measured
# without anyone remembering to list it (#34). What this covers is the DEFAULT
# tag set only; integration-tagged code runs in the devcontainer, without -race,
# and the reasoning is recorded at the race legs in .github/workflows/ci.yml (the Race job).
#
# -count=1, because a cached result would report a runtime of zero against the
# budget and a profile from some earlier tree.
#
# Raced by default; UNIT_TEST_RACE= (test-unit-norace) runs the same two legs
# uninstrumented. CI's PR tier runs that, and its full tier runs this one
# raced, against UNIT_TEST_TARGET (#341).
test-unit: ## Run only unit tests with coverage and the race detector (fast, no I/O, no root required)
	@echo "$(COLOR_BOLD)Running unit tests with coverage $(UNIT_TEST_MODE)...$(COLOR_RESET)"
	@rm -f $(COVERAGE_UNIT_LEGS) $(COVERAGE_FILE)
	@set -u; \
	start=$$(date +%s); rc=0; \
	$(GO) test $(UNIT_TEST_FLAGS) -count=1 $(UNIT_TEST_RACE) -timeout $(UNIT_TEST_TIMEOUT) -covermode=atomic \
		-coverprofile=$(COVERAGE_LEG_PKG) ./pkg/luks2 || rc=$$?; \
	elapsed=$$(( $$(date +%s) - start )); \
	echo "pkg/luks2 $(UNIT_TEST_MODE) took $${elapsed}s: target $(UNIT_TEST_TARGET)s (UNIT_TEST_TARGET), ceiling $(UNIT_TEST_TIMEOUT) (UNIT_TEST_TIMEOUT)"; \
	if [ "$$elapsed" -gt "$(UNIT_TEST_TARGET)" ]; then \
		echo "::warning::pkg/luks2 $(UNIT_TEST_MODE) took $${elapsed}s, over its $(UNIT_TEST_TARGET)s budget (#92). Profile it with go test -json -race and move the slowest setup onto shared fixtures; do not raise the budget."; \
	fi; \
	exit $$rc
	@pkgs=$$($(GO) list ./... | grep -vx 'github.com/jeremyhahn/go-luks2/pkg/luks2') && test -n "$$pkgs" || \
		{ echo "$(COLOR_RED)go list named no package besides pkg/luks2$(COLOR_RESET)"; exit 1; }; \
	$(GO) test $(UNIT_TEST_FLAGS) -count=1 $(UNIT_TEST_RACE) -timeout $(UNIT_TEST_TIMEOUT) -covermode=atomic \
		-coverprofile=$(COVERAGE_LEG_REST) $$pkgs
	@# The merged copy, for the report only. A missing leg is still an error
	@# here: a report computed over the legs that happened to write a profile
	@# is the number that used to go UP when a package went missing.
	@echo "mode: atomic" > $(COVERAGE_FILE)
	@for leg in $(COVERAGE_UNIT_LEGS); do \
		test -s "$$leg" || { echo "$(COLOR_RED)$$leg is missing or empty$(COLOR_RESET)"; exit 1; }; \
		sed '/^mode:/d' "$$leg" >> $(COVERAGE_FILE) || exit 1; \
	done
	@echo ""
	@echo "$(COLOR_BOLD)Coverage from unit tests (gated per package by coverage-gate):$(COLOR_RESET)"
	@$(GO) tool cover -func=$(COVERAGE_FILE) | tail -1

# The PR tier's unit run (#341): test-unit's legs, profiles and coverage report,
# without the race detector. Not a second command line -- the knob above is the
# only difference, so the two cannot drift. The race run is the full tier's.
test-unit-norace: ## Run the unit tests with coverage but without -race (CI's PR tier)
	@$(MAKE) --no-print-directory test-unit UNIT_TEST_RACE=

# The public-releasability gate (#211) over THIS checkout's git index: no fleet
# address, hostname or owner path in a tracked file, and no tracked file the
# public release must not carry. It is a command rather than a test because it
# needs the git index, and the package tests also run where there is none --
# the integration image excludes .git/ and runs `go test ./...`. Without a
# checkout it fails; it never reports a tree it could not list as clean.
releasability: ## Run the public-releasability gate over the tracked tree (needs a git checkout)
	@$(GO) run ./test/tools/releasability-gate .

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
#
# The real-time checks live here too (#233). The calibration arithmetic, the
# waits and their bounds are unit-tested on injected rates and clocks, which no
# host load can move; what only the real machine can answer -- that a real
# calibration costs about its budget, that the system clock is the time
# package's -- is in BENCHMARKS, which the ordinary unit suite never runs.
# This target runs each once, and a failure fails the build.
CALIBRATION_TESTS := TestBenchmarkPBKDF2|TestCalibratePBKDF2|TestPBKDF2IterationFloor|TestScalePBKDF2Iterations|TestCreateKDFPBKDF2|TestDigestCalibration
CALIBRATION_BENCHMARKS := BenchmarkDigestCalibrationCostsItsBudget|BenchmarkPBKDF2CalibrationCostsItsBudget

test-calibration: ## Run the PBKDF2 calibration tests without -race (the mode the defect lives in)
	@echo "$(COLOR_BOLD)Running PBKDF2 calibration tests (no -race)...$(COLOR_RESET)"
	@$(GO) test -count=1 -timeout 10m -run '$(CALIBRATION_TESTS)' -bench '$(CALIBRATION_BENCHMARKS)' -benchtime=1x ./pkg/luks2
	@$(GO) test -count=1 -timeout 10m -run '$(CALIBRATION_TESTS)' ./internal/kdf
	@echo "$(COLOR_GREEN)✓ Calibration tests passed$(COLOR_RESET)"

test-cli: ## Run CLI unit tests only
	@echo "$(COLOR_BOLD)Running unit tests for ./internal/cli ./cmd/luks2 (cli)...$(COLOR_RESET)"
	@$(GO) test -v -race -count=1 ./internal/cli ./cmd/luks2

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
#
# The two derived names use the SAME shape, and that is the point (#146). They
# were `:=`, which OVERRIDES the environment instead of deferring to it. CI
# sets ITEST_IMAGE and ITEST_CONTAINER as job-level env and its `if: always()`
# cleanup removes exactly those two names; the moment a CI step calls a `make`
# integration target -- a change that looks safe -- make would ignore the job's
# values, build and run under names of its own, and the cleanup would delete
# names that were never created. Both halves succeed, nothing fails, and the
# real container keeps running on the host. That is #105's defect in a new
# place: cleanup keyed on a name that does not match the thing that exists.
#
# The *_ORIGIN captures must come BEFORE the assignments. The flattening `:=`
# rewrites a variable's origin to "file", which destroys the only answer to
# "did anyone outside this make name this image?" -- see ITEST_BUILD_IS_GOAL.
ITEST_ID_ORIGIN := $(origin ITEST_ID)
ITEST_IMAGE_ORIGIN := $(origin ITEST_IMAGE)
ITEST_ID ?= $(shell date +%s)-$(shell od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
ITEST_ID := $(ITEST_ID)
export ITEST_ID
ITEST_IMAGE ?= go-luks2-integration-test:$(ITEST_ID)
ITEST_IMAGE := $(ITEST_IMAGE)
export ITEST_IMAGE
ITEST_CONTAINER ?= go-luks2-test-runner-$(ITEST_ID)
ITEST_CONTAINER := $(ITEST_CONTAINER)
export ITEST_CONTAINER

# ---- bounding what the per-invocation tags leave behind (#146) ----
#
# Every image this repository builds for the integration suite carries this
# label. The label is the only handle that survives a kill -9: a trap runs on
# INT and TERM, SIGKILL cannot be caught, and an image orphaned that way is
# otherwise indistinguishable from any other image on the host.
ITEST_LABEL := go-luks2-itest=1

# The reap is scoped three ways and every one of them is load-bearing:
#
#   --filter label=   only images this repository built.
#   --all             our tags are unique per invocation, so an orphan is never
#                     dangling; without --all, prune skips every one of them.
#   --filter until=   an age floor. prune already skips an image that any
#                     container references, which covers a run whose suite is
#                     executing, but NOT the seconds between another run's
#                     `docker build` and its `docker run`. Deleting an image in
#                     that window fails that run with "Unable to find image
#                     locally", which is #105's race wearing a new hat. An
#                     hours-wide floor cannot land inside a seconds-wide
#                     window, and a labelled image built two hours ago that no
#                     container references is not a live run.
ITEST_PRUNE_AGE ?= 2h
ITEST_PRUNE := docker image prune --force --all \
  --filter label=$(ITEST_LABEL) --filter until=$(ITEST_PRUNE_AGE)

# `make docker-build-integration` with nothing after it builds an image NOTHING
# can consume: the next invocation computes a different ITEST_ID, so the tag it
# looks for is not this one. Before #105 the tag was constant and a rebuild
# replaced its predecessor, bounding the cost at one image; unique tags turned
# every standalone build into hundreds of MB kept forever. So a standalone
# build removes what it built. The BuildKit layer cache -- the only reason to
# pre-build at all -- is stored separately and survives that removal.
#
# "Standalone" is two conditions, and the second is the escape hatch: you name
# it, you own it.
#
#   MAKELEVEL 0     no consuming target delegated here. Their
#                   `$(MAKE) docker-build-integration` runs at level 1 and must
#                   leave the image for the run on the following line.
#   both undefined  make invented both names, so nothing outside this
#                   invocation can even spell them. Set ITEST_ID or ITEST_IMAGE
#                   in the environment and the image is yours: it is kept, and
#                   the same value makes it findable again. It still carries the
#                   label -- everything built here does, or the reaper would
#                   have holes exactly where the orphans are -- so an image kept
#                   this way and then left unused is collected once it passes
#                   ITEST_PRUNE_AGE. Raise that if you need it for longer.
ITEST_NAMES_ARE_OURS := $(if $(filter-out undefined,$(ITEST_ID_ORIGIN) $(ITEST_IMAGE_ORIGIN)),,yes)
ITEST_BUILD_IS_GOAL := $(if $(filter 0,$(MAKELEVEL)),$(ITEST_NAMES_ARE_OURS))

# The ONE image every CI stage runs in (devcontainer.md §1): its toolchain
# stage runs build, test, lint, security and deps-check, its integration stage
# runs the integration suite. There is no other CI image.
DEVCONTAINER_DOCKERFILE := build/docker/devcontainer/Dockerfile

# Stages the private-module credentials for an image build into "$$stage", a
# mktemp file the calling recipe hands to `docker build --secret`. One logical
# shell line (make joins the continuations), so it shares the recipe's shell
# and its EXIT trap; see docker-build-integration for why it is shaped so.
#
# MODULE_ENV_FILE names a credentials file the caller already wrote -- CI does,
# as KEY=value lines outside the checkout (ci.yml's image and integration
# jobs). It is used as it is and left for its writer to remove; a name that is
# not a file fails the build rather than quietly building without credentials.
MODULE_ENV_FILE ?=
GOMODAUTH_STAGE = umask 077; \
	if [ -n "$(MODULE_ENV_FILE)" ]; then \
		stage="$(MODULE_ENV_FILE)"; \
		if [ ! -f "$$stage" ]; then \
			echo "$(COLOR_RED)MODULE_ENV_FILE=$$stage is not a file$(COLOR_RESET)" >&2; \
			exit 1; \
		fi; \
		echo "$(COLOR_BOLD)Using private module credentials from MODULE_ENV_FILE$(COLOR_RESET)"; \
	else \
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
	fi

# Builds the integration image -- the integration stage of the devcontainer
# Dockerfile -- handing the private-module credentials over as a BuildKit
# secret.
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
	@# Reap first, so a build that later fails has still bounded the host. The
	@# reap's output is shown only when something was actually removed: an
	@# orphan means a run died here and that is worth reading, while "0B
	@# reclaimed" on every build is noise. If docker ever reworded that output
	@# the reap still happens and only the report goes quiet.
	@set -eu; \
	out="$$($(ITEST_PRUNE) 2>/dev/null || true)"; \
	case "$$out" in *Deleted*) printf '%s\n' "$$out";; esac; \
	$(GOMODAUTH_STAGE); \
	DOCKER_BUILDKIT=1 docker build \
		--secret id=gomodauth,src="$$stage" \
		--build-arg GO_BUILD_PROXY \
		--label $(ITEST_LABEL) \
		-f $(DEVCONTAINER_DOCKERFILE) --target integration \
		-t $(ITEST_IMAGE) .; \
	if [ -n "$(ITEST_BUILD_IS_GOAL)" ]; then \
		docker image rm -f $(ITEST_IMAGE) >/dev/null 2>&1 || true; \
		echo "$(COLOR_BOLD)Removed $(ITEST_IMAGE): a tag this invocation invented, which no later run can name.$(COLOR_RESET)"; \
		echo "$(COLOR_BOLD)The build cache is kept. Export ITEST_ID or ITEST_IMAGE to keep the image itself.$(COLOR_RESET)"; \
	fi

# The reaper on its own, for an operator who wants to run it directly. It is
# also the first thing every integration build does, so on any host that builds
# this suite at all, orphans are bounded whether or not anyone remembers this
# target exists.
#
# Reaping by label is what covers the cases no trap can: a run killed with
# SIGKILL, a runner that died with the job, and the window between a consuming
# target's build line and the next line that arms its trap. That window cannot
# be closed by moving the build into the trapped shell -- each recipe line is
# its own shell, and folding `$(MAKE) docker-build-integration` in was measured
# to break `make -n`, because make EXECUTES a recipe line containing $(MAKE)
# under -n and the dry run then started containers (#146). The label needs no
# window closed: it outlives the process that created the image.
docker-prune-itest: ## Remove orphaned integration images (label-scoped, age-bounded)
	@$(ITEST_PRUNE)

# The label, for the one other place that builds this image: ci.yml. Both the
# build that applies it and the prune that reaps by it have to spell it the
# same way or the reaper silently matches nothing -- cleanup keyed on a name
# that does not match the thing that exists, which is the defect this whole
# section descends from. So the workflow reads it from here rather than
# repeating the literal, the same reason the privilege flags live in
# test/tools/docker-run and not in five call sites. Deliberately
# undocumented in help: it is a seam for the workflow, not a target anyone runs.
print-itest-label:
	@echo $(ITEST_LABEL)

# THE INTEGRATION STAGE (ci-standard.md): the devcontainer's integration stage
# run as compose.yaml's `integration` service, here and in CI alike. The
# service carries test/tools/docker-run's privilege set and nothing more; the
# three values that set cannot spell statically are computed here:
#
#   GO_LUKS2_SECCOMP_PROFILE  the profile's absolute path. docker reads it on
#                             the client side, so it is this checkout's file.
#   GO_LUKS2_DM_MAJOR         device-mapper's major, from /proc/devices. It
#                             differs between machines; with none found the
#                             target fails rather than write an empty rule.
#   GO_LUKS2_TEST_STATE_DIR   TEST_STATE_DIR, or its root-ledger subdirectory
#                             when an ordinary user owns it -- the launcher's
#                             rule, see TEST_STATE_DIR below.
#
# The compose project is named per invocation (IT_PROJECT; CI passes one under
# the prefix ci-reap-stacks reaps). The container is kept until the coverage
# profile is copied out, with the same pass/fail rule as
# docker-integration-test: a container that passed without leaving a profile
# fails. The trap removes the container, the project and the image on every
# exit path.
#
# docker-integration-test, the launcher path, stays for the soak workflow.
DEVCONTAINER_COMPOSE := build/docker/devcontainer/compose.yaml
IT_PROJECT ?= go-luks2-it-$(ITEST_ID)
PROC_DEVICES ?= /proc/devices

integration-test: export GO_LUKS2_IT_IMAGE := $(ITEST_IMAGE)
integration-test: export GO_LUKS2_SECCOMP_PROFILE := $(CURDIR)/test/integration/seccomp.json
integration-test: ## Run all integration tests in the devcontainer's integration stage (compose)
	@echo "$(COLOR_BOLD)Building the integration image...$(COLOR_RESET)"
	@$(MAKE) --no-print-directory docker-build-integration
	@echo "$(COLOR_BOLD)Running the integration suite under compose (project $(IT_PROJECT))...$(COLOR_RESET)"
	@rm -f $(COVERAGE_INTEGRATION)
	@set -eu; \
	trap 'docker rm -f $(ITEST_CONTAINER) >/dev/null 2>&1 || true; \
	      docker compose -f $(DEVCONTAINER_COMPOSE) -p $(IT_PROJECT) down --volumes >/dev/null 2>&1 || true; \
	      docker image rm -f $(ITEST_IMAGE) >/dev/null 2>&1 || true' EXIT INT TERM; \
	GO_LUKS2_DM_MAJOR="$$(awk '$$2 == "device-mapper" { print $$1 }' $(PROC_DEVICES))"; \
	if [ -z "$$GO_LUKS2_DM_MAJOR" ]; then \
		echo "$(COLOR_RED)no device-mapper line in $(PROC_DEVICES): load dm_mod on this host$(COLOR_RESET)" >&2; \
		exit 1; \
	fi; \
	GO_LUKS2_TEST_STATE_DIR="$(TEST_STATE_DIR)"; \
	if [ -d "$$GO_LUKS2_TEST_STATE_DIR" ] && [ "$$(stat -c %u "$$GO_LUKS2_TEST_STATE_DIR")" != 0 ]; then \
		GO_LUKS2_TEST_STATE_DIR="$$GO_LUKS2_TEST_STATE_DIR/root-ledger"; \
	fi; \
	export GO_LUKS2_DM_MAJOR GO_LUKS2_TEST_STATE_DIR; \
	rc=0; \
	docker compose -f $(DEVCONTAINER_COMPOSE) -p $(IT_PROJECT) run --name $(ITEST_CONTAINER) integration || rc=$$?; \
	if [ "$$rc" -eq 0 ]; then \
		if ! docker cp $(ITEST_CONTAINER):/app/$(COVERAGE_INTEGRATION) $(COVERAGE_INTEGRATION) || \
		   ! test -s $(COVERAGE_INTEGRATION); then \
			echo "$(COLOR_RED)the container passed and left no /app/$(COVERAGE_INTEGRATION)$(COLOR_RESET)"; \
			exit 1; \
		fi; \
	elif docker container inspect $(ITEST_CONTAINER) >/dev/null 2>&1; then \
		docker cp $(ITEST_CONTAINER):/app/$(COVERAGE_INTEGRATION) $(COVERAGE_INTEGRATION) || true; \
	fi; \
	exit $$rc
	@echo "$(COLOR_GREEN)✓ Integration tests passed; profile in $(COVERAGE_INTEGRATION)$(COLOR_RESET)"

integration-test-cli: build docker-run-bin ## Run CLI integration tests in Docker
	@echo "$(COLOR_BOLD)Running CLI integration tests in Docker...$(COLOR_RESET)"
	@$(MAKE) docker-build-integration
	@# One shell with a trap: the per-invocation image tag is never reused, so
	@# if this target simply exits -- and it aborts on a failing suite -- the
	@# image is orphaned on the host forever.
	@set -eu; \
	trap 'docker image rm -f $(ITEST_IMAGE) >/dev/null 2>&1 || true' EXIT INT TERM; \
	  env IMAGE="$(ITEST_IMAGE)" TEST_STATE_DIR="$(TEST_STATE_DIR)" \
	    $(INTEGRATION_DOCKER_RUN) --rm -- \
		go test -v -tags=integration ./test/integration/cli/...

# THE COVERAGE GATE (#141). project-scaffold.md 6: "The `coverage` target
# enforces a hard threshold that fails the build, never a warning."
#
# It did not. COVERAGE_THRESHOLD was compared in exactly one target -- ci-full
# -- that ci.yml never invokes, while the workflow step that looked like the
# gate printed a number and exited 0; the merges ended in `|| true`, so a leg
# with no profile made the total go UP; and the one comparison there was
# truncated the percentage to an integer, so 89.9% passed a 90% bar.
#
# test/tools/covergate is the gate, and every caller reaches it through these
# targets: ci.yml's unit job runs `make coverage-gate`, the devcontainer's
# entrypoint runs `make coverage-combined`, so a developer's number is the
# number that blocks the merge. It is a Go program with its own tests rather
# than an awk pipeline, because a gate is only known to be a gate once it has
# been seen to fail, and its tests are where that is seen.

coverage-gate: ## Refuse unit coverage below any package's floor (reads test-unit's profiles)
	@$(COVERAGE_GATE) -tier unit $(foreach leg,$(COVERAGE_UNIT_LEGS),-profile $(leg)) $$($(GO) list ./...)

coverage: test-unit ## Measure unit coverage, gate it per package, and write the HTML report
	@$(MAKE) --no-print-directory coverage-gate
	@$(MAKE) --no-print-directory coverage-report

# coverage-report is coverage's own last two lines, split out so the report
# can be regenerated from an already-gated $(COVERAGE_FILE) -- e.g. right
# after `make coverage-gate` in CI -- without paying for `test-unit` again.
# It never gates: coverage-gate already did, over the SEPARATE per-leg
# profiles (#141); this only reads the merged copy test-unit leaves behind.
coverage-report: ## Print the func summary and write the HTML report from the already-gated profile
	@test -s $(COVERAGE_FILE) || { echo "$(COLOR_RED)✗ $(COVERAGE_FILE) is missing or empty; run 'make coverage-gate' (or 'make coverage') first$(COLOR_RESET)"; exit 1; }
	@$(GO) tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@$(GO) tool cover -func=$(COVERAGE_FILE) | tail -1
	@echo "$(COLOR_GREEN)✓ Coverage report: $(COVERAGE_HTML)$(COLOR_RESET)"

# The COMBINED tier: unit plus integration, for the packages whose remaining
# statements need a real kernel. It runs INSIDE the devcontainer -- it is the
# entrypoint's default command -- and never on a host (testing-guidelines.md).
# `make integration-test` / `make ci-full` / ci.yml's integration job all reach
# it through that entrypoint.
#
# Both suites are measured in the same container so the union is of two
# profiles of the same tree. The integration leg instruments the combined
# packages through -coverpkg, so each test/integration/<pkg> suite's calls
# into the library count toward its package, and dm/keyring's ledger and
# reaper use counts toward test/internal/harness -- whose own integration
# tests drive the reaper's removals against the real kernel. -p 1 keeps the
# integration packages from contending for loop devices at once. The unit
# leg is not raced: -race is the Race job's business, and this leg is here
# for its profile.
coverage-combined: ## (devcontainer only) Run the integration suite and gate unit+integration coverage
	@rm -f $(COVERAGE_INTEGRATION) $(COVERAGE_COMBINED_UNIT)
	@echo "$(COLOR_BOLD)Integration suite, instrumenting $(COVERAGE_COMBINED_COVERPKG)...$(COLOR_RESET)"
	@$(GO) test -v -count=1 -p 1 -tags=integration -timeout 30m -covermode=atomic \
		-coverpkg=$(COVERAGE_COMBINED_COVERPKG) -coverprofile=$(COVERAGE_INTEGRATION) \
		./test/internal/harness ./test/integration/cli/... \
		./test/integration/luks2/... ./test/integration/loop/... ./test/integration/wipe/... \
		./test/integration/dmcrypt/... ./test/integration/keyring/... ./test/integration/header/... \
		./test/integration/kdf/... ./test/integration/device/... ./test/integration/filesystem/... \
		./test/integration/interop/... ./pkg/luks2
	@echo "$(COLOR_BOLD)Unit suite for the combined packages...$(COLOR_RESET)"
	@$(GO) test -count=1 -timeout $(UNIT_TEST_TIMEOUT) -covermode=atomic \
		-coverprofile=$(COVERAGE_COMBINED_UNIT) $(COVERAGE_COMBINED_PKGS)
	@$(COVERAGE_GATE) -tier combined -profile $(COVERAGE_COMBINED_UNIT) -profile $(COVERAGE_INTEGRATION) $$($(GO) list ./...)

docker-integration-test: docker-run-bin ## Run integration tests in Docker (isolated, recommended)
	@echo "$(COLOR_BOLD)Building Docker image for integration tests...$(COLOR_RESET)"
	@$(MAKE) docker-build-integration
	@echo ""
	@echo "$(COLOR_BOLD)Running integration tests in Docker container...$(COLOR_RESET)"
	@rm -f $(COVERAGE_INTEGRATION) coverage-docker.out
	@# ONE shell with a trap, deliberately. Each recipe line is its own shell,
	@# so when the suite failed the following lines never ran: the container was
	@# left behind and the NEXT invocation's `docker rm -f` collected it -- the
	@# line that did the killing. The trap removes this invocation's container
	@# on every exit path, including failure, and by a name no other invocation
	@# can hold. There is no pre-run delete: with a unique name there is nothing
	@# of ours to clear, and a delete by any broader name is the race itself.
	@#
	@# The container's default command is `make coverage-combined`, so its exit
	@# status already carries the combined coverage gate. The profile is copied
	@# out for the report, and a container that PASSED without leaving one --
	@# or that can no longer be reached to copy it from -- is a failure (#141):
	@# it used to be a yellow line and a green run. A container that FAILED has
	@# already failed this target; its profile is copied only for diagnosis.
	@set -eu; \
	trap 'docker rm -f $(ITEST_CONTAINER) >/dev/null 2>&1 || true; \
	      docker image rm -f $(ITEST_IMAGE) >/dev/null 2>&1 || true' EXIT INT TERM; \
	rc=0; 	  env IMAGE="$(ITEST_IMAGE)" TEST_STATE_DIR="$(TEST_STATE_DIR)" \
	    $(INTEGRATION_DOCKER_RUN) --name $(ITEST_CONTAINER) -- || rc=$$?; \
	if [ "$$rc" -eq 0 ]; then \
		if ! docker cp $(ITEST_CONTAINER):/app/$(COVERAGE_INTEGRATION) $(COVERAGE_INTEGRATION) || \
		   ! test -s $(COVERAGE_INTEGRATION); then \
			echo "$(COLOR_RED)the container passed and left no /app/$(COVERAGE_INTEGRATION)$(COLOR_RESET)"; \
			exit 1; \
		fi; \
	elif docker container inspect $(ITEST_CONTAINER) >/dev/null 2>&1; then \
		docker cp $(ITEST_CONTAINER):/app/$(COVERAGE_INTEGRATION) $(COVERAGE_INTEGRATION); \
	fi; \
	exit $$rc
	@$(GO) tool cover -html=$(COVERAGE_INTEGRATION) -o coverage-integration.html
	@echo "$(COLOR_GREEN)✓ Integration coverage report: coverage-integration.html$(COLOR_RESET)"
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
#
# If the directory already exists and an ordinary user owns it -- because
# something ran as that user first -- the launcher (test/integration/cmd/
# docker-run) mounts its root-ledger subdirectory instead, which Docker creates
# as root. The harness still refuses a ledger directory a non-root user owns.
TEST_STATE_DIR ?= /var/tmp/go-luks2-test-state

# Every target that starts the integration container goes through this command,
# and none of them spells out a privilege flag. There used to be four `docker
# run --privileged` lines here and a fifth in the CI workflow; five copies of a
# security-critical invocation is how one of them quietly grows a flag the
# others do not have. The command carries the capabilities, the seccomp profile
# and the device scoping, with the measurement behind each one written beside
# it (#80), and a unit test pins the set flag by flag.
#
# It is Go rather than the shell script it replaces because the public release
# ships no shell scripts (#211). It execs docker in place, so docker's exit
# status and an interactive -it terminal reach the caller unchanged -- which
# holds only because the targets run the BUILT binary. Under `go run` the go
# tool stays as the parent process and reports any nonzero child status as 1,
# so docker's 125/126/127 would be lost. test/tools/docker-run's
# TestBinary_PropagatesDockersExitStatus pins this.
DOCKER_RUN_BIN := $(BUILD_DIR)/docker-run
INTEGRATION_DOCKER_RUN := $(DOCKER_RUN_BIN)

# Phony so an edit to the command is always picked up; `go build` is cached,
# so a rebuild with nothing changed costs next to nothing.
docker-run-bin: ## Build the integration container launcher (build/docker-run)
	@mkdir -p $(BUILD_DIR)
	@$(GO) build -o $(DOCKER_RUN_BIN) ./test/tools/docker-run

# ---- the CLI image ----
#
# build/docker/cli is the production image: the luks2 binary and the
# cryptsetup userspace tools it shells out to, nothing a developer or CI
# needs (no go toolchain, no lint/scan tools). It is built and run exactly
# like docker-build-integration/$(INTEGRATION_DOCKER_RUN) do, because the
# library needs the same device-mapper and loop access either way; see
# test/integration/cmd/docker-run for what that privilege set is and why.
docker-build: ## Build the CLI image from build/docker/cli
	@echo "$(COLOR_BOLD)Building $(CLI_IMAGE)...$(COLOR_RESET)"
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
	fi; \
	DOCKER_BUILDKIT=1 docker build \
		--secret id=gomodauth,src="$$stage" \
		-f build/docker/cli/Dockerfile \
		-t $(CLI_IMAGE) .
	@echo "$(COLOR_GREEN)✓ CLI image built: $(CLI_IMAGE)$(COLOR_RESET)"

docker-run: docker-build docker-run-bin ## Run the CLI image, with the integration seccomp profile and device scoping (ARGS="..." passes CLI args)
	@IMAGE=$(CLI_IMAGE) $(INTEGRATION_DOCKER_RUN) --rm -it -- $(ARGS)

# ---- the per-package quartet ----
#
# PKG_<name> maps a short name to its import path, one entry per pkg/ and
# internal/ package: every package `go list` finds there has a line, and a new
# package adds its own. PKG_NAMES lists every key so test-%,
# coverage-%, bench-% and integration-test-% below can resolve PKG_$* for
# ANY name without a second edit anywhere else: adding a package is exactly
# the two lines below, nothing in the pattern rules changes.
PKG_af          := ./internal/af
PKG_areacipher  := ./internal/areacipher
PKG_cli         := ./internal/cli
PKG_clock       := ./internal/clock
PKG_command     := ./internal/command
PKG_device      := ./internal/device
PKG_dm          := ./internal/dm
PKG_errs        := ./internal/errs
PKG_fips        := ./internal/fips
PKG_header      := ./internal/header
PKG_kdf         := ./internal/kdf
PKG_keyring     := ./internal/keyring
PKG_recoverykey := ./internal/recoverykey
PKG_secret      := ./internal/secret
PKG_volkey      := ./internal/volkey
PKG_dmcrypt     := ./pkg/dmcrypt
PKG_filesystem  := ./pkg/filesystem
PKG_keyprovider := ./pkg/keyprovider
PKG_loop        := ./pkg/loop
PKG_wipe        := ./pkg/wipe
PKG_luks2       := ./pkg/luks2
PKG_NAMES := af areacipher cli clock command device dm errs fips header kdf keyring recoverykey secret volkey dmcrypt filesystem keyprovider loop wipe luks2

test-%: ## Unit tests for one package by name, e.g. `make test-kdf` (see PKG_NAMES)
	@pkg="$(PKG_$*)"; test -n "$$pkg" || { echo "$(COLOR_RED)✗ no package mapped to '$*'; add PKG_$* to the Makefile$(COLOR_RESET)"; exit 1; }; \
	echo "$(COLOR_BOLD)Running unit tests for $$pkg ($*)...$(COLOR_RESET)"; \
	$(GO) test -v -race -count=1 "$$pkg"

# Named coverage-<name>.out rather than a shared file: running two of these
# back to back must not clobber each other's profile, unlike test-unit's
# fixed legs, which only ever run as a pair. `make clean` already removes
# every *.out file.
coverage-%: ## Coverage for one package by name, e.g. `make coverage-kdf` (writes coverage-<name>.out)
	@pkg="$(PKG_$*)"; test -n "$$pkg" || { echo "$(COLOR_RED)✗ no package mapped to '$*'; add PKG_$* to the Makefile$(COLOR_RESET)"; exit 1; }; \
	echo "$(COLOR_BOLD)Running coverage for $$pkg ($*)...$(COLOR_RESET)"; \
	$(GO) test -count=1 -covermode=atomic -coverprofile=coverage-$*.out "$$pkg" && \
	$(GO) tool cover -func=coverage-$*.out | tail -1

bench-%: ## Benchmarks for one package by name, e.g. `make bench-kdf` (a package with none exits clean)
	@pkg="$(PKG_$*)"; test -n "$$pkg" || { echo "$(COLOR_RED)✗ no package mapped to '$*'; add PKG_$* to the Makefile$(COLOR_RESET)"; exit 1; }; \
	echo "$(COLOR_BOLD)Running benchmarks for $$pkg ($*)...$(COLOR_RESET)"; \
	$(GO) test -run='^$$' -bench=. -benchmem "$$pkg"

# integration-test-% runs the per-package suite in test/integration/<name>/.
# A name with no directory yet exits clean rather than claiming a pass for a suite that does not exist: a
# silent no-op here is indistinguishable from "nothing to test" only if it
# is the TRUTH, not an assumption. No ITEST_DIR_<name> overrides remain --
# every mapped name's test directory now matches its own.

# ITEST_BUILD_IMAGE holds the recursive call, so the pattern rule below can
# reference it WITHOUT the literal text "$(MAKE)" appearing in its own
# recipe. That literal text is what GNU make scans a recipe line for to mark
# it "always run, even under -n" (the docker-prune-itest comment above
# explains why that exception exists and the #146 container it once started
# during a dry run). The whole point here is the OPPOSITE: the skip branch
# below must stay inert under -n, and it shares a shell with the build/run
# steps so an absent integration directory can `exit 0` before either of
# them -- which only works if they are ONE recipe line. Indirecting through
# this variable keeps that one line a plain command as far as the scan is
# concerned, confirmed by a throwaway Makefile: a recipe referencing a
# variable whose VALUE contains $(MAKE) is not force-run under -n; one that
# spells $(MAKE) directly, is.
ITEST_BUILD_IMAGE := $(MAKE) --no-print-directory docker-build-integration

integration-test-%: docker-run-bin ## Integration tests for one package by name, in the devcontainer (see ITEST_DIR_<name>)
	@pkg="$(PKG_$*)"; test -n "$$pkg" || { echo "$(COLOR_RED)✗ no package mapped to '$*'; add PKG_$* to the Makefile$(COLOR_RESET)"; exit 1; }; \
	dir="$(if $(ITEST_DIR_$*),$(ITEST_DIR_$*),$*)"; \
	if [ ! -d "test/integration/$$dir" ]; then \
		echo "$(COLOR_YELLOW)no integration suite yet for $$pkg ($*); nothing to run$(COLOR_RESET)"; \
		exit 0; \
	fi; \
	echo "$(COLOR_BOLD)Running the test/integration/$$dir suite for $$pkg ($*)...$(COLOR_RESET)"; \
	$(ITEST_BUILD_IMAGE); \
	set -eu; \
	trap 'docker image rm -f $(ITEST_IMAGE) >/dev/null 2>&1 || true' EXIT INT TERM; \
	env IMAGE="$(ITEST_IMAGE)" TEST_STATE_DIR="$(TEST_STATE_DIR)" \
		$(INTEGRATION_DOCKER_RUN) --rm -- \
		go test -v -tags=integration "./test/integration/$$dir/..."

test-pkg: ## Unit tests for one package by import path (make test-pkg PKG=./internal/kdf)
	@test -n "$(PKG)" || { echo "$(COLOR_RED)✗ state the package: make test-pkg PKG=./internal/kdf$(COLOR_RESET)"; exit 1; }
	@echo "$(COLOR_BOLD)Running unit tests for $(PKG)...$(COLOR_RESET)"
	@$(GO) test -v -race -count=1 $(PKG)

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

# No host lock. Every device-mapper name the suite creates carries the
# container's scope and the process's run id (test/internal/harness VolumeName), so
# concurrent runs cannot collide and nothing needs serializing (#178).
#
# The lock that used to live here was also inert in CI: the runner executes job
# steps inside a container, so a flock on a job-local path is private per job,
# while the loop pool and device-mapper namespace it protected are host-global.


docker-test-specific: docker-run-bin ## Run specific integration test in Docker (use TEST=TestName)
	@echo "$(COLOR_BOLD)Building Docker image...$(COLOR_RESET)"
	@$(MAKE) docker-build-integration
	@echo ""
	@echo "$(COLOR_BOLD)Running test: $(TEST)$(COLOR_RESET)"
	@# One shell with a trap: the per-invocation image tag is never reused, so
	@# if this target simply exits -- and it aborts on a failing suite -- the
	@# image is orphaned on the host forever.
	@set -eu; \
	trap 'docker image rm -f $(ITEST_IMAGE) >/dev/null 2>&1 || true' EXIT INT TERM; \
	  env IMAGE="$(ITEST_IMAGE)" TEST_STATE_DIR="$(TEST_STATE_DIR)" \
	    $(INTEGRATION_DOCKER_RUN) --rm -- \
		go test -v -tags=integration -run="$(TEST)" ./...

host-integration-test: build ## Run integration tests on host (requires sudo, NOT recommended)
	@echo "$(COLOR_YELLOW)⚠ WARNING: Running integration tests on HOST system$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)  This requires root privileges and modifies the system.$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)  Recommended: use 'make integration-test' (runs in Docker)$(COLOR_RESET)"
	@echo ""
	@if [ "$$(id -u)" -eq 0 ]; then \
		$(GO) test -v -tags=integration ./...; \
	else \
		sudo -E PATH="$(PATH)" $(GO) test -v -tags=integration ./...; \
	fi
	@echo "$(COLOR_GREEN)✓ Host integration tests complete$(COLOR_RESET)"

test-integration: integration-test ## Alias for integration-test

# ---- the exported-API record ----
#
# test/tools/apidump/baseline holds the API as released in 0.5.0-alpha and the
# redesign's disposition of every pkg/luks2 identifier. That the dispositions
# cover the baseline exactly is a unit test of the tool, so test-unit gates
# it. api-diff is the gate that every disposition is HONOURED: a KEEP
# identifier is still there, and every RENAME/MOVE/UNEXPORT/DELETE identifier
# is gone from the current API.
API_BASELINE=test/tools/apidump/baseline

api-dump: ## Print the exported API of pkg/luks2 and cmd/luks2
	@$(GO) run ./test/tools/apidump dump ./pkg/luks2
	@$(GO) run ./test/tools/apidump dump ./cmd/luks2

api-diff: ## Gate: the current pkg/luks2 API honors every disposition in baseline/disposition-luks2.tsv
	@$(GO) run ./test/tools/apidump honor $(API_BASELINE)/luks2.tsv $(API_BASELINE)/disposition-luks2.tsv ./pkg/luks2

bench: ## Run benchmarks
	@echo "$(COLOR_BOLD)Running benchmarks...$(COLOR_RESET)"
	@$(GO) test -bench=. -benchmem ./...

proto: ## No-op: this module has no .proto sources (scaffold §4 contract; Layer 0 library, docs/00 L1 exemption)
	@echo "no .proto sources (Layer 0 library)"

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

vet: ## Run go vet, including the integration build tag
	@echo "$(COLOR_BOLD)Running go vet...$(COLOR_RESET)"
	@$(GO) vet ./...
	@$(GO) vet -tags=integration ./...
	@echo "$(COLOR_GREEN)✓ Vet passed$(COLOR_RESET)"

# actionlint validates workflow syntax, expressions, shell steps and runner
# labels before CI parses them (devops.md, the `make lint` row). It is
# required, not skipped when absent: a lint that passes without running is the
# vacuous gate the testing convention forbids. Self-hosted runner labels go in
# .github/actionlint.yaml, read when the file exists; none of the workflows
# uses one today. A finding is fixed in the workflow, never silenced here.
# ACTIONLINT_VERSION is in the tool-pin file (TOOL PINS, below).
ACTIONLINT_CONFIG   = .github/actionlint.yaml

lint: export AL_CONFIG := $(ACTIONLINT_CONFIG)
lint: ## Run golangci-lint (if installed) and actionlint over .github/workflows
	@echo "$(COLOR_BOLD)Running golangci-lint...$(COLOR_RESET)"
	@LINTER=$$(command -v golangci-lint 2>/dev/null || echo "$(GOBIN)/golangci-lint"); \
	if [ -x "$$LINTER" ]; then \
		$$LINTER run ./... || exit 1; \
		echo "$(COLOR_GREEN)✓ Lint passed$(COLOR_RESET)"; \
	else \
		echo "$(COLOR_YELLOW)⚠ golangci-lint not installed, skipping...$(COLOR_RESET)"; \
		echo "  Install: go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)"; \
	fi
	@echo "$(COLOR_BOLD)Running actionlint...$(COLOR_RESET)"
	@AL=$$(command -v actionlint 2>/dev/null || echo "$(GOBIN)/actionlint"); \
	if [ ! -x "$$AL" ]; then \
		echo "$(COLOR_RED)✗ actionlint is not installed; the workflows were not checked$(COLOR_RESET)"; \
		echo "  Install: go install github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)"; \
		exit 1; \
	fi; \
	set -- .github/workflows/*.yml .github/workflows/*.yaml; \
	files=; for f in "$$@"; do [ -f "$$f" ] && files=1; done; \
	[ -n "$$files" ] || { echo "$(COLOR_RED)✗ no workflow files under .github/workflows$(COLOR_RESET)"; exit 1; }; \
	if [ -f "$$AL_CONFIG" ]; then \
		"$$AL" -config-file "$$AL_CONFIG" || exit 1; \
	else \
		"$$AL" || exit 1; \
	fi; \
	echo "$(COLOR_GREEN)✓ actionlint passed$(COLOR_RESET)"

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
# the developer's machine. A missing gosec or govulncheck prints how to get it
# and the target skips -- unless TOOLS_REQUIRED=1, which turns every skip into
# a failure. A missing trivy always fails, with the same hint (#296): a local
# trivy skip would read as a pass.
# Where each tool gates (#247):
#
#   the whole target, trivy fs included CI's image job, every push and pull
#                                       request: `make security` in the
#                                       toolchain image, which sets
#                                       TOOLS_REQUIRED=1, after ci.yml asserts
#                                       the image's gosec and govulncheck pins;
#                                       also every RELEASE
#   trivy fs alone                      the NIGHTLY workflow, dispatch-only
#
# The release runs this whole target with TOOLS_REQUIRED=1, so a release never
# publishes on a scan that skipped.
TOOLS_REQUIRED ?= 0
export TOOLS_REQUIRED

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
		if [ "$$TOOLS_REQUIRED" = 1 ]; then echo "$(COLOR_RED)✗ gosec is not installed and TOOLS_REQUIRED=1$(COLOR_RESET)"; exit 1; fi; \
		echo "$(COLOR_YELLOW)⚠ gosec not installed, skipping...$(COLOR_RESET)"; \
		echo "  Install, the way the devcontainer image builds it:"; \
		echo "    d=\$$(mktemp -d) && cd \"\$$d\" && go mod init gosec-build &&"; \
		echo "    go get github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION) golang.org/x/tools@$(XTOOLS_VERSION) &&"; \
		echo "    go install -ldflags \"-X main.Version=$(GOSEC_VERSION)\" github.com/securego/gosec/v2/cmd/gosec"; \
		echo "  (a throwaway module, because the x/tools gosec's go.mod names cannot"; \
		echo "   read the export data this Go writes; and the -ldflags are REQUIRED:"; \
		echo "   gosec reads its version from ldflags, not the module path, so without"; \
		echo "   them it self-reports 'dev' and its findings cannot be attributed — #21)"; \
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
# The pins live in ONE file that the devcontainer image reads too
# (devcontainer.md §2), so the tools in the image are the tools named here and
# a bump is one edit, one issue per bump. It carries every tool pin: the three
# Go scanners, actionlint and trivy with its four SHA-256s.
TOOL_PINS := build/docker/devcontainer/tool-pins.env
include $(TOOL_PINS)

govulncheck: ## Run govulncheck (known vulns in stdlib and the dependency call graph)
	@echo "$(COLOR_BOLD)Running govulncheck...$(COLOR_RESET)"
	@GOVULN=$$(command -v govulncheck 2>/dev/null || echo "$(GOBIN)/govulncheck"); \
	if [ -x "$$GOVULN" ]; then \
		$$GOVULN ./... || exit 1; \
		echo "$(COLOR_GREEN)✓ govulncheck passed$(COLOR_RESET)"; \
	else \
		if [ "$$TOOLS_REQUIRED" = 1 ]; then echo "$(COLOR_RED)✗ govulncheck is not installed and TOOLS_REQUIRED=1$(COLOR_RESET)"; exit 1; fi; \
		echo "$(COLOR_YELLOW)⚠ govulncheck not installed, skipping...$(COLOR_RESET)"; \
		echo "  Install: go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)"; \
	fi

vuln: govulncheck ## Alias for govulncheck (scaffold §4 contract names it `vuln`)

# ---- trivy: a pinned release archive, verified before it is unpacked (#247) ----
#
# trivy is not in the runner image, so the nightly workflow and the release
# install it with `make trivy-install`; the devcontainer's toolchain image runs
# the same target at build time, which is the trivy CI's image job uses. That
# replaced `curl .../contrib/install.sh
# from main | sh`: an unreviewed script from a moving branch, run as the build
# user, which then fetched whatever trivy was newest.
#
# Four SHA-256s, raised together or not at all: the archive per architecture,
# checked BEFORE anything is unpacked, and the binary inside it, checked after
# unpacking and again before an installed copy is reused. The archive hashes
# match upstream's trivy_0.75.0_checksums.txt; the binary hashes are go-enclave's
# pins for the same release. Never a checksum file fetched next to the archive:
# whoever can replace the archive can replace that file too.
#
# The binary lands in build/tools, inside the checkout, so the target does not
# touch anything outside the repository. TRIVY_VERSION and the four hashes are
# in the tool-pin file (TOOL PINS, above).
TRIVY_DOWNLOAD_BASE          ?= https://github.com/aquasecurity/trivy/releases/download
TOOLS_DIR                    ?= $(CURDIR)/$(BUILD_DIR)/tools
TRIVY_BIN                     = $(TOOLS_DIR)/trivy-$(TRIVY_VERSION)/trivy

# Values reach the recipe through the environment, never spliced into its
# shell source, so a TOOLS_DIR with a quote in it is a path and not a command.
trivy-install: export TI_VERSION     := $(TRIVY_VERSION)
trivy-install: export TI_SUM_AMD64   := $(TRIVY_SHA256_LINUX_AMD64)
trivy-install: export TI_SUM_ARM64   := $(TRIVY_SHA256_LINUX_ARM64)
trivy-install: export TI_BIN_AMD64   := $(TRIVY_BIN_SHA256_LINUX_AMD64)
trivy-install: export TI_BIN_ARM64   := $(TRIVY_BIN_SHA256_LINUX_ARM64)
trivy-install: export TI_BASE        := $(TRIVY_DOWNLOAD_BASE)
trivy-install: export TI_DEST        := $(TRIVY_BIN)
trivy-install: ## Install the pinned trivy into build/tools, verified by SHA-256
	@set -eu; \
	case "$$(uname -s)/$$(uname -m)" in \
	  Linux/x86_64|Linux/amd64)  arch=64bit; sum=$$TI_SUM_AMD64; binsum=$$TI_BIN_AMD64 ;; \
	  Linux/aarch64|Linux/arm64) arch=ARM64; sum=$$TI_SUM_ARM64; binsum=$$TI_BIN_ARM64 ;; \
	  *) echo "trivy-install: no pinned trivy for $$(uname -s)/$$(uname -m)"; exit 1 ;; \
	esac; \
	if [ -x "$$TI_DEST" ] && printf '%s  %s\n' "$$binsum" "$$TI_DEST" | sha256sum -c --status -; then \
		echo "$(COLOR_GREEN)✓ trivy $$TI_VERSION already installed: $$TI_DEST$(COLOR_RESET)"; exit 0; \
	fi; \
	tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	file="trivy_$${TI_VERSION#v}_Linux-$$arch.tar.gz"; \
	curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$$tmp/$$file" "$$TI_BASE/$$TI_VERSION/$$file"; \
	printf '%s  %s\n' "$$sum" "$$tmp/$$file" | sha256sum -c --quiet - || { \
		echo "$(COLOR_RED)✗ $$file does not match its pinned SHA-256; refusing to unpack it$(COLOR_RESET)"; exit 1; }; \
	tar -xzf "$$tmp/$$file" -C "$$tmp" trivy; \
	printf '%s  %s\n' "$$binsum" "$$tmp/trivy" | sha256sum -c --quiet - || { \
		echo "$(COLOR_RED)✗ the trivy binary in $$file does not match its pinned SHA-256$(COLOR_RESET)"; exit 1; }; \
	mkdir -p "$$(dirname "$$TI_DEST")"; \
	install -m 0755 "$$tmp/trivy" "$$TI_DEST"; \
	echo "$(COLOR_GREEN)✓ trivy $$TI_VERSION installed: $$TI_DEST$(COLOR_RESET)"

# The pinned binary from trivy-install when it is there, else a trivy on PATH.
# With neither, every trivy target FAILS with the install hint: a scan that
# skips is a gate that cannot fail, and `make security` passing without trivy
# would claim a scan that never ran (#296). TOOLS_REQUIRED does not soften it.
TRIVY_RESOLVE = TRIVY=$$TI_DEST; [ -x "$$TRIVY" ] || TRIVY=$$(command -v trivy 2>/dev/null || true); \
	if [ -z "$$TRIVY" ]; then \
		echo "$(COLOR_RED)✗ trivy is not installed; nothing was scanned$(COLOR_RESET)"; \
		echo "  Install: make trivy-install   (pinned $(TRIVY_VERSION), SHA-256 verified)"; \
		exit 1; \
	fi

# build/ is skipped: it holds the pinned trivy itself and the built CLI, and
# trivy reads the dependencies compiled into every Go binary it finds -- so it
# would report trivy's own dependencies as this module's.
trivy-fs: export TI_DEST := $(TRIVY_BIN)
trivy-fs: ## Scan the working tree with trivy (dependency CVEs and leaked secrets)
	@echo "$(COLOR_BOLD)Running trivy filesystem scan...$(COLOR_RESET)"
	@$(TRIVY_RESOLVE); \
	"$$TRIVY" fs --scanners vuln,secret --severity CRITICAL,HIGH --exit-code 1 --skip-dirs build . || exit 1; \
	echo "$(COLOR_GREEN)✓ Trivy scan passed$(COLOR_RESET)"

# The same scan as SARIF, for github.com's code-scanning upload (nightly only).
trivy-sarif: export TI_DEST := $(TRIVY_BIN)
trivy-sarif:
	@$(TRIVY_RESOLVE); \
	"$$TRIVY" fs --scanners vuln,secret --exit-code 0 --format sarif --output trivy-results.sarif --skip-dirs build .

# Misconfiguration scanning, ADVISORY: it reports and never fails on a finding.
trivy-misconfig: export TI_DEST := $(TRIVY_BIN)
trivy-misconfig:
	@$(TRIVY_RESOLVE); \
	"$$TRIVY" fs --scanners misconfig --exit-code 0 --format table --skip-dirs build .

security: gosec govulncheck verify trivy-fs ## Run the full §8 security suite (gosec, govulncheck, go mod verify, trivy fs)
	@echo "$(COLOR_GREEN)✓ Security suite complete$(COLOR_RESET)"

# The tests, the gate and the rest run IN ORDER, from the recipe, not as
# sibling prerequisites. Under `make -j` -- or a MAKEFLAGS a parent passes down
# -- siblings run concurrently, so the gate could read the profiles while
# test-unit was still deleting and rewriting them: a missing-input failure on a
# clean tree, or a pass on the previous run's profiles (#141 review).
ci: fmt-check vet lint security ## Run CI pipeline locally (format, lint, security suite, releasability gate, unit tests + coverage gate, build)
	@$(MAKE) --no-print-directory releasability
	@$(MAKE) --no-print-directory api-diff
	@$(MAKE) --no-print-directory test-unit
	@$(MAKE) --no-print-directory coverage-gate
	@$(MAKE) --no-print-directory test-calibration
	@$(MAKE) --no-print-directory build
	@echo ""
	@echo "$(COLOR_BOLD)======================================$(COLOR_RESET)"
	@echo "$(COLOR_BOLD)CI Pipeline Complete$(COLOR_RESET)"
	@echo "$(COLOR_BOLD)======================================$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_GREEN)✓ Format check passed$(COLOR_RESET)"
	@echo "$(COLOR_GREEN)✓ Vet passed$(COLOR_RESET)"
	@echo "$(COLOR_GREEN)✓ Lint passed$(COLOR_RESET)"
	@echo "$(COLOR_GREEN)✓ Security scan passed$(COLOR_RESET)"
	@echo "$(COLOR_GREEN)✓ API-diff gate passed (every disposition honored)$(COLOR_RESET)"
	@echo "$(COLOR_GREEN)✓ Unit tests passed$(COLOR_RESET)"
	@echo "$(COLOR_GREEN)✓ Unit coverage at or above every package floor$(COLOR_RESET)"
	@echo "$(COLOR_GREEN)✓ Build successful$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_YELLOW)The combined (unit + integration) floors are gated in the devcontainer: make ci-full$(COLOR_RESET)"
	@echo "$(COLOR_GREEN)All CI checks passed! Ready to push.$(COLOR_RESET)"
	@echo ""

# The full pipeline: everything `ci` runs, then the devcontainer, whose default
# command is coverage-combined -- so the combined floors are enforced by the
# container's own exit status. There is no coverage summary after it any more.
# The one that was here compared a truncated integer and, when the profile was
# missing, printed a warning and reported success (#141).
ci-full: ## Run the full CI pipeline, including the devcontainer integration suite and the combined coverage gate
	@echo "$(COLOR_BOLD)Running full CI pipeline with integration tests...$(COLOR_RESET)"
	@echo ""
	@$(MAKE) --no-print-directory ci
	@$(MAKE) --no-print-directory docker-integration-test
	@echo ""
	@echo "$(COLOR_GREEN)✓ Unit tier, integration suite and combined coverage gate passed$(COLOR_RESET)"
	@echo ""

check: fmt vet test ## Run all quality checks (format, vet, test)
	@echo "$(COLOR_GREEN)✓ All checks passed$(COLOR_RESET)"

clean: ## Clean build artifacts and test files
	@echo "$(COLOR_BOLD)Cleaning...$(COLOR_RESET)"
	@# $(BUILD_DIR)/docker holds TRACKED Dockerfiles (source), not
	@# build output -- the same reason .gitignore excludes it from "build/*".
	@# A plain `rm -rf $(BUILD_DIR)` would delete committed source from the
	@# working tree on every `make clean`, recoverable only via `git checkout`.
	@if [ -d $(BUILD_DIR) ]; then find $(BUILD_DIR) -mindepth 1 -maxdepth 1 ! -name docker -exec rm -rf {} +; fi
	@rm -f *.log *.test
	@rm -f $(BINARY_NAME)
	@rm -f $(COVERAGE_FILE) $(COVERAGE_HTML)
	@rm -f coverage-docker.out coverage-docker.html $(COVERAGE_INTEGRATION) $(COVERAGE_COMBINED_UNIT) coverage-integration.html $(COVERAGE_UNIT_LEGS)
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

# `go mod verify` checks only the modules already in the module cache, so on an
# empty cache it verifies nothing and passes. The download first fills the cache
# with every module the build needs, each checked against go.sum as it lands,
# or fails: where nothing can be fetched (GOPROXY=off) an empty cache is an
# error, never a pass.
verify: ## Verify dependencies
	@echo "$(COLOR_BOLD)Verifying dependencies...$(COLOR_RESET)"
	@$(GO) mod download
	@$(GO) mod verify
	@echo "$(COLOR_GREEN)✓ Dependencies verified$(COLOR_RESET)"

# deps-check (devops.md §4, §9): fails when any module go.mod requires, first-
# or third-party, direct or indirect, is behind its latest release with no
# reason written beside its require or replace line. A held-back module is a
# decision with its reason in go.mod, printed with the result; anything else
# is drift. test/tools/depscheck documents what "latest" means and why the
# check fails closed.
#
# It is the one target that must ask a module host, so it takes its proxy
# from DEPS_CHECK_GOPROXY when that is set (the toolchain image and the lane
# sandboxes run with GOPROXY=off) and otherwise from the environment.
# First-party modules resolve the way the build resolves them: GOPRIVATE and
# git's GIT_CONFIG_* rewrite to the internal module host. It installs nothing.
DEPS_CHECK_GOPROXY ?=
deps-check: export DC_GOPROXY := $(DEPS_CHECK_GOPROXY)
deps-check: ## Fail when a go.mod module is behind its latest release with no reason written beside it
	@echo "$(COLOR_BOLD)Checking every go.mod module against its latest release...$(COLOR_RESET)"
	@if [ -n "$$DC_GOPROXY" ]; then GOPROXY="$$DC_GOPROXY"; export GOPROXY; fi; \
	$(GO) run ./test/tools/depscheck || exit 1; \
	echo "$(COLOR_GREEN)✓ Every module is at its latest release or documents why not$(COLOR_RESET)"

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

# The devcontainer image: the toolchain stage under a fixed tag, which
# .devcontainer/devcontainer.json opens after running this target as its
# initializeCommand. The base stage's `go mod download` resolves the private
# module, so the build gets the same credentials staging and module proxy as
# docker-build-toolchain; a bare `docker build` dies on go-enclave.
DEVCONTAINER_IMAGE ?= go-luks2-devcontainer

devcontainer: ## Build and run the devcontainer
	@echo "$(COLOR_BOLD)Building devcontainer...$(COLOR_RESET)"
	@set -eu; \
	$(GOMODAUTH_STAGE); \
	DOCKER_BUILDKIT=1 docker build \
		--secret id=gomodauth,src="$$stage" \
		--build-arg GO_BUILD_PROXY \
		-f $(DEVCONTAINER_DOCKERFILE) --target toolchain \
		-t $(DEVCONTAINER_IMAGE) .
	@echo "$(COLOR_GREEN)✓ Devcontainer built$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_BOLD)To run:$(COLOR_RESET)"
	@echo "  make docker-run-bin && IMAGE=$(DEVCONTAINER_IMAGE) $(INTEGRATION_DOCKER_RUN) \\"
	@echo "      --rm -it -v \$$(pwd):/workspace -- bash"
	@echo ""
	@echo "$(COLOR_YELLOW)  It used to say --privileged here. Going through the command gets the$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)  same scoped capabilities, seccomp profile and device access the$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)  integration suite runs under, so a shell you debug in behaves like$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)  the suite instead of like a machine with no restrictions (#80).$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_YELLOW)  Note: .devcontainer/devcontainer.json still carries --privileged and$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)  a bind mount of the host /dev, so opening this repo through the VS$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)  Code devcontainer is NOT the same thing. Tracked separately: a$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)  devcontainer.json cannot read the dm major out of /proc/devices, and$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)  a hard-coded one is wrong on the next machine.$(COLOR_RESET)"

# ---- the toolchain image: where build, test, lint, security and deps-check run ----
#
# The devcontainer's toolchain stage, tagged by the hash of everything it is
# built from (devcontainer.md §6), so the same inputs name the same image and
# a changed pin, Dockerfile or go.sum names a new one. `make toolchain-image`
# prints the tag; CI uses it to build once and run every stage in it.
TOOLCHAIN_INPUTS := $(DEVCONTAINER_DOCKERFILE) $(TOOL_PINS) go.mod go.sum
TOOLCHAIN_IMAGE ?= go-luks2-toolchain:$(shell cat $(TOOLCHAIN_INPUTS) 2>/dev/null | sha256sum | cut -c1-16)

toolchain-image: ## Print the content-hashed tag of the toolchain image
	@echo $(TOOLCHAIN_IMAGE)

docker-build-toolchain: ## Build the toolchain image (the devcontainer's toolchain stage)
	@set -eu; \
	$(GOMODAUTH_STAGE); \
	DOCKER_BUILDKIT=1 docker build \
		--secret id=gomodauth,src="$$stage" \
		--build-arg GO_BUILD_PROXY \
		-f $(DEVCONTAINER_DOCKERFILE) --target toolchain \
		-t $(TOOLCHAIN_IMAGE) .

# Runs CMD in the toolchain image over this checkout, as the uid that owns it
# and with HOME=/tmp (devcontainer.md §5), so files it writes stay the
# developer's. CMD reaches the container through the environment, never
# spliced into this recipe's shell source. The proxy and credential variables
# are forwarded by NAME only (`-e VAR`): docker reads their values from this
# environment, so a token never appears on a command line. They matter only to
# deps-check; the image itself has GOPROXY=off. An empty CMD is refused before
# anything is built.
#
#   make toolchain-run CMD="make build test security deps-check releasability"
toolchain-run: export TR_CMD := $(CMD)
toolchain-run: export TR_IMAGE := $(TOOLCHAIN_IMAGE)
toolchain-run: ## Run CMD in the toolchain image (make toolchain-run CMD="make test")
	@test -n "$$TR_CMD" || { echo "$(COLOR_RED)✗ state the command: make toolchain-run CMD=\"make test\"$(COLOR_RESET)"; exit 1; }
	@$(MAKE) --no-print-directory docker-build-toolchain
	@docker run --rm \
		--user "$$(id -u):$$(id -g)" \
		-e HOME=/tmp \
		-e DEPS_CHECK_GOPROXY -e GOPRIVATE -e GONOSUMDB -e GONOPROXY \
		-e GIT_CONFIG_COUNT -e GIT_CONFIG_KEY_0 -e GIT_CONFIG_VALUE_0 \
		-e GOSEC_EXTRA \
		-v "$(CURDIR):/workspace" -w /workspace \
		"$$TR_IMAGE" bash -c "$$TR_CMD"

# ---- CI: the stages in the toolchain image, and what a dead job leaves ----
#
# Every name CI gives a container or a compose project starts with this prefix
# and nothing else this repository starts does, so ci-reap-stacks can never
# touch another project's stack. `override`: it is not a knob.
override CI_STACK_PREFIX := go-luks2-ci-

# How CI runs a stage in the toolchain image (ci-standard.md §2): the canonical
# workflow's in-toolchain-image script, as a recipe because the public release
# ships no shell scripts (#211). A runner reaches its daemon through a socket,
# so a bind mount -- toolchain-run's way -- would resolve on the daemon's host,
# where this checkout does not exist. This creates the container, streams the
# checkout in (.git included: the releasability tests read it) owned by the
# image's CI uid, starts it and returns CMD's exit status.
#
# The container drops every capability, sets no-new-privileges, bounds pids
# and ulimits (memlock leaves go-enclave its locked pages), and has no network.
# IN_IMAGE_NETWORK=bridge gives it one for the stages that must reach one --
# deps-check asks for the newest releases, security fetches the vulnerability
# databases -- and only then reopens GOPROXY, moves the module cache to a
# writable /tmp, and passes the module credentials by NAME, so no token is on a
# command line. CMD reaches docker as one argument, never spliced into this
# recipe's source. The container is removed on every exit.
#
# The reopened GOPROXY reads the image's own module cache first, as a file://
# proxy, so the modules a stage fetches are the ones baked and verified at
# build time, and `make verify` checks every one of them rather than an empty
# /tmp cache. The baked cache stays root's and read-only; the image build
# asserts its path. A module not baked falls through to the network. deps-check
# asks for the newest releases, which the baked cache cannot answer, so it is
# given the network proxy alone.
#
# GOPATH moves to /tmp too. The go command keeps the checksum database's cache
# in $GOPATH/pkg/sumdb, not in the module cache, and the image's GOPATH is
# root's /go, so every lookup a networked stage makes -- deps-check resolving
# the newest release of a public module -- failed to open it. The checksum
# database is still consulted and its answers still checked; only where they
# are cached moves. A run without a network keeps /go: it makes no lookup, and
# its module cache is the baked one under it.
#
#   make ci-toolchain-run CMD="make deps-check" IN_IMAGE_NETWORK=bridge
#
# CI_OUT names the files CMD writes under the checkout that the job needs back
# on the runner -- the gosec SARIF, the coverage profile, the release binaries
# -- relative to the checkout. Each is copied out after CMD exits, whatever its
# status, before the container is removed, so a failed scan still leaves its
# report for the upload. A file a passing CMD did not write fails the run: an
# artifact step that uploads nothing would read as one that uploaded it. They
# land at the same path under CI_OUT_DIR, the checkout unless a test says
# otherwise.
#
#   make ci-toolchain-run CMD="make build-linux" CI_OUT="luks-linux-amd64 luks-linux-arm64"
IN_IMAGE_NETWORK ?= none
CI_OUT ?=
CI_OUT_DIR ?= $(CURDIR)
CI_TOOLCHAIN_UID := 10001
IMAGE_GOMODCACHE := /go/pkg/mod
CI_NETWORK_GOPROXY := https://proxy.golang.org,direct

ci-toolchain-run: export TR_CMD := $(CMD)
ci-toolchain-run: export TR_IMAGE := $(TOOLCHAIN_IMAGE)
ci-toolchain-run: export TR_NETWORK := $(IN_IMAGE_NETWORK)
ci-toolchain-run: export TR_OUT := $(CI_OUT)
ci-toolchain-run: export TR_OUT_DIR := $(CI_OUT_DIR)
ci-toolchain-run: ## Run CMD in the toolchain image over a copy of the checkout (CI)
	@test -n "$$TR_CMD" || { echo "$(COLOR_RED)✗ state the command: make ci-toolchain-run CMD=\"make test\"$(COLOR_RESET)"; exit 2; }
	@set -eu; \
	case "$$TR_NETWORK" in \
		none|bridge) ;; \
		*) echo "$(COLOR_RED)IN_IMAGE_NETWORK must be none or bridge: $$TR_NETWORK$(COLOR_RESET)" >&2; exit 2 ;; \
	esac; \
	for f in $$TR_OUT; do \
		case "$$f" in \
			/*|..|../*|*/..|*/../*) echo "$(COLOR_RED)CI_OUT names a file under the checkout: $$f$(COLOR_RESET)" >&2; exit 2 ;; \
		esac; \
	done; \
	uid=$(CI_TOOLCHAIN_UID); \
	name="$(CI_STACK_PREFIX)tc-$$$$-$$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"; \
	set -- --name "$$name" --init --cap-drop ALL \
		--security-opt no-new-privileges:true --pids-limit 4096 \
		--ulimit memlock=67108864:67108864 --ulimit core=1048576:1048576 \
		--ulimit nofile=65536:65536 \
		--tmpfs /tmp:rw,exec,nosuid,nodev,size=3g,mode=1777 \
		--network "$$TR_NETWORK" --user "$$uid:$$uid" --workdir /src \
		--env HOME=/tmp --env CI="$${CI:-}"; \
	if [ "$$TR_NETWORK" = bridge ]; then \
		set -- "$$@" --env "GOPROXY=file://$(IMAGE_GOMODCACHE)/cache/download,$(CI_NETWORK_GOPROXY)" \
			--env "DEPS_CHECK_GOPROXY=$(CI_NETWORK_GOPROXY)" --env GOMODCACHE=/tmp/gomodcache \
			--env GOPATH=/tmp/gopath; \
		for v in GOPRIVATE GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0; do \
			eval "val=\$${$$v:-}"; \
			if [ -n "$$val" ]; then set -- "$$@" --env "$$v"; fi; \
		done; \
	fi; \
	trap 'docker rm -f -v "$$name" >/dev/null 2>&1 || true' EXIT INT TERM; \
	docker create "$$@" "$$TR_IMAGE" sh -c "$$TR_CMD" >/dev/null; \
	tar -C "$(CURDIR)" --owner="$$uid" --group="$$uid" --numeric-owner -cf - . | \
		docker cp -a - "$$name:/src"; \
	rc=0; docker start -a "$$name" || rc=$$?; \
	for f in $$TR_OUT; do \
		mkdir -p "$$(dirname "$$TR_OUT_DIR/$$f")"; \
		if ! docker cp "$$name:/src/$$f" "$$TR_OUT_DIR/$$f"; then \
			echo "$(COLOR_RED)✗ CI_OUT: the run left no $$f$(COLOR_RESET)" >&2; \
			[ "$$rc" -ne 0 ] || rc=1; \
		fi; \
	done; \
	exit "$$rc"

# The canonical workflow's stale-stack reaper (ci-template v1.18), as a recipe
# for the same reason. A job's `if: always()` teardown runs only while the job
# lives; when the runner or its daemon dies mid-job the stack stays behind,
# stopped, and nothing else removes it. So the first step of every CI job that
# starts containers runs this. On the daemon the job talks to it removes:
#
#   - a compose project whose name starts with CI_STACK_PREFIX, when EVERY
#     container in it is stale, then the project's networks and volumes;
#   - a container outside compose whose name starts with the prefix, when
#     stale, with its anonymous volumes.
#
# Stale: exited or dead and finished at least REAP_MIN_AGE seconds ago, or
# created and never started that long ago. A project with any container
# running, paused, restarting or removing is never touched. 11100 s is the
# runners' 3 h job timeout plus 5 min, so no job that could own the stack is
# alive. A failed removal is reported and skipped: the reaper never fails the
# job. REAP_DRY_RUN=1 prints what would be removed and removes nothing.
REAP_MIN_AGE ?= 11100
REAP_DRY_RUN ?= 0

ci-reap-stacks: export RP_MIN_AGE := $(REAP_MIN_AGE)
ci-reap-stacks: export RP_DRY := $(REAP_DRY_RUN)
ci-reap-stacks: ## Remove this repository's stale CI containers and compose stacks
	@set -u; \
	prefix="$(CI_STACK_PREFIX)"; \
	case "$$RP_MIN_AGE" in \
		''|*[!0-9]*) echo "REAP_MIN_AGE must be a number of seconds: $$RP_MIN_AGE" >&2; exit 2 ;; \
	esac; \
	now=$$(date +%s); \
	run() { if [ "$$RP_DRY" = 1 ]; then echo "dry   $$*"; else "$$@" >/dev/null; fi; }; \
	stale() { \
		set -- $$(docker inspect -f '{{.State.Status}} {{.State.FinishedAt}} {{.Created}}' "$$1" 2>/dev/null); \
		[ "$$#" -eq 3 ] || return 1; \
		case "$$1" in \
			exited|dead) t=$$2 ;; \
			created) t=$$3 ;; \
			*) return 1 ;; \
		esac; \
		t=$$(date -d "$$t" +%s 2>/dev/null) || return 1; \
		[ $$((now - t)) -ge "$$RP_MIN_AGE" ]; \
	}; \
	reaped=0; \
	for project in $$(docker ps -a --filter label=com.docker.compose.project \
			--format '{{.Label "com.docker.compose.project"}}' | sort -u); do \
		case "$$project" in "$$prefix"*) ;; *) continue ;; esac; \
		ids=$$(docker ps -aq --filter "label=com.docker.compose.project=$$project"); \
		keep=0; \
		for id in $$ids; do stale "$$id" || { keep=1; break; }; done; \
		if [ "$$keep" = 1 ]; then \
			echo "keep  $$project (a container is live or stopped within $${RP_MIN_AGE}s)"; \
			continue; \
		fi; \
		echo "reap  $$project: $$(echo $$ids | wc -w) container(s)"; \
		run docker rm -v $$ids || echo "warn  $$project: container removal failed"; \
		for net in $$(docker network ls -q --filter "label=com.docker.compose.project=$$project"); do \
			run docker network rm "$$net" || echo "warn  $$project: network $$net not removed"; \
		done; \
		for vol in $$(docker volume ls -q --filter "label=com.docker.compose.project=$$project"); do \
			run docker volume rm "$$vol" || echo "warn  $$project: volume $$vol not removed"; \
		done; \
		reaped=$$((reaped + 1)); \
	done; \
	docker ps -a --filter "name=^$$prefix" \
		--format '{{.ID}} {{.Names}} {{.Label "com.docker.compose.project"}}' | \
	while read -r id cname project; do \
		[ -z "$$project" ] || continue; \
		case "$$cname" in "$$prefix"*) ;; *) continue ;; esac; \
		if stale "$$id"; then \
			echo "reap  container $$cname"; \
			run docker rm -v "$$id" || echo "warn  container $$cname not removed"; \
		fi; \
	done; \
	if [ "$$RP_DRY" = 1 ]; then done_as="would be removed"; else done_as=removed; fi; \
	echo "reaper: $$reaped compose project(s) $$done_as for prefix '$$prefix'"; \
	exit 0

# Builds never resolve through a workspace: cross-repository modules come from
# published TAGS, never from wherever a sibling repo happens to be checked out.
# Immunizes against a stray go.work file changing what gets built.
export GOWORK=off

# ---- toolchain binding (#201) ----
#
# Every target runs on EXACTLY the toolchain go.mod's `go` directive names,
# derived from the file so the two cannot drift. Go's own resolution is
# GOTOOLCHAIN=auto: a host whose installed go is older than the directive
# fetches the named version through GOPROXY, cached once under GOMODCACHE.
# Hosts that set GOTOOLCHAIN=local opt out of that, and on such a host a
# module whose floor has moved past the installed go does not build at all:
#
#   go: go.mod requires go >= 1.27.0 (running go 1.26.7; GOTOOLCHAIN=local)
#
# Measured on #201, adopting go-enclave v0.5.0-alpha (floor `go 1.27.0`):
# the review harness carried 1.26.7 with GOTOOLCHAIN=local and could neither
# build nor test the change it was asked to verify -- the same failure the
# handbook recorded on 2026-08-27, when thirteen repos moved to 1.26.7 ahead
# of the shared image. A gate that READS instead of BUILDS and still votes is
# the thing to close, and pinning the exact directive is the remedy the
# handbook names (OWNER-QUEUE-2026-08-28 item 26) and the mechanism the dev
# hosts already use by hand (`GOTOOLCHAIN=go1.27.1`).
#
# Why the exact version and not `auto`: `auto` may pick a NEWER toolchain
# than the directive when one is installed, so two hosts build one commit on
# two compilers. The pin is the Makefile counterpart of the workflows'
# GO_VERSION (devops.md: bind the toolchain to the pinned version wherever
# the file supports it) and of the Dockerfiles' `golang:<pinned>` tags. It is
# derived, never typed here, so there is one place the floor is written.
#
# HOW it is derived, and why it is `override`, are both about not depending
# on the host the binding exists to rescue. The directive is read with make's
# own `$(file <)` and text functions -- no sed, no awk, no `go` (which is the
# very command that refuses to run) -- so a stripped PATH cannot silently
# leave GO_FLOOR empty and the export unset. `override` makes the pin win
# over `make -e` and over a GOTOOLCHAIN=... on make's command line, either of
# which a harness may set for hermeticity: an environment that pins the
# toolchain to "whatever is installed" is precisely the environment that
# cannot build this module, and a binding that yields to it is no binding.
#
# The opt-out is explicit and named: `make TOOLCHAIN_PIN=0 <target>` leaves
# GOTOOLCHAIN exactly as the environment has it, so a host that must not
# fetch gets go's clear refusal above rather than a download it did not
# want. A silent knob (an empty GO_FLOOR, a missing tool) is not an opt-out,
# it is the failure mode this block was written against.
#
# The pairing trick below reads as: list every word of go.mod suffixed with
# `@`, zip it against the word list shifted by one, and keep the pair whose
# left half is the bare token `go` and whose right half starts with a digit
# -- i.e. `go@1.27.1` from the directive, never `toolchain go1.27.1` (its
# token is `go1.27.1`, not `go`) and never a module path containing `go`.
TOOLCHAIN_PIN ?= 1
GO_MOD_WORDS := $(file < go.mod)
GO_FLOOR := $(firstword $(patsubst go@%,%,$(filter go@0% go@1% go@2% go@3% go@4% go@5% go@6% go@7% go@8% go@9%,$(join $(addsuffix @,$(GO_MOD_WORDS)),$(wordlist 2,$(words $(GO_MOD_WORDS)),$(GO_MOD_WORDS)) end-of-go-mod))))
ifeq ($(TOOLCHAIN_PIN),1)
ifeq ($(GO_FLOOR),)
$(error go.mod has no `go` directive to bind the toolchain to; see the toolchain binding block in this Makefile)
endif
override export GOTOOLCHAIN := go$(GO_FLOOR)
endif

# ---- dependency-resolution targets (2026-08-13 cutover) ----
# deps-latest runs before compiling in a consumer repo; release-alpha,
# release-candidate and release each publish one kind of tag (-alpha, -rc.N and
# final) for this repo.
#
# SUBMODULE_TAGS is GONE with the old recipe (#19). It existed to tag nested
# modules in lockstep with the root, and it was always empty here: `find . -name
# go.mod` returns exactly one file, the root. An empty knob for a case this
# repository does not have is a thing to maintain and to misread, not a
# feature. A repo that grows a nested module adds its lockstep check back as a
# PREREQUISITE of each release target, where a failure aborts before the tag exists.
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

# ---- release-alpha, release-candidate, release: one target per kind (template v2.3.5) ----
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
#   - There is ONE TARGET PER KIND (release-versioning.md 1a), each refusing
#     the other two BEFORE anything is written, and naming the right target in the refusal:
#       make release-alpha    [VERSION=vX.Y.Z-alpha]  an alpha (derived if omitted)
#       make release-candidate VERSION=vX.Y.Z-rc.N    a release candidate
#       make release           VERSION=vX.Y.Z         a final release
#     All three expand the same RELEASE_RECIPE (below), so the guards cannot
#     drift apart; a target adds only the kind it exports.
#   - The version is EXPLICIT for release-candidate and release: whoever cuts
#     one decides patch/minor/major and says so, and the recipe refuses to guess.
#     release-alpha alone derives it (release-versioning.md 1a and 2): with no VERSION it takes the highest vX.Y.Z-alpha tag, local and
#     on the release remote, adds 1 to PATCH, prints the result and then runs the
#     same RELEASE_RECIPE on it through a nested make, so every guard below still
#     runs on the derived version. It refuses, and prints the explicit form, when
#     there is no alpha tag to count from, when the remote cannot be listed, or
#     when any existing tag (an rc or a final release of the same or a higher
#     X.Y.Z outranks the alpha) is at or above the result. An explicit
#     VERSION=vX.Y.Z-alpha is still valid and is how a MINOR bump is cut by hand;
#     derivation is skipped for it.
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
# grammar guard ran, so `make release 'VERSION=v0.0.0-alpha`cmd`'`
# executed the backtick at the first guard line. Quoting is no boundary against
# a value that becomes recipe source. `$(value VERSION)` also stops the double
# evaluation the export would otherwise add.
# ADOPTER CHECK: `grep -P '(?<!\$)\$\((?!\()'` over the recipe BODY must be
# empty — no $(...) carrying a settable value below the export lines.
# KNOWN LIMIT, stated so nobody over-trusts this: a $(shell ...) FUNCTION typed
# into a `make VAR=...` command line runs during make's own variable expansion
# whether or not any rule names the variable. That is a property of invoking
# make, not of this recipe, and this recipe cannot close it.

.PHONY: release release-alpha release-candidate deps-latest

# changelog-assemble folds changelog.d fragments into a new CHANGELOG.md section.
#
# A COMMITTED STEP PERFORMED BEFORE TAGGING, not something release.yml does --
# the workflow only overwrites the runner-workspace copy, so a fragment folded in
# there would never reach the repository (release-versioning.md 5).
#
# Run it, read the diff, commit it, then the release target for the kind
# (release-alpha, release-candidate or release) with the same VERSION. It
# does not commit for you: the changelog is the one artefact of a release a human
# should look at before it is published.
changelog-assemble: export ASM_VERSION := $(value VERSION)
changelog-assemble: ## Fold changelog.d fragments into a CHANGELOG.md section (VERSION=vX.Y.Z-alpha or vX.Y.Z-rc.N)
	@test -n "$$ASM_VERSION" || { echo 'ERROR: state the version explicitly: make changelog-assemble VERSION=vX.Y.Z[-alpha|-rc.N] (the same VERSION the release target will take)'; exit 1; }
	@ls changelog.d/*.md >/dev/null 2>&1 || { echo 'ERROR: changelog.d holds no fragments; nothing to assemble'; exit 1; }
	@set -eu; \
	ver="$${ASM_VERSION#v}"; \
	frags=$$(ls changelog.d/*.md | grep -v '/README\.md$$' || true); \
	test -n "$$frags" || { echo 'ERROR: changelog.d holds only README.md; nothing to assemble'; exit 1; }; \
	{ \
	  printf '## [%s] - %s\n\n' "$$ver" "$$(date -u +%Y-%m-%d)"; \
	  for f in $$frags; do cat "$$f"; printf '\n'; done; \
	} > .changelog-section; \
	awk 'NR==FNR { sec = sec $$0 "\n"; next } \
	     !done && /^## \[/ && $$0 !~ /^## \[Unreleased\]/ { printf "%s", sec; done = 1 } \
	     { print } \
	     END { if (!done) printf "%s", sec }' .changelog-section CHANGELOG.md > .changelog-new; \
	mv .changelog-new CHANGELOG.md; \
	rm -f .changelog-section; \
	rm -f $$frags; \
	echo "Assembled $$(echo "$$frags" | wc -w) fragment(s) into CHANGELOG.md as [$$ver]."; \
	echo "Review the diff, then commit CHANGELOG.md and the fragment deletions together."

# ONE RECIPE, THREE TARGETS. RELEASE_RECIPE holds every guard and every write;
# release-alpha, release-candidate and release each expand it and differ only in
# the kind they export as REL_TARGET, which the first guard after the grammar
# check compares with the kind the VERSION argument is. The recipe is a variable
# rather than a shared prerequisite on purpose: a prerequisite runs once per
# invocation, so `make release-candidate release VERSION=...` would run it once
# under whichever kind make visited first and clear the other target's check.
# Expanded per target, each gets its own kind check and its own run.
#
# The body references only shell parameters ($$REL_*), as v2.3.3 requires: the
# one $(RELEASE_RECIPE) reference in each target below carries no settable value.
define RELEASE_RECIPE
	@test -n "$$REL_VERSION" || { echo "ERROR: state the version explicitly: make $$REL_TARGET VERSION=$$REL_SHAPE (you decide patch/minor/major — the recipe refuses to guess)"; exit 1; }
	@printf '%s' "$$REL_VERSION" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-alpha|-rc\.[1-9][0-9]*)?$$' || { echo "ERROR: VERSION is not of the form vX.Y.Z, vX.Y.Z-alpha or vX.Y.Z-rc.N (no leading zeroes): $$REL_VERSION"; exit 1; }
	@# One target per kind (release-versioning.md 1a). The kind is read off the
	@# VERSION just validated; a mismatch is refused here, before any guard that
	@# reads the repository and long before anything is written.
	@case "$$REL_VERSION" in \
	  *-alpha) got=release-alpha; what='an alpha' ;; \
	  *-rc.*)  got=release-candidate; what='a release candidate' ;; \
	  *)       got=release; what='a final release' ;; \
	esac; \
	test "$$got" = "$$REL_TARGET" || { echo "ERROR: $$REL_VERSION is $$what, which make $$REL_TARGET does not cut. Use: make $$got VERSION=$$REL_VERSION"; exit 1; }
	@test "$$(git rev-parse --abbrev-ref HEAD)" = main || { echo "ERROR: releases are cut from main; you are on $$(git rev-parse --abbrev-ref HEAD). 'push $$REL_REMOTE HEAD' would publish this branch."; exit 1; }
	@test -n "$$REL_REPO" || { echo 'ERROR: REPO_NAME is empty — set it to the literal repo name, never $$(notdir $$(CURDIR))'; exit 1; }
	@test -x "$$REL_AGENT_GIT" || { echo "ERROR: AGENT_GIT does not point at an executable agent-git.sh. Every git write below signs through it, and a bad path must fail HERE rather than at the first signed write, with a tag already cut. No default path is baked in (#20): put agent-git.sh on PATH, or run: make $$REL_TARGET AGENT_GIT=/path/to/agent-git.sh VERSION=$$REL_SHAPE"; exit 1; }
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
	@# Captured, not piped into a test. `grep -q` closes the pipe on its first
	@# match, so under pipefail the pipeline reports ls's SIGPIPE rather than
	@# grep's verdict and the check silently never fires -- measured.
	@frags=$$(ls changelog.d/*.md 2>/dev/null | grep -v '/README\.md$$' || true); \
	test -z "$$frags" || { echo "ERROR: changelog.d still holds unassembled fragments:"; echo "$$frags" | sed 's/^/  /'; echo "Tagging now would publish a release whose CHANGELOG omits them. Run: make changelog-assemble VERSION=$$REL_VERSION, review, commit, then make $$REL_TARGET."; exit 1; }
	@ver="## [$${REL_VERSION#v}]"; awk -v ver="$$ver" 'index($$0, ver) == 1 { f = 1 } END { exit f ? 0 : 1 }' CHANGELOG.md || { echo "ERROR: CHANGELOG.md has no \"$$ver\" section heading. Matched LITERALLY and anchored at the line start — an unanchored prose mention does not count, and neither does a near-miss heading"; exit 1; }
	@# Idempotent: when VERSION already reads this release (the rc.1 case, where
	@# the file was bumped ahead of the tag) there is nothing to commit, and an
	@# empty commit would fail the recipe with the tag not yet cut.
	@printf '%s\n' "$${REL_VERSION#v}" > VERSION
	@if git diff --quiet HEAD -- VERSION; then \
	  echo "VERSION already reads $${REL_VERSION#v}; no version commit"; \
	else \
	  "$$REL_AGENT_GIT" "$$REL_REPO" add VERSION && \
	  "$$REL_AGENT_GIT" "$$REL_REPO" commit -m "chore(release): $$REL_VERSION"; \
	fi
	"$$REL_AGENT_GIT" "$$REL_REPO" tag -a "$$REL_VERSION" -m "$$REL_VERSION"
	"$$REL_AGENT_GIT" "$$REL_REPO" push --atomic "$$REL_REMOTE" HEAD "refs/tags/$$REL_VERSION"
	@echo "Released $$REL_VERSION (signed, annotated, single tag pushed)"
endef

# release-alpha with no VERSION: derive the next alpha, print it, and hand it to
# a nested make that runs RELEASE_RECIPE on it, so every guard (main only, the
# remote, the duplicate tag, a clean tree, the changelog checks) sees the derived
# version exactly as it would see a typed one. Nothing here writes.
#
# The derivation reads the tags of BOTH the checkout and the release remote: a
# tag cut from another checkout is as real as a local one, and a published tag
# is immutable. An unreachable remote refuses rather than deriving from local
# tags alone, the same fail-closed reading as the duplicate-tag guard.
#
# Semver order decides what the result may be. The alpha of an X.Y.Z sorts below
# its rc and its final release, so the result is refused unless its X.Y.Z is
# strictly above the X.Y.Z of EVERY tag (alpha, rc or final): anything else
# would be a version at or below an existing tag.
#
# The nested make receives the version as a command-line VERSION, which also
# wins over any VERSION= the caller passed empty. The leading + keeps the make
# jobserver and lets the line run under -n, as a line naming a recursive make
# does.
define ALPHA_DERIVE
	@test -n "$$REL_REMOTE" || { echo 'ERROR: RELEASE_REMOTE is empty — set it to the git remote that serves this module'; exit 1; }
	@git remote get-url "$$REL_REMOTE" >/dev/null 2>&1 || { echo "ERROR: no git remote named $$REL_REMOTE. Set RELEASE_REMOTE; the next alpha cannot be derived without its tags"; exit 1; }
	+@set -eu; \
	core='(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'; \
	byver() { sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1; }; \
	rc=0; remote=$$(git ls-remote --tags --refs "$$REL_REMOTE" 2>/dev/null) || rc=$$?; \
	test "$$rc" = 0 || { echo "ERROR: could not list the tags on $$REL_REMOTE. Refusing to derive from local tags alone: an unreachable remote is not an absent tag. To go ahead, state the version explicitly: make $$REL_TARGET VERSION=$$REL_SHAPE"; exit 1; }; \
	tags=$$({ git tag -l 'v*'; printf '%s\n' "$$remote" | sed 's|^.*refs/tags/||'; } | sort -u); \
	latest=$$(printf '%s\n' "$$tags" | grep -E "^v$$core-alpha$$" | sed 's/^v//; s/-alpha$$//' | byver || true); \
	test -n "$$latest" || { echo "ERROR: no vX.Y.Z-alpha tag exists, locally or on $$REL_REMOTE, to count from. Nothing to derive: state the version explicitly: make $$REL_TARGET VERSION=$$REL_SHAPE"; exit 1; }; \
	oldifs="$$IFS"; IFS=.; set -- $$latest; IFS="$$oldifs"; \
	next="$$1.$$2.$$(( $$3 + 1 ))"; \
	top=$$(printf '%s\n' "$$tags" | grep -E "^v$$core(-alpha|-rc\.[1-9][0-9]*)?$$" | sed 's/^v//; s/-.*$$//' | byver || true); \
	hi=$$(printf '%s\n%s\n' "$$top" "$$next" | byver); \
	if test "$$hi" != "$$next" || test "$$top" = "$$next"; then \
	  topre=$$(printf '%s' "$$top" | sed 's/\./\\./g'); \
	  blocker=$$(printf '%s\n' "$$tags" | grep -E "^v$$topre(-|$$)" | sort -V | tail -n 1); \
	  echo "ERROR: the next alpha after v$$latest-alpha would be v$$next-alpha, which does not outrank the existing tag $$blocker (an rc or a final release outranks the alpha of the same X.Y.Z). To choose a version above it, state the version explicitly: make $$REL_TARGET VERSION=$$REL_SHAPE"; exit 1; \
	fi; \
	v="v$$next-alpha"; \
	echo "Next alpha: $$v (PATCH + 1 on the highest alpha tag, v$$latest-alpha; tags read from the checkout and $$REL_REMOTE)"; \
	exec "$$REL_MAKE" --no-print-directory $$REL_TARGET VERSION="$$v"
endef

release-alpha: export REL_TARGET    := release-alpha
release-alpha: export REL_SHAPE     := vX.Y.Z-alpha
release-alpha: export REL_VERSION   := $(value VERSION)
release-alpha: export REL_REMOTE    := $(RELEASE_REMOTE)
release-alpha: export REL_REPO      := $(REPO_NAME)
release-alpha: export REL_AGENT_GIT := $(AGENT_GIT)
release-alpha: export REL_MAKE      := $(MAKE)
release-alpha: ## Tag and push the next alpha (derived, PATCH + 1) or VERSION=vX.Y.Z-alpha; refuses any other kind
# ifndef does not expand VERSION; it asks only whether VERSION has a value, so
# no settable text is read as make syntax here.
ifndef VERSION
	$(ALPHA_DERIVE)
else
	$(RELEASE_RECIPE)
endif

release-candidate: export REL_TARGET    := release-candidate
release-candidate: export REL_SHAPE     := vX.Y.Z-rc.N
release-candidate: export REL_VERSION   := $(value VERSION)
release-candidate: export REL_REMOTE    := $(RELEASE_REMOTE)
release-candidate: export REL_REPO      := $(REPO_NAME)
release-candidate: export REL_AGENT_GIT := $(AGENT_GIT)
release-candidate: ## Tag and push a release candidate (VERSION=vX.Y.Z-rc.N); refuses any other kind
	$(RELEASE_RECIPE)

release: export REL_TARGET    := release
release: export REL_SHAPE     := vX.Y.Z
release: export REL_VERSION   := $(value VERSION)
release: export REL_REMOTE    := $(RELEASE_REMOTE)
release: export REL_REPO      := $(REPO_NAME)
release: export REL_AGENT_GIT := $(AGENT_GIT)
release: ## Tag and push a final release (VERSION=vX.Y.Z); refuses any other kind
	$(RELEASE_RECIPE)

deps-latest:
	@GOWORK=off sh -c ' \
	SELF=$$(go list -m); \
	for m in $$(go list -m -f "{{if not .Indirect}}{{.Path}}{{end}}" all 2>/dev/null | grep "^github.com/jeremyhahn/" | grep -vx "$$SELF"); do \
	  case "$$(go list -m -f "{{if .Replace}}{{.Replace.Path}}{{end}}" "$$m" 2>/dev/null)" in .*|/*) continue;; esac; \
	  V=$$(go list -m -versions "$$m" 2>/dev/null | tr " " "\n" | tail -1); \
	  if [ -n "$$V" ] && [ "$$V" != "$$m" ]; then go get "$$m@$$V" || exit 1; fi; \
	done; go mod tidy'
