# Makefile for go-luks2
# LUKS2 encryption library and tools in pure Go

.PHONY: coverage-gate coverage-combined changelog-assemble help build install test test-verbose test-coverage test-integration coverage clean fmt vet lint gosec govulncheck trivy-fs security ci ci-full fmt-check all check test-cli docker-run-bin releasability integration-test-pkg integration-test-cli docker-build-integration docker-prune-itest print-itest-label test-calibration seccomp-diff

# Default target
.DEFAULT_GOAL := help

# Variables
BINARY_NAME=luks2
BUILD_DIR=build
CMD_DIR=cmd/luks2
COVERAGE_FILE=coverage.out
COVERAGE_HTML=coverage.html

# ---- the coverage gate (#141) ----
#
# COVERAGE_THRESHOLD is the bar testing-guidelines.md sets for EVERY package
# (project-scaffold.md 6). COVERAGE_FLOORS holds one floor per package per
# tier, and test/covergate compares each package against its own floor in
# integer arithmetic -- never the aggregate, and never a rounded percentage.
# The gate also refuses a floors file that leaves a package unmeasured, names
# one that no longer exists, or holds a package to the target in no tier, so a
# floor cannot be lowered past the target without the gate saying so.
COVERAGE_THRESHOLD=90
COVERAGE_FLOORS=coverage-floors.txt
COVERAGE_GATE=$(GO) run ./test/covergate -floors $(COVERAGE_FLOORS) -target $(COVERAGE_THRESHOLD)

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
COVERAGE_COMBINED_PKGS=./pkg/luks2 ./test/harness
COVERAGE_COMBINED_COVERPKG=./pkg/luks2,./test/harness
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

# Simple expansion (:=), not recursive (=), and that is load-bearing (#205).
# GNU make 4.4 exports environment-origin variables into $(shell ...). GOPATH is
# in the environment on the build workers, so a recursive GO had to expand the
# redefined GOPATH first, whose own $(GO) was still empty there: the command
# became `env GOPATH`, and env printed "can't execute 'GOPATH'" to stderr on
# every make invocation. Harmless to the build, but it landed as the first line
# of every failing verification's output and got diagnosed as the failure twice.
# Evaluating both once, in order, keeps the `which` fallback that `sudo make`
# relies on while leaving nothing for a later GOPATH expansion to re-enter.
GO := $(shell which go 2>/dev/null || echo /usr/local/go/bin/go)
GOPATH := $(shell $(GO) env GOPATH)
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
# and the reasoning is recorded at the race legs in .github/workflows/ci.yml.
#
# -count=1, because a cached result would report a runtime of zero against the
# budget and a profile from some earlier tree.
test-unit: ## Run only unit tests with coverage and the race detector (fast, no I/O, no root required)
	@echo "$(COLOR_BOLD)Running unit tests with coverage and -race...$(COLOR_RESET)"
	@rm -f $(COVERAGE_UNIT_LEGS) $(COVERAGE_FILE)
	@set -u; \
	start=$$(date +%s); rc=0; \
	$(GO) test $(UNIT_TEST_FLAGS) -count=1 -race -timeout $(UNIT_TEST_TIMEOUT) -covermode=atomic \
		-coverprofile=$(COVERAGE_LEG_PKG) ./pkg/luks2 || rc=$$?; \
	elapsed=$$(( $$(date +%s) - start )); \
	echo "pkg/luks2 under -race took $${elapsed}s: target $(UNIT_TEST_TARGET)s (UNIT_TEST_TARGET), ceiling $(UNIT_TEST_TIMEOUT) (UNIT_TEST_TIMEOUT)"; \
	if [ "$$elapsed" -gt "$(UNIT_TEST_TARGET)" ]; then \
		echo "::warning::pkg/luks2 under -race took $${elapsed}s, over its $(UNIT_TEST_TARGET)s budget (#92). Profile it with go test -json -race and move the slowest setup onto shared fixtures; do not raise the budget."; \
	fi; \
	exit $$rc
	@pkgs=$$($(GO) list ./... | grep -vx 'github.com/jeremyhahn/go-luks2/pkg/luks2') && test -n "$$pkgs" || \
		{ echo "$(COLOR_RED)go list named no package besides pkg/luks2$(COLOR_RESET)"; exit 1; }; \
	$(GO) test $(UNIT_TEST_FLAGS) -count=1 -race -timeout $(UNIT_TEST_TIMEOUT) -covermode=atomic \
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

# The public-releasability gate (#211) over THIS checkout's git index: no fleet
# address, hostname or owner path in a tracked file, and no tracked file the
# public release must not carry. It is a command rather than a test because it
# needs the git index, and the package tests also run where there is none --
# the integration image excludes .git/ and runs `go test ./...`. Without a
# checkout it fails; it never reports a tree it could not list as clean.
releasability: ## Run the public-releasability gate over the tracked tree (needs a git checkout)
	@$(GO) run ./test/labstrings/cmd/releasability-gate .

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
CALIBRATION_BENCHMARKS := BenchmarkDigestCalibrationCostsItsBudget|BenchmarkPBKDF2CalibrationCostsItsBudget|BenchmarkSystemClockIsTheRealClock

test-calibration: ## Run the PBKDF2 calibration tests without -race (the mode the defect lives in)
	@echo "$(COLOR_BOLD)Running PBKDF2 calibration tests (no -race)...$(COLOR_RESET)"
	@$(GO) test -count=1 -timeout 10m -run '$(CALIBRATION_TESTS)' -bench '$(CALIBRATION_BENCHMARKS)' -benchtime=1x ./pkg/luks2
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
	@# Reap first, so a build that later fails has still bounded the host. The
	@# reap's output is shown only when something was actually removed: an
	@# orphan means a run died here and that is worth reading, while "0B
	@# reclaimed" on every build is noise. If docker ever reworded that output
	@# the reap still happens and only the report goes quiet.
	@set -eu; \
	out="$$($(ITEST_PRUNE) 2>/dev/null || true)"; \
	case "$$out" in *Deleted*) printf '%s\n' "$$out";; esac; \
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
		--label $(ITEST_LABEL) \
		-f test/integration/Dockerfile \
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
# test/integration/cmd/docker-run and not in five call sites. Deliberately
# undocumented in help: it is a seam for the workflow, not a target anyone runs.
print-itest-label:
	@echo $(ITEST_LABEL)

integration-test: build ## Run all integration tests in Docker (isolated, recommended)
	@echo "$(COLOR_BOLD)Running all integration tests in Docker container...$(COLOR_RESET)"
	@$(MAKE) docker-integration-test

integration-test-pkg: build docker-run-bin ## Run package integration tests in Docker
	@echo "$(COLOR_BOLD)Running package integration tests in Docker...$(COLOR_RESET)"
	@$(MAKE) docker-build-integration
	@# One shell with a trap: the per-invocation image tag is never reused, so
	@# if this target simply exits -- and it aborts on a failing suite -- the
	@# image is orphaned on the host forever.
	@set -eu; \
	trap 'docker image rm -f $(ITEST_IMAGE) >/dev/null 2>&1 || true' EXIT INT TERM; \
	  env IMAGE="$(ITEST_IMAGE)" TEST_STATE_DIR="$(TEST_STATE_DIR)" \
	    $(INTEGRATION_DOCKER_RUN) --rm -- \
		go test -v -tags=integration ./test/integration/pkg/...

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
# test/covergate is the gate, and every caller reaches it through these
# targets: ci.yml's unit job runs `make coverage-gate`, the devcontainer's
# entrypoint runs `make coverage-combined`, so a developer's number is the
# number that blocks the merge. It is a Go program with its own tests rather
# than an awk pipeline, because a gate is only known to be a gate once it has
# been seen to fail, and its tests are where that is seen.

coverage-gate: ## Refuse unit coverage below any package's floor (reads test-unit's profiles)
	@$(COVERAGE_GATE) -tier unit $(foreach leg,$(COVERAGE_UNIT_LEGS),-profile $(leg)) $$($(GO) list ./...)

coverage: test-unit ## Measure unit coverage, gate it per package, and write the HTML report
	@$(MAKE) --no-print-directory coverage-gate
	@$(GO) tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@echo "$(COLOR_GREEN)✓ Coverage report: $(COVERAGE_HTML)$(COLOR_RESET)"

# The COMBINED tier: unit plus integration, for the packages whose remaining
# statements need a real kernel. It runs INSIDE the devcontainer -- it is the
# entrypoint's default command -- and never on a host (testing-guidelines.md).
# `make integration-test` / `make ci-full` / ci.yml's integration job all reach
# it through that entrypoint.
#
# Both suites are measured in the same container so the union is of two
# profiles of the same tree. The integration leg instruments the combined
# packages through -coverpkg, so test/integration/pkg's calls into the library
# count toward pkg/luks2, and its ledger and reaper use counts toward
# test/harness -- whose own integration tests drive the reaper's removals
# against the real kernel. -p 1 keeps the integration packages from contending
# for loop devices at once. The unit leg is not raced: -race is the unit job's
# business, and this leg is here for its profile.
coverage-combined: ## (devcontainer only) Run the integration suite and gate unit+integration coverage
	@rm -f $(COVERAGE_INTEGRATION) $(COVERAGE_COMBINED_UNIT)
	@echo "$(COLOR_BOLD)Integration suite, instrumenting $(COVERAGE_COMBINED_COVERPKG)...$(COLOR_RESET)"
	@$(GO) test -v -count=1 -p 1 -tags=integration -timeout 30m -covermode=atomic \
		-coverpkg=$(COVERAGE_COMBINED_COVERPKG) -coverprofile=$(COVERAGE_INTEGRATION) \
		./pkg/luks2 ./test/harness ./test/integration/pkg/... ./test/integration/cli/...
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
# so docker's 125/126/127 would be lost. test/integration/cmd/docker-run's
# TestBinary_PropagatesDockersExitStatus pins this.
DOCKER_RUN_BIN := $(BUILD_DIR)/docker-run
INTEGRATION_DOCKER_RUN := $(DOCKER_RUN_BIN)

# Phony so an edit to the command is always picked up; `go build` is cached,
# so a rebuild with nothing changed costs next to nothing.
docker-run-bin: ## Build the integration container launcher (build/docker-run)
	@mkdir -p $(BUILD_DIR)
	@$(GO) build -o $(DOCKER_RUN_BIN) ./test/integration/cmd/docker-run

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
# container's scope and the process's run id (test/harness VolumeName), so
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

vet: ## Run go vet, including the integration build tag
	@echo "$(COLOR_BOLD)Running go vet...$(COLOR_RESET)"
	@$(GO) vet ./...
	@$(GO) vet -tags=integration ./...
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

# The tests, the gate and the rest run IN ORDER, from the recipe, not as
# sibling prerequisites. Under `make -j` -- or a MAKEFLAGS a parent passes down
# -- siblings run concurrently, so the gate could read the profiles while
# test-unit was still deleting and rewriting them: a missing-input failure on a
# clean tree, or a pass on the previous run's profiles (#141 review).
ci: fmt-check vet lint security ## Run CI pipeline locally (format, lint, security suite, releasability gate, unit tests + coverage gate, build)
	@$(MAKE) --no-print-directory releasability
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
	@rm -rf $(BUILD_DIR) *.log *.test
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
	@echo "  make docker-run-bin && IMAGE=go-luks2-devcontainer $(INTEGRATION_DOCKER_RUN) \\"
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
# hosts already use by hand (`GOTOOLCHAIN=go1.27.0`).
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
# -- i.e. `go@1.27.0` from the directive, never `toolchain go1.27.0` (its
# token is `go1.27.0`, not `go`) and never a module path containing `go`.
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

# changelog-assemble folds changelog.d fragments into a new CHANGELOG.md section.
#
# A COMMITTED STEP PERFORMED BEFORE TAGGING, not something release.yml does --
# the workflow only overwrites the runner-workspace copy, so a fragment folded in
# there would never reach the repository (release-versioning.md 5).
#
# Run it, read the diff, commit it, then `make release-alpha VERSION=...`. It
# does not commit for you: the changelog is the one artefact of a release a human
# should look at before it is published.
changelog-assemble: export ASM_VERSION := $(value VERSION)
changelog-assemble: ## Fold changelog.d fragments into a CHANGELOG.md section (VERSION=vX.Y.Z-alpha)
	@test -n "$$ASM_VERSION" || { echo 'ERROR: state the version explicitly: make changelog-assemble VERSION=vX.Y.Z-alpha'; exit 1; }
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
	@# Captured, not piped into a test. `grep -q` closes the pipe on its first
	@# match, so under pipefail the pipeline reports ls's SIGPIPE rather than
	@# grep's verdict and the check silently never fires -- measured.
	@frags=$$(ls changelog.d/*.md 2>/dev/null | grep -v '/README\.md$$' || true); \
	test -z "$$frags" || { echo "ERROR: changelog.d still holds unassembled fragments:"; echo "$$frags" | sed 's/^/  /'; echo "Tagging now would publish a release whose CHANGELOG omits them. Run: make changelog-assemble VERSION=$$REL_VERSION, review, commit, then release."; exit 1; }
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
