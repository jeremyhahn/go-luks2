# Makefile for go-luks2
# LUKS2 encryption library and tools in pure Go

.PHONY: api-dump api-diff coverage-gate coverage-combined changelog-assemble help build build-linux vet-32bit install test test-verbose test-coverage test-integration coverage coverage-report clean fmt vet lint gosec govulncheck vuln trivy-fs trivy-install trivy-sarif trivy-misconfig security ci ci-full fmt-check all check test-cli docker-run-bin releasability integration-test-cli docker-build-integration docker-prune-itest print-itest-label test-calibration test-unit-norace seccomp-diff proto test-pkg docker-build docker-build-cli docker-run deps-check test-fips-mode assert-build-tags toolchain-image it-image apk-index-sum apt-index-sum docker-build-toolchain toolchain-run ci-toolchain-run ci-reap-stacks ci-trim-caches ci-mask-lan ci-image-history

# Default target
.DEFAULT_GOAL := help

# Variables
BINARY_NAME=luks2
BUILD_DIR=build
CMD_DIR=cmd/luks2
COVERAGE_FILE=coverage.out
COVERAGE_HTML=coverage.html
# The image `docker-build-cli`/`docker-run` build and run: the CLI alone, from
# build/docker/cli, for someone who wants the tool without a devcontainer or
# the integration suite's test dependencies.
CLI_IMAGE ?= go-luks2-cli

# Coverage gate: test/tools/covergate checks each package against its own floor in COVERAGE_FLOORS.
COVERAGE_THRESHOLD=90
COVERAGE_FLOORS=coverage-floors.txt
COVERAGE_GATE=$(GO) run ./test/tools/covergate -floors $(COVERAGE_FLOORS) -target $(COVERAGE_THRESHOLD)

# Unit-tier profiles, one per test-unit leg, gated separately; coverage.out is only for the report.
COVERAGE_LEG_PKG=coverage-pkg.out
COVERAGE_LEG_REST=coverage-rest.out
COVERAGE_UNIT_LEGS=$(COVERAGE_LEG_PKG) $(COVERAGE_LEG_REST)

# Combined tier, measured inside the devcontainer: unit plus integration profiles for kernel-only code.
COVERAGE_COMBINED_PKGS=./pkg/luks2 ./pkg/dmcrypt ./pkg/loop ./pkg/filesystem ./test/internal/harness ./internal/dm ./internal/keyring
COVERAGE_COMBINED_COVERPKG=./pkg/luks2,./pkg/dmcrypt,./pkg/loop,./pkg/filesystem,./test/internal/harness,./internal/dm,./internal/keyring
COVERAGE_COMBINED_UNIT=coverage-combined-unit.out
COVERAGE_INTEGRATION=coverage-integration.out

# UNIT_TEST_TIMEOUT is the go test ceiling; UNIT_TEST_TARGET is the reported budget for ./pkg/luks2 under -race.
UNIT_TEST_TIMEOUT ?= 10m
UNIT_TEST_TARGET ?= 240
# Extra `go test` flags for the unit legs; CI passes -v.
UNIT_TEST_FLAGS ?=
# Race detector for the unit legs; test-unit-norace empties it.
UNIT_TEST_RACE ?= -race
UNIT_TEST_MODE = $(if $(strip $(UNIT_TEST_RACE)),under -race,without -race)

# Simple expansion keeps GOPATH from re-expanding an empty GO; GOPATH is asked only of a go that exists.
GO := $(shell which go 2>/dev/null || echo /usr/local/go/bin/go)
GOPATH := $(if $(wildcard $(GO)),$(shell $(GO) env GOPATH))
GOBIN=$(GOPATH)/bin
# Build tags lint and gosec analyse with; build and unit tests never take integration.
GO_BUILD_TAGS ?=
comma := ,
space := $(subst ,, )
# Version stamped into the binary; named BUILD_VERSION so it does not shadow the VERSION= argument of the release targets.
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

# Compile-only 32-bit check: go vet type-checks packages and tests for 386 and arm.
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

# Never suppress a failure that is the result (go test, guards); || true is only for absent-is-fine cases like docker rm -f.
test: ## Run unit tests only (no I/O, no root required)
	@echo "$(COLOR_BOLD)Running unit tests only...$(COLOR_RESET)"
	@$(GO) test -v ./...
	@echo "$(COLOR_GREEN)✓ Unit tests complete$(COLOR_RESET)"

# Unit tier, raced, in two legs: ./pkg/luks2 timed alone, then every other package; -count=1 so nothing is cached.
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

# The PR tier's unit run: test-unit without the race detector.
test-unit-norace: ## Run the unit tests with coverage but without -race (CI's PR tier)
	@$(MAKE) --no-print-directory test-unit UNIT_TEST_RACE=

# Releasability gate over the git index: no internal address, hostname or owner path in a tracked file.
releasability: ## Run the public-releasability gate over the tracked tree (needs a git checkout)
	@$(GO) run ./test/tools/releasability-gate .

# PBKDF2 calibration tests without -race: the uninstrumented build ships, and -race hides calibration defects.
CALIBRATION_TESTS := TestBenchmarkPBKDF2|TestCalibratePBKDF2|TestPBKDF2IterationFloor|TestScalePBKDF2Iterations|TestCreateKDFPBKDF2|TestDigestCalibration
CALIBRATION_BENCHMARKS := BenchmarkDigestCalibrationCostsItsBudget|BenchmarkPBKDF2CalibrationCostsItsBudget

test-calibration: ## Run the PBKDF2 calibration tests without -race (the mode the defect lives in)
	@echo "$(COLOR_BOLD)Running PBKDF2 calibration tests (no -race)...$(COLOR_RESET)"
	@$(GO) test -count=1 -timeout 10m -run '$(CALIBRATION_TESTS)' -bench '$(CALIBRATION_BENCHMARKS)' -benchtime=1x ./pkg/luks2
	@$(GO) test -count=1 -timeout 10m -run '$(CALIBRATION_TESTS)' ./internal/kdf
	@echo "$(COLOR_GREEN)✓ Calibration tests passed$(COLOR_RESET)"

# FIPS 140-3 gate: GOFIPS140=latest and GODEBUG=fips140=only make any non-approved algorithm fail at its call.
test-fips-mode: export GOFIPS140 := latest
test-fips-mode: export GODEBUG := fips140=only
test-fips-mode: ## Build and test the module in FIPS 140-3 only mode (GOFIPS140=latest, GODEBUG=fips140=only)
	go build ./...
	go test -count=1 -timeout=900s -v -run '^TestFIPSImportOf(ACryptsetupArgon2idVolume|ACryptsetupVolumeWithShortSalts|ACryptsetupVolumeWithAnUnboundKey|SHA1AFVolumes)$$' ./pkg/luks2
	go test -count=1 -timeout=900s ./...

# assert-build-tags: each declared GO_BUILD_TAGS tag must change the selected file set, test files included.
BUILD_TAG_FILES = {{$$p := .ImportPath}}{{range .GoFiles}}{{$$p}}/{{.}}{{"\n"}}{{end}}{{range .CgoFiles}}{{$$p}}/{{.}}{{"\n"}}{{end}}{{range .TestGoFiles}}{{$$p}}/{{.}}{{"\n"}}{{end}}{{range .XTestGoFiles}}{{$$p}}/{{.}}{{"\n"}}{{end}}

assert-build-tags: ## Fail when a GO_BUILD_TAGS tag selects no code
	@set -eu; \
	tags='$(strip $(GO_BUILD_TAGS))'; \
	[ -n "$$tags" ] || { echo "GO_BUILD_TAGS is empty: nothing to assert"; exit 0; }; \
	files_for() { csv=$$(echo $$1 | tr ' ' ','); $(GO) list -tags="$$csv" -f '$(BUILD_TAG_FILES)' ./... 2>/dev/null | sort -u; }; \
	bare=$$(files_for ''); \
	full=$$(files_for "$$tags"); \
	nb=$$(printf '%s\n' "$$bare" | grep -c . || true); \
	nf=$$(printf '%s\n' "$$full" | grep -c . || true); \
	echo "files selected: untagged=$$nb tagged=$$nf (tags: $$tags)"; \
	rc=0; \
	if [ "$$full" = "$$bare" ]; then \
		echo "::error::-tags '$$tags' changed nothing: the same files are selected with and without it. Either it names tags no file declares, or GO_BUILD_TAGS should be empty."; \
		rc=1; \
	fi; \
	for t in $$tags; do \
		rest=$$(printf '%s\n' $$tags | grep -vx -- "$$t" | tr '\n' ' '); \
		if [ "$$(files_for "$$rest")" = "$$full" ]; then \
			echo "::error::build tag '$$t' selects nothing: removing it from GO_BUILD_TAGS changes no file. Misspelled, or it should be removed."; \
			rc=1; \
		fi; \
	done; \
	[ "$$rc" -ne 0 ] || echo "OK: every declared tag selects code"; \
	exit "$$rc"

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

# Per-invocation docker names: ITEST_ID is computed once and exported; ITEST_IMAGE and ITEST_CONTAINER defer to the environment so CI cleanup matches.
ifneq ($(IT_IMAGE),)
ITEST_IMAGE := $(IT_IMAGE)
endif
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

# Every integration image carries this label so the reaper can find orphans a SIGKILL left.
ITEST_LABEL := go-luks2-itest=1

# Reap only this repository's labelled images (--all), and only those older than ITEST_PRUNE_AGE so a live build-to-run window is never hit.
ITEST_PRUNE_AGE ?= 2h
ITEST_PRUNE := docker image prune --force --all \
  --filter label=$(ITEST_LABEL) --filter until=$(ITEST_PRUNE_AGE)

# A standalone build (MAKELEVEL 0, ITEST_ID and ITEST_IMAGE unset) removes the image it built; set either to keep it.
ITEST_NAMES_ARE_OURS := $(if $(filter-out undefined,$(ITEST_ID_ORIGIN) $(ITEST_IMAGE_ORIGIN)),,yes)
ITEST_BUILD_IS_GOAL := $(if $(filter 0,$(MAKELEVEL)),$(ITEST_NAMES_ARE_OURS))

# The ONE image every CI stage runs in (devcontainer.md §1): its toolchain
# stage runs build, test, lint, security and deps-check, its integration stage
# runs the integration suite. There is no other CI image.
DEVCONTAINER_DOCKERFILE := build/docker/devcontainer/Dockerfile

# Stages private-module credentials into "$$stage" for docker build --secret; MODULE_ENV_FILE names a caller-written file used as is.
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

# $(call CONTENT_IMAGE_BUILD,<tag>,<args>,<pattern>): builds <tag>, passing only when a concurrent build already exported the same content tag.
CONTENT_IMAGE_BUILD = imgtmp="$$(mktemp -d -t imagebuild.XXXXXX)"; \
	[ -n "$(MODULE_ENV_FILE)" ] || trap 'rm -f "$$stage"; rm -rf "$$imgtmp"' EXIT INT TERM; \
	[ -z "$(MODULE_ENV_FILE)" ] || trap 'rm -rf "$$imgtmp"' EXIT INT TERM; \
	{ rc=0; DOCKER_BUILDKIT=1 docker build $(2) -t $(1) . 2>&1 || rc=$$?; echo "$$rc" > "$$imgtmp/rc"; } | tee "$$imgtmp/log"; \
	rc="$$(cat "$$imgtmp/rc")"; \
	if [ "$$rc" -ne 0 ]; then \
		case "$(1)" in $(3)) \
			if grep -qF -e '"$(1)": already exists' -e '"docker.io/library/$(1)": already exists' "$$imgtmp/log" \
				&& docker image inspect $(1) >/dev/null 2>&1; then \
				echo "$(1) was built concurrently: another job built the same content under this tag while this build ran, so this build is not a failure."; \
				rc=0; \
			fi;; \
		esac; \
		[ "$$rc" -eq 0 ] || exit "$$rc"; \
	fi

# Builds the integration image with module credentials and GO_BUILD_PROXY as BuildKit secrets, staged outside the build context; never build args.
GO_BUILD_PROXY_SECRET = $(if $(GO_BUILD_PROXY),--secret id=goproxy$(comma)env=GO_BUILD_PROXY)

ITEST_BUILD_ARGS = --secret id=gomodauth$(comma)src="$$stage" \
	$(GO_BUILD_PROXY_SECRET) --build-arg APK_INDEX_SUM --build-arg APT_INDEX_SUM --label $(ITEST_LABEL) \
	-f $(DEVCONTAINER_DOCKERFILE) --target integration

docker-build-integration:
	@# Reap first, so a build that later fails has still bounded the host. The
	@# reap's output is shown only when something was actually removed: an
	@# orphan means a run died here and that is worth reading, while "0B
	@# reclaimed" on every build is noise. If docker ever reworded that output
	@# the reap still happens and only the report goes quiet.
	@#
	@# A content tag is checked before the build, and a failed build of one
	@# is a concurrent build of the same content only when BuildKit refused
	@# that exact tag as already existing and it now resolves
	@# (CONTENT_IMAGE_BUILD); anything else fails with the build's own status.
	@set -eu; \
	out="$$($(ITEST_PRUNE) 2>/dev/null || true)"; \
	case "$$out" in *Deleted*) printf '%s\n' "$$out";; esac; \
	case "$(ITEST_IMAGE)" in $(CI_STACK_PREFIX)it:*) \
		if docker image inspect $(ITEST_IMAGE) >/dev/null 2>&1; then \
			echo "$(ITEST_IMAGE) is held: the tag is the content (make it-image), so it is not rebuilt."; \
			exit 0; \
		fi;; \
	esac; \
	$(GOMODAUTH_STAGE); \
	$(call CONTENT_IMAGE_BUILD,$(ITEST_IMAGE),$(ITEST_BUILD_ARGS),$(CI_STACK_PREFIX)it:*); \
	if [ -n "$(ITEST_BUILD_IS_GOAL)" ]; then \
		docker image rm -f $(ITEST_IMAGE) >/dev/null 2>&1 || true; \
		echo "$(COLOR_BOLD)Removed $(ITEST_IMAGE): a tag this invocation invented, which no later run can name.$(COLOR_RESET)"; \
		echo "$(COLOR_BOLD)The build cache is kept. Export ITEST_ID or ITEST_IMAGE to keep the image itself.$(COLOR_RESET)"; \
	fi

# The label reaper on its own; every integration build also runs it first.
docker-prune-itest: ## Remove orphaned integration images (label-scoped, age-bounded)
	@$(ITEST_PRUNE)

# The image label, read by ci.yml so build and prune spell it the same way.
print-itest-label:
	@echo $(ITEST_LABEL)

# Integration stage as compose.yaml's integration service, with the seccomp path, device-mapper major and state dir computed here; cleaned up on every exit.
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
	      $(if $(filter $(CI_STACK_PREFIX)it:%,$(ITEST_IMAGE)),:,docker image rm -f $(ITEST_IMAGE) >/dev/null 2>&1 || true)' EXIT INT TERM; \
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

# Coverage gate: test/tools/covergate, reached through these targets by CI and the devcontainer alike.

coverage-gate: ## Refuse unit coverage below any package's floor (reads test-unit's profiles)
	@$(COVERAGE_GATE) -tier unit $(foreach leg,$(COVERAGE_UNIT_LEGS),-profile $(leg)) $$($(GO) list ./...)

coverage: test-unit ## Measure unit coverage, gate it per package, and write the HTML report
	@$(MAKE) --no-print-directory coverage-gate
	@$(MAKE) --no-print-directory coverage-report

# Regenerates the report from an already-gated $(COVERAGE_FILE); never gates.
coverage-report: ## Print the func summary and write the HTML report from the already-gated profile
	@test -s $(COVERAGE_FILE) || { echo "$(COLOR_RED)✗ $(COVERAGE_FILE) is missing or empty; run 'make coverage-gate' (or 'make coverage') first$(COLOR_RESET)"; exit 1; }
	@$(GO) tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@$(GO) tool cover -func=$(COVERAGE_FILE) | tail -1
	@echo "$(COLOR_GREEN)✓ Coverage report: $(COVERAGE_HTML)$(COLOR_RESET)"

# Combined tier, inside the devcontainer: unit plus integration profiles of the same tree, integration with -coverpkg and -p 1.
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

# TEST_STATE_DIR holds the run ledgers on the host; never clean it routinely, and it is not created here because it is part of the root reaper's trust boundary.
TEST_STATE_DIR ?= /var/tmp/go-luks2-test-state

# Every integration container starts through test/tools/docker-run, which holds the privilege set; the built binary keeps docker's exit status.
DOCKER_RUN_BIN := $(BUILD_DIR)/docker-run
INTEGRATION_DOCKER_RUN := $(DOCKER_RUN_BIN)

# Phony so an edit to the command is always picked up; `go build` is cached,
# so a rebuild with nothing changed costs next to nothing.
docker-run-bin: ## Build the integration container launcher (build/docker-run)
	@mkdir -p $(BUILD_DIR)
	@$(GO) build -o $(DOCKER_RUN_BIN) ./test/tools/docker-run

# build/docker/cli is the production image: the luks2 binary and the cryptsetup tools it calls.
docker-build-cli: ## Build the CLI image from build/docker/cli
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

docker-run: docker-build-cli docker-run-bin ## Run the CLI image, with the integration seccomp profile and device scoping (ARGS="..." passes CLI args)
	@IMAGE=$(CLI_IMAGE) $(INTEGRATION_DOCKER_RUN) --rm -it -- $(ARGS)

# PKG_<name> maps a short name to its import path; adding a package adds one PKG_ line and its PKG_NAMES entry.
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

# Per-package profiles, so back-to-back runs do not clobber each other.
coverage-%: ## Coverage for one package by name, e.g. `make coverage-kdf` (writes coverage-<name>.out)
	@pkg="$(PKG_$*)"; test -n "$$pkg" || { echo "$(COLOR_RED)✗ no package mapped to '$*'; add PKG_$* to the Makefile$(COLOR_RESET)"; exit 1; }; \
	echo "$(COLOR_BOLD)Running coverage for $$pkg ($*)...$(COLOR_RESET)"; \
	$(GO) test -count=1 -covermode=atomic -coverprofile=coverage-$*.out "$$pkg" && \
	$(GO) tool cover -func=coverage-$*.out | tail -1

bench-%: ## Benchmarks for one package by name, e.g. `make bench-kdf` (a package with none exits clean)
	@pkg="$(PKG_$*)"; test -n "$$pkg" || { echo "$(COLOR_RED)✗ no package mapped to '$*'; add PKG_$* to the Makefile$(COLOR_RESET)"; exit 1; }; \
	echo "$(COLOR_BOLD)Running benchmarks for $$pkg ($*)...$(COLOR_RESET)"; \
	$(GO) test -run='^$$' -bench=. -benchmem "$$pkg"

# integration-test-% runs test/integration/<name>/; a name with no directory exits clean.

# Indirect through a variable so make -n does not force-run this recipe line.
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

# Diffs test/integration/seccomp.json against Docker's default profile for the local dockerd version, fetched through the module proxy.
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

# No host lock: every device-mapper name carries the container scope and run id.


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

# api-diff checks every disposition in test/tools/apidump/baseline is honoured by the current API.
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

# actionlint validates workflows and is required; self-hosted labels go in .github/actionlint.yaml.
# ACTIONLINT_VERSION is in the tool-pin file (TOOL PINS, below).
ACTIONLINT_CONFIG   = .github/actionlint.yaml

# With GO_BUILD_TAGS set, golangci-lint runs untagged with every linter, then tagged without unused.
LINT_TAGGED_PASS = $$LINTER run --output.text.print-issued-lines=false --build-tags=$(subst $(space),$(comma),$(strip $(GO_BUILD_TAGS))) --disable=unused ./... || exit 1;

lint: export AL_CONFIG := $(ACTIONLINT_CONFIG)
lint: ## Run gofmt, golangci-lint and actionlint over .github/workflows (all required)
	@echo "$(COLOR_BOLD)Checking gofmt...$(COLOR_RESET)"
	@UNFORMATTED=$$(gofmt -l .); \
	if [ -n "$$UNFORMATTED" ]; then \
		echo "$(COLOR_RED)✗ not gofmt-formatted (run 'make fmt'):$(COLOR_RESET)"; \
		echo "$$UNFORMATTED"; \
		exit 1; \
	fi
	@echo "$(COLOR_BOLD)Running golangci-lint...$(COLOR_RESET)"
	@LINTER=$$(command -v golangci-lint 2>/dev/null || echo "$(GOBIN)/golangci-lint"); \
	if [ ! -x "$$LINTER" ]; then \
		echo "$(COLOR_RED)✗ golangci-lint is not installed; the code was not linted$(COLOR_RESET)"; \
		echo "  Install: go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)"; \
		exit 1; \
	fi; \
	$$LINTER run --output.text.print-issued-lines=false ./... || exit 1; \
	$(if $(strip $(GO_BUILD_TAGS)),$(LINT_TAGGED_PASS)) \
	echo "$(COLOR_GREEN)✓ Lint passed$(COLOR_RESET)"
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

# make security is the CI contract: gosec (line-level #nosec only), govulncheck, go mod verify and trivy fs; missing tools skip unless TOOLS_REQUIRED=1, and a missing trivy always fails.
# scans.yml on main and every release run this target with TOOLS_REQUIRED=1; nightly runs trivy fs alone.
TOOLS_REQUIRED ?= 0
export TOOLS_REQUIRED

# GOSEC_EXTRA appends flags for a one-off run, e.g. a local SARIF report.
GOSEC_EXTRA ?=

# Bound gosec's worker pool: it sizes from host cores, and an OOM kill would read as a security finding.
GOSEC_CONCURRENCY ?= 4

gosec: ## Run gosec security scanner
	@echo "$(COLOR_BOLD)Running gosec security scanner...$(COLOR_RESET)"
	@GOSEC=$$(command -v gosec 2>/dev/null || echo "$(GOBIN)/gosec"); \
	if [ -x "$$GOSEC" ]; then \
		$$GOSEC -concurrency $(GOSEC_CONCURRENCY) -exclude-generated -severity medium -confidence medium $(if $(GO_BUILD_TAGS),-tags=$(subst $(space),$(comma),$(strip $(GO_BUILD_TAGS)))) $(GOSEC_EXTRA) ./... || exit 1; \
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

# Tool pins, shared with ci.yml and the devcontainer image; gosec needs -X to report its version.
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

# trivy: a pinned release archive, verified against the pinned SHA-256s before and after unpacking, installed under build/tools.
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

# Pinned trivy, else one on PATH; with neither, trivy targets fail.
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

# Misconfiguration scan, advisory: never fails on a finding.
trivy-misconfig: export TI_DEST := $(TRIVY_BIN)
trivy-misconfig:
	@$(TRIVY_RESOLVE); \
	"$$TRIVY" fs --scanners misconfig --exit-code 0 --format table --skip-dirs build .

security: gosec govulncheck verify trivy-fs ## Run the full §8 security suite (gosec, govulncheck, go mod verify, trivy fs)
	@echo "$(COLOR_GREEN)✓ Security suite complete$(COLOR_RESET)"

# Run in order from the recipe so make -j cannot gate on half-written profiles.
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

# Everything ci runs, then the devcontainer, whose exit status enforces the combined floors.
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

# Download first so go mod verify checks every module the build needs.
verify: ## Verify dependencies
	@echo "$(COLOR_BOLD)Verifying dependencies...$(COLOR_RESET)"
	@$(GO) mod download
	@$(GO) mod verify
	@echo "$(COLOR_GREEN)✓ Dependencies verified$(COLOR_RESET)"

# deps-check fails when a required module lags its latest release without a reason beside it in go.mod; uses DEPS_CHECK_GOPROXY when set.
DEPS_CHECK_GOPROXY ?=
deps-check: export DC_GOPROXY := $(DEPS_CHECK_GOPROXY)
deps-check: ## Fail when a go.mod module is behind a latest release 7+ days old with no reason written beside it
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

# The devcontainer image: the toolchain stage under a fixed tag, built with the same credentials staging.
DEVCONTAINER_IMAGE ?= go-luks2-devcontainer

devcontainer: ## Build and run the devcontainer
	@echo "$(COLOR_BOLD)Building devcontainer...$(COLOR_RESET)"
	@set -eu; \
	$(GOMODAUTH_STAGE); \
	DOCKER_BUILDKIT=1 docker build \
		--secret id=gomodauth,src="$$stage" \
		$(GO_BUILD_PROXY_SECRET) \
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

# The toolchain image, tagged by a hash of its inputs; make toolchain-image prints the tag.
TOOLCHAIN_INPUTS := $(DEVCONTAINER_DOCKERFILE) $(TOOL_PINS) go.mod go.sum
TOOLCHAIN_CONTENT_TAG = go-luks2-toolchain:$(shell cat $(TOOLCHAIN_INPUTS) 2>/dev/null | sha256sum | cut -c1-16)
TOOLCHAIN_IMAGE ?= $(TOOLCHAIN_CONTENT_TAG)

# docker-build-toolchain's arguments. Its concurrent-build tolerance
# (CONTENT_IMAGE_BUILD) covers only the tag computed from TOOLCHAIN_INPUTS: a
# TOOLCHAIN_IMAGE set by name is not known to be a hash of the inputs.
TOOLCHAIN_BUILD_ARGS = --secret id=gomodauth$(comma)src="$$stage" \
	$(GO_BUILD_PROXY_SECRET) -f $(DEVCONTAINER_DOCKERFILE) --target toolchain

toolchain-image: ## Print the content-hashed tag of the toolchain image
	@echo $(TOOLCHAIN_IMAGE)

# devcontainer_bases DOCKERFILE OVERRIDE OVERRIDE_VAR: sets bases to the external FROM images, or OVERRIDE's words; caller defines fail().
define DEVCONTAINER_BASES_FN
devcontainer_bases() {
local dockerfile=$1 override=$2 override_var=$3
bases=()
if [ -n "$override" ]; then
  read -r -a bases <<< "$override"
else
  [ -f "$dockerfile" ] || fail "no Dockerfile at $dockerfile"
  local -A arg=() stage=() seen=()
  # shellcheck disable=SC2016 # a regex, not an expansion
  ref='\$\{([A-Za-z_][A-Za-z0-9_]*)(:-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)'
  from=0
  # Join continuation lines, drop comments, then read one instruction a line.
  while read -r kw rest; do
    case ${kw^^} in
      ARG)
        # Only a global ARG (before the first FROM) can name a base image.
        [ "$from" = 0 ] || continue
        read -r -a kvs <<< "$rest"
        for kv in "${kvs[@]}"; do
          case $kv in
            *=*) v=${kv#*=}; v=${v#\"}; v=${v%\"}; arg[${kv%%=*}]=$v ;;
          esac
        done
        ;;
      FROM)
        from=1
        read -r -a w <<< "$rest"
        i=0
        while [ "$i" -lt "${#w[@]}" ] && [ "${w[$i]#--}" != "${w[$i]}" ]; do i=$((i + 1)); done
        img=${w[$i]:-}
        [ -n "$img" ] || fail "a FROM line in $dockerfile names no image"
        # ${NAME}, ${NAME:-default} and $NAME from the global ARG defaults.
        while [[ $img =~ $ref ]]; do
          n=${BASH_REMATCH[1]:-${BASH_REMATCH[4]}}
          v=${arg[$n]:-${BASH_REMATCH[3]}}
          [ -n "$v" ] || fail "FROM $img in $dockerfile names \$$n, which has no global ARG default; set $override_var"
          img=${img/"${BASH_REMATCH[0]}"/$v}
        done
        if [ "${w[$((i + 1))]:-}" != "" ] && [ "${w[$((i + 1))],,}" = as ]; then
          stage[${w[$((i + 2))],,}]=1
        fi
        [ "${img,,}" = scratch ] && continue
        [ -n "${stage[${img,,}]:-}" ] && continue
        [ -n "${seen[$img]:-}" ] && continue
        seen[$img]=1
        bases+=("$img")
        ;;
    esac
  done < <(sed -e ':a' -e '/\\$/N; s/\\\n/ /; ta' -e 's/^[[:space:]]*#.*//' "$dockerfile")
fi

}
endef

# apk-index-sum: one sha256 over each base image's apk repositories and index checksums, or none; fails when a base cannot be read.
define APK_INDEX_SUM_RECIPE
dockerfile=${APK_DOCKERFILE:-build/docker/devcontainer/Dockerfile}

fail() {
  echo "::error::apk-index-sum: $*" >&2
  exit 1
}

devcontainer_bases "$dockerfile" "${APK_BASE_IMAGES:-}" APK_BASE_IMAGES

[ "${#bases[@]}" -gt 0 ] || fail "no base image found in $dockerfile"

# Runs in the base image. A base without apk contributes `none`.
# shellcheck disable=SC2016 # expanded by the container's shell
probe='command -v apk >/dev/null 2>&1 || { echo none; exit 0; }
apk update --quiet >/dev/null || exit 3
set -- /var/cache/apk/APKINDEX.*.tar.gz
[ -f "$1" ] || exit 4
sed "s/[[:space:]]*$//" /etc/apk/repositories | grep -v "^#" | grep . | sort
sha256sum "$@" | sed "s|  .*/| |" | sort'

sum_input=
alpine=0
for img in "${bases[@]}"; do
  out=$(docker run --rm --pull missing --network bridge --user 0 \
          --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
          --security-opt no-new-privileges --entrypoint /bin/sh "$img" -c "$probe") ||
    fail "reading the Alpine package index of $img failed (exit $?)"
  [ "$out" = none ] || alpine=1
  echo "apk-index-sum: $img: $(printf '%s\n' "$out" | grep -c 'APKINDEX' || true) index file(s)" >&2
  sum_input+="$img"$'\n'"$out"$'\n'
done

if [ "$alpine" = 0 ]; then
  echo none
else
  printf '%s' "$sum_input" | sha256sum | cut -d' ' -f1
fi
endef

# The recipe runs as the script did, under bash -euo pipefail, from the
# environment, so make expands none of it; no other recipe changes shell.
apk-index-sum: SHELL := /bin/bash
apk-index-sum: .SHELLFLAGS := -euo pipefail -c
apk-index-sum: export DEVCONTAINER_BASES_SH := $(value DEVCONTAINER_BASES_FN)
apk-index-sum: export APK_INDEX_SUM_SH := $(value APK_INDEX_SUM_RECIPE)
apk-index-sum: ## Print the Alpine package index checksum of the devcontainer's base images (none without apk)
	@eval "$$DEVCONTAINER_BASES_SH"; eval "$$APK_INDEX_SUM_SH"

# apt-index-sum: one sha256 over each base image's apt Packages indexes, or none, so a Debian security fix changes the image tag.
define APT_INDEX_SUM_RECIPE
dockerfile=${APT_DOCKERFILE:-build/docker/devcontainer/Dockerfile}

fail() {
  echo "::error::apt-index-sum: $*" >&2
  exit 1
}

devcontainer_bases "$dockerfile" "${APT_BASE_IMAGES:-}" APT_BASE_IMAGES

[ "${#bases[@]}" -gt 0 ] || fail "no base image found in $dockerfile"

# Runs under the base image's /bin/sh; one unreadable index fails the probe (exit 5).
# shellcheck disable=SC2016 # expanded by the container's shell
probe='export LC_ALL=C
command -v apt-get >/dev/null 2>&1 || { echo none; exit 0; }
apt-get update -qq -o APT::Update::Error-Mode=any >/dev/null || exit 3
cd /var/lib/apt/lists || exit 4
set -- *_Packages*
[ -f "$1" ] || exit 4
sums=$(sha256sum "$@") || exit 5
printf "%s\n" "$sums" | sort -k2'

sum_input=
debian=0
for img in "${bases[@]}"; do
  out=$(docker run --rm --pull missing --network bridge --user 0 \
          --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
          --cap-add SETUID --cap-add SETGID \
          --security-opt no-new-privileges --entrypoint /bin/sh "$img" -c "$probe") ||
    fail "reading the Debian package index of $img failed (exit $?)"
  if [ "$out" != none ]; then
    debian=1
    while read -r sum file; do
      [[ $sum =~ ^[0-9a-f]{64}$ && $file == *_Packages* ]] || fail "$img printed '$sum $file', not a _Packages checksum"
    done <<< "$out"
  fi
  echo "apt-index-sum: $img: $(printf '%s\n' "$out" | grep -c '_Packages' || true) index file(s)" >&2
  sum_input+="$img"$'\n'"$out"$'\n'
done

if [ "$debian" = 0 ]; then
  echo none
else
  printf '%s' "$sum_input" | sha256sum | cut -d' ' -f1
fi
endef

apt-index-sum: SHELL := /bin/bash
apt-index-sum: .SHELLFLAGS := -euo pipefail -c
apt-index-sum: export DEVCONTAINER_BASES_SH := $(value DEVCONTAINER_BASES_FN)
apt-index-sum: export APT_INDEX_SUM_SH := $(value APT_INDEX_SUM_RECIPE)
apt-index-sum: ## Print the Debian package index checksum of the devcontainer's base images (none without apt)
	@eval "$$DEVCONTAINER_BASES_SH"; eval "$$APT_INDEX_SUM_SH"

# Integration image named by content (<CI_STACK_PREFIX>it:<hash>) over build args and the whole build context; fails closed when git cannot read the tree.
it-image: ## Print the content-addressed tag of the integration image
	@set -eu; \
	d=$$(mktemp -d); trap 'rm -rf "$$d"' EXIT; \
	fail() { echo "it-image: $$1 failed, so this tree has no integration image name" >&2; exit 1; }; \
	git rev-parse 'HEAD^{tree}' > "$$d/in" || fail "git rev-parse 'HEAD^{tree}'"; \
	git diff HEAD --binary >> "$$d/in" || fail 'git diff HEAD --binary'; \
	git ls-files -z --others --exclude-standard > "$$d/untracked" || fail 'git ls-files --others'; \
	xargs -0r sha256sum -- < "$$d/untracked" >> "$$d/in" || fail 'hashing the untracked files'; \
	printf 'GO_BUILD_PROXY=%s\nlabel=%s\ntarget=integration\n' "$${GO_BUILD_PROXY:-}" '$(ITEST_LABEL)' >> "$$d/in"; \
	printf 'APK_INDEX_SUM=%s\n' "$${APK_INDEX_SUM:-}" >> "$$d/in"; \
	printf 'APT_INDEX_SUM=%s\n' "$${APT_INDEX_SUM:-}" >> "$$d/in"; \
	h=$$(sha256sum < "$$d/in" | cut -c1-16); \
	case "$$h" in *[!0-9a-f]*|'') fail 'sha256sum' ;; esac; \
	echo "$(CI_STACK_PREFIX)it:$$h"

docker-build-toolchain: ## Build the toolchain image (the devcontainer's toolchain stage)
	@set -eu; \
	$(GOMODAUTH_STAGE); \
	$(call CONTENT_IMAGE_BUILD,$(TOOLCHAIN_IMAGE),$(TOOLCHAIN_BUILD_ARGS),$(TOOLCHAIN_CONTENT_TAG))

# devcontainer.md §6: both devcontainer images, the toolchain image under its
# content-hashed tag and the integration image under IT_IMAGE. CI's image job
# builds them once; MODULE_ENV_FILE reaches both builds.
docker-build: ## Build both devcontainer images: the toolchain image and the integration image (IT_IMAGE)
	@$(MAKE) --no-print-directory docker-build-toolchain
	@$(MAKE) --no-print-directory docker-build-integration

# Runs CMD in the toolchain image as the checkout's owner; credentials are forwarded by name only.
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

# Prefix for every CI container and compose project name, so ci-reap-stacks touches only ours.
override CI_STACK_PREFIX := go-luks2-ci-

# Runs CMD in the toolchain image for CI: checkout streamed in, no capabilities, no network unless IN_IMAGE_NETWORK=bridge, CPU and memory bounded to the job slot, caches in named volumes, CI_OUT files copied back.
#
#   make ci-toolchain-run CMD="make deps-check" IN_IMAGE_NETWORK=bridge
#   make ci-toolchain-run CMD="make build-linux" CI_OUT="luks-linux-amd64 luks-linux-arm64"
IN_IMAGE_NETWORK ?= none
CI_OUT ?=
CI_OUT_DIR ?= $(CURDIR)
CI_TOOLCHAIN_UID := 10001
IMAGE_GOMODCACHE := /go/pkg/mod
# DEVCACHE_GOPROXY first when set, then the public proxy, never direct.
CI_NETWORK_GOPROXY := $(if $(DEVCACHE_GOPROXY),$(DEVCACHE_GOPROXY)|)https://proxy.golang.org
CGROUP_CPU_MAX ?= /sys/fs/cgroup/cpu.max
CGROUP_MEMORY_MAX ?= /sys/fs/cgroup/memory.max

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
	cache="$${CI_CACHE:-on}"; \
	case "$$cache" in \
		on|off) ;; \
		*) echo "$(COLOR_RED)CI_CACHE must be on or off: $$cache$(COLOR_RESET)" >&2; exit 2 ;; \
	esac; \
	class="$${CI_CACHE_CLASS:-pr}"; \
	case "$$class" in \
		pr|main) ;; \
		*) echo "$(COLOR_RED)CI_CACHE_CLASS must be pr or main: $$class$(COLOR_RESET)" >&2; exit 2 ;; \
	esac; \
	cpus="$${IN_IMAGE_CPUS:-}"; \
	if [ -z "$$cpus" ]; then \
		quota=max; period=100000; \
		if [ -r "$(CGROUP_CPU_MAX)" ]; then read -r quota period < "$(CGROUP_CPU_MAX)"; fi; \
		case "$$quota" in \
			max|""|*[!0-9]*) cpus=$$(nproc) ;; \
			*) cpus=$$(( (quota + period - 1) / period )) ;; \
		esac; \
	fi; \
	case "$$cpus" in \
		""|0|*[!0-9]*) echo "$(COLOR_RED)IN_IMAGE_CPUS must be a positive integer: $$cpus$(COLOR_RESET)" >&2; exit 2 ;; \
	esac; \
	for f in $$TR_OUT; do \
		case "$$f" in \
			/*|..|../*|*/..|*/../*) echo "$(COLOR_RED)CI_OUT names a file under the checkout: $$f$(COLOR_RESET)" >&2; exit 2 ;; \
		esac; \
	done; \
	memory="$${IN_IMAGE_MEMORY:-}"; \
	if [ -z "$$memory" ]; then \
		limit=max; \
		if [ -r "$(CGROUP_MEMORY_MAX)" ]; then read -r limit < "$(CGROUP_MEMORY_MAX)"; fi; \
		case "$$limit" in \
			max|""|*[!0-9]*) memory=8g ;; \
			*) memory=$$limit ;; \
		esac; \
	fi; \
	case "$${memory%[mg]}" in \
		""|0*|*[!0-9]*) echo "$(COLOR_RED)IN_IMAGE_MEMORY must be a size in bytes, m or g, e.g. 16g: $$memory$(COLOR_RESET)" >&2; exit 2 ;; \
	esac; \
	scratch="$${IN_IMAGE_SCRATCH:-/var/tmp}"; \
	case "$$scratch" in \
		/*) ;; \
		*) echo "$(COLOR_RED)IN_IMAGE_SCRATCH must be an absolute path: $$scratch$(COLOR_RESET)" >&2; exit 2 ;; \
	esac; \
	ncpu=$$(docker info --format '{{.NCPU}}' 2>/dev/null || true); \
	case "$$ncpu" in \
		""|0|*[!0-9]*) ;; \
		*) if [ "$$ncpu" -lt "$$cpus" ]; then cpus=$$ncpu; fi ;; \
	esac; \
	uid=$(CI_TOOLCHAIN_UID); \
	name="$(CI_STACK_PREFIX)tc-$$$$-$$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"; \
	set -- --name "$$name" --cpus "$$cpus" --env GOMAXPROCS="$$cpus" \
		--memory "$$memory" --memory-swap "$$memory" --init --cap-drop ALL \
		--security-opt no-new-privileges:true --pids-limit 4096 \
		--ulimit memlock=67108864:67108864 --ulimit core=1048576:1048576 \
		--ulimit nofile=65536:65536 \
		--tmpfs /tmp:rw,exec,nosuid,nodev,size=3g,mode=1777 \
		-v "$$scratch" --env TMPDIR="$$scratch" --env GOTMPDIR="$$scratch" \
		--network "$$TR_NETWORK" --user "$$uid:$$uid" --workdir /src \
		--env HOME=/tmp --env CI="$${CI:-}"; \
	modcache=/tmp/gomodcache; \
	if [ "$$cache" = on ]; then \
		vols="$(CI_STACK_PREFIX)cache-$$class"; \
		docker run --rm --network none --cap-drop ALL --cap-add CHOWN \
			--security-opt no-new-privileges:true --user 0:0 \
			-v "$$vols-gobuild:/c/gobuild" -v "$$vols-golangci:/c/golangci" -v "$$vols-gomod:/c/gomod" \
			"$$TR_IMAGE" sh -c "for d in /c/*; do [ \"\$$(stat -c %u:%g \"\$$d\")\" = $$uid:$$uid ] || chown $$uid:$$uid \"\$$d\"; done" >/dev/null; \
		set -- "$$@" \
			-v "$$vols-gobuild:/cache/gobuild" --env GOCACHE=/cache/gobuild \
			-v "$$vols-golangci:/cache/golangci" --env GOLANGCI_LINT_CACHE=/cache/golangci; \
		if [ "$$TR_NETWORK" = bridge ]; then \
			set -- "$$@" -v "$$vols-gomod:/cache/gomod"; \
			modcache=/cache/gomod; \
		fi; \
	fi; \
	if [ "$$TR_NETWORK" = bridge ]; then \
		set -- "$$@" --env "GOPROXY=file://$(IMAGE_GOMODCACHE)/cache/download,$(CI_NETWORK_GOPROXY)" \
			--env "DEPS_CHECK_GOPROXY=$(CI_NETWORK_GOPROXY)" --env "GOMODCACHE=$$modcache" \
			--env GOPATH=/tmp/gopath; \
		for v in GOPRIVATE GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0; do \
			eval "val=\$${$$v:-}"; \
			if [ -n "$$val" ]; then set -- "$$@" --env "$$v"; fi; \
		done; \
	fi; \
	trap 'docker rm -f -v "$$name" >/dev/null 2>&1 || true' EXIT INT TERM; \
	guard='[ -d "$$TMPDIR" ] && [ -w "$$TMPDIR" ] || { echo "ci-toolchain-run: scratch directory $$TMPDIR is missing or not writable" >&2; exit 2; }'; \
	docker create "$$@" "$$TR_IMAGE" sh -c "$$guard; $$TR_CMD" >/dev/null; \
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

# Reaps stale CI stacks, containers and integration images under CI_STACK_PREFIX older than REAP_MIN_AGE, holding the image lock; never fails the job. REAP_DRY_RUN=1 only prints.
REAP_MIN_AGE ?= 11100
REAP_IMAGE_MIN_AGE ?= 7200
REAP_LOCK_WAIT ?= 60
REAP_DRY_RUN ?= 0

ci-reap-stacks: export RP_MIN_AGE := $(REAP_MIN_AGE)
ci-reap-stacks: export RP_DRY := $(REAP_DRY_RUN)
ci-reap-stacks: export RP_IMAGE_MIN_AGE := $(REAP_IMAGE_MIN_AGE)
ci-reap-stacks: export RP_LOCK_WAIT := $(REAP_LOCK_WAIT)
ci-reap-stacks: ## Remove this repository's stale CI containers, compose stacks and integration images
	@set -u; \
	prefix="$(CI_STACK_PREFIX)"; \
	case "$$RP_MIN_AGE" in \
		''|*[!0-9]*) echo "REAP_MIN_AGE must be a number of seconds: $$RP_MIN_AGE" >&2; exit 2 ;; \
	esac; \
	case "$$RP_IMAGE_MIN_AGE" in \
		''|*[!0-9]*) echo "REAP_IMAGE_MIN_AGE must be a number of seconds: $$RP_IMAGE_MIN_AGE" >&2; exit 2 ;; \
	esac; \
	case "$$RP_LOCK_WAIT" in \
			''|*[!0-9]*) echo "REAP_LOCK_WAIT must be a number of seconds: $$RP_LOCK_WAIT" >&2; exit 2 ;; \
		esac; \
	now=$$(date +%s); \
		lock="$${prefix}image-lock"; \
		lock_id=; \
		image_lock() { \
			base="$$lock:base"; i=0; \
			while [ "$$i" -lt "$$RP_LOCK_WAIT" ]; do \
				docker image inspect "$$base" >/dev/null 2>&1 || \
					head -c 1024 /dev/zero | docker import - "$$base" >/dev/null 2>&1; \
				lock_id=$$(docker create --pull never --name "$$lock" "$$base" true 2>/dev/null) && return 0; \
				lock_id=; \
				set -- $$(docker inspect -f '{{.Id}} {{.Created}}' "$$lock" 2>/dev/null); \
				if [ "$$#" -eq 2 ] && at=$$(date -d "$$2" +%s 2>/dev/null) && [ $$(($$(date +%s) - at)) -ge 600 ]; then \
					echo "lock  removing the stale $$lock (created $$2)"; \
					docker rm "$$1" >/dev/null 2>&1; \
					i=$$((i + 1)); continue; \
				fi; \
				sleep 1; i=$$((i + 1)); \
			done; \
			return 1; \
		}; \
		image_unlock() { [ -z "$$lock_id" ] || docker rm "$$lock_id" >/dev/null 2>&1; lock_id=; }; \
		trap image_unlock EXIT; \
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
	images=0; \
		refs=; \
		if [ "$$RP_DRY" = 1 ] || image_lock; then \
			refs=$$(docker images --filter "reference=$${prefix}it" --format '{{.Repository}}:{{.Tag}}'); \
		else \
			echo "keep  every $${prefix}it image (the image lock was not free within $${RP_LOCK_WAIT}s)"; \
		fi; \
		for ref in $$refs; do \
			case "$$ref" in "$${prefix}it:"*) ;; *) continue ;; esac; \
			set -- $$(docker image inspect -f '{{.Id}} {{.Created}}' "$$ref" 2>/dev/null); \
			if [ "$$#" -ne 2 ]; then \
				echo "keep  image $$ref (docker image inspect gave no id)"; \
				continue; \
			fi; \
			id=$$1; \
			t=$$(date -d "$$2" +%s 2>/dev/null) || continue; \
			tagged=$$(docker image inspect -f '{{.Metadata.LastTagTime}}' "$$ref" 2>/dev/null | sed -E 's/\.[0-9]+//; s/ [A-Z]+$$//'); \
			tagged=$$(date -d "$$tagged" +%s 2>/dev/null) || tagged=; \
			case "$$tagged" in ''|*[!0-9]*) ;; *) [ "$$tagged" -le "$$t" ] || t=$$tagged ;; esac; \
			if [ $$((now - t)) -lt "$$RP_IMAGE_MIN_AGE" ]; then \
				echo "keep  image $$ref (created or tagged within $${RP_IMAGE_MIN_AGE}s)"; \
				continue; \
			fi; \
			if ! users=$$(docker ps -a -q --filter "ancestor=$$id" 2>/dev/null); then \
				echo "keep  image $$ref (could not list the containers on $$id)"; \
				continue; \
			fi; \
			if [ -n "$$users" ]; then \
				echo "keep  image $$ref (in use: $$(echo "$$users" | wc -l) container(s) on $$id)"; \
				continue; \
			fi; \
			echo "reap  image $$ref"; \
			if run docker image rm "$$ref"; then images=$$((images + 1)); else echo "warn  image $$ref not removed (in use?)"; fi; \
		done; \
		image_unlock; \
	if [ "$$RP_DRY" = 1 ]; then done_as="would be removed"; else done_as=removed; fi; \
	echo "reaper: $$reaped compose project(s) and $$images image(s) $$done_as for prefix '$$prefix'"; \
	exit 0

# Trims the CI cache volumes while their total exceeds CI_CACHE_MAX_GIB, largest unused first; never fails the job. REAP_DRY_RUN=1 only prints.
CI_CACHE_MAX_GIB ?= 32

ci-trim-caches: export TM_IMAGE := $(TOOLCHAIN_IMAGE)
ci-trim-caches: export TM_MAX_GIB := $(CI_CACHE_MAX_GIB)
ci-trim-caches: export RP_DRY := $(REAP_DRY_RUN)
ci-trim-caches: ## Keep this repository's CI cache volumes under CI_CACHE_MAX_GIB
	@set -u; \
	prefix="$(CI_STACK_PREFIX)"; \
	max_gib="$${TM_MAX_GIB:-32}"; \
	case "$$max_gib" in \
		''|*[!0-9]*) echo "CI_CACHE_MAX_GIB must be a number: $$max_gib" >&2; exit 2 ;; \
	esac; \
	if [ -z "$$TM_IMAGE" ]; then echo "state the image: make ci-trim-caches TOOLCHAIN_IMAGE=..." >&2; exit 2; fi; \
	max_kib=$$((max_gib * 1024 * 1024)); \
	uid=$(CI_TOOLCHAIN_UID); \
	size() { \
		docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges:true \
			--user "$$uid:$$uid" -v "$$1:/c:ro" --entrypoint du "$$TM_IMAGE" -sk /c 2>/dev/null | awk '{print $$1}'; \
	}; \
	list=$$(mktemp) || { echo "warn  no list file; nothing trimmed"; exit 0; }; \
	trap 'rm -f "$$list"' EXIT; \
	total=0; \
	for vol in $$(docker volume ls -q --filter "name=$${prefix}cache-"); do \
		case "$$vol" in "$${prefix}cache-"*) ;; *) continue ;; esac; \
		kib=$$(size "$$vol"); \
		case "$$kib" in \
			''|*[!0-9]*) echo "warn  $$vol: size not read"; continue ;; \
		esac; \
		echo "$$kib $$vol" >> "$$list"; \
		total=$$((total + kib)); \
	done; \
	echo "caches: $$((total / 1024 / 1024)) GiB of $${max_gib} GiB for prefix '$$prefix'"; \
	sort -rn "$$list" | { \
		removed=0; \
		while read -r kib vol; do \
			[ "$$total" -gt "$$max_kib" ] || break; \
			if [ -n "$$(docker ps -aq --filter "volume=$$vol")" ]; then \
				echo "keep  $$vol ($$((kib / 1024)) MiB, in use)"; \
				continue; \
			fi; \
			if [ "$$RP_DRY" = 1 ]; then \
				echo "dry   docker volume rm $$vol ($$((kib / 1024)) MiB)"; \
			elif docker volume rm "$$vol" >/dev/null 2>&1; then \
				echo "trim  $$vol ($$((kib / 1024)) MiB)"; \
			else \
				echo "warn  $$vol not removed"; \
				continue; \
			fi; \
			total=$$((total - kib)); \
			removed=$$((removed + 1)); \
		done; \
		echo "trim: $$removed volume(s), $$((total / 1024 / 1024)) GiB left for prefix '$$prefix'"; \
	}; \
	exit 0

# ci-mask-lan and ci-image-history as Makefile recipes; test/makefile holds them to the template.

# ci-mask-lan prints ::add-mask:: for every private-IPv4 host in the runner's proxy, cache and registry variables.
ci-mask-lan: SHELL := /bin/bash
ci-mask-lan: .SHELLFLAGS := -euo pipefail -c
ci-mask-lan: ## Mask the LAN addresses the runner's environment names (CI, ruling 887)
	@private() { \
		case $$1 in \
		10.* | 192.168.* | 172.1[6-9].* | 172.2[0-9].* | 172.3[01].*) return 0 ;; \
		esac; \
		return 1; \
	}; \
	for v in $$(compgen -e); do \
		case $$v in \
		DEVCACHE_* | GOPROXY | CI_REGISTRY | CI_IMAGE_REGISTRY | RELEASE_REGISTRY | GITHUB_SERVER_URL) ;; \
		*) continue ;; \
		esac; \
		IFS='|, ' read -ra entries <<<"$${!v}"; \
		for entry in "$${entries[@]}"; do \
			hostport=$${entry#*://}; \
			hostport=$${hostport%%/*}; \
			host=$${hostport%%:*}; \
			private "$$host" || continue; \
			echo "::add-mask::$$entry"; \
			[ "$$hostport" = "$$entry" ] || echo "::add-mask::$$hostport"; \
			[ "$$host" = "$$hostport" ] || echo "::add-mask::$$host"; \
		done; \
	done

# ci-image-history fails when an image's history or config carries an RFC 1918 address; it names the entry, never the address.
IMAGES ?=
ci-image-history: export IH_IMAGES := $(IMAGES)
ci-image-history: SHELL := /bin/bash
ci-image-history: .SHELLFLAGS := -euo pipefail -c
ci-image-history: ## Fail when an image's history or config carries a private address (CI, ruling 888)
	@set -f; set -- $$IH_IMAGES; set +f; \
	if [ $$# -eq 0 ]; then \
		echo "usage: make ci-image-history IMAGES='<image>...'" >&2; \
		exit 2; \
	fi; \
	octet='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'; \
	private="(^|[^0-9.])(10\.$$octet|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.$$octet\.$$octet([^0-9]|\$$)"; \
	status=0; \
	for image in "$$@"; do \
		if ! history=$$(docker history --no-trunc --format '{{.CreatedBy}} {{.Comment}}' "$$image") || \
			! config=$$(docker image inspect --format '{{json .Config}}' "$$image"); then \
			echo "ci-image-history: cannot read $$image" >&2; \
			exit 1; \
		fi; \
		while IFS=: read -r entry _; do \
			echo "ci-image-history: $$image: history entry $$entry carries a private address" >&2; \
			status=1; \
		done < <(grep -En "$$private" <<<"$$history" || :); \
		if grep -Eq "$$private" <<<"$$config"; then \
			echo "ci-image-history: $$image: its config (env, labels, command) carries a private address" >&2; \
			status=1; \
		fi; \
	done; \
	exit "$$status"

# Never build through a go.work workspace.
export GOWORK=off

# Every target runs on exactly the toolchain go.mod's go directive names, read with make's own functions; override wins over make -e. TOOLCHAIN_PIN=0 opts out.
TOOLCHAIN_PIN ?= 1
GO_MOD_WORDS := $(file < go.mod)
GO_FLOOR := $(firstword $(patsubst go@%,%,$(filter go@0% go@1% go@2% go@3% go@4% go@5% go@6% go@7% go@8% go@9%,$(join $(addsuffix @,$(GO_MOD_WORDS)),$(wordlist 2,$(words $(GO_MOD_WORDS)),$(GO_MOD_WORDS)) end-of-go-mod))))
ifeq ($(TOOLCHAIN_PIN),1)
ifeq ($(GO_FLOOR),)
$(error go.mod has no `go` directive to bind the toolchain to; see the toolchain binding block in this Makefile)
endif
override export GOTOOLCHAIN := go$(GO_FLOOR)
endif

# deps-latest picks the highest tag including -alpha prereleases; release-alpha, release-candidate and release each publish one tag kind.

# AGENT_GIT is the signing wrapper every git write goes through; no default path, and the guard fails closed when it is unset.
AGENT_GIT ?= $(shell command -v agent-git.sh 2>/dev/null)

# The literal repository name: the signing identity must not follow the checkout's directory name.
REPO_NAME ?= go-luks2

# The release remote; override for a checkout that names it differently.
RELEASE_REMOTE ?= dev

# release-alpha [VERSION=vX.Y.Z-alpha], release-candidate VERSION=vX.Y.Z-rc.N, release VERSION=vX.Y.Z: one RELEASE_RECIPE, from main only, signed annotated tag, commit and tag pushed atomically, fail closed before the tag exists.
# Settable variables reach the recipe only through target-specific exports ($$REL_*), never as recipe text.

.PHONY: release release-alpha release-candidate deps-latest

# changelog-assemble folds changelog.d fragments into a new CHANGELOG.md section; review and commit it before the release target.
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

# RELEASE_RECIPE holds every guard and write; each release target expands it with its own REL_TARGET kind.
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

# release-alpha with no VERSION derives the next alpha from local and remote tags, refusing when it would not be above every existing tag, then runs RELEASE_RECIPE in a nested make.
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
