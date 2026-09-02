# syntax=docker/dockerfile:1.7
#
# Dockerfile for running go-luks2 integration tests in isolation
# This ensures tests run in a clean environment without affecting the host

FROM golang:1.26.7

# Install required system dependencies for LUKS operations
RUN apt-get update && apt-get install -y --no-install-recommends \
    util-linux \
    e2fsprogs \
    xfsprogs \
    lvm2 \
    cryptsetup-bin \
    udev \
    kmod \
    && rm -rf /var/lib/apt/lists/*

# Where the run ledgers live.
#
# This path must be BIND-MOUNTED from the host for the mechanism to work at
# all: a record that lives inside the container dies with the run it describes,
# which is the one thing it may not do. The CI invocation and the Makefile
# mount it; without a mount the image still builds and runs, and simply offers
# no protection -- which is the pre-existing behaviour, not a regression.
ENV LUKS2_TEST_STATE_DIR=/var/lib/go-luks2-test-state

# The marker declares that THIS directory -- the image's own -- does not
# outlive the container. A bind mount shadows it, so the file is visible
# exactly when the mount is absent, and the harness refuses to run.
#
# Running without persistence is worse than not running: every mapping and loop
# device the suite creates would be recorded into a file that vanishes with the
# container, while the host devices it records do not, so the host accumulates
# debris nothing can attribute and the #85 guard blocks the next run with no
# record to reap. That is the defect this image exists to prevent, reached by
# omitting a flag -- which is exactly how it was reached: two `make` targets
# ran privileged without the mount.
RUN mkdir -p /var/lib/go-luks2-test-state \
    && touch /var/lib/go-luks2-test-state/.ephemeral-not-a-persistent-mount

# Set working directory
WORKDIR /app

# Copy go module files first (for layer caching)
COPY go.mod go.sum ./

# go.mod pins a first-party module -- github.com/jeremyhahn/go-enclave, the
# portfolio locked-memory primitive -- whose module PATH says github.com while
# it is in fact served from a private module host. Resolving it needs GOPRIVATE
# plus git's insteadOf rewrite carrying a read-only token. Without that, this
# build dies on
#
#	fatal: could not read Username for 'https://github.com'
#
# because the module path says github.com and nothing here says otherwise.
#
# This repository had NO private dependency until the go-enclave adoption, so a
# bare `go mod download` was sufficient and this image never needed credentials.
# It is the first go-luks2 build to need them, which is why the gap appeared in
# CI rather than in review.
#
# The token arrives as a BuildKit SECRET, not a build arg and not an ENV: an arg
# is recorded in image metadata and readable with `docker history`, while a
# secret is mounted on tmpfs for this RUN alone and never becomes a layer. It is
# `source`d rather than exported, so the value never reaches a command line
# either -- `ps` on the build host would show that.
#
# The mount is OPTIONAL by design. Where no secret is supplied -- GitHub Actions,
# or a developer building against the public proxy -- the file is simply absent
# and the same Dockerfile still builds.
#
# GOPROXY and GOSUMDB are deliberately NOT set here, as ENV or otherwise: an
# image that bakes GOPROXY=direct/GOSUMDB=off turns checksum verification off
# for every container it spawns. That is the worst place for such a change to
# live: it hides in a Dockerfile ENV line rather than in a workflow, where
# someone reviewing the supply chain would look.
RUN --mount=type=secret,id=gomodauth \
    set -eu; \
    if [ -f /run/secrets/gomodauth ]; then . /run/secrets/gomodauth; fi; \
    go mod download

# Copy source code
COPY . .

# `go mod tidy` used to run here, after the copy, "to handle version
# differences". It is gone for two reasons. It needs the network -- so it would
# have to carry the credentials too, defeating the point of pre-fetching every
# module in the step above so the finished image needs none at run time. And it
# REWRITES go.mod inside the image, which means the artifact under test is built
# against a dependency set the repository never committed. What go.mod and
# go.sum say is what gets built.

# Build the CLI for integration tests
RUN go build -o /app/build/luks2 ./cmd/luks2

# Build the reaper the entrypoint runs BEFORE the device-mapper guard.
#
# It removes the host state a PREVIOUS run recorded and did not clean up (#96).
# The order matters and is not negotiable: the guard below refuses on any
# mapping it cannot attribute, so a reap placed after it would never execute on
# exactly the hosts that need one -- which is the deadlock #96 describes, where
# one failed run poisons a runner until a human clears it by hand.
RUN go build -o /usr/local/bin/luks2-testreap ./test/harness/cmd/luks2-testreap

# Create entrypoint script for flexible test execution
RUN echo '#!/bin/bash' > /entrypoint.sh && \
    echo 'set -e' >> /entrypoint.sh && \
    echo '' >> /entrypoint.sh && \
    echo '# Start udevd for device-mapper symlink creation' >> /entrypoint.sh && \
    echo '/usr/lib/systemd/systemd-udevd --daemon 2>/dev/null || true' >> /entrypoint.sh && \
    echo 'sleep 1' >> /entrypoint.sh && \
    echo 'udevadm trigger 2>/dev/null || true' >> /entrypoint.sh && \
    echo 'udevadm settle 2>/dev/null || true' >> /entrypoint.sh && \
    echo '' >> /entrypoint.sh && \
    echo '# NO GLOBAL DEVICE CLEANUP HERE. This block used to run' >> /entrypoint.sh && \
    echo '# a global device-mapper wipe and a global loop detach, both with' >> /entrypoint.sh && \
    echo '# their errors discarded.' >> /entrypoint.sh && \
    echo '# device-mapper and loop devices are NOT namespaced, and this' >> /entrypoint.sh && \
    echo '# container runs --privileged, so both commands operated on the HOST:' >> /entrypoint.sh && \
    echo '# every dm mapping and every loop device on the machine running the' >> /entrypoint.sh && \
    echo '# suite, including a developer root filesystem (nvme0n1p3_crypt ->' >> /entrypoint.sh && \
    echo '# vgmint-root, measured 2026-08-31). It survived only because those' >> /entrypoint.sh && \
    echo '# devices were busy: DM_DEV_REMOVE returned EBUSY and "|| true" ate it.' >> /entrypoint.sh && \
    echo '# A host where they are not busy loses them, silently.' >> /entrypoint.sh && \
    echo '#' >> /entrypoint.sh && \
    echo '# Tests own their own teardown and remove only what they created.' >> /entrypoint.sh && \
    echo '# A suite must never destroy state it did not make.' >> /entrypoint.sh && \
    echo '' >> /entrypoint.sh && \
    echo '# REAP FIRST, GUARD SECOND. The reaper removes only what a previous' >> /entrypoint.sh && \
    echo '# run RECORDED, and only where the live resource still carries the' >> /entrypoint.sh && \
    echo '# recorded identity -- see test/harness. It has no sweep and no name' >> /entrypoint.sh && \
    echo '# pattern, so a host carrying state this suite never recorded is left' >> /entrypoint.sh && \
    echo '# exactly as found and the guard below still decides whether running' >> /entrypoint.sh && \
    echo '# is safe. Running it AFTER the guard would be useless: the guard' >> /entrypoint.sh && \
    echo '# refuses on precisely the debris the reaper exists to remove.' >> /entrypoint.sh && \
    echo '#' >> /entrypoint.sh && \
    echo '# No "|| true". A reaper that cannot finish leaves the host in an' >> /entrypoint.sh && \
    echo '# unknown state, and a suite that runs anyway reports whatever it' >> /entrypoint.sh && \
    echo '# finds there as a test result.' >> /entrypoint.sh && \
    echo 'if ! luks2-testreap; then' >> /entrypoint.sh && \
    echo '  echo "REFUSING TO RUN: recorded host state from a previous run could" >&2' >> /entrypoint.sh && \
    echo '  echo "not be removed, so this host is not known to be clean." >&2' >> /entrypoint.sh && \
    echo '  exit 1' >> /entrypoint.sh && \
    echo 'fi' >> /entrypoint.sh && \
    echo '' >> /entrypoint.sh && \
    echo '# Refuse to run if the host device-mapper is visible with mappings we' >> /entrypoint.sh && \
    echo '# did not create. This guard FAILS CLOSED: an inventory it cannot take' >> /entrypoint.sh && \
    echo '# is not evidence of an empty host. An earlier draft ended the pipeline' >> /entrypoint.sh && \
    echo '# in "|| true" and defaulted the count to 0, so a failing dmsetup meant' >> /entrypoint.sh && \
    echo '# "no mappings" and the suite proceeded exactly when the guard could not' >> /entrypoint.sh && \
    echo '# verify it was safe -- the same swallow-the-error defect this change' >> /entrypoint.sh && \
    echo '# exists to remove, reintroduced in the fix for it.' >> /entrypoint.sh && \
    echo 'if ! command -v dmsetup >/dev/null 2>&1; then' >> /entrypoint.sh && \
    echo '  echo "REFUSING TO RUN: dmsetup is absent, so the host device-mapper" >&2' >> /entrypoint.sh && \
    echo '  echo "cannot be inspected and this suite cannot confirm it is safe." >&2' >> /entrypoint.sh && \
    echo '  exit 1' >> /entrypoint.sh && \
    echo 'fi' >> /entrypoint.sh && \
    echo 'if ! dm_inventory=$(dmsetup ls 2>&1); then' >> /entrypoint.sh && \
    echo '  echo "REFUSING TO RUN: could not inventory the device-mapper state:" >&2' >> /entrypoint.sh && \
    echo '  echo "${dm_inventory}" >&2' >> /entrypoint.sh && \
    echo '  exit 1' >> /entrypoint.sh && \
    echo 'fi' >> /entrypoint.sh && \
    echo 'case "${dm_inventory}" in' >> /entrypoint.sh && \
    echo '  "No devices found"*|"") ;;' >> /entrypoint.sh && \
    echo '  *)' >> /entrypoint.sh && \
    echo '    echo "REFUSING TO RUN: the host device-mapper is visible from this" >&2' >> /entrypoint.sh && \
    echo '    echo "container and already has mappings this suite did not create:" >&2' >> /entrypoint.sh && \
    echo '    echo "${dm_inventory}" >&2' >> /entrypoint.sh && \
    echo '    echo "Running here risks the host. Scope the container device" >&2' >> /entrypoint.sh && \
    echo '    echo "access (see issue #80) or run where there is no dm state." >&2' >> /entrypoint.sh && \
    echo '    exit 1' >> /entrypoint.sh && \
    echo '    ;;' >> /entrypoint.sh && \
    echo 'esac' >> /entrypoint.sh && \
    echo '' >> /entrypoint.sh && \
    echo '# Default: run all integration tests with coverage' >> /entrypoint.sh && \
    echo 'if [ "$#" -eq 0 ]; then' >> /entrypoint.sh && \
    echo '    echo "Running all integration tests with coverage..."' >> /entrypoint.sh && \
    echo '    # Run package integration tests (in pkg/luks2)' >> /entrypoint.sh && \
    echo '    go test -v -tags=integration -coverprofile=/tmp/coverage-pkg.out -covermode=atomic ./pkg/luks2' >> /entrypoint.sh && \
    echo '    # Run new integration tests (in test/integration/pkg)' >> /entrypoint.sh && \
    echo '    # No `|| true` on any of these three: a suite that cannot fail the' >> /entrypoint.sh && \
    echo '    # job is not a gate (#25). Both trailing suites carried one, and the' >> /entrypoint.sh && \
    echo '    # CLI suite had in fact been failing the whole time.' >> /entrypoint.sh && \
    echo '    go test -v -tags=integration -coverprofile=/tmp/coverage-int-pkg.out -covermode=atomic ./test/integration/pkg/...' >> /entrypoint.sh && \
    echo '    # Run CLI integration tests (in test/integration/cli)' >> /entrypoint.sh && \
    echo '    go test -v -tags=integration -coverprofile=/tmp/coverage-int-cli.out -covermode=atomic ./test/integration/cli/...' >> /entrypoint.sh && \
    echo '    # Merge coverage files' >> /entrypoint.sh && \
    echo '    echo "mode: atomic" > /tmp/coverage.out' >> /entrypoint.sh && \
    echo '    grep -v "^mode:" /tmp/coverage-pkg.out >> /tmp/coverage.out 2>/dev/null || true' >> /entrypoint.sh && \
    echo '    grep -v "^mode:" /tmp/coverage-int-pkg.out >> /tmp/coverage.out 2>/dev/null || true' >> /entrypoint.sh && \
    echo '    grep -v "^mode:" /tmp/coverage-int-cli.out >> /tmp/coverage.out 2>/dev/null || true' >> /entrypoint.sh && \
    echo '    cp /tmp/coverage.out /app/coverage.out 2>/dev/null || true' >> /entrypoint.sh && \
    echo '    echo ""' >> /entrypoint.sh && \
    echo '    echo "Coverage Summary:"' >> /entrypoint.sh && \
    echo '    go tool cover -func=/tmp/coverage.out | tail -1' >> /entrypoint.sh && \
    echo 'else' >> /entrypoint.sh && \
    echo '    exec "$@"' >> /entrypoint.sh && \
    echo 'fi' >> /entrypoint.sh && \
    chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
