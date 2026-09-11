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
    echo '# Create the loop device nodes this container may be handed.' >> /entrypoint.sh && \
    echo '#' >> /entrypoint.sh && \
    echo '# /dev in here is a bare tmpfs. The container is no longer --privileged,' >> /entrypoint.sh && \
    echo '# so the host /dev is not bind-mounted in and nothing creates /dev/loopN' >> /entrypoint.sh && \
    echo '# for us. udev cannot do it either: without --privileged Docker mounts' >> /entrypoint.sh && \
    echo '# /sys read-only, udevadm trigger fails to write the uevent and no node is' >> /entrypoint.sh && \
    echo '# ever made -- measured, which is why the udevd start that used to be here' >> /entrypoint.sh && \
    echo '# is gone rather than moved. Nothing is lost with it: pkg/luks2 mknods its' >> /entrypoint.sh && \
    echo '# own dm nodes (unlock.go), the fallback it has always carried for' >> /entrypoint.sh && \
    echo '# environments without udev, and cryptsetup skips the udev cookie wait' >> /entrypoint.sh && \
    echo '# when no udevd is running.' >> /entrypoint.sh && \
    echo '#' >> /entrypoint.sh && \
    echo '# A POOL, not an exact answer, because the number is not knowable in' >> /entrypoint.sh && \
    echo '# advance: pkg/luks2 opens /dev/loopN for the N that LOOP_CTL_GET_FREE' >> /entrypoint.sh && \
    echo '# hands back, so the node has to exist before the number is known.' >> /entrypoint.sh && \
    echo '#' >> /entrypoint.sh && \
    echo '# 256 is a ceiling on the MINOR a runner may hand out, not a count of what' >> /entrypoint.sh && \
    echo '# this suite uses -- it uses a handful. LOOP_CTL_GET_FREE returns the' >> /entrypoint.sh && \
    echo '# first FREE device and only allocates past the highest existing one when' >> /entrypoint.sh && \
    echo '# every one of them is busy, so the pool has to clear whatever a shared' >> /entrypoint.sh && \
    echo '# runner already has attached, which on Ubuntu is one loop per snap. A' >> /entrypoint.sh && \
    echo '# node above what the kernel has created costs nothing and is not a lie:' >> /entrypoint.sh && \
    echo '# the loop module creates the device on first open (measured on 6.17 with' >> /entrypoint.sh && \
    echo '# /dev/loop200).' >> /entrypoint.sh && \
    echo 'for minor in $(seq 0 255); do' >> /entrypoint.sh && \
    echo '  if [ ! -e /dev/loop$minor ] && ! mknod /dev/loop$minor b 7 $minor; then' >> /entrypoint.sh && \
    echo '    echo "REFUSING TO RUN: cannot create /dev/loop$minor, so this suite" >&2' >> /entrypoint.sh && \
    echo '    echo "cannot attach a backing file to anything. The container needs" >&2' >> /entrypoint.sh && \
    echo '    echo "CAP_MKNOD and a device-cgroup rule for major 7; both are set by" >&2' >> /entrypoint.sh && \
    echo '    echo "test/integration/docker-run.sh, which is the supported way to" >&2' >> /entrypoint.sh && \
    echo '    echo "start this image." >&2' >> /entrypoint.sh && \
    echo '    exit 1' >> /entrypoint.sh && \
    echo '  fi' >> /entrypoint.sh && \
    echo 'done' >> /entrypoint.sh && \
    echo '' >> /entrypoint.sh && \
    echo '# NO GLOBAL DEVICE CLEANUP HERE. This block used to run' >> /entrypoint.sh && \
    echo '# a global device-mapper wipe and a global loop detach, both with' >> /entrypoint.sh && \
    echo '# their errors discarded.' >> /entrypoint.sh && \
    echo '# device-mapper and loop devices are NOT namespaced, so both' >> /entrypoint.sh && \
    echo '# commands operated on the HOST -- and still would today. Dropping' >> /entrypoint.sh && \
    echo '# --privileged (#80) did not change this: scoping the device access' >> /entrypoint.sh && \
    echo '# decides which nodes are reachable, not which kernel the dm and' >> /entrypoint.sh && \
    echo '# loop subsystems belong to, and there is only the one:' >> /entrypoint.sh && \
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
    echo '# Refuse to run only if the host device-mapper already has a mapping' >> /entrypoint.sh && \
    echo '# this suite could actually collide with by name. This guard FAILS' >> /entrypoint.sh && \
    echo '# CLOSED: an inventory it cannot take is not evidence of an empty host.' >> /entrypoint.sh && \
    echo '# An earlier draft ended the pipeline in "|| true" and defaulted the' >> /entrypoint.sh && \
    echo '# count to 0, so a failing dmsetup meant "no mappings" and the suite' >> /entrypoint.sh && \
    echo '# proceeded exactly when the guard could not verify it was safe -- the' >> /entrypoint.sh && \
    echo '# same swallow-the-error defect this change exists to remove,' >> /entrypoint.sh && \
    echo '# reintroduced in the fix for it.' >> /entrypoint.sh && \
    echo '#' >> /entrypoint.sh && \
    echo '# It used to refuse on ANY pre-existing mapping (#162), because this' >> /entrypoint.sh && \
    echo '# entrypoint also ran the global device-mapper wipe described above --' >> /entrypoint.sh && \
    echo '# with the whole host in scope for removal, every mapping was a risk.' >> /entrypoint.sh && \
    echo '# That global wipe is gone: tests own their own teardown and remove only' >> /entrypoint.sh && \
    echo '# the name they created, and the reaper above removes only what a' >> /entrypoint.sh && \
    echo '# previous run recorded. With the global wipe gone, the only way this' >> /entrypoint.sh && \
    echo '# suite can still touch a mapping it did not make is a NAME COLLISION:' >> /entrypoint.sh && \
    echo '# Lock() and the CLI "close" command remove /dev/mapper/<name> by name,' >> /entrypoint.sh && \
    echo '# and MakeFilesystem/Mount operate on it directly, so a pre-existing' >> /entrypoint.sh && \
    echo '# mapping that happens to share a name this suite uses would be touched' >> /entrypoint.sh && \
    echo '# by a teardown or a filesystem op that believes it owns that name. A' >> /entrypoint.sh && \
    echo '# pre-existing mapping with an unrelated name -- e.g. a runners own' >> /entrypoint.sh && \
    echo '# root, ubuntu--vg-ubuntu--lv -- carries none of that risk, and refusing' >> /entrypoint.sh && \
    echo '# on it anyway is exactly the over-broad check #162 reports: it fails' >> /entrypoint.sh && \
    echo '# every LVM-root runner for a reason never in the diff.' >> /entrypoint.sh && \
    echo '#' >> /entrypoint.sh && \
    echo '# The families below were derived by grepping every literal' >> /entrypoint.sh && \
    echo '# device-mapper/volume name the suite uses -- pkg/luks2/*_integration_' >> /entrypoint.sh && \
    echo '# test.go and test/integration/{pkg,cli} -- as of the #162 fix. Nearly' >> /entrypoint.sh && \
    echo '# all of them share one of four prefixes; the one that does not is' >> /entrypoint.sh && \
    echo '# listed by itself:' >> /entrypoint.sh && \
    echo '#' >> /entrypoint.sh && \
    echo '#   test*             every runVolume(t, "test-...") base (test-fs-ext4,' >> /entrypoint.sh && \
    echo '#                     test-mount, test-unlock, test-wrong-pass, ...), the' >> /entrypoint.sh && \
    echo '#                     bare "test" literal, and the test/integration names' >> /entrypoint.sh && \
    echo '#                     issue #162s follow-up will make run-unique' >> /entrypoint.sh && \
    echo '#                     (test-keyring, test-workflow, test-cli-workflow,' >> /entrypoint.sh && \
    echo '#                     test-cli-open, test-kdf-<case>, test-volume)' >> /entrypoint.sh && \
    echo '#   luks-*            every runVolume(t, "luks-...") base (luks-rapid,' >> /entrypoint.sh && \
    echo '#                     luks-concurrent, luks-large, luks-ismounted, ...)' >> /entrypoint.sh && \
    echo '#   nonexistent*      negative-path fixtures ("nonexistent-volume",' >> /entrypoint.sh && \
    echo '#                     "nonexistent-volume-12345", "nonexistent")' >> /entrypoint.sh && \
    echo '#   definitely-not-a* CLI negative-path fixtures' >> /entrypoint.sh && \
    echo '#                     ("definitely-not-a-volume-12345",' >> /entrypoint.sh && \
    echo '#                     "definitely-not-a-real-volume")' >> /entrypoint.sh && \
    echo '#   myvolume          the one CLI usage-error fixture that fits no other' >> /entrypoint.sh && \
    echo '#                     family (test/integration/cli/cli_test.go)' >> /entrypoint.sh && \
    echo '#' >> /entrypoint.sh && \
    echo '# A mapping matches when its name equals one of these, or starts with' >> /entrypoint.sh && \
    echo '# one of the "*" prefixes -- the shape runVolume(t, base) produces at' >> /entrypoint.sh && \
    echo '# test run time is "<base>-<run-suffix>". This is an ALLOWLIST OF NAMES,' >> /entrypoint.sh && \
    echo '# not of mappings: it says which names to refuse over, never which' >> /entrypoint.sh && \
    echo '# mappings to touch -- a match still only refuses, it is never removed' >> /entrypoint.sh && \
    echo '# or modified here.' >> /entrypoint.sh && \
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
    echo '    while IFS= read -r dm_line; do' >> /entrypoint.sh && \
    echo '      [ -z "${dm_line}" ] && continue' >> /entrypoint.sh && \
    echo '      # Parameter expansion, NOT `set --`. `set --` would overwrite' >> /entrypoint.sh && \
    echo '      # THIS SCRIPTs positional parameters, and the dispatch at the' >> /entrypoint.sh && \
    echo '      # bottom branches on "$#" and then runs `exec "$@"`. Clobbering' >> /entrypoint.sh && \
    echo '      # them here made a host carrying ANY non-colliding mapping -- an' >> /entrypoint.sh && \
    echo '      # LVM root, the exact case this allowlist exists to let through --' >> /entrypoint.sh && \
    echo '      # take the exec branch and try to run the mapping name as a' >> /entrypoint.sh && \
    echo '      # command, so the suite silently ran NOTHING instead of running.' >> /entrypoint.sh && \
    echo '      # Measured before the fix: "$#" became 2 and "$@" became the' >> /entrypoint.sh && \
    echo '      # mapping name and its major:minor.' >> /entrypoint.sh && \
    echo '      dm_name="${dm_line%%[[:space:]]*}"' >> /entrypoint.sh && \
    echo '      case "${dm_name}" in' >> /entrypoint.sh && \
    echo '        test*|luks-*|nonexistent*|definitely-not-a*|myvolume)' >> /entrypoint.sh && \
    echo '          echo "REFUSING TO RUN: the host device-mapper already has a" >&2' >> /entrypoint.sh && \
    echo '          echo "mapping this suite could collide with by name:" >&2' >> /entrypoint.sh && \
    echo '          echo "  ${dm_line}" >&2' >> /entrypoint.sh && \
    echo '          echo "\"${dm_name}\" matches a name this suite creates or" >&2' >> /entrypoint.sh && \
    echo '          echo "touches (see the comment above this guard for the" >&2' >> /entrypoint.sh && \
    echo '          echo "derivation), so a teardown or filesystem op that" >&2' >> /entrypoint.sh && \
    echo '          echo "believes it owns that name would touch this" >&2' >> /entrypoint.sh && \
    echo '          echo "pre-existing mapping instead. Run where no mapping" >&2' >> /entrypoint.sh && \
    echo '          echo "shares a name this suite uses." >&2' >> /entrypoint.sh && \
    echo '          exit 1' >> /entrypoint.sh && \
    echo '          ;;' >> /entrypoint.sh && \
    echo '      esac' >> /entrypoint.sh && \
    echo '    done <<< "${dm_inventory}"' >> /entrypoint.sh && \
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
