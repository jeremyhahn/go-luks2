# syntax=docker/dockerfile:1.7
#
# The devcontainer image: the ONE image every CI stage runs in (devcontainer.md
# §1). There is no other CI image.
#
#   base         the Go toolchain pinned by digest, the system tools the suite
#                drives, a non-root user and the module cache.
#   tools        build-only: fetches the pinned tools. Nothing from it ships
#                except the binaries the toolchain stage copies out.
#   toolchain    base + the pinned tools + make, bash, git, jq. build, test,
#                lint, security and deps-check run here
#                (`make toolchain-run CMD=...`), and it is the VS Code
#                devcontainer (.devcontainer/devcontainer.json).
#   integration  base + the source: the privileged integration suite
#                (`make integration-test`). Built FROM base, never from
#                toolchain, so no dev tool ships into the image that runs with
#                device access.
#
# Tool versions come from tool-pins.env next to this file, which the Makefile
# includes too: one pin, read by both (devcontainer.md §2).

# golang:1.27.2, by digest: a tag can be re-pointed, a digest cannot. Raise the
# version and the digest together, with go.mod's go directive.
ARG GO_IMAGE=golang:1.27.2@sha256:820153096fda4de6ac1b7194d12e416b7dd8f4e9a33d17e0345b111b945162d8

# ---- base ----
FROM ${GO_IMAGE} AS base

# The system tools the library drives and the suite inspects: cryptsetup for
# the cryptsetup-compatibility tests, the mkfs tools, dmsetup (lvm2) and
# losetup (util-linux). The digest pins Go, not the Debian packages under it:
# the upgrade takes the Debian security fixes that trivy image gates on
# (fixable HIGH and CRITICAL findings).
RUN apt-get update && apt-get upgrade -y --no-install-recommends && apt-get install -y --no-install-recommends \
    util-linux \
    e2fsprogs \
    xfsprogs \
    lvm2 \
    cryptsetup-bin \
    udev \
    kmod \
    && rm -rf /var/lib/apt/lists/*

ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID
RUN groupadd --gid $USER_GID $USERNAME && \
    useradd --uid $USER_UID --gid $USER_GID -m $USERNAME

# GOWORK=off so a stray go.work cannot change what is built; GOFLAGS so
# nothing run in the image rewrites go.mod. -buildvcs=false because stamping
# the main module's version from its git tags writes a stat cache into the
# module cache, which is root's and only readable to the uid a stage runs as;
# the binary's version comes from -X main.version, not from the stamp.
ENV GOWORK=off \
    GOFLAGS="-mod=readonly -buildvcs=false" \
    GOTOOLCHAIN=local

WORKDIR /workspace

# The module cache, filled once at build time so nothing run in the image
# needs the network to build or test.
#
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
# The token arrives as a BuildKit SECRET, not a build arg and not an ENV: an arg
# is recorded in image metadata and readable with `docker history`, while a
# secret is mounted on tmpfs for this RUN alone and never becomes a layer. It is
# `source`d rather than exported, so the value never reaches a command line
# either -- `ps` on the build host would show that. `set -a` exports what it
# assigns, so the file may hold plain KEY=value lines (the CI workflow's
# MODULE_ENV_FILE) or `export` lines (the Makefile's own staging).
#
# The mount is OPTIONAL by design. Where no secret is supplied -- GitHub Actions,
# or a developer building against the public proxy -- the file is simply absent
# and the same Dockerfile still builds.
#
# GO_BUILD_PROXY is the module proxy for build-time fetches (devcontainer.md
# §4): an ARG, so it applies to the fetch alone and is not baked into the
# image. GOSUMDB is deliberately NOT changed, as ENV or otherwise: an image
# that bakes GOSUMDB=off turns checksum verification off for every container
# it spawns. The cache is made readable to every uid, because the image runs
# as whatever uid owns the checkout (devcontainer.md §5).
COPY go.mod go.sum ./
ARG GO_BUILD_PROXY
RUN --mount=type=secret,id=gomodauth \
    set -eu; \
    if [ -f /run/secrets/gomodauth ]; then set -a; . /run/secrets/gomodauth; set +a; fi; \
    if [ -n "${GO_BUILD_PROXY:-}" ]; then export GOPROXY="$GO_BUILD_PROXY"; fi; \
    go mod download; \
    chmod -R a+rX "$(go env GOMODCACHE)"

# ---- tools (build-only) ----
FROM base AS tools

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Every version is the pin file's. gosec takes its version string from
# ldflags, not from the module path, so the -X flag is what makes it
# self-report the pin that ci.yml asserts (#21). gosec builds in a throwaway
# module so x/tools can be raised to XTOOLS_VERSION (see tool-pins.env); the
# others build with the x/tools their go.mod names. gopls is the language server
# devcontainer.json enables; the toolchain stage sets GOPROXY=off, so an
# editor could not fetch it later. trivy is installed by the
# Makefile's own trivy-install, so the image and a developer verify the same
# archive and binary hashes the same way.
COPY Makefile go.mod /src/
COPY build/docker/devcontainer/tool-pins.env /src/build/docker/devcontainer/
ARG GO_BUILD_PROXY
RUN set -eu; \
    cd /src; \
    . build/docker/devcontainer/tool-pins.env; \
    if [ -n "${GO_BUILD_PROXY:-}" ]; then export GOPROXY="$GO_BUILD_PROXY"; fi; \
    export GOBIN=/opt/tools/bin GOFLAGS=; \
    go install "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_LINT_VERSION}"; \
    ( d="$(mktemp -d)"; cd "$d"; \
      go mod init gosec-build; \
      go get "github.com/securego/gosec/v2/cmd/gosec@${GOSEC_VERSION}" "golang.org/x/tools@${XTOOLS_VERSION}"; \
      go install -ldflags "-X main.Version=${GOSEC_VERSION}" github.com/securego/gosec/v2/cmd/gosec; \
      cd /; rm -rf "$d" ); \
    go install "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}"; \
    go install "github.com/rhysd/actionlint/cmd/actionlint@${ACTIONLINT_VERSION}"; \
    go install "golang.org/x/tools/gopls@${GOPLS_VERSION}"; \
    make --no-print-directory trivy-install TOOLS_DIR=/opt/tools/trivy; \
    install -m 0755 "/opt/tools/trivy/trivy-${TRIVY_VERSION}/trivy" /opt/tools/bin/trivy

# ---- toolchain ----
FROM base AS toolchain

# make ships in the Go image already; jq, git and bash are asserted here
# rather than assumed. shellcheck is what actionlint runs over the workflows'
# shell steps: without it actionlint skips them silently. sudo is for the VS
# Code devcontainer's integration-test-setup guard below.
#
# curl, libcurl4t64 and libcurl3t64-gnutls come with the Go base image, and this
# image keeps all three: it is also the devcontainer, where `make trivy-install`
# downloads the pinned trivy with curl, and git fetches the first-party module
# over https through libcurl3t64-gnutls. They are taken at Debian's current
# security update in this layer, and the build fails if any of them is missing
# or older than 8.14.1-2+deb13u7, the first release that fixes CVE-2026-8286
# and CVE-2026-8927. The base image is pinned by digest; the packages, like
# every apt install here, are Debian's at build time, and the floor keeps a
# rebuild from shipping an older curl.
RUN set -eu; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      make \
      bash \
      git \
      jq \
      shellcheck \
      sudo \
      curl \
      libcurl4t64 \
      libcurl3t64-gnutls; \
    rm -rf /var/lib/apt/lists/*; \
    for p in curl libcurl4t64 libcurl3t64-gnutls; do \
      v="$(dpkg-query -W -f '${Version}' "$p")" || { echo "$p is not installed" >&2; exit 1; }; \
      dpkg --compare-versions "$v" ge 8.14.1-2+deb13u7 || { echo "$p $v predates the curl security fixes" >&2; exit 1; }; \
    done; \
    for c in make bash git jq shellcheck sudo curl; do \
      command -v "$c" >/dev/null || { echo "$c is not installed" >&2; exit 1; }; \
    done

COPY --from=tools /opt/tools/bin/ /usr/local/bin/

RUN echo "$USERNAME ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/$USERNAME && \
    chmod 0440 /etc/sudoers.d/$USERNAME

# Entrypoint wrapper for running the integration suite in this devcontainer.
#
# This block used to end with `dmsetup remove_all` and `losetup -D`, both with
# their errors discarded, under the heading "Clean up any leftover state". It
# was the FOURTH call site of that pattern in this repository (#17) and the one
# the fix for the other three did not reach — this file is not part of the CI
# image, so nothing that looked at CI saw it.
#
# Neither device-mapper nor loop devices are namespaced. A devcontainer running
# this suite is privileged, so both commands operated on the HOST: every dm
# mapping and every loop device on the developer's own machine, including the
# mapping under their root filesystem. It survived only because those devices
# were busy — DM_DEV_REMOVE returned EBUSY and `|| true` ate it. A machine
# where they are not busy loses them, silently, and it is the developer's
# machine rather than a runner.
#
# Tests own their own teardown and remove only what they created. What replaces
# the cleanup is the same refusal the CI integration image uses, so a developer
# and a runner behave identically: if the host device-mapper is visible with
# mappings this suite did not create, running here risks the host, and the
# right answer is to stop rather than to tidy.
#
# The guard FAILS CLOSED. An inventory it cannot take is not evidence of an
# empty host — defaulting an unreadable `dmsetup ls` to "no mappings" would
# proceed exactly when the guard could not confirm it was safe, which is the
# same swallow-the-error defect this change removes.
RUN printf '%s\n' \
    '#!/bin/bash' \
    'set -e' \
    '' \
    '# Start udevd for device-mapper symlink creation' \
    '/usr/lib/systemd/systemd-udevd --daemon 2>/dev/null || true' \
    'sleep 1' \
    'udevadm trigger 2>/dev/null || true' \
    'udevadm settle 2>/dev/null || true' \
    '' \
    '# NO GLOBAL DEVICE CLEANUP. A suite must never destroy state it did not' \
    '# make; see the comment in .devcontainer/Dockerfile for what was here.' \
    'if ! command -v dmsetup >/dev/null 2>&1; then' \
    '  echo "REFUSING TO RUN: dmsetup is absent, so the host device-mapper" >&2' \
    '  echo "cannot be inspected and this suite cannot confirm it is safe." >&2' \
    '  exit 1' \
    'fi' \
    'if ! dm_inventory=$(dmsetup ls 2>&1); then' \
    '  echo "REFUSING TO RUN: could not inventory the device-mapper state:" >&2' \
    '  echo "${dm_inventory}" >&2' \
    '  exit 1' \
    'fi' \
    'case "${dm_inventory}" in' \
    '  "No devices found"*|"") ;;' \
    '  *)' \
    '    echo "REFUSING TO RUN: the host device-mapper is visible from this" >&2' \
    '    echo "container and already has mappings this suite did not create:" >&2' \
    '    echo "${dm_inventory}" >&2' \
    '    echo "Running here risks your machine. Run the suite where there is" >&2' \
    '    echo "no host dm state, or scope this container device access." >&2' \
    '    exit 1' \
    '    ;;' \
    'esac' \
    '' \
    'exec "$@"' \
    > /usr/local/bin/integration-test-setup && \
    chmod +x /usr/local/bin/integration-test-setup

# Where CI copies the checkout (`make ci-toolchain-run`): a runner's daemon
# cannot bind-mount it, so it is streamed in, owned by the uid the stage runs
# as. The directory must already be that uid's for the stage to write in it.
RUN install -d -m 0755 -o 10001 -g 10001 /src

# Every fetch is done (devcontainer.md §4). A tool that reaches for the
# network from here on fails instead of fetching something unpinned; make
# deps-check, the one target that must ask a module host, is handed a proxy
# explicitly (DEPS_CHECK_GOPROXY). The image runs as any uid with HOME=/tmp
# (§5); the named user is the VS Code devcontainer's.
#
# GOCACHE is keyed by the Go version. The build cache holds export data in the
# format of the Go that wrote it, and a reader older than that format fails on
# every import, so a cache directory is never shared between two Gos. Go
# creates it on first use, owned by the uid that runs and not world-writable.
ENV GOPROXY=off \
    TOOLS_REQUIRED=1 \
    GOCACHE=/tmp/.cache/go-build-go${GOLANG_VERSION}

# Prove the image is what the Makefile and CI assume, or fail the build:
# GOLANG_VERSION is the Go that runs, GOCACHE is keyed by it, the module cache
# is where ci-toolchain-run reads it from, and gosec was built by this Go
# against XTOOLS_VERSION, so it reads the export data this Go writes.
RUN --mount=type=bind,source=build/docker/devcontainer/tool-pins.env,target=/tmp/tool-pins.env \
    set -eu; \
    . /tmp/tool-pins.env; \
    gover="$(go env GOVERSION)"; \
    test "$gover" = "go${GOLANG_VERSION}" || { echo "go reports $gover, the image names go${GOLANG_VERSION}" >&2; exit 1; }; \
    test "$(go env GOCACHE)" = "/tmp/.cache/go-build-$gover" || { echo "GOCACHE $(go env GOCACHE) is not keyed by $gover" >&2; exit 1; }; \
    test "$(go env GOMODCACHE)" = /go/pkg/mod || { echo "GOMODCACHE $(go env GOMODCACHE) is not /go/pkg/mod" >&2; exit 1; }; \
    built="$(go version -m "$(command -v gosec)")"; \
    printf '%s\n' "$built" | head -n 1 | grep -qx ".*: $gover" || { echo "gosec was not built by $gover" >&2; exit 1; }; \
    printf '%s\n' "$built" | grep -Eq "^[[:space:]]+dep[[:space:]]+golang\.org/x/tools[[:space:]]+${XTOOLS_VERSION}[[:space:]]" || { echo "gosec is not built against golang.org/x/tools ${XTOOLS_VERSION}" >&2; exit 1; }; \
    echo "gosec: built by $gover against golang.org/x/tools ${XTOOLS_VERSION}"
USER $USERNAME

# ---- integration ----
FROM base AS integration

# strace is a test instrument, not a dependency of the library: it delays one
# of cryptsetup's own syscalls so a test can make real cryptsetup hold its
# metadata lock on cue (pkg/luks2/unlockreadlock_integration_test.go).
#
# curl, libcurl and git come with the Go base image, which ships them to fetch
# modules, and nothing in this image uses them: the modules are baked into the
# cache, GOPROXY is off and -buildvcs=false, so the go command never calls git
# and the suite never fetches. They are purged in this layer, so the image that
# runs with device access carries no HTTP client and none of its advisories.
# Purging libcurl3t64-gnutls takes git with it, which depends on it. The build
# fails if any of them is still installed, or if the purge took a tool the
# suite drives.
RUN set -eu; \
    apt-get update; \
    apt-get install -y --no-install-recommends strace; \
    apt-get purge -y --auto-remove curl libcurl4t64 libcurl3t64-gnutls; \
    rm -rf /var/lib/apt/lists/*; \
    if dpkg-query -W -f '${db:Status-Abbrev} ${Package}\n' curl 'libcurl*' git 2>/dev/null | grep -q '^ii'; then \
      echo "curl, libcurl or git is still installed" >&2; exit 1; \
    fi; \
    for c in go cryptsetup dmsetup losetup mkfs.ext4 mkfs.xfs udevadm modprobe strace; do \
      command -v "$c" >/dev/null || { echo "purging curl removed $c" >&2; exit 1; }; \
    done

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

# The suite runs as root: it creates loop nodes, dm mappings and filesystems.
WORKDIR /app

# The modules are already in the cache (base). `go mod tidy` used to run here,
# after the copy, "to handle version differences". It is gone for two reasons.
# It needs the network -- so it would have to carry the credentials too,
# defeating the point of pre-fetching every module so the finished image needs
# none at run time. And it REWRITES go.mod inside the image, which means the
# artifact under test is built against a dependency set the repository never
# committed. What go.mod and go.sum say is what gets built.
COPY . .
ENV GOPROXY=off

# Build the CLI for integration tests
RUN go build -o /app/build/luks2 ./cmd/luks2

# Build the reaper the entrypoint runs BEFORE the device-mapper guard.
#
# It removes the host state a PREVIOUS run recorded and did not clean up (#96).
# The order matters and is not negotiable: the guard below refuses on any
# mapping it cannot attribute, so a reap placed after it would never execute on
# exactly the hosts that need one -- which is the deadlock #96 describes, where
# one failed run poisons a runner until a human clears it by hand.
RUN go build -o /usr/local/bin/luks2-testreap ./test/tools/luks2-testreap

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
    echo '    echo "test/tools/docker-run, which is the supported way to" >&2' >> /entrypoint.sh && \
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
    echo '# recorded identity -- see test/internal/harness. It has no sweep and no name' >> /entrypoint.sh && \
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
    echo '# Refuse to run only if the host device-mapper already holds a mapping THIS' >> /entrypoint.sh && \
    echo '# INVOCATION could collide with -- that is, one already carrying' >> /entrypoint.sh && \
    echo '# this containers own scope. This guard FAILS CLOSED: an inventory it cannot take' >> /entrypoint.sh && \
    echo '# is not evidence of an empty host.' >> /entrypoint.sh && \
    echo '#' >> /entrypoint.sh && \
    echo '# WHY THE SCOPE AND NOT A LIST OF NAMES.' >> /entrypoint.sh && \
    echo '#' >> /entrypoint.sh && \
    echo '# It used to refuse on a mapping whose name matched one of the families the' >> /entrypoint.sh && \
    echo '# suite uses (test*, luks-*, nonexistent*, definitely-not-a*, myvolume). Every' >> /entrypoint.sh && \
    echo '# name the suite creates is now <base>-<container scope>-<run id>, so a' >> /entrypoint.sh && \
    echo '# family match is satisfied by ANOTHER LIVE RUNs mapping -- which cannot be' >> /entrypoint.sh && \
    echo '# collided with, because the scope and run id differ. The old check therefore' >> /entrypoint.sh && \
    echo '# refused on evidence of CONCURRENCY rather than evidence of COLLISION, and' >> /entrypoint.sh && \
    echo '# two overlapping runs failed each other for a reason never in the diff.' >> /entrypoint.sh && \
    echo '# Measured 2026-09-12: run 17641 refused over' >> /entrypoint.sh && \
    echo '# luks-multifile-7071-dldmvo78hv64, a sibling runs own mapping, while the' >> /entrypoint.sh && \
    echo '# reaper said in the line above it that the owning run was still alive.' >> /entrypoint.sh && \
    echo '#' >> /entrypoint.sh && \
    echo '# Scoping to this container keeps exactly what the guard was for. The suite' >> /entrypoint.sh && \
    echo '# only ever removes or writes a name it built, and every such name carries' >> /entrypoint.sh && \
    echo '# this scope, so a mapping that does NOT carry it cannot be reached by a' >> /entrypoint.sh && \
    echo '# teardown or a filesystem op here -- including a runners own LVM root' >> /entrypoint.sh && \
    echo '# (ubuntu--vg-ubuntu--lv), which is #162. A mapping that DOES carry it is' >> /entrypoint.sh && \
    echo '# either debris from a crashed run of this very container or a genuine' >> /entrypoint.sh && \
    echo '# collision, and both are worth refusing over.' >> /entrypoint.sh && \
    echo '#' >> /entrypoint.sh && \
    echo '# The scope is the hostname, which Docker sets to the container id. The suite' >> /entrypoint.sh && \
    echo '# derives it the same way (test/internal/harness NewScope), so the guard and the tests' >> /entrypoint.sh && \
    echo '# cannot disagree about what this invocation is called, and there is no' >> /entrypoint.sh && \
    echo '# environment variable to plumb or forget.' >> /entrypoint.sh && \
    echo 'if ! command -v dmsetup >/dev/null 2>&1; then' >> /entrypoint.sh && \
    echo '  echo "REFUSING TO RUN: dmsetup is absent, so the host device-mapper" >&2' >> /entrypoint.sh && \
    echo '  echo "cannot be inspected and this suite cannot confirm it is safe." >&2' >> /entrypoint.sh && \
    echo '  exit 1' >> /entrypoint.sh && \
    echo 'fi' >> /entrypoint.sh && \
    echo 'itest_scope=$(hostname 2>/dev/null | tr -c "A-Za-z0-9-" "-")' >> /entrypoint.sh && \
    echo 'if [ -z "${itest_scope}" ]; then' >> /entrypoint.sh && \
    echo '  echo "REFUSING TO RUN: this container has no usable hostname, so the" >&2' >> /entrypoint.sh && \
    echo '  echo "scope every volume name is built from cannot be determined." >&2' >> /entrypoint.sh && \
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
    echo '      # them here made a host carrying ANY non-matching mapping -- an' >> /entrypoint.sh && \
    echo '      # LVM root, the exact case this guard exists to let through --' >> /entrypoint.sh && \
    echo '      # take the exec branch and try to run the mapping name as a' >> /entrypoint.sh && \
    echo '      # command, so the suite silently ran NOTHING instead of running.' >> /entrypoint.sh && \
    echo '      # Measured before the fix: "$#" became 2 and "$@" became the' >> /entrypoint.sh && \
    echo '      # mapping name and its major:minor.' >> /entrypoint.sh && \
    echo '      dm_name="${dm_line%%[[:space:]]*}"' >> /entrypoint.sh && \
    echo '      case "${dm_name}" in' >> /entrypoint.sh && \
    echo '        *-"${itest_scope}"-*)' >> /entrypoint.sh && \
    echo '          echo "REFUSING TO RUN: the host device-mapper already has a" >&2' >> /entrypoint.sh && \
    echo '          echo "mapping carrying THIS containers scope:" >&2' >> /entrypoint.sh && \
    echo '          echo "  ${dm_line}" >&2' >> /entrypoint.sh && \
    echo '          echo "Every name this suite creates is" >&2' >> /entrypoint.sh && \
    echo '          echo "<base>-${itest_scope}-<run id>, so this mapping is either" >&2' >> /entrypoint.sh && \
    echo '          echo "debris from a crashed run of this container or a name this" >&2' >> /entrypoint.sh && \
    echo '          echo "run would collide with. A mapping belonging to a different" >&2' >> /entrypoint.sh && \
    echo '          echo "container, or to the host, is not reported here and does" >&2' >> /entrypoint.sh && \
    echo '          echo "not block this run." >&2' >> /entrypoint.sh && \
    echo '          exit 1' >> /entrypoint.sh && \
    echo '          ;;' >> /entrypoint.sh && \
    echo '      esac' >> /entrypoint.sh && \
    echo '    done <<< "${dm_inventory}"' >> /entrypoint.sh && \
    echo '    ;;' >> /entrypoint.sh && \
    echo 'esac' >> /entrypoint.sh && \
    echo '' >> /entrypoint.sh && \
    echo '# Default: the integration suite, measured, then the COMBINED coverage' >> /entrypoint.sh && \
    echo '# gate (#141) -- one Makefile target, so this container and a developer' >> /entrypoint.sh && \
    echo '# run the same commands. It used to run three go test commands and merge' >> /entrypoint.sh && \
    echo '# their profiles with `|| true`, so a suite that wrote no profile dropped' >> /entrypoint.sh && \
    echo '# out of the total silently and nothing compared the total to anything.' >> /entrypoint.sh && \
    echo '# The gate fails this container, and with it the job, below a floor.' >> /entrypoint.sh && \
    echo 'if [ "$#" -eq 0 ]; then' >> /entrypoint.sh && \
    echo '    exec make --no-print-directory coverage-combined' >> /entrypoint.sh && \
    echo 'else' >> /entrypoint.sh && \
    echo '    exec "$@"' >> /entrypoint.sh && \
    echo 'fi' >> /entrypoint.sh && \
    chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
