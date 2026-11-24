# syntax=docker/dockerfile:1.7
# The devcontainer image, the one image every CI stage runs in: base, tools (build-only), toolchain (build, test, lint, security, deps-check; the VS Code devcontainer) and integration (base plus source, no dev tools).
# Tool versions come from tool-pins.env, which the Makefile includes too.

# golang:1.27.4, by digest: a tag can be re-pointed, a digest cannot. Raise the
# version and the digest together, with go.mod's go directive.
ARG GO_IMAGE=golang:1.27.4@sha256:5e8afd493a7124a8586e134d9b532731161d4b9becf9dee5a5956b107426f93d

# ---- base ----
FROM ${GO_IMAGE} AS base

# Tools the library drives and the suite inspects; apt upgrade takes the Debian security fixes trivy gates on.
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

# No go.work, no go.mod rewrites, no VCS stamping (the version comes from -X main.version).
ENV GOWORK=off \
    GOFLAGS="-mod=readonly -buildvcs=false" \
    GOTOOLCHAIN=local

WORKDIR /workspace

# Fill the module cache at build time; private-module credentials and the build proxy arrive as optional BuildKit secrets, never ARG or ENV. GOSUMDB is never changed.
COPY go.mod go.sum ./
RUN --mount=type=secret,id=gomodauth --mount=type=secret,id=goproxy \
    set -eu; \
    if [ -f /run/secrets/gomodauth ]; then set -a; . /run/secrets/gomodauth; set +a; fi; \
    if [ -s /run/secrets/goproxy ]; then GOPROXY="$(cat /run/secrets/goproxy)"; export GOPROXY; fi; \
    go mod download; \
    chmod -R a+rX "$(go env GOMODCACHE)"

# ---- tools (build-only) ----
FROM base AS tools

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Every version is the pin file's; gosec gets its version through -X and builds in a throwaway module against XTOOLS_VERSION; trivy comes from make trivy-install.
COPY Makefile go.mod /src/
COPY build/docker/devcontainer/tool-pins.env /src/build/docker/devcontainer/
RUN --mount=type=secret,id=goproxy \
    set -eu; \
    cd /src; \
    . build/docker/devcontainer/tool-pins.env; \
    if [ -s /run/secrets/goproxy ]; then GOPROXY="$(cat /run/secrets/goproxy)"; export GOPROXY; fi; \
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

# make, jq, git, bash and shellcheck for the toolchain; curl and libcurl must be at least 8.14.1-2+deb13u7.
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

# Integration entrypoint: no dmsetup remove_all or losetup -D, since dm and loop are host-global; the guard refuses, fail closed, when the host has mappings this suite did not create.
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

# Where CI streams the checkout in, owned by the stage's uid, which needs a passwd entry for ssh signing.
RUN install -d -m 0755 -o 10001 -g 10001 /src && \
    groupadd --gid 10001 ci && \
    useradd --uid 10001 --gid 10001 --no-create-home --no-log-init \
        --home-dir /src --shell /usr/sbin/nologin ci

# No network from here on; deps-check gets DEPS_CHECK_GOPROXY explicitly. GOCACHE is keyed by the Go version.
ENV GOPROXY=off \
    TOOLS_REQUIRED=1 \
    GOCACHE=/tmp/.cache/go-build-go${GOLANG_VERSION}

# Fail the build unless Go, GOCACHE, the module cache and gosec are what the Makefile and CI assume.
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

# Alpine index checksum for the content tag; this Debian base takes `none`.
ARG APK_INDEX_SUM

# Debian index checksum for the content tag, so a new index reruns this stage's apt-get upgrade; a stale index fails.
ARG APT_INDEX_SUM

# strace lets a test hold cryptsetup's metadata lock on cue; curl, libcurl and git are purged so the privileged image has no HTTP client.
RUN set -eu; \
    apt-get -o APT::Update::Error-Mode=any update; \
    apt-get upgrade -y --no-install-recommends; \
    apt-get install -y --no-install-recommends strace; \
    apt-get purge -y --auto-remove curl libcurl4t64 libcurl3t64-gnutls; \
    rm -rf /var/lib/apt/lists/*; \
    if dpkg-query -W -f '${db:Status-Abbrev} ${Package}\n' curl 'libcurl*' git 2>/dev/null | grep -q '^ii'; then \
      echo "curl, libcurl or git is still installed" >&2; exit 1; \
    fi; \
    for c in go cryptsetup dmsetup losetup mkfs.ext4 mkfs.xfs udevadm modprobe strace; do \
      command -v "$c" >/dev/null || { echo "purging curl removed $c" >&2; exit 1; }; \
    done

# Run ledgers; must be bind-mounted from the host to survive the run.
ENV LUKS2_TEST_STATE_DIR=/var/lib/go-luks2-test-state

# This marker is visible only when the ledger mount is absent, and then the harness refuses to run.
RUN mkdir -p /var/lib/go-luks2-test-state \
    && touch /var/lib/go-luks2-test-state/.ephemeral-not-a-persistent-mount

# The suite runs as root: it creates loop nodes, dm mappings and filesystems.
WORKDIR /app

# No go mod tidy: what go.mod and go.sum say is what gets built.
COPY . .
ENV GOPROXY=off

# Build the CLI for integration tests
RUN go build -o /app/build/luks2 ./cmd/luks2

# Build the reaper, which runs before the device-mapper guard so a previous run's recorded state is removed first.
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
