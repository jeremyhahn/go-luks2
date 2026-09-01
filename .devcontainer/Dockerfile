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
    git \
    curl \
    make \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Install Go development tools
RUN go install golang.org/x/tools/gopls@latest && \
    go install github.com/go-delve/delve/cmd/dlv@latest && \
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest && \
    go install github.com/securego/gosec/v2/cmd/gosec@latest && \
    go install gotest.tools/gotestsum@latest

# Create non-root user with sudo access
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME && \
    useradd --uid $USER_UID --gid $USER_GID -m $USERNAME && \
    echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME && \
    chmod 0440 /etc/sudoers.d/$USERNAME

# Setup workspace
WORKDIR /workspace

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

USER $USERNAME
