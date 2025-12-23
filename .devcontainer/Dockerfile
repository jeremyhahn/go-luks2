FROM golang:1.25.5

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

# Create entrypoint script for integration tests
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Start udevd for device-mapper symlink creation\n\
/usr/lib/systemd/systemd-udevd --daemon 2>/dev/null || true\n\
sleep 1\n\
udevadm trigger 2>/dev/null || true\n\
udevadm settle 2>/dev/null || true\n\
\n\
# Clean up any leftover state\n\
dmsetup remove_all 2>/dev/null || true\n\
losetup -D 2>/dev/null || true\n\
\n\
exec "$@"\n\
' > /usr/local/bin/integration-test-setup && \
    chmod +x /usr/local/bin/integration-test-setup

USER $USERNAME
