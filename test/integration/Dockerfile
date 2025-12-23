# Dockerfile for running go-luks2 integration tests in isolation
# This ensures tests run in a clean environment without affecting the host

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
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy go module files first (for layer caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Ensure go.mod is tidy (handles version differences)
RUN go mod tidy

# Build the CLI for integration tests
RUN go build -o /app/build/luks2 ./cmd/luks2

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
    echo '# Clean up any leftover state' >> /entrypoint.sh && \
    echo 'dmsetup remove_all 2>/dev/null || true' >> /entrypoint.sh && \
    echo 'losetup -D 2>/dev/null || true' >> /entrypoint.sh && \
    echo '' >> /entrypoint.sh && \
    echo '# Default: run all integration tests with coverage' >> /entrypoint.sh && \
    echo 'if [ "$#" -eq 0 ]; then' >> /entrypoint.sh && \
    echo '    echo "Running all integration tests with coverage..."' >> /entrypoint.sh && \
    echo '    # Run package integration tests (in pkg/luks2)' >> /entrypoint.sh && \
    echo '    go test -v -tags=integration -coverprofile=/tmp/coverage-pkg.out -covermode=atomic ./pkg/luks2' >> /entrypoint.sh && \
    echo '    # Run new integration tests (in test/integration/pkg)' >> /entrypoint.sh && \
    echo '    go test -v -tags=integration -coverprofile=/tmp/coverage-int-pkg.out -covermode=atomic ./test/integration/pkg/... || true' >> /entrypoint.sh && \
    echo '    # Run CLI integration tests (in test/integration/cli)' >> /entrypoint.sh && \
    echo '    go test -v -tags=integration -coverprofile=/tmp/coverage-int-cli.out -covermode=atomic ./test/integration/cli/... || true' >> /entrypoint.sh && \
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
