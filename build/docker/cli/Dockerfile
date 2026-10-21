# syntax=docker/dockerfile:1.7
#
# The production CLI image: the luks2 binary plus the cryptsetup userspace
# tools it shells out to (CLAUDE.md: "must interface correctly with the
# cryptsetup userspace tools"), nothing else. Built with `make docker-build-cli`,
# run with `make docker-run`, which goes through the same launcher and
# privilege set as the integration suite (test/integration/cmd/docker-run) --
# this binary needs the same device-mapper and loop access either way.
#
# The devcontainer's integration stage (build/docker/devcontainer/Dockerfile)
# IS the Go toolchain plus every test dependency, by design, and ships
# nothing. This one ships to a user, so the build stage's toolchain and
# module cache stay out of the final layer.

FROM golang:1.27.3 AS build
WORKDIR /app

# go.mod pins github.com/jeremyhahn/go-enclave, served from a private module
# host despite its github.com module path. The credential arrives as a
# BuildKit secret, exactly as build/docker/devcontainer/Dockerfile takes it
# (see that file for why: not a build arg, not baked into GOPROXY/GOSUMDB).
# Absent, the build still runs, resolving from whatever proxy this machine
# can reach.
COPY go.mod go.sum ./
RUN --mount=type=secret,id=gomodauth \
    set -eu; \
    if [ -f /run/secrets/gomodauth ]; then . /run/secrets/gomodauth; fi; \
    go mod download

COPY . .

RUN set -eu; \
    build_version="$(tr -d 'v' < VERSION)"; \
    go build -ldflags "-X main.version=${build_version}" -o /out/luks2 ./cmd/luks2

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    cryptsetup-bin \
    util-linux \
    kmod \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/luks2 /usr/local/bin/luks2
ENTRYPOINT ["/usr/local/bin/luks2"]
