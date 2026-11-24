# syntax=docker/dockerfile:1.7
# The production CLI image: the luks2 binary plus the cryptsetup tools it calls; the build toolchain stays out of the final layer.

FROM golang:1.27.4 AS build
WORKDIR /app

# The private module credential arrives as a BuildKit secret; without it the build resolves from whatever proxy is reachable.
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
