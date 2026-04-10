# go-luks2

Pure Go implementation of LUKS2 disk encryption. No external dependency on cryptsetup.

## Purpose
Provides both a library (`pkg/luks2`) and CLI tool (`cmd/luks2`) for LUKS2 encrypted volume operations: create, open, close, mount, unmount, info, wipe.

## Tech Stack
- Language: Go 1.25.5
- Module: `github.com/jeremyhahn/go-luks2`
- Build: Makefile
- CI: GitHub Actions + Docker (privileged containers for integration tests)
- Linting: golangci-lint, gosec
- Coverage threshold: 90%
- Key deps: devmapper.go, x/crypto, x/sys

## Architecture
- `pkg/luks2/` - Core LUKS2 library (header parsing, key derivation, encryption, device mapper)
- `cmd/luks2/` - CLI tool
- `test/integration/` - Docker-based integration tests (require privileged mode)
- Integration tests require root/Docker due to block device and device mapper operations

## Important Notes
- CLI commands require root privileges
- Integration tests run in Docker with `--privileged` flag
- Supports both block devices and file-based volumes
