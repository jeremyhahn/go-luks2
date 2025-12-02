# Testing Guide

This project uses a clean separation between **unit tests** and **integration tests**, with comprehensive coverage of both.

## Current Coverage

- **Total Coverage (unit + integration): 85%**
- **Unit Test Coverage (pure functions only): 42%**
- **Integration Test Coverage: 85%**

## Test Types

### Unit Tests (Pure Functions, No I/O)

Unit tests test pure functions with no file I/O or system calls. They run **fast** (typically <100ms total) and require **no special permissions**.

**Run unit tests only:**
```bash
make test-unit
```

Unit tests include:
- Pure function tests (parseSize, formatSize, alignTo, etc.)
- In-memory cryptographic operations (AFSplit, PBKDF2, etc.)
- Data structure tests (header struct size, JSON marshaling, etc.)
- Checksum calculations

**Expected runtime:** ~2s
**Permissions required:** None
**I/O operations:** None
**Coverage:** 42% (pure functions only)

### Integration Tests (Real System Resources)

Integration tests perform real file I/O, device-mapper operations, and LUKS volume creation. They test the complete workflow from volume creation to mounting and data operations.

**Run ALL tests (unit + integration) with full coverage:**
```bash
make test  # Requires root privileges
```

**Run integration tests only:**
```bash
make integration-test  # Requires root
```

**Run integration tests in Docker (recommended, isolated):**
```bash
make docker-integration-test
```

Integration tests include:
- LUKS volume formatting and unlocking
- Device-mapper operations
- Loop device management
- Filesystem creation and mounting
- Header read/write operations
- Volume wiping

**Expected runtime:** ~50 seconds
**Permissions required:** Root (sudo)
**I/O operations:** Creates temporary files in /tmp
**Coverage:** 85% (system operations)

## Combined Coverage

When running `make test`, both unit and integration tests are executed, providing **85% total coverage** of the codebase. The remaining 15% consists primarily of:
- Unused legacy code (`makeExt4Filesystem`)
- Error handling for exceptional conditions (disk failures, OOM, etc.)
- Defensive code paths that are difficult to trigger in tests

This is **excellent coverage** for systems-level encryption software.

## Test Organization

### Directory Structure

All tests are located in `pkg/luks/`:
- `pkg/luks/*_test.go` - Unit tests (pure functions, no build tags)
- `pkg/luks/*_integration_test.go` - Integration tests (tagged with `//go:build integration`)

### File Naming Convention

- `*_test.go` - Unit tests for pure functions (no I/O, no system calls)
- `*_integration_test.go` - Integration tests (file I/O, system operations)
- All integration tests have the `//go:build integration` build tag

### Coverage

The default `make test` target now runs both unit and integration tests for complete coverage:

```bash
make test          # Full coverage: 85% (requires root)
make test-unit     # Unit tests only: 42% (no root required)
```

## Docker Integration Testing

The Docker-based integration tests provide complete isolation from your host system:

1. Builds a clean container with all dependencies
2. Runs all integration tests inside the container
3. Automatically cleans up when complete
4. No artifacts left on host system

**Requirements:**
- Docker installed and running
- Sufficient disk space for container image (~500MB)

**Usage:**
```bash
make docker-integration-test
```

This is the **recommended** way to run integration tests as it keeps your host machine clean.

## Quick Reference

| Command | What it does | Coverage | Speed | Permissions |
|---------|-------------|----------|-------|-------------|
| `make test` | All tests (unit + integration) | 85% | ~50s | Root (sudo) |
| `make test-unit` | Unit tests only (pure functions) | 42% | ~2s | None |
| `make integration-test` | Integration tests on host | 85% | ~50s | Root (sudo) |
| `make docker-integration-test` | Integration tests in Docker | 85% | ~60s | Docker |
| `make ci` | CI pipeline (lint, test, build) | 42% | ~5s | None |
| `make ci-full` | Full CI with Docker tests | 85% | ~90s | Docker |

## Troubleshooting

**Q: Unit tests are slow or showing permission errors**
A: Make sure you're running `make test` (not `make integration-test`). Unit tests should complete in <100ms with no permissions required.

**Q: Integration tests fail with "operation not permitted"**
A: Integration tests require root privileges. Run with `sudo make integration-test` or use `make docker-integration-test`.

**Q: Docker integration tests fail to start**
A: Ensure Docker is running and you have the `--privileged` flag enabled in the Dockerfile (required for device-mapper operations).

**Q: Tests leave temporary files**
A: Use `make docker-integration-test` for complete isolation, or manually clean `/tmp/luks-*` files after host-based integration tests.
