# Suggested Commands

## Build
- `make build` - Build CLI binary to `build/luks2`
- `make install` - Install CLI to `$GOPATH/bin`
- `make run ARGS="info /dev/sdb1"` - Build and run CLI with args (requires sudo)

## Testing
- `make test` - Run unit tests only (no root required)
- `make test-unit` - Unit tests with coverage
- `make test-cli` - CLI unit tests only
- `make integration-test` - All integration tests in Docker (recommended)
- `make integration-test-pkg` - Package integration tests in Docker
- `make integration-test-cli` - CLI integration tests in Docker
- `make docker-test-specific TEST=TestName` - Run specific integration test

## Code Quality
- `make fmt` - Format with gofmt
- `make fmt-check` - Check formatting (CI-style)
- `make vet` - Run go vet
- `make lint` - Run golangci-lint
- `make gosec` - Run security scanner
- `make check` - Format + vet + test

## Coverage
- `make coverage` - Full coverage (unit + integration, requires root)
- `make test-coverage` - Tests with coverage report

## CI
- `make ci` - Local CI pipeline (format, lint, security, unit tests, build)
- `make ci-full` - Full CI with Docker integration tests (enforces 90% threshold)

## Clean
- `make clean` - Clean all artifacts
