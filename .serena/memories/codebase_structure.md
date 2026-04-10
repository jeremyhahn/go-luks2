# Codebase Structure

```
go-luks2/
├── pkg/luks2/              # Core LUKS2 library
├── cmd/luks2/              # CLI tool
├── test/
│   └── integration/
│       ├── Dockerfile      # Privileged Docker test environment
│       ├── pkg/            # Package integration tests
│       └── cli/            # CLI integration tests
├── build/                  # Build output directory
├── docs/
├── .github/                # CI workflows
├── .devcontainer/          # Dev container config
├── Makefile
├── VERSION
└── go.mod / go.sum
```
