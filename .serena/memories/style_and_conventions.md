# Style and Conventions

- Standard Go conventions (gofmt enforced)
- Single core package (`pkg/luks2`) for the library
- CLI in `cmd/luks2/`
- Integration tests separated and gated with `//go:build integration` tag
- Integration tests require Docker with `--privileged` due to block device/device mapper ops
- Coverage threshold: 90%
- Version injected via ldflags from VERSION file
