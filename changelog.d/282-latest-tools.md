### Changed

- **CI tool pins moved to the upstream latest (#282).** golangci-lint v2.13.2 →
  v2.14.0, govulncheck v1.7.0 → v1.8.0, and Go 1.27.0 → 1.27.1 in `go.mod`, the
  workflows and the Dockerfiles, and trivy v0.74.0 → v0.75.0 with its four
  SHA-256s; gosec stays at v2.29.0, already the latest. The
  pins move in step with the shared runner image, which asserts that the baked
  tool matches. Building now needs Go 1.27.1.
