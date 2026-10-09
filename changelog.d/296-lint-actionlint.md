### Changed

- **`make lint` runs actionlint over `.github/workflows/`, and the trivy targets
  fail when trivy is missing (#296).** Workflow syntax, expressions and runner
  labels are now checked locally before CI parses them; `.github/actionlint.yaml`
  is read when it exists. A missing actionlint fails `make lint` with the
  `go install` line for the pinned version. `trivy-fs`, `trivy-sarif` and
  `trivy-misconfig` no longer skip or fail obscurely without trivy: they exit
  non-zero and point at `make trivy-install`, so `make security` can no longer
  pass on a scan that never ran. Scanners, severities and exit codes are
  unchanged when trivy is present.
