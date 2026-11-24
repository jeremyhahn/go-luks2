# CLAUDE.md

Context for agents working in go-luks2. Capped at 120 lines; context only, no
procedure that a gate already enforces. Never shipped: the public release
strips it (docs/release/public-releasability.md).

## What this is

A Go library and CLI for LUKS2 disk encryption. Formatting, keyslots, the
header and the dm-crypt mapping run in process, with no cryptsetup. Volumes
interoperate with cryptsetup in both directions. Module
`github.com/jeremyhahn/go-luks2`; Go version from `go.mod`.

## Layout

- `pkg/luks2` — the public library API. Its surface is pinned by
  `make api-diff` against
  `test/tools/apidump/baseline/disposition-luks2.tsv`.
- `pkg/dmcrypt`, `pkg/loop`, `pkg/filesystem`, `pkg/keyprovider`, `pkg/wipe` —
  public building blocks (mapping, loop devices, mkfs/detect, key sources,
  wiping).
- `internal/` — header codec and validation, keyslot AF, area ciphers, KDF,
  kernel keyring, FIPS mode, secrets and volume keys, the CLI commands.
- `cmd/luks2` — the CLI entry point.
- `test/integration` — root/device tests that run only in the integration
  container (`make integration-test`). `test/ci`, `test/makefile` — tests of
  the build and CI plumbing.
- `docs/<area>/` — api, architecture and engineering notes per feature area.
  `docs/SPEC.md` is the feature spec; `ROADMAP.md` tracks rows.
- `pm/rows.md` — the SPEC row ledger.

## Work rules

- One SPEC row = one row issue = one branch `row/<issue>-<slug>` = one PR.
  Dependency updates and CI-configuration changes go on the standing
  maintenance row, `row/503-maintenance` (#503).
- A PR body names its issue (`Closes #n`, or `Refs #503` for maintenance).
- Every user-visible change adds one fragment `changelog.d/<issue>-<slug>.md`
  (format in `changelog.d/README.md`). Never edit `CHANGELOG.md` by hand.
- `SPEC.md`, `ROADMAP.md`, `CLAUDE.md` and `.github/workflows/` change only
  when the task names them.
- Workflows come from the shared CI template. Adopt a template release whole;
  never hand-patch template code. Template defects go back to the template.
- Commits are signed. Never force-push or rewrite shared history.

## Gates

- `make ci` — fmt-check, vet, lint (gofmt, golangci-lint, actionlint),
  security, releasability, api-diff, unit tests with race detector, coverage
  floors (`coverage-floors.txt`), calibration, build.
- `make test-fips-mode` — the module under `GOFIPS140=latest`,
  `GODEBUG=fips140=only`. The FIPS gate is never weakened or skipped.
- `make integration-test` — needs root and device-mapper; runs in the
  integration container, never on a shared host.
- `make deps-check` — fails when a module lags a release 7+ days old without
  a written reason.
- `make releasability` — the tracked tree must carry no lab values (host
  names, addresses, internal paths or identifiers). Write generic examples.
- Code Review (Codex) must approve the PR head; a P1 is fixed, never
  overridden.

## Code conventions

- Secrets (passphrases, volume keys, derived keys) live in locked memory and
  are wiped after use; never log or format them into errors.
- Only FIPS-approved algorithms on the FIPS path; non-approved KDFs and
  ciphers are refused in FIPS mode, not silently replaced.
- On-disk format follows the LUKS2 spec in `docs/reference/`; cryptsetup
  interop is tested both ways (`docs/cryptsetup-interop`).
- Errors wrap with `%w` and use the sentinel errors of their package.
- Unit tests need no root and no I/O; anything touching devices is an
  integration test.
