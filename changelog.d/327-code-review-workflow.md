### Added

- **CI reviews a pull request labelled `code-review` and `task:ready` with
  Codex (#327).** `.github/workflows/code-review.yml` adopts the fleet template
  v4 verbatim: it posts the verdict as the `codex` user on the head commit,
  which `automerge.yml` waits for before it merges a `code-review` pull request.
  `.github/actionlint.yaml` (fleet template v3) lists the self-hosted runner
  labels, so `make lint` accepts `runs-on: codex` and still catches a
  misspelled label.
