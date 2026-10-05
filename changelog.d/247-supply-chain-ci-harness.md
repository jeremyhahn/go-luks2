### Security

- **golang.org/x/crypto is v0.57.0, and every direct dependency is at its
  latest (#247).** v0.55.0 carried GO-2026-6355 and GO-2026-6354, two
  x/crypto/ssh denial-of-service advisories fixed in v0.56.0. This module never
  imports x/crypto/ssh, so neither was reachable, but a consumer's govulncheck
  reported both. golang.org/x/term is v0.46.0 and
  github.com/anatol/devmapper.go is at its 2026-03-15 commit, which copies a
  caller's crypt flags instead of appending to them. govulncheck now reports
  only GO-2026-5932: x/crypto/openpgp is unmaintained, has no fixed version, and
  is not imported here.
- **A release waits for CI and runs the security suite (#247).** A `v*` tag
  used to publish on its own: it had no dependency on CI, tested only
  ./pkg/luks2, ran no scanner, and built without `-trimpath`. release.yml now
  publishes only when every one of these passes:
  - the tagged commit is on main;
  - CI's gate passed for that exact commit. `test/ci/cmd/release-gate` waits
    for the gate's result and refuses on anything but a pass.
  - the ./pkg/luks2 and ./cmd/luks2 tests;
  - `make security` with `TOOLS_REQUIRED=1`, so no scanner can skip.

  The publish step then builds with `-trimpath`. The tag name is treated as
  data and is never spliced into a script.
- **Every workflow action is pinned to a full commit SHA, and trivy is installed
  from a checksummed archive (#247).** `aquasecurity/trivy-action@master` and
  `curl …/install.sh | sh` are gone. `make trivy-install` downloads the pinned
  v0.74.0 archive and checks its SHA-256 before unpacking. It then checks the
  binary's SHA-256 before installing it, and again before reusing an installed
  copy. The Makefile no longer claims trivy gates every push: it gates the
  nightly workflow and every release.
- **Automerge requires an approval for a PR that changes CI definitions
  (#247).** CI_DEFINITIONS covers `.github/`, `.gitea/`, the Makefile,
  `test/ci/`, `test/covergate/`, `test/labstrings/`, `coverage-floors.txt`,
  `releasability-exempt.txt`, `.golangci.yml`, and the integration job's
  `test/integration/Dockerfile`, `test/integration/cmd/`,
  `test/integration/seccomp.json` and `.dockerignore`. A PR touching any of them,
  whether by adding, editing, deleting or renaming, now needs the same
  approval as a `code-review` PR. Before, it could change
  its own gate and merge on that green. automerge.yml reads the changed files
  from the forge and refuses to merge if it cannot read the whole list.

### Fixed

- **Test harness hardening (#247).** These changes affect only the
  integration harness:
  - The reaper no longer detaches under a recorded root unless the root is
    named like a run root.
  - The state directory is used only through the handle it was validated by.
  - A run's temp root is named `go-luks2-run-<run id>-<n>`. A root is reaped
    only for the run whose ledger carries that id, so a dead run's root can no
    longer share a name with a live sibling's and have the sibling's loop
    devices detached.
  - A pre-#247 ledger whose root still has loop devices under it fails the reap
    and must be cleared by hand (docs/TESTING.md).
