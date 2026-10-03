### Changed

- **The repository ships no shell scripts (#211).** `.github/require-tool.sh`
  is now the Go command `test/ci/cmd/require-tool`, and CI calls it with
  `go run`. `test/integration/docker-run.sh` is now
  `test/integration/cmd/docker-run`, which every Makefile integration target
  and the CI workflow build (`make docker-run-bin`) and run as
  `build/docker-run`, so docker's own exit status reaches the caller.
  Behaviour is unchanged: the same fail-closed version assertion, and the same measured privilege set for the integration
  container, which a unit test now pins flag by flag. For an interactive shell
  under that set, run `make docker-run-bin` and then
  `build/docker-run --rm -it -- bash`.
- **`CLAUDE.md` is no longer tracked (#211).** Agent instructions stay out of
  the published tree. The file is gitignored, so it can still exist in a
  working checkout.

### Added

- **A public-releasability gate, `make releasability` (#211).** It runs in
  `make ci` and in CI, over the staged content of the checkout's git index, not the working tree. It fails on any tracked
  file that names a fleet address, fleet hostname or owner path, in its content
  or in its path. It also fails on any tracked file the public release must not
  carry: a shell script, agent instructions, or any workflow other than
  `ci.yml`, `nightly.yml` and `release.yml`. Each half has a test that plants
  a violation and checks that it is caught. The gate's package tests need no
  checkout, so `go test ./...` still passes in the integration image, which
  carries no `.git`. One workflow, `automerge.yml`, is pending a ruling: the
  gate lists it as an open item on every run and does not call the tree
  publishable while it is tracked, but does not fail on it. See
  `docs/RELEASABILITY.md`.
- **Binary and oversize files fail the gate unless `releasability-exempt.txt`
  lists them (#211),** each with the reason a person accepted it. The list is
  read from the index; a stale entry, a missing reason or a duplicate stops
  the gate, and every exemption is printed on every run.
- **`docs/COMPATIBILITY.md` (#211)** states the compatibility policy from the
  first public release on: what a version number promises, how a breaking
  change is announced, and that published tags are immutable.
- The release and CI tooling packages (`test/labstrings`, the gate command,
  `test/ci/cmd/require-tool`, `test/integration/cmd/docker-run`) are held to
  the 90% coverage floor like every other package.
