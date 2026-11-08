# Public releasability

> **Status: REFERENCE** · Last verified: 2026-10-13
> The rule itself is the package documentation of `test/internal/labstrings`
> (`go doc ./test/internal/labstrings`). Where this page and that package
> disagree, the package wins and this page is the defect.

go-luks2 is developed on an internal forge and published to a public mirror.
The development tree carries files the public release must not: instructions
for the coding agents, tool configuration, and workflows that only run on the
internal forge and its self-hosted runners. It must also never carry a value
that only means something inside the development fleet. This page describes
how both are kept out of what is published, and what that does not cover.

## The rule

Nothing published may carry a fleet address, a fleet hostname or an owner's
home path. The classes and their replacement values (RFC 5737 addresses, RFC
2606 names, role names, repository-relative paths) are described in the
package documentation of `test/internal/labstrings`. The patterns themselves
name the values they ban, so they live in a file that is stripped at publish
(next section) and is the only file the allow-list accepts; this page does not
repeat them. The published tests of the scanner use documentation values, and
a development-tree test requires that an archive export of the commit names no
value of the set anywhere, a waiver notwithstanding.

The internal release tag names a commit on the development trunk, which still
tracks the internal-only files below. The public tree is that commit's archive
export: the export-ignored paths are removed and every other tracked file is
published byte-for-byte. Nothing rewrites a file on the way out, so a fleet
value has to be scrubbed in the source before tagging. Publishing the tree and
tagging it on the public mirror are separate steps, each taken by the owner.

Two further classes of tracked file are refused outright, whatever they
contain:

- **Unpublishable files** (`DefaultUnpublishable` in
  `test/internal/labstrings/published.go`): shell scripts, by extension or by
  a leading `#!`, and binary files the exemption list does not name. Any
  workflow under `.github/workflows/` other than `ci.yml`, `nightly.yml` and
  `release.yml` is refused too. A file in this class must leave the index.
- **Strip-at-publish files** (`DefaultStripAtPublish`, same file): files that
  belong on the development trunk and never in the release. They are tracked,
  their content is still scanned like any other file, and they are excluded
  mechanically, as the next section describes.

## What stays private, and how it is excluded

The strip-at-publish set is:

| Pattern | What it is |
|---|---|
| `**/CLAUDE.md`, `**/AGENTS.md`, `**/.claude/**` | Agent instructions and agent tool settings, at any depth |
| `**/.serena/**` | Code-analysis tool state, at any depth; gitignored whole |
| `.github/workflows/code-review.yml`, `.github/workflows/qwen-review.yml` | Internal code-review workflows |
| `test/internal/labstrings/fleet.go`, `test/internal/labstrings/fleet_test.go` | The fleet pattern set and its tests: generic shapes plus SHA-256 digests of the values the gate bans, never the values themselves. Digests of short values are hygiene, not secrecy, so the set stays out of the release |

A test that reads only a strip-at-publish file is itself stripped at publish,
with the file it tests: the published tree has no such file to read, and
`go test ./...` must pass there. A test that also covers published files
iterates the files present and requires every published workflow by name, so
it holds in a checkout and in the archive alike.

Each pattern appears verbatim in two files. A directory pattern (`<dir>/**`,
such as `**/.serena/**`) is followed there by a line for the directory itself
(`**/.serena`): the `/**` form leaves out the files, but `git archive` still
writes an entry for the directory, and an empty `.serena/` in the archive
tells the public tree the tool directory exists.

- **`.gitattributes`**, as `<pattern> export-ignore`. `git archive` and a
  forge's tag tarball both honor the attribute, so an archive of any commit
  leaves these files out. The public tree is produced that way: as an archive
  export of the release commit.
- **`.dockerignore`**. The build and integration images copy the whole build
  context, so without these lines a local image build would bake the files
  into a layer.

`DefaultStripAtPublish` is the one list. Adding a pattern there without adding
it to both files fails the tests below.

## The gate and its tests

`make releasability` runs `test/tools/releasability-gate` over the git index
(the staged content, which is what the next commit carries). It exits:

- **0** when nothing is found. The summary lists each strip-at-publish file as
  excluded from every archive by `.gitattributes`.
- **1** on any finding: a fleet value, an unpublishable file, or a
  strip-at-publish file that the staged `.gitattributes` does not
  export-ignore (it would ship in the archive). This finding is how the
  published manifest of the checkout is checked: run with the checkout
  present, as CI does on every pull request, the gate fails on any tracked
  strip-at-publish file the archive would carry.
- **2** when the gate cannot run: no checkout, a blob it could not read in
  full, an attribute git could not report, or a tree that tracks a
  strip-at-publish file but has no pattern set to scan it with. A gate that
  could not look is never reported clean.

In a published tree there is neither a pattern set nor a strip-at-publish
file. There the gate checks the file rules, exits 0, and says on every run
that content was not scanned for fleet values: the scan that matters ran on
the development tree before the export.

Only the staged `.gitattributes` files decide what is export-ignored, because
only they travel with the commit a forge archives. The gate does not ask git
about the checkout's attributes, which would also read
`.git/info/attributes` and any `core.attributesFile` (repository, global,
system or the XDG default) and so could call a file excluded that the archive
ships. It writes the staged `.gitattributes` files into a scratch repository
created without templates and asks git there, with no system, global or XDG
configuration and no inherited `GIT_` variable.

The exclusion itself is tested in `test/tools/releasability-gate/export_test.go`:

- a throwaway repository carrying this tree's `.gitattributes` and a sample of
  every strip-at-publish pattern, at the root and nested where the pattern
  allows any depth (a directory sample holds a file directly in it and one
  deeper), is archived with `git archive` as a forge would, and no archive
  entry, file or directory, names or lies under a strip-at-publish path, while
  the published files are kept;
- `.dockerignore` lists every strip-at-publish pattern, and the directory of
  every directory pattern.

The labstrings package tests cover the false clean: an export-ignore rule
placed only in `.git/info/attributes`, a global or repository
`core.attributesFile`, or the XDG default does not count.

These tests need git and fail without it; they do not skip. They need no
checkout: each builds the repository it reads. A test copies what an archive
export carries (every file `.gitignore` does not ignore, less every path
`.gitattributes` export-ignores) into a directory with no `.git`, and runs
the tests of the gate's packages, the workflow tests and the Makefile tests
there, as in the published tree or the integration image.

## Not covered

`export-ignore` governs archives only. Two ways of publishing ignore it:

- **The Go module zip.** The module proxy builds it from the repository at the
  tag, not from an archive, and `.gitattributes` has no effect on what it
  includes. It is clean only because the public repository's tag points at a tree made from the
  archive export. Tagging the development trunk's commit on the public mirror
  would publish the strip-at-publish files in the module zip.
- **A history push.** Every commit on the development trunk carries these
  files. Pushing that history to the public mirror publishes all of them,
  in every past revision. The public tree must be produced as an export (a
  `git archive` of the release commit), committed on its own history.
