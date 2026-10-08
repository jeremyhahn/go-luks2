# changelog.d

One fragment per pull request, `changelog.d/<issue>-<slug>.md`, holding only
that change's entry. A shared `## [Unreleased]` section makes every open pull
request conflict on one file; fragments do not.

## Format

A fragment starts with the Keep a Changelog heading it belongs under, so
assembly is concatenation:

```markdown
### Fixed

- **What changed, in one sentence (#123).** Why it mattered, and what a reader
  must do about it.
```

Headings: `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`.
Mark a breaking change in the heading:

```markdown
### Changed — BREAKING: `Config.Requirements` is now `*Requirements`
```

## Release

```bash
make changelog-assemble VERSION=vX.Y.Z-rc.N
```

(`vX.Y.Z-alpha` or `vX.Y.Z` for the other kinds.) This inserts a
`## [X.Y.Z-rc.N] - <date>` section built from the fragments
into `CHANGELOG.md`, below `## [Unreleased]`, and deletes the fragments
(`README.md` stays). Commit both before tagging: `release.yml` takes the release
notes from that section of the committed `CHANGELOG.md`. It publishes only if
the tagged commit is on main and CI's gate passed for that commit; it waits for
CI if CI is still running.

Then tag with the one target for the kind. Each refuses the other two kinds and
names the right target:

```bash
make release-alpha                            # the next alpha: PATCH + 1 on the highest vX.Y.Z-alpha tag
make release-alpha     VERSION=vX.Y.Z-alpha   # an alpha you name, e.g. a MINOR bump
make release-candidate VERSION=vX.Y.Z-rc.N    # a release candidate
make release           VERSION=vX.Y.Z         # a final release
```

`release-alpha` with no `VERSION` prints the version it derived before it writes
anything. The changelog section must already exist for that version: the
changelog guard names the missing heading, and `make changelog-assemble
VERSION=<that version>` creates it. It refuses when
there is no alpha tag to count from or when an rc or a final release already
sits at or above the result. `release-candidate` and `release` always need
`VERSION`.

The `## [Unreleased]` section that predates fragments is not touched by
assembly. Move any entries still in it into the new section by hand before
tagging. New entries go here.
