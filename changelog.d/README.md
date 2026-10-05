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
make changelog-assemble VERSION=vX.Y.Z-alpha
```

This inserts a `## [X.Y.Z-alpha] - <date>` section built from the fragments
into `CHANGELOG.md`, below `## [Unreleased]`, and deletes the fragments
(`README.md` stays). Commit both before tagging: `release.yml` takes the release
notes from that section of the committed `CHANGELOG.md`.

The `## [Unreleased]` section that predates fragments is not touched by
assembly. Move any entries still in it into the new section by hand before
tagging. New entries go here.
