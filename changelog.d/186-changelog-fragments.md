### Added

- **`changelog.d/` fragments replace the shared `## [Unreleased]` section
  (#186).** Each PR now adds `changelog.d/<issue>-<slug>.md` holding only its
  own entry, carrying the Keep a Changelog heading it will land under.

  A shared section makes every open sibling PR conflict on one file, and each
  resulting rebase changes the head SHA — invalidating a reviewer's approval and
  re-queueing CI. Measured here: on 2026-09-13 two PRs edited that section and
  one could not merge until it was rebased, costing a full CI cycle for a
  docs-only collision.

  `make changelog-assemble VERSION=vX.Y.Z-alpha` folds the fragments into a new
  `CHANGELOG.md` section and deletes them. It does not commit: the changelog is
  the one release artefact a human should read before it is published.
  `release-alpha` refuses to tag while unassembled fragments remain, so a
  release cannot silently omit them.

  Adoption is additive per the convention — the existing `## [Unreleased]`
  content stays where it is and releases normally at the next tag.
