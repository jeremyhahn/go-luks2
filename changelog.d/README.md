# changelog.d

One fragment per pull request: `changelog.d/<issue>-<slug>.md`, holding **only
that change's entry**.

The release step concatenates the fragments into the new version's section in
`CHANGELOG.md` and empties this directory. Assembly is a **committed step
performed before tagging** — `release.yml` only overwrites the runner-workspace
copy, so a fragment folded in by the workflow would never reach the repository.

## Why fragments and not a shared `## [Unreleased]` section

A shared section makes every open sibling PR conflict on one file. Each
resulting rebase changes the head SHA, which invalidates a reviewer's approval
bound to the previous head and re-queues CI on shared runners; `main` collects
duplicate subsection headings belonging to no single PR; and it pressures a
branch into carrying unrelated issues, contradicting one-issue-one-branch.

Measured here on 2026-09-13: #180 and #158 both edited the shared section and
#158 could not merge until it was rebased — a docs-only collision that cost a
full CI cycle.

## Format

A fragment carries the Keep a Changelog subsection heading it will land under,
so assembly is a concatenation and not an editing pass:

```markdown
### Fixed

- **What changed, in a sentence (#123).** Then why it mattered, and what a
  reader needs in order to act on it.
```

Headings in use: `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`,
`Security`. Mark a breaking change in the heading itself:

```markdown
### Changed — BREAKING: `Config.Requirements` is now `*Requirements`
```

## Adoption

Additive, no history rewrite. The `## [Unreleased]` section already in
`CHANGELOG.md` stays where it is and releases normally at the next tag; only
NEW entries come here.
