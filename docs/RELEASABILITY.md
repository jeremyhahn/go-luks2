# Public releasability

> **Status: NORMATIVE** · Last verified: 2026-10-07 against v1.0.0-rc.1 (ef01368)
> Conflicts with this rule are defects.

The public release is a single commit whose tree is byte-identical to the
internal release tag's tree, so **everything tracked at the tag is published**.
Anything that must not be published is removed from the source before tagging.

## The rule

No tracked file names the private development fleet, in its content or its
path.

| Class | Covers | Use instead |
|---|---|---|
| `lab-address` | An address on the fleet subnet | RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` |
| `lab-host` | A fleet hostname | A role: `ci-runner-01`, `luks.example.com`, `*.internal` |
| `owner-path` | A path under the owner's home or the lab NFS mount | A repository-relative path, or `/var/lib`, `/srv`, `/var/tmp` |

The patterns live in one place, `patterns` in `test/internal/labstrings/labstrings.go`.

These files are never published, whatever their content:

- Shell scripts: `*.sh`, `*.bash`, or anything starting with `#!`. Tools are
  Go commands (`test/tools/require-tool`, `test/tools/docker-run`)
  or Makefile recipes.
- Workflows other than `ci.yml`, `nightly.yml` and `release.yml`
  (`PublishedWorkflows`), including `.yaml` variants and subdirectories.

These files are tracked on `main` and stripped at publish (#211):

- Agent files: `CLAUDE.md`, `AGENTS.md` and `.claude/`, at any depth
  (standards `project-scaffold.md` §7, #252). Only local tool state,
  `.claude/settings.local.json`, is gitignored.
- `.github/workflows/automerge.yml`, which the forge requires. Only that exact
  name; a `.yaml` variant or nested copy fails.

The gate passes them, lists each on every run and does not call the tree
publishable while one is tracked. Their content is still scanned, and a script
or binary among them still fails. The lists are `DefaultUnpublishable` and
`DefaultStripAtPublish` in `test/internal/labstrings/published.go`.

## The gate

`make releasability` (part of `make ci` and CI's unit job) runs
`test/tools/releasability-gate`. It scans the staged blobs of every
git index entry, not the working tree, because the index is what the next
commit carries. Matching is textual, so it covers every file type. Without a
git checkout, or with an unreadable blob, it exits 2 rather than reporting
clean.

A failure names the file, line, class, matched text and the replacement. A
match in a path is reported as such.

Binary and oversize files fail unless listed in `releasability-exempt.txt`
with a reason: a file holding a NUL byte, or a blob over 32 MiB (exit 2). A
listed binary is still scanned; a listed oversize file is not, and the gate
says so on every run. The list is read from the index, and a stale entry, a
missing reason or a duplicate stops the gate. It is empty.

### Waivers

Put `lab-string-ok: <reason>` on the offending line or the line above, in the
file's comment syntax. Without a reason it is not a waiver.

```go
Expr: regexp.MustCompile(`...`), // lab-string-ok: the pattern this gate matches on
```

For a whole tree, or a file that cannot hold a comment, add an entry with
classes and a reason to `DefaultAllowList` in `test/internal/labstrings/allowlist.go`.
It has one entry, the gate's own test fixtures.

There is no waiver for an unpublishable file: remove it from the index.

## The first-release scrub

When the gate was added the tree already held no lab address, hostname or owner
path. The scrub replaced `.github/require-tool.sh` and
`test/integration/docker-run.sh` with the Go commands above (same behaviour).
It also removed `CLAUDE.md` from the index; #252 tracks it again, stripped at
publish.
