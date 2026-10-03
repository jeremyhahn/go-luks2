# Public releasability

go-luks2 is released publicly. The public release is a single commit whose tree
is byte-identical to the internal release tag's tree, so **everything tracked
here at the tag is published**. A value that must not be published is removed
from the source before tagging. Rewriting it at publication would break that
identity.

This page states the rule and the gate that enforces it. The model is
go-quicbaas's gate of the same name.

## The rule

No tracked file names the private development fleet, in its content or in its
path: a filename ships as surely as the bytes in it. There are three classes:

| Class | What it covers | Use instead |
|---|---|---|
| `lab-address` | An address on the fleet subnet | An RFC 5737 documentation address: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` |
| `lab-host` | A fleet hostname | The role, not the machine: `ci-runner-01`, `luks.example.com`, `*.internal` |
| `owner-path` | A path under the owner's home directory or the lab's NFS mount | A repository-relative path, or `/var/lib`, `/srv`, `/var/tmp` |

The fleet's subnet, hostnames and path prefixes are written down in exactly one
place, the `patterns` list in `test/labstrings/labstrings.go`. Read them there
rather than repeating them here.

The public release also carries none of these files, whatever their content:

- **Shell scripts.** No `*.sh` or `*.bash` file, and no file that opens with
  `#!`. A tool is a Go command (`test/ci/cmd/require-tool`,
  `test/integration/cmd/docker-run`) or a Makefile recipe.
- **Agent instructions.** No `CLAUDE.md`, `AGENTS.md` or `.claude/`. They are
  gitignored, so they can exist in a working checkout without being tracked.
- **Internal workflows.** Only `ci.yml`, `nightly.yml` and `release.yml` ship.
  This is an allow-list: any other file under `.github/workflows/` fails,
  including a `.yaml` variant of an allowed name, a renamed factory workflow
  and anything in a subdirectory.

  **One workflow is pending: `automerge.yml`.** The forge's merge automation
  requires it in every repository, and the public release must not carry it;
  the published tree is the release tag's tree, so both cannot hold for one
  tag. Until that is ruled on, the gate does not fail on that exact name (its
  `.yaml` variant and any copy in a subdirectory still fail), and it does not
  call the tree publishable either: every run prints it as an open item, and
  the readiness checklist stays open while it is listed. The list is
  `PendingWorkflows`, beside the allow-list.

The file list is `DefaultUnpublishable`, and the workflow allow-list
`PublishedWorkflows`, both in `test/labstrings/published.go`.

## The gate

`test/labstrings/cmd/releasability-gate` scans every entry in the git index,
reading the staged blobs rather than the working tree: the index is what the
next commit carries. A value staged and then edited out of the working tree
without staging the edit, a staged file deleted from the working tree, and a
path a sparse checkout never wrote are all still scanned. It runs as `make releasability`, which `make ci` depends on and CI's unit-test
job runs. It is a command and not a package test because it needs the git
index: the package tests also run where there is none (the integration image
excludes `.git/` and runs `go test ./...`), so they build any index they need
in a temporary directory. Without a checkout the gate exits 2; it never
reports a tree it could not list as clean, and an index entry whose blob it
cannot read (missing from a partial clone, for example) also exits 2. Matching is textual, so it works on a tree that
does not compile, and it covers Markdown, YAML, Dockerfiles and JSON as well as
Go. Binary content is scanned for lab values like any other, and the shebang
check looks at the start of every regular file's staged content, whatever
follows it.

**Binary and oversize files fail closed.** A tracked binary file (one holding
a NUL byte) fails the gate, and a staged blob over the 32 MiB scan limit exits
2 — the gate cannot vouch for what it did not read — unless the file is listed
in `releasability-exempt.txt` at the repository root, with the reason a person
accepted it. A listed binary is still scanned for lab values; a listed
oversize file is not read, and the gate prints every exemption, marking the
unread ones, on every run. The list is read from the index like everything
else, so an exemption that is not staged does not count, and a stale entry, a
missing reason or a duplicate stops the gate. The list is empty today.

```
make releasability
```

A failure names the file, the line, the class, the matched text, and what to use
instead. A value found in a file's path is reported as being in the path; a path
cannot carry an inline waiver, so the only way to accept one is an allow-list
entry.

Each half has a test that plants a violation and checks that it is reported. A
gate nobody has seen fail cannot be told apart from a gate that does not run.

### Accepting a line

The preferred way is an **inline waiver**: `lab-string-ok: <reason>` on the
offending line or the line immediately above it, in the file's own comment
syntax:

```go
Expr: regexp.MustCompile(`...`), // lab-string-ok: the pattern this gate matches on
```

The reason is what makes it a waiver. `lab-string-ok:` with nothing after it is
not one.

The other way is an entry in `DefaultAllowList` (`test/labstrings/allowlist.go`),
for a whole tree or for a file that cannot carry a comment. Each entry names the
classes it accepts and why. An entry with no reason fails the gate rather than
widening it. Today the list has one entry: the gate's own test fixtures.

There is no waiver for an unpublishable file (a script, agent instructions,
an internal workflow). Remove it from the index, and gitignore it if it has to
exist in a checkout. A binary or oversize file is accepted only through
`releasability-exempt.txt`, above.

## The scrub for the first public release (#211)

When the gate was added, the tracked tree already had no lab address, fleet
hostname or owner path. The scrub made three changes:

- `.github/require-tool.sh` became `test/ci/cmd/require-tool`, and
  `test/integration/docker-run.sh` became `test/integration/cmd/docker-run`.
  Their behaviour did not change, and a unit test pins the container's privilege
  set flag by flag.
- `CLAUDE.md` was removed from the index and gitignored.
- When the gate was written no internal-only workflow was tracked. The forge's
  automerge workflow (`automerge.yml`) has been added to every repository
  since, and is the one pending item above.
