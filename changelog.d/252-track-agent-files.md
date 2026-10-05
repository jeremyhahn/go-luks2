### Changed

- **`CLAUDE.md` and the new `AGENTS.md` are tracked; agent files are stripped
  at publish (#252).** The releasability gate no longer fails on `CLAUDE.md`,
  `AGENTS.md` or `.claude/` at any depth. It lists them, with
  `automerge.yml`, as files the public release strips (#211), and does not call
  the tree publishable while one is tracked. Their content is still scanned, and
  shell scripts, binaries and unpublished workflows still fail.
  `PendingWorkflows` and `Pending` are replaced by `DefaultStripAtPublish` and
  `StripAtPublish`, and `ScanUnpublishable` takes the strip list.
  Only local tool state (`.claude/settings.local.json`) stays gitignored, per
  the standards' project-scaffold §7.
