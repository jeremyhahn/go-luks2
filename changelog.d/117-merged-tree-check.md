### Added

- **CI evaluates the tree a merge would produce, not just the branch head
  (#117).** Every other check reads the PR head; Gitea publishes only
  `refs/pull/N/head`, so there is no `/merge` ref to check out, and
  `git merge-tree` answers *"do these conflict?"* rather than *"is the result
  correct?"*. That left one state invisible to the whole pipeline: **branch
  green, `main` green, the merge of the two red.**

  The `Merged Tree` job constructs the merge, extracts it, and compiles it. It
  runs `go vet`, in both build-tag configurations, because `vet` compiles the
  test files and that is where the real breakages were — `go build` alone passes
  over them.

  Measured on the two that happened: #173 removed the exported `DeriveKey` while
  #158 still called it from a test, and #180 added four marshalers while #158
  changed the encoder they use. Both branches green, `main` green, both merges
  red, both found by hand one command before merging.
