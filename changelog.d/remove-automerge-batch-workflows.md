### Removed

- **The merge-on-green and batch workflows are gone.** Landing is the forge's
  native auto-merge on green, with the required checks set by a ruleset, so the
  self-merging workflow and the dispatch-only batch-runner workflow (fuzz, race,
  soak, benchmarks) are retired, with the strip-at-publish entries and tests
  that named them.
