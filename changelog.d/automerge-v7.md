### Changed

- **automerge.yml is the shared v7 template.** It runs only from the base
  branch (`pull_request_target`, `workflow_run` and a schedule sweep), so a PR
  can no longer rewrite the check that merges it. It replaces the per-repo
  hold from 0.4.0-alpha, where PRs changing CI definitions needed an approval
  (#247). That hold and its tests (`test/ci/workflows/automerge_test.go`) are
  removed, because a per-repo copy of the template is a defect; the template
  is tested where it is maintained.
