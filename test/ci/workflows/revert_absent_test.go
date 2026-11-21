package workflows

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestNoRevertRedMainWorkflow: go-luks2 carries no revert-red-main.yml.
// The ci-template's revert workflow commits its reverts unsigned
// (commit.gpgSign=false), which signatures.yml rejects, and it calls the
// Gitea /api/v1 API behind a job guard that is off on GitHub, so here it
// could never run and, if it did, its commits could never land. Re-adopt it
// when the template signs its commits and supports GitHub.
func TestNoRevertRedMainWorkflow(t *testing.T) {
	path := filepath.Join(repoRoot(t), ".github", "workflows", "revert-red-main.yml")
	_, err := os.Stat(path)
	if err == nil {
		t.Fatal(".github/workflows/revert-red-main.yml exists: it makes unsigned commits and needs the Gitea API; " +
			"leave it out until the template signs and supports GitHub")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("stat %s: %v", path, err)
	}
}
