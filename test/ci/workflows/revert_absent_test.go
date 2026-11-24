package workflows

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestNoRevertRedMainWorkflow: go-luks2 carries no revert-red-main.yml, whose unsigned commits signatures.yml would reject.
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
