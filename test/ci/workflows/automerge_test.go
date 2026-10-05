// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package workflows

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// The automerge decision is a shell script inside automerge.yml. These tests
// run THAT script, extracted from the file the forge runs, against a fake
// Gitea API: the rule is exercised as written, not a copy of it.

const (
	mergeStep = "- name: Merge, hold, or wait"
	prNumber  = 7
	headSHA   = "1111111111111111111111111111111111111111"
	gateCtx   = "CI / CI Gate (pull_request)"
)

// stepScript returns the run: block of the named step and its env: entries
// that are literal values (not ${{ }} expressions).
func stepScript(t *testing.T, workflow, stepName string) (script string, env map[string]string) {
	t.Helper()
	lines := strings.Split(workflow, "\n")
	at := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == stepName {
			at = i
			break
		}
	}
	if at < 0 {
		t.Fatalf("no step %q", stepName)
	}
	env = map[string]string{}
	inEnv := false
	for i := at + 1; i < len(lines); i++ {
		l := lines[i]
		trimmed := strings.TrimSpace(l)
		switch {
		case trimmed == "env:":
			inEnv = true
		case trimmed == "run: |":
			indent := len(l) - len(strings.TrimLeft(l, " "))
			var body []string
			bodyIndent := -1
			for _, b := range lines[i+1:] {
				if strings.TrimSpace(b) == "" {
					body = append(body, "")
					continue
				}
				ind := len(b) - len(strings.TrimLeft(b, " "))
				if ind <= indent {
					break
				}
				if bodyIndent < 0 {
					bodyIndent = ind
				}
				body = append(body, b[bodyIndent:])
			}
			if len(body) < 20 {
				t.Fatalf("extracted only %d lines of the %q script", len(body), stepName)
			}
			return strings.Join(body, "\n"), env
		case inEnv && strings.HasPrefix(trimmed, "#"):
		case inEnv:
			k, v, ok := strings.Cut(trimmed, ":")
			if !ok {
				inEnv = false
				continue
			}
			v = strings.TrimSpace(v)
			if strings.HasPrefix(v, "${{") {
				continue
			}
			if strings.HasPrefix(v, "'") && strings.HasSuffix(v, "'") {
				v = strings.ReplaceAll(v[1:len(v)-1], "''", "'")
			}
			env[k] = v
		}
	}
	t.Fatalf("step %q has no run: | block", stepName)
	return "", nil
}

type changedFile struct {
	Filename         string `json:"filename"`
	PreviousFilename string `json:"previous_filename,omitempty"`
	Status           string `json:"status"`
}

type review struct {
	ID        int    `json:"id"`
	State     string `json:"state"`
	CommitID  string `json:"commit_id"`
	Stale     bool   `json:"stale"`
	Dismissed bool   `json:"dismissed"`
	User      struct {
		Login string `json:"login"`
	} `json:"user"`
}

// fakeGitea answers the calls automerge.yml makes for one open PR.
type fakeGitea struct {
	label   bool
	files   []changedFile
	reviews []review

	// filesStatus, when non-zero, is the answer to every files request.
	filesStatus int
	// totalHeader overrides X-Total-Count; "-" omits it.
	totalHeader string
	// filesBody, when set, replaces the files listing's JSON.
	filesBody string

	mu      sync.Mutex
	merged  bool
	deletes int
}

func (g *fakeGitea) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	const prefix = "/api/v1/repos/o/r"
	path := strings.TrimPrefix(r.URL.Path, prefix)
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page == 0 {
		page = 1
	}
	if r.Header.Get("Authorization") != "token bot-token" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	reply := func(v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	pr := fmt.Sprintf("/pulls/%d", prNumber)
	switch {
	case r.Method == http.MethodGet && path == pr:
		reply(map[string]any{"number": prNumber, "state": "open", "draft": false,
			"head": map[string]any{"sha": headSHA}, "base": map[string]any{"ref": "main"}})
	case r.Method == http.MethodGet && path == "/branch_protections/main":
		reply(map[string]any{"enable_status_check": true, "status_check_contexts": []string{gateCtx}})
	case r.Method == http.MethodGet && path == fmt.Sprintf("/issues/%d/labels", prNumber):
		labels := []map[string]string{{"name": "enhancement"}}
		if g.label {
			labels = append(labels, map[string]string{"name": "code-review"})
		}
		reply(labels)
	case r.Method == http.MethodDelete && path == pr+"/merge":
		g.mu.Lock()
		g.deletes++
		g.mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
	case r.Method == http.MethodGet && path == pr+"/files":
		if g.filesStatus != 0 {
			http.Error(w, "boom", g.filesStatus)
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		switch g.totalHeader {
		case "":
			w.Header().Set("X-Total-Count", strconv.Itoa(len(g.files)))
		case "-":
		default:
			w.Header().Set("X-Total-Count", g.totalHeader)
		}
		if g.filesBody != "" {
			_, _ = w.Write([]byte(g.filesBody))
			return
		}
		lo, hi := (page-1)*limit, page*limit
		if lo > len(g.files) {
			lo = len(g.files)
		}
		if hi > len(g.files) {
			hi = len(g.files)
		}
		reply(g.files[lo:hi])
	case r.Method == http.MethodGet && path == "/commits/"+headSHA+"/status":
		statuses := []map[string]string{}
		if page == 1 {
			statuses = append(statuses, map[string]string{"context": gateCtx, "status": "success"})
		}
		reply(map[string]any{"total_count": 1, "statuses": statuses})
	case r.Method == http.MethodGet && path == pr+"/reviews":
		if page == 1 {
			reply(g.reviews)
			return
		}
		reply([]review{})
	case r.Method == http.MethodPost && path == pr+"/merge":
		g.mu.Lock()
		g.merged = true
		g.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "unexpected "+r.Method+" "+r.URL.String(), http.StatusTeapot)
	}
}

// runAutomerge runs the real merge script against g and returns its exit
// status and output.
func runAutomerge(t *testing.T, g *fakeGitea) (int, string) {
	t.Helper()
	for _, tool := range []string{"bash", "curl", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s is required to run automerge.yml's script (the runner has it): %v", tool, err)
		}
	}
	script, env := stepScript(t, readFile(t, ".github/workflows/automerge.yml"), mergeStep)
	for _, k := range []string{"APPROVERS", "CI_DEFINITIONS"} {
		if env[k] == "" {
			t.Fatalf("automerge.yml's merge step sets no %s", k)
		}
	}

	srv := httptest.NewServer(g)
	defer srv.Close()

	cmd := exec.Command("bash", "--noprofile", "--norc", "-c", script) // #nosec G204 -- this repository's own workflow script
	cmd.Env = []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"BOT=bot-token",
		"REPO_API=" + srv.URL + "/api/v1/repos/o/r",
		"PR_FROM_EVENT=" + strconv.Itoa(prNumber),
		"RUN_SHA=",
		"APPROVERS=" + env["APPROVERS"],
		"CI_DEFINITIONS=" + env["CI_DEFINITIONS"],
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return exit.ExitCode(), string(out)
		}
		t.Fatalf("running the script: %v\n%s", err, out)
	}
	return 0, string(out)
}

func approvedBy(login string) review {
	r := review{ID: 1, State: "APPROVED", CommitID: headSHA}
	r.User.Login = login
	return r
}

func files(paths ...string) []changedFile {
	var f []changedFile
	for _, p := range paths {
		f = append(f, changedFile{Filename: p, Status: "modified"})
	}
	return f
}

// The baseline the rule must not disturb: an unlabelled code change merges on
// green CI with no review.
func TestAutomergeMergesACodeChangeOnGreenCI(t *testing.T) {
	g := &fakeGitea{files: files("pkg/luks2/unlock.go", "docs/README.md", "test/harness/reap.go")}
	code, out := runAutomerge(t, g)
	if code != 0 || !g.merged {
		t.Fatalf("exit %d, merged %v; want a merge\n%s", code, g.merged, out)
	}
	if g.deletes != 0 {
		t.Errorf("an unheld PR canceled an armed merge %d times", g.deletes)
	}
}

// ciDefinitionFilter is the jq program automerge.yml runs over the changed
// files. TestCIDefinitionsCoverWhatCIRuns asserts the script still carries it
// verbatim, so the regex tests below test what the workflow runs.
const ciDefinitionFilter = `.[] | (.filename, (.previous_filename // empty)) | select(test($re))`

// ciPaths are changes to what CI runs or how it decides; lookAlikes are not.
var (
	ciPaths = []string{
		".github/workflows/ci.yml",
		".github/workflows/automerge.yml",
		".gitea/workflows/x.yml",
		"Makefile",
		"test/ci/cmd/require-tool/main.go",
		"test/covergate/gate.go",
		"coverage-floors.txt",
		".golangci.yml",
		"test/labstrings/published.go",
		"test/labstrings/cmd/releasability-gate/main.go",
		"releasability-exempt.txt",
		"test/integration/Dockerfile",
		"test/integration/cmd/docker-run/main.go",
		"test/integration/seccomp.json",
		".dockerignore",
	}
	lookAlikes = []string{
		"docs/Makefile.md", "pkg/test/ci/x.go", "docs/.github/x", "Makefile.old",
		"docs/releasability-exempt.txt", "test/integration/pkg/x_test.go",
		"test/integration/Dockerfile.old", "pkg/luks2/unlock.go", "docs/.dockerignore",
	}
)

// TestCIDefinitionsCoverWhatCIRuns runs the workflow's own filter and regex
// over every path at once: each CI path is caught, under its new name or its
// old one, and no look-alike is.
func TestCIDefinitionsCoverWhatCIRuns(t *testing.T) {
	script, env := stepScript(t, readFile(t, ".github/workflows/automerge.yml"), mergeStep)
	if !strings.Contains(script, "'"+ciDefinitionFilter+"'") {
		t.Fatalf("automerge.yml no longer runs the filter this test checks: %s", ciDefinitionFilter)
	}
	var changed []changedFile
	for _, p := range ciPaths {
		changed = append(changed, changedFile{Filename: p, Status: "modified"})
		changed = append(changed, changedFile{Filename: "moved/" + p, PreviousFilename: p, Status: "renamed"})
	}
	for _, p := range lookAlikes {
		changed = append(changed, changedFile{Filename: p, Status: "modified"})
	}
	in, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("jq", "-r", "--arg", "re", env["CI_DEFINITIONS"], ciDefinitionFilter) // #nosec G204 -- this repository's own regex
	cmd.Stdin = strings.NewReader(string(in))
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("jq: %v", err)
	}
	matched := map[string]int{}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		matched[l]++
	}
	for _, p := range ciPaths {
		// Once as a changed file, once as the old name of a rename.
		if matched[p] != 2 {
			t.Errorf("%s matched %d times, want 2 (edited, and renamed away)", p, matched[p])
		}
	}
	for _, p := range lookAlikes {
		if matched[p] != 0 {
			t.Errorf("look-alike %s is treated as a CI definition", p)
		}
	}
}

// THE FINDING (#247), end to end: a PR that changes what CI runs, with no
// label, used to merge on its own green CI. It must now wait for an approval.
func TestAutomergeHoldsACIDefinitionChangeWithoutTheLabel(t *testing.T) {
	for _, path := range []string{".github/workflows/ci.yml", "Makefile", "test/integration/Dockerfile"} {
		t.Run(path, func(t *testing.T) {
			g := &fakeGitea{files: files("pkg/luks2/unlock.go", path)}
			code, out := runAutomerge(t, g)
			if code != 0 || g.merged {
				t.Fatalf("exit %d, merged %v; want a held PR waiting for approval\n%s", code, g.merged, out)
			}
			if !strings.Contains(out, "changes CI definitions") || !strings.Contains(out, path) {
				t.Errorf("output does not name the CI change:\n%s", out)
			}
			if !strings.Contains(out, "waiting for an approval") {
				t.Errorf("output does not say it is waiting for an approval:\n%s", out)
			}
			if g.deletes != 1 {
				t.Errorf("an armed merge was canceled %d times, want 1", g.deletes)
			}
		})
	}
}

// Look-alikes are not CI definitions, end to end.
func TestAutomergeDoesNotHoldLookAlikePaths(t *testing.T) {
	g := &fakeGitea{files: files(lookAlikes...)}
	code, out := runAutomerge(t, g)
	if code != 0 || !g.merged {
		t.Fatalf("exit %d, merged %v; want a merge\n%s", code, g.merged, out)
	}
}

// Moving a workflow away is a change to it: the OLD path counts.
func TestAutomergeHoldsARenameOutOfCIDefinitions(t *testing.T) {
	g := &fakeGitea{files: []changedFile{{Filename: "docs/old-ci.yml", PreviousFilename: ".github/workflows/ci.yml", Status: "renamed"}}}
	code, out := runAutomerge(t, g)
	if code != 0 || g.merged {
		t.Fatalf("exit %d, merged %v; want held\n%s", code, g.merged, out)
	}
}

func TestAutomergeMergesACIDefinitionChangeOnceApproved(t *testing.T) {
	g := &fakeGitea{files: files(".github/workflows/ci.yml"), reviews: []review{approvedBy("codex")}}
	code, out := runAutomerge(t, g)
	if code != 0 || !g.merged {
		t.Fatalf("exit %d, merged %v; want a merge\n%s", code, g.merged, out)
	}
	if !strings.Contains(out, "approved on "+headSHA+" by codex") {
		t.Errorf("output does not name the approval:\n%s", out)
	}
}

// An approval from someone outside APPROVERS, or a stale one, does not count.
func TestAutomergeIgnoresAnApprovalThatDoesNotCount(t *testing.T) {
	stale := approvedBy("codex")
	stale.Stale = true
	other := approvedBy("mallory")
	old := approvedBy("codex")
	old.CommitID = strings.Repeat("2", 40)
	for name, r := range map[string]review{"stale": stale, "not an approver": other, "older head": old} {
		t.Run(name, func(t *testing.T) {
			g := &fakeGitea{files: files("Makefile"), reviews: []review{r}}
			code, out := runAutomerge(t, g)
			if code != 0 || g.merged {
				t.Fatalf("exit %d, merged %v; want held\n%s", code, g.merged, out)
			}
		})
	}
}

// The CI-definition file is on the second page: every page is read.
func TestAutomergeReadsEveryPageOfFiles(t *testing.T) {
	var f []changedFile
	for i := 0; i < 60; i++ {
		f = append(f, changedFile{Filename: fmt.Sprintf("pkg/luks2/f%02d.go", i), Status: "modified"})
	}
	f = append(f, changedFile{Filename: ".github/workflows/release.yml", Status: "modified"})
	g := &fakeGitea{files: f}
	code, out := runAutomerge(t, g)
	if code != 0 || g.merged {
		t.Fatalf("exit %d, merged %v; want held by a file on page 2\n%s", code, g.merged, out)
	}
}

// Fail closed: nothing merges unless the whole list was read.
func TestAutomergeRefusesWithoutTheWholeFileList(t *testing.T) {
	cases := map[string]*fakeGitea{
		"files endpoint fails": {files: files("pkg/x.go"), filesStatus: http.StatusInternalServerError},
		"count higher":         {files: files("pkg/x.go"), totalHeader: "3"},
		"no count":             {files: files("pkg/x.go"), totalHeader: "-"},
		"non-numeric count":    {files: files("pkg/x.go"), totalHeader: "lots"},
		"malformed body":       {files: files("pkg/x.go"), filesBody: "<html>"},
	}
	for name, g := range cases {
		t.Run(name, func(t *testing.T) {
			code, out := runAutomerge(t, g)
			if code == 0 || g.merged {
				t.Fatalf("exit %d, merged %v; want a refusal\n%s", code, g.merged, out)
			}
			if !strings.Contains(out, "::error::") {
				t.Errorf("no ::error:: annotation:\n%s", out)
			}
			// Codex round 6: a merge a legacy workflow armed must not survive
			// a list that could not be read.
			if g.deletes == 0 {
				t.Error("an armed merge was not canceled when the file list could not be read")
			}
		})
	}
}

// The existing label path still works alongside the new rule.
func TestAutomergeLabelStillHolds(t *testing.T) {
	g := &fakeGitea{label: true, files: files("pkg/luks2/unlock.go")}
	code, out := runAutomerge(t, g)
	if code != 0 || g.merged {
		t.Fatalf("exit %d, merged %v; want held by the label\n%s", code, g.merged, out)
	}
	g = &fakeGitea{label: true, files: files("Makefile"), reviews: []review{{ID: 2, State: "REQUEST_CHANGES", CommitID: headSHA}}}
	g.reviews = append(g.reviews, approvedBy("codex"))
	g.reviews[0].User.Login = "opencode"
	code, out = runAutomerge(t, g)
	if code != 0 || g.merged {
		t.Fatalf("exit %d, merged %v; changes were requested\n%s", code, g.merged, out)
	}
	if g.deletes != 1 {
		t.Errorf("an armed merge was canceled %d times for a labeled CI change, want 1", g.deletes)
	}
}
