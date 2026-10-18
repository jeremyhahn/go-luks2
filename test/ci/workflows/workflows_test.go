// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package workflows

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/test/internal/labstrings"
)

// repoRoot is the directory holding .github/workflows.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("resolving the repository root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".github", "workflows")); err != nil {
		t.Fatalf("no .github/workflows under %s: %v", root, err)
	}
	return root
}

func readFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), rel)) // #nosec G304 -- a fixed path in this repository
	if err != nil {
		t.Fatalf("reading %s: %v", rel, err)
	}
	return string(b)
}

// workflowFiles lists every workflow present in the tree. A list without every
// published workflow fails, so it is never empty: a check over no files passes
// for nothing.
func workflowFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	for _, pattern := range []string{"*.yml", "*.yaml"} {
		m, err := filepath.Glob(filepath.Join(repoRoot(t), ".github", "workflows", pattern))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	sort.Strings(files)
	// The internal workflows are absent from the published tree, so the
	// published ones are required by name: a test iterating this list covers
	// each of them in a checkout and in the archive alike.
	for _, name := range labstrings.PublishedWorkflows {
		want := filepath.Join(repoRoot(t), ".github", "workflows", name)
		if i := sort.SearchStrings(files, want); i == len(files) || files[i] != want {
			t.Fatalf("published workflow %s is missing", name)
		}
	}
	return files
}

// batchWorkflow is the internal batch-runner workflow. It is stripped at
// publish, so it is present in a checkout and absent from the published tree;
// a test over workflowFiles that exempts it must hold either way.
const batchWorkflow = ".github/workflows/batch.yml"

var (
	usesLine = regexp.MustCompile(`^\s*(?:-\s+)?uses:\s*(.*)$`)
	// owner/repo[/path]@<40 hex> # <tag>. The tag in the comment is what a
	// reader and an updater need; the SHA is what the runner fetches.
	pinnedUses = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}\s+#\s+v\d[\w.-]*$`)
)

// TestEveryActionIsPinnedToACommit: a tag or branch can be moved to new code
// after it was reviewed; a commit id cannot. trivy-action@master ran whatever
// that branch held on the night it ran (#247).
func TestEveryActionIsPinnedToACommit(t *testing.T) {
	seen := 0
	for _, path := range workflowFiles(t) {
		for i, line := range strings.Split(readFile(t, rel(t, path)), "\n") {
			m := usesLine.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			seen++
			if !pinnedUses.MatchString(strings.TrimSpace(m[1])) {
				t.Errorf("%s:%d: %q is not pinned as owner/repo@<full commit sha> # <tag>",
					filepath.Base(path), i+1, strings.TrimSpace(m[1]))
			}
		}
	}
	if seen == 0 {
		t.Fatal("no `uses:` line found in any workflow; the check checked nothing")
	}
}

func TestPinCheckRefusesTagsAndBranches(t *testing.T) {
	for _, bad := range []string{
		"actions/checkout@v6",
		"aquasecurity/trivy-action@master",
		"actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803",
		"actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af8 # v6",
		"docker://alpine:3",
	} {
		if pinnedUses.MatchString(bad) {
			t.Errorf("%q passes the pin check", bad)
		}
	}
	if !pinnedUses.MatchString("github/codeql-action/upload-sarif@1190a975f95ce23525efb6a3fc21ea29567c1b52 # v3") {
		t.Error("a pinned sub-path action fails the pin check")
	}
}

func rel(t *testing.T, path string) string {
	t.Helper()
	r, err := filepath.Rel(repoRoot(t), path)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

var pipedInstall = regexp.MustCompile(`(curl|wget)\b[^|#]*\|\s*(sudo\s+)?(ba|z|da)?sh\b`)

// TestNoPipedInstallScripts: `curl ... | sh` runs whatever the URL serves that
// day, unreviewed and unverified (#247). Tools are installed from pinned
// archives checked against a SHA-256 instead (make trivy-install).
func TestNoPipedInstallScripts(t *testing.T) {
	files := append(workflowFiles(t), filepath.Join(repoRoot(t), "Makefile"))
	for _, path := range files {
		for i, line := range strings.Split(readFile(t, rel(t, path)), "\n") {
			if pipedInstall.MatchString(line) {
				t.Errorf("%s:%d pipes a download into a shell: %s", rel(t, path), i+1, strings.TrimSpace(line))
			}
		}
	}
	if !pipedInstall.MatchString("run: curl -sfL https://x/install.sh | sh -s -- -b /usr/local/bin") {
		t.Error("the piped-install pattern misses the form it exists for")
	}
}

// job returns the text of one job in a workflow: from its two-space-indented
// key to the next one.
func job(t *testing.T, workflow, name string) string {
	t.Helper()
	lines := strings.Split(workflow, "\n")
	start := -1
	for i, l := range lines {
		if l == "  "+name+":" {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("no job %q", name)
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		l := lines[i]
		if len(l) > 2 && l[:2] == "  " && l[2] != ' ' && l[2] != '#' {
			end = i
			break
		}
	}
	return strings.Join(lines[start:end], "\n")
}

var needsLine = regexp.MustCompile(`(?m)^    needs:\s*\[([^\]]*)\]`)

func needs(t *testing.T, jobText string) []string {
	t.Helper()
	m := needsLine.FindStringSubmatch(jobText)
	if m == nil {
		return nil
	}
	var out []string
	for _, n := range strings.Split(m[1], ",") {
		out = append(out, strings.TrimSpace(n))
	}
	return out
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// TestReleaseRequiresMainAndCIsGate: the release used to publish on any v* tag
// with no dependency on CI (#247). The publishing job must need every stage,
// check each by name, and the CI stage must be the release gate itself.
func TestReleaseRequiresMainAndCIsGate(t *testing.T) {
	wf := readFile(t, ".github/workflows/release.yml")

	publish := job(t, wf, "publish")
	for _, stage := range []string{"verify", "ci-gate", "test", "security"} {
		if !contains(needs(t, publish), stage) {
			t.Errorf("publish does not need %q: %v", stage, needs(t, publish))
		}
	}
	for _, check := range []string{"needs.ci-gate.result", "needs.test.result", "needs.security.result", "needs.verify.result"} {
		if !strings.Contains(publish, check) {
			t.Errorf("publish does not check %s by name", check)
		}
	}
	if !strings.Contains(publish, "if: always()") {
		t.Error("publish is not always(): a failed stage would skip it silently instead of failing it")
	}

	gate := job(t, wf, "ci-gate")
	for _, want := range []string{
		"go run ./test/tools/release-gate",
		"-main-ref FETCH_HEAD",
		"git fetch --no-tags --quiet origin main",
		"-status-context 'CI / CI Gate (push)'",
		"-workflow ci.yml -job-name 'CI Gate'",
		"fetch-depth: 0",
	} {
		if !strings.Contains(gate, want) {
			t.Errorf("ci-gate job lacks %q", want)
		}
	}

	// The context must be the one ci.yml's gate job reports, under the name
	// the workflow and the job carry.
	ci := readFile(t, ".github/workflows/ci.yml")
	if !regexp.MustCompile(`(?m)^name: CI$`).MatchString(ci) || !strings.Contains(job(t, ci, "ci-gate"), "    name: CI Gate\n") {
		t.Error("ci.yml's workflow or gate job was renamed; release.yml's -status-context and -job-name must follow")
	}
}

// TestReleaseTestsTheCLIAndRunsTheSecuritySuite (#247): only ./pkg/luks2 was
// tested, and nothing was scanned.
func TestReleaseTestsTheCLIAndRunsTheSecuritySuite(t *testing.T) {
	wf := readFile(t, ".github/workflows/release.yml")
	if test := job(t, wf, "test"); !regexp.MustCompile(`go test [^\n]*\./pkg/luks2 \./cmd/luks2`).MatchString(test) {
		t.Error("the release test job does not run ./pkg/luks2 and ./cmd/luks2")
	}
	security := job(t, wf, "security")
	for _, want := range []string{"make trivy-install", "make security TOOLS_REQUIRED=1", "require-tool"} {
		if !strings.Contains(security, want) {
			t.Errorf("the release security job lacks %q", want)
		}
	}
}

var goBuild = regexp.MustCompile(`\bgo build\b[^\n]*`)

// TestReleaseAndCIBuildWithTrimpath: without -trimpath a binary records the
// build host's paths (#247).
func TestReleaseAndCIBuildWithTrimpath(t *testing.T) {
	builds := 0
	// Join shell line continuations so a command split over lines is read
	// whole.
	text := regexp.MustCompile(`\\\n\s*`).ReplaceAllString(readFile(t, ".github/workflows/release.yml"), " ")
	for _, cmd := range goBuild.FindAllString(text, -1) {
		if !strings.Contains(cmd, "./cmd/luks2") {
			continue
		}
		builds++
		if !strings.Contains(cmd, "-trimpath") {
			t.Errorf("release.yml: %q builds without -trimpath", cmd)
		}
	}
	if builds == 0 {
		t.Error("release.yml: found no go build of the CLI")
	}

	// CI builds its binaries in the toolchain image, through build-linux.
	if !strings.Contains(job(t, readFile(t, ".github/workflows/ci.yml"), "image"), `CMD="make build-linux`) {
		t.Error("ci.yml's image job does not build the linux binaries with make build-linux")
	}
	recipe := regexp.MustCompile(`(?m)^build-linux:.*\n((?:\t.*\n)+)`).FindStringSubmatch(readFile(t, "Makefile"))
	if recipe == nil {
		t.Fatal("the Makefile has no build-linux recipe")
	}
	if !regexp.MustCompile(`\$\(GO\) build -trimpath -o luks-linux-\$\$arch \./\$\(CMD_DIR\)`).MatchString(recipe[1]) {
		t.Errorf("build-linux does not build the CLI with -trimpath:\n%s", recipe[1])
	}
}

// TestTagIsDataInRelease: a tag name is chosen by whoever pushes it, and git
// accepts names such as v$(id). It must never be spliced into a script.
func TestTagIsDataInRelease(t *testing.T) {
	wf := readFile(t, ".github/workflows/release.yml")
	for i, line := range strings.Split(wf, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(line, "outputs.tag }}") && !regexp.MustCompile(`^(TAG|[a-z-]+):\s`).MatchString(trimmed) &&
			!strings.HasPrefix(trimmed, "luks-${{") {
			t.Errorf("release.yml:%d expands the tag outside an env: or with: value: %s", i+1, trimmed)
		}
		if strings.Contains(line, "steps.version.outputs") {
			t.Errorf("release.yml:%d still reads the removed steps.version output", i+1)
		}
	}
}

// TestMakefileSaysWhereTrivyGates: the Makefile claimed "CI installs trivy
// unconditionally, so this scan still gates every push" while trivy ran only
// nightly (#247). The comment must say where it actually gates, and ci.yml
// must not have quietly started running it (which would make it wrong again).
func TestMakefileSaysWhereTrivyGates(t *testing.T) {
	mk := readFile(t, "Makefile")
	if strings.Contains(mk, "gates every push") {
		t.Error("the Makefile still claims trivy gates every push")
	}
	if !strings.Contains(mk, "the whole target, trivy fs included CI's image job") ||
		!strings.Contains(mk, "the NIGHTLY") {
		t.Error("the Makefile does not say where trivy gates")
	}
	// What the Makefile says, ci.yml must do: the full security target, trivy
	// fs included, in the image job and nowhere else in the workflow.
	ci := readFile(t, ".github/workflows/ci.yml")
	if !strings.Contains(job(t, ci, "image"), `make ci-toolchain-run CMD="make security `) {
		t.Error("ci.yml's image job no longer runs make security in the toolchain image; update the Makefile's account of where trivy gates")
	}
	if regexp.MustCompile(`make trivy|trivy fs|trivy-action`).MatchString(ci) {
		t.Error("ci.yml runs trivy outside make security; update the Makefile's account of where it gates")
	}
	nightly := job(t, readFile(t, ".github/workflows/nightly.yml"), "trivy")
	for _, want := range []string{"make trivy-install", "make trivy-fs TOOLS_REQUIRED=1"} {
		if !strings.Contains(nightly, want) {
			t.Errorf("nightly's trivy job lacks %q", want)
		}
	}
}
