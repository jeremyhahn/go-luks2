package workflows

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The CI standard: build, test, security and deps-check run in the toolchain
// image built at the commit under test, the integration suite in its
// integration image, and no stage runs on the runner itself. These pin the two
// jobs that do it to the make targets that carry the mechanism, so a step
// quietly moved back onto the runner fails here rather than in a review.

// stepRun maps each step name in a job to its `run:` text.
func stepRun(t *testing.T, jobText string) map[string]string {
	t.Helper()
	steps := map[string]string{}
	name := ""
	for _, block := range strings.Split(jobText, "\n      - ") {
		if m := regexp.MustCompile(`(?m)^name: (.+)$`).FindStringSubmatch(block); m != nil {
			name = m[1]
		} else {
			continue
		}
		if i := strings.Index(block, "run: "); i >= 0 {
			run := block[i+len("run: "):]
			// A one-line run ends at its newline; anything after it is the
			// next step's leading comment.
			if !strings.HasPrefix(run, "|") {
				run, _, _ = strings.Cut(run, "\n")
			}
			steps[name] = run
		}
	}
	return steps
}

func TestImageJobRunsEveryToolchainStageInTheImage(t *testing.T) {
	image := job(t, readFile(t, ".github/workflows/ci.yml"), "image")
	steps := stepRun(t, image)

	for stage, network := range map[string]string{
		"make lint":       "",
		"make build":      "",
		"make test":       "",
		"make security":   "bridge",
		"make deps-check": "bridge",
	} {
		name := stage + " (toolchain image)"
		run, ok := steps[name]
		if !ok {
			t.Errorf("the image job has no step %q", name)
			continue
		}
		// The stage, with nothing before it in CMD; make variables may follow.
		if want := regexp.MustCompile(`make ci-toolchain-run CMD="` + regexp.QuoteMeta(stage) + `[" ]`); !want.MatchString(run) {
			t.Errorf("step %q does not run %s", name, want)
		}
		block := image[strings.Index(image, "name: "+name):]
		block = block[:strings.Index(block, "run: ")]
		if got := strings.Contains(block, "IN_IMAGE_NETWORK: bridge"); got != (network == "bridge") {
			t.Errorf("step %q: network bridge = %v, want %v", name, got, network == "bridge")
		}
	}

	// Every step after the image build runs in the toolchain image and runs
	// after a failed one, so one run reports every stage (ci-template v1.21).
	built := false
	for _, block := range strings.Split(image, "\n      - ")[1:] {
		name, _, _ := strings.Cut(strings.TrimPrefix(block, "name: "), "\n")
		switch {
		case name == "Build the devcontainer images":
			built = true
		case !built, name == "Tear down", strings.HasPrefix(name, "Upload "):
		case !strings.Contains(block, "if: ${{ !cancelled() && env.TOOLCHAIN_IMAGE != '' }}"): //nolint:misspell // the Actions function's spelling, not prose
			t.Errorf("step %q does not keep running after a failed step once the toolchain image exists", name)
		}
	}

	build := steps["Build the devcontainer images"]
	for _, want := range []string{
		`make docker-build MODULE_ENV_FILE="$RUNNER_TEMP/gomodauth.env" IT_IMAGE="$IT_IMAGE"`,
		`rm -f "$RUNNER_TEMP/gomodauth.env"`,
		`TOOLCHAIN_IMAGE=$(make -s toolchain-image)`,
	} {
		if !strings.Contains(build, want) {
			t.Errorf("the image build step lacks %q", want)
		}
	}
	if !strings.Contains(image, "IT_IMAGE: go-luks2-ci-") {
		t.Error("the image job's integration image is not named under the CI prefix")
	}
}

// What the Security Scan and Build jobs ran on the runner now runs in the
// image job, and what their uploads read comes back through CI_OUT. (The unit
// legs and their gates: TestUnitTiers.)
func TestImageJobCarriesTheChecksThatLeftTheRunner(t *testing.T) {
	image := job(t, readFile(t, ".github/workflows/ci.yml"), "image")
	steps := stepRun(t, image)
	for name, want := range map[string]string{
		"make security (toolchain image)":                            `make ci-toolchain-run CMD="make security GO_BUILD_TAGS='$GO_BUILD_TAGS'"`,
		"Require the analysis tools at their pins (toolchain image)": `make ci-toolchain-run CMD="go run ./test/tools/require-tool golangci-lint $GOLANGCI_LINT_VERSION github.com/golangci/golangci-lint/v2/cmd/golangci-lint && go run ./test/tools/require-tool gosec $GOSEC_VERSION github.com/securego/gosec/v2/cmd/gosec && go run ./test/tools/require-tool govulncheck $GOVULNCHECK_VERSION golang.org/x/vuln/cmd/govulncheck"`,
		"Linux binaries and 32-bit vet (toolchain image)":            `make ci-toolchain-run CMD="make build-linux vet-32bit" CI_OUT="luks-linux-amd64 luks-linux-arm64"`,
		"Assert every build tag selects code (toolchain image)":      `make ci-toolchain-run CMD="make assert-build-tags GO_BUILD_TAGS='$GO_BUILD_TAGS'"`,
	} {
		if strings.TrimSpace(steps[name]) != want {
			t.Errorf("step %q runs %q, want %q", name, steps[name], want)
		}
	}
	for _, want := range []string{"path: luks-linux-*", "path: coverage.out"} {
		if !strings.Contains(image, want) {
			t.Errorf("the image job's uploads lack %q", want)
		}
	}
	// Nothing goes to code scanning (ci-template v1.21: CI runs on the forge).
	for _, ban := range []string{"upload-sarif", "security-events", "GOSEC_EXTRA", "GO_VERSION"} {
		if strings.Contains(readFile(t, ".github/workflows/ci.yml"), ban) {
			t.Errorf("ci.yml still carries %q", ban)
		}
	}
	// The pin assertion runs before the lint and the scan it vouches for.
	pins := strings.Index(image, "name: Require the analysis tools")
	if pins < 0 || pins > strings.Index(image, "name: make lint") || pins > strings.Index(image, "name: make security") {
		t.Error("the tool pins are not asserted before make lint and make security run")
	}
	mk := readFile(t, "Makefile")
	for _, want := range []string{"VET_32BIT_ARCHES := 386 arm", "GOOS=linux GOARCH=$$arch $(GO) vet ./...", "LINUX_ARCHES := amd64 arm64"} {
		if !strings.Contains(mk, want) {
			t.Errorf("the Makefile lacks %q", want)
		}
	}
}

// The DevOps standard, security scanning: trivy image fails on CRITICAL and
// HIGH findings that have a fix, with --ignore-unfixed on the OS layer, since
// a base image carries advisories its distribution has not fixed. trivy fs
// never takes --ignore-unfixed: a vulnerable dependency of this module always
// fails.
func TestImageJobGatesFixableFindings(t *testing.T) {
	run := stepRun(t, job(t, readFile(t, ".github/workflows/ci.yml"), "image"))["trivy image (integration image)"]
	cmd := ""
	for _, line := range strings.Split(run, "\n") {
		if i := strings.Index(line, "trivy image "); i >= 0 {
			cmd = line[i:]
		}
	}
	if !strings.HasPrefix(cmd, "trivy image --input it-image.tar") {
		t.Fatalf("the image job does not gate the integration image with trivy image: %q", run)
	}
	for _, flag := range []string{"--ignore-unfixed", "--severity CRITICAL,HIGH", "--exit-code 1"} {
		if !regexp.MustCompile(`(^|\s)` + regexp.QuoteMeta(flag) + `(\s|"|$)`).MatchString(cmd) {
			t.Errorf("trivy image lacks %s: %q", flag, cmd)
		}
	}
}

func TestTrivyFSNeverIgnoresUnfixed(t *testing.T) {
	makefile := readFile(t, "Makefile")
	fs := 0
	for _, line := range strings.Split(makefile, "\n") {
		if !strings.Contains(line, " fs ") || !strings.Contains(strings.ToLower(line), "trivy") {
			continue
		}
		fs++
		if strings.Contains(line, "--ignore-unfixed") {
			t.Errorf("a Makefile trivy fs line ignores unfixed findings: %q", strings.TrimSpace(line))
		}
	}
	if fs == 0 {
		t.Fatal("the Makefile has no trivy fs invocation")
	}
	security := stepRun(t, job(t, readFile(t, ".github/workflows/ci.yml"), "image"))["make security (toolchain image)"]
	if strings.Contains(security, "--ignore-unfixed") || strings.Contains(security, "TRIVY") {
		t.Errorf("the make security step passes trivy options: %q", security)
	}
}

func TestIntegrationJobRunsUnderCompose(t *testing.T) {
	it := job(t, readFile(t, ".github/workflows/ci.yml"), "integration")
	steps := stepRun(t, it)
	if strings.TrimSpace(steps["make integration-test (integration image)"]) !=
		`make integration-test MODULE_ENV_FILE="$RUNNER_TEMP/gomodauth.env" IT_PROJECT="$IT_PROJECT" IT_IMAGE="$IT_IMAGE" GO_BUILD_TAGS="$GO_BUILD_TAGS"` {
		t.Error("the integration job does not run make integration-test with the job's project and image")
	}
	for _, want := range []string{
		"IT_PROJECT: go-luks2-ci-${{ github.run_id }}-${{ github.run_attempt }}",
		"IT_IMAGE: go-luks2-ci-",
		"ITEST_CONTAINER: go-luks2-ci-",
	} {
		if !strings.Contains(it, want) {
			t.Errorf("the integration job lacks %q", want)
		}
	}
	teardown := it[strings.Index(it, "name: Tear down"):]
	if !strings.Contains(teardown, "if: always()") ||
		!strings.Contains(teardown, `-p "$IT_PROJECT" down --volumes`) {
		t.Error("the integration job's teardown does not take the compose project down under always()")
	}
}

// Both jobs reap first, and neither installs a toolchain on the runner: every
// stage they run is in the image.
func TestImageAndIntegrationJobsUseNoRunnerToolchain(t *testing.T) {
	ci := readFile(t, ".github/workflows/ci.yml")
	for _, name := range toolchainJobs {
		j := job(t, ci, name)
		if strings.Contains(j, "setup-go") {
			t.Errorf("%s sets up Go on the runner; its stages run in the image", name)
		}
		if strings.Contains(j, "apt-get") {
			t.Errorf("%s installs a tool on the runner; the image carries it", name)
		}
		// ci-template v1.21.1: the forge credentials are masked before any
		// other step, then stale stacks are reaped.
		named := regexp.MustCompile(`(?m)^      - name: (.+)$`).FindAllStringSubmatch(j, 2)
		if len(named) < 2 || named[0][1] != "Mask the forge credentials" || named[1][1] != "Reap stale CI stacks" {
			t.Errorf("%s does not start by masking the credentials, then reaping: %v", name, named)
		}
		steps := stepRun(t, j)
		if !strings.Contains(steps["Mask the forge credentials"], `echo "::add-mask::$val"`) {
			t.Errorf("%s's first step does not mask the credentials", name)
		}
		if strings.TrimSpace(steps["Reap stale CI stacks"]) != "make ci-reap-stacks" {
			t.Errorf("%s does not reap with make ci-reap-stacks", name)
		}
	}
}

// cacheClass is ci-template v1.22's trust class for the cache volumes: only a
// push to main writes the caches main's build reads (ci-standard.md §6).
const cacheClass = `CI_CACHE_CLASS: ${{ github.event_name == 'push' && 'main' || 'pr' }}`

// TestToolchainStagesCacheByTrustClass: ci-template v1.22. Every job that runs
// a stage through ci-toolchain-run -- the image job as the template has it,
// and the race, FIPS and merged-tree jobs, which run in the same image the
// same way -- names the cache class the recipe mounts its volumes under.
func TestToolchainStagesCacheByTrustClass(t *testing.T) {
	ci := readFile(t, ".github/workflows/ci.yml")
	if !strings.HasPrefix(ci, "# ci-template: v1.22.1 (customized)\n") {
		t.Errorf("ci.yml does not declare ci-template v1.22.1: %.60q", ci)
	}
	for _, name := range []string{"image", "merge-check", "test-race", "fips"} {
		j := job(t, ci, name)
		if !strings.Contains(j, "make ci-toolchain-run ") {
			t.Errorf("%s runs no stage in the toolchain image", name)
		}
		if !regexp.MustCompile(`(?m)^      ` + regexp.QuoteMeta(cacheClass) + `$`).MatchString(j) {
			t.Errorf("%s's env does not set %s", name, cacheClass)
		}
	}
	for _, name := range toolchainJobs {
		j := job(t, ci, name)
		if strings.Contains(j, "make ci-toolchain-run ") && !strings.Contains(j, cacheClass) {
			t.Errorf("%s runs ci-toolchain-run without a cache class", name)
		}
	}
}

// TestImageJobTrimsTheCachesBeforeTheStages: ci-template v1.22's `Trim the CI
// caches` step, as `make ci-trim-caches`, comes right after the image build
// and before any stage adds to the volumes.
func TestImageJobTrimsTheCachesBeforeTheStages(t *testing.T) {
	j := job(t, readFile(t, ".github/workflows/ci.yml"), "image")
	var names []string
	for _, m := range regexp.MustCompile(`(?m)^      - name: (.+)$`).FindAllStringSubmatch(j, -1) {
		names = append(names, m[1])
	}
	steps := stepRun(t, j)
	trim, firstStage := -1, -1
	for i, n := range names {
		if n == "Trim the CI caches" {
			trim = i
		}
		if firstStage < 0 && strings.Contains(steps[n], "make ci-toolchain-run ") {
			firstStage = i
		}
	}
	if trim < 1 || names[trim-1] != "Build the devcontainer images" {
		t.Fatalf("Trim the CI caches does not follow the image build: %v", names)
	}
	if firstStage < 0 || trim > firstStage {
		t.Errorf("Trim the CI caches (step %d) is not before the first stage (step %d): %v", trim, firstStage, names)
	}
	if got := strings.TrimSpace(steps["Trim the CI caches"]); got != "make ci-trim-caches" {
		t.Errorf("Trim the CI caches runs %q, want make ci-trim-caches", got)
	}
	block := j[strings.Index(j, "- name: Trim the CI caches"):]
	block, _, _ = strings.Cut(block, "\n\n")
	if !strings.Contains(block, "\n        if: ${{ !cancelled() && env.TOOLCHAIN_IMAGE != '' }}\n") { //nolint:misspell // the Actions function's spelling, not prose
		t.Errorf("Trim the CI caches is not conditioned as the template's:\n%s", block)
	}
	if strings.Contains(block, "continue-on-error") {
		t.Error("Trim the CI caches hides a failure; the recipe itself never fails")
	}
}

// toolchainJobs are the jobs that build the devcontainer images on bigdisk
// and run their stages in them.
var toolchainJobs = []string{"image", "integration", "test-race", "fips", "merge-check"}

// TestNoStepPrintsTheCredentials: ci-template v1.21.1 after a forge token
// printed in a run. No step prints the credential file or the job
// environment, and nothing traces the shell.
func TestNoStepPrintsTheCredentials(t *testing.T) {
	ci := readFile(t, ".github/workflows/ci.yml")
	for _, ban := range []*regexp.Regexp{
		regexp.MustCompile(`(?m)^\s*(printenv|env)\s*($|[|>])`),
		regexp.MustCompile(`(?m)\bset -[a-z]*x`),
		regexp.MustCompile(`(cat|less|head|tail)\s+"?\$RUNNER_TEMP/gomodauth\.env`),
	} {
		if m := ban.FindString(ci); m != "" {
			t.Errorf("ci.yml prints what it must not: %q", m)
		}
	}
}

// runnerJobs are exempt from the rule below. Since ci-template v1.21 only CI
// Gate is: it reads `needs` and runs no stage. Lint is an image-job step, and
// Race, FIPS and Merged Tree run in the toolchain image like the stages.
var runnerJobs = []string{"ci-gate"}

// runnerTargets are the make targets any other job may run on the runner: they
// build the images, run a command in the toolchain image, run the integration
// suite under compose, print the image's tag, reap what a dead job left, or
// trim the cache volumes (ci-template v1.22). Everything else -- every stage,
// and every check beside one -- is a CMD for ci-toolchain-run.
var runnerTargets = []string{
	"ci-toolchain-run", "ci-reap-stacks", "ci-trim-caches", "docker-build", "docker-build-toolchain",
	"docker-build-integration", "toolchain-image", "integration-test",
}

var (
	// setupGo is a step that installs Go on the runner.
	setupGo = regexp.MustCompile(`(?m)^\s*(-\s+)?uses:\s*actions/setup-go@`)
	// quotedVar is a quoted make variable: CMD, what ci-toolchain-run runs in
	// the image, and the other quoted values, which hold no command.
	quotedVar = regexp.MustCompile(`\b([A-Z_][A-Z0-9_]*)=("[^"]*"|'[^']*')`)
	// makeCall is a make invocation up to the end of its shell command.
	makeCall = regexp.MustCompile(`(?:^|[\s(])make\s+([^;&|)\n]*)`)
	// goTool is the go command running anything on the runner.
	goTool = regexp.MustCompile(`(?:^|[\s(;&|])go\s+(build|test|vet|run|install|generate|mod|tool)\b`)
)

// runnerViolations lists what a job's steps run on the runner that is not
// docker or a runnerTargets target: a Go setup, the go command, or any other
// make target.
func runnerViolations(t *testing.T, jobText string) []string {
	t.Helper()
	var bad []string
	if setupGo.MatchString(jobText) {
		bad = append(bad, "sets up Go on the runner")
	}
	// Every step's run text, named or not: stepRun keys by name, and a step
	// without one would pass unread.
	for i, block := range strings.Split(jobText, "\n      - ")[1:] {
		name := fmt.Sprintf("#%d", i+1)
		if m := regexp.MustCompile(`(?m)^name: (.+)$`).FindStringSubmatch(block); m != nil {
			name = m[1]
		}
		at := regexp.MustCompile(`(?m)^(?:\s*)run: `).FindStringIndex(block)
		if at == nil {
			continue
		}
		run := block[at[1]:]
		if !strings.HasPrefix(run, "|") {
			run, _, _ = strings.Cut(run, "\n")
		}
		var lines []string
		for _, l := range strings.Split(regexp.MustCompile(`\\\n\s*`).ReplaceAllString(run, " "), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(l), "#") {
				lines = append(lines, l)
			}
		}
		text := quotedVar.ReplaceAllString(strings.Join(lines, "\n"), "$1=_")
		if m := goTool.FindString(text); m != "" {
			bad = append(bad, fmt.Sprintf("step %q runs %q on the runner", name, strings.TrimSpace(m)))
		}
		for _, m := range makeCall.FindAllStringSubmatch(text, -1) {
			for _, word := range strings.Fields(m[1]) {
				if strings.HasPrefix(word, "-") || strings.Contains(word, "=") {
					continue
				}
				if !contains(runnerTargets, word) {
					bad = append(bad, fmt.Sprintf("step %q runs make %s on the runner", name, word))
				}
			}
		}
	}
	sort.Strings(bad)
	return bad
}

// The CI standard: every stage runs in the devcontainer image built at the
// commit under test -- the toolchain stages through ci-toolchain-run, the
// integration suite under compose -- and none on the runner. Every job but
// runnerJobs is held to it, so a new job, or a step moved back onto the
// runner, fails here.
func TestNoStageRunsOnTheRunner(t *testing.T) {
	ci := readFile(t, ".github/workflows/ci.yml")
	for _, id := range jobIDs(t, ci) {
		if contains(runnerJobs, id) {
			continue
		}
		for _, v := range runnerViolations(t, job(t, ci, id)) {
			t.Errorf("job %s %s", id, v)
		}
	}
}

// The check itself, on the shapes it must refuse and the ones it must pass.
func TestRunnerViolationsReadsTheSteps(t *testing.T) {
	for _, tc := range []struct {
		name, job string
		bad       int
	}{
		{"in the image", "  j:\n    steps:\n      - name: a\n        run: make ci-toolchain-run CMD=\"make test && go vet ./...\" CI_OUT=\"x y\"\n", 0},
		{"image tag and compose", "  j:\n    steps:\n      - name: a\n        run: |\n          make docker-build-toolchain X=\"$Y\"\n          echo \"T=$(make -s toolchain-image)\"\n          make integration-test IT_PROJECT=\"$P\"\n", 0},
		{"a comment", "  j:\n    steps:\n      - name: a\n        run: |\n          # make test, go build\n          make ci-reap-stacks\n", 0},
		{"a nameless step", "  j:\n    steps:\n      - run: make test\n", 1},
		{"setup-go", "  j:\n    steps:\n      - uses: actions/setup-go@0123 # v6\n", 1},
		{"go build", "  j:\n    steps:\n      - name: a\n        run: go build -o x ./cmd/luks2\n", 1},
		{"go vet, continued", "  j:\n    steps:\n      - name: a\n        run: |\n          GOARCH=arm \\\n            go vet ./...\n", 1},
		{"a stage target", "  j:\n    steps:\n      - name: a\n        run: make gosec GOSEC_EXTRA=\"-fmt=sarif\"\n", 1},
		{"a second target", "  j:\n    steps:\n      - name: a\n        run: make ci-reap-stacks test\n", 1},
	} {
		if got := runnerViolations(t, tc.job); len(got) != tc.bad {
			t.Errorf("%s: %d violations %v, want %d", tc.name, len(got), got, tc.bad)
		}
	}
}
