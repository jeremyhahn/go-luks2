package workflows

import (
	"regexp"
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
		if want := `make ci-toolchain-run CMD="` + stage + `"`; !strings.Contains(run, want) {
			t.Errorf("step %q does not run %s", name, want)
		}
		block := image[strings.Index(image, "name: "+name):]
		block = block[:strings.Index(block, "run: ")]
		if got := strings.Contains(block, "IN_IMAGE_NETWORK: bridge"); got != (network == "bridge") {
			t.Errorf("step %q: network bridge = %v, want %v", name, got, network == "bridge")
		}
	}

	build := steps["Build the toolchain and integration images"]
	for _, want := range []string{
		"make docker-build-toolchain docker-build-integration",
		`MODULE_ENV_FILE="$RUNNER_TEMP/gomodauth.env"`,
		`TOOLCHAIN_IMAGE=$(make -s toolchain-image)`,
	} {
		if !strings.Contains(build, want) {
			t.Errorf("the image build step lacks %q", want)
		}
	}
	if !strings.Contains(image, "ITEST_IMAGE: go-luks2-ci-") {
		t.Error("the image job's integration image is not named under the CI prefix")
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
	it := job(t, readFile(t, ".github/workflows/ci.yml"), "test-integration")
	steps := stepRun(t, it)
	if !strings.Contains(steps["Run integration suite in the integration image"],
		`make integration-test MODULE_ENV_FILE="$RUNNER_TEMP/gomodauth.env" IT_PROJECT="$IT_PROJECT"`) {
		t.Error("the integration job does not run make integration-test with the job's project")
	}
	for _, want := range []string{
		"IT_PROJECT: go-luks2-ci-${{ github.run_id }}-${{ github.run_attempt }}",
		"ITEST_IMAGE: go-luks2-ci-",
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
	for _, name := range []string{"image", "test-integration"} {
		j := job(t, ci, name)
		if strings.Contains(j, "setup-go") {
			t.Errorf("%s sets up Go on the runner; its stages run in the image", name)
		}
		if strings.Contains(j, "go test") || strings.Contains(j, "go build") {
			t.Errorf("%s runs go on the runner", name)
		}
		first := regexp.MustCompile(`(?m)^      - name: (.+)$`).FindStringSubmatch(j)
		if first == nil || first[1] != "Reap stale CI stacks" {
			t.Errorf("%s's first named step is not the reaper: %v", name, first)
		}
		if steps := stepRun(t, j); strings.TrimSpace(steps["Reap stale CI stacks"]) != "make ci-reap-stacks" {
			t.Errorf("%s does not reap with make ci-reap-stacks", name)
		}
	}
}
