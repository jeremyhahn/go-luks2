// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package workflows

import (
	"regexp"
	"strings"
	"testing"
)

// batch.yml (#350) is token-free CPU work on the `batch` runners: fuzz,
// race-full, soak and bench on main. The coordinator dispatches it; it must
// never run on its own, never take a CI slot and never gate a merge. These
// tests are what fails when an edit makes it do any of the three.
const batchWorkflow = ".github/workflows/batch.yml"

var (
	topKey     = regexp.MustCompile(`(?m)^  ([A-Za-z_][\w-]*):`)
	runsOnLine = regexp.MustCompile(`(?m)^    runs-on: (\S+)`)
	goVersion  = regexp.MustCompile(`(?m)^  GO_VERSION: ['"]?([0-9.]+)['"]?`)
)

// block returns the body of the top-level key `name:`, up to the next line
// that is neither indented, blank nor a comment.
func block(t *testing.T, workflow, name string) string {
	t.Helper()
	lines := strings.Split(workflow, "\n")
	start := -1
	for i, l := range lines {
		if l == name+":" {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("no top-level %q", name)
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		l := lines[i]
		if l != "" && l[0] != ' ' && l[0] != '#' {
			end = i
			break
		}
	}
	return strings.Join(lines[start+1:end], "\n")
}

// TestBatchIsDispatchOnly: a schedule, push or pull_request trigger would run
// an hour of soak and three -race passes unowned, or on every PR.
func TestBatchIsDispatchOnly(t *testing.T) {
	wf := readFile(t, batchWorkflow)
	var triggers []string
	for _, m := range topKey.FindAllStringSubmatch(block(t, wf, "on"), -1) {
		triggers = append(triggers, m[1])
	}
	if !sameSet(triggers, []string{"workflow_dispatch"}) {
		t.Errorf("batch.yml triggers on %v, want workflow_dispatch only", triggers)
	}
	if scheduleOn.MatchString(wf) {
		t.Error("batch.yml has a schedule: trigger")
	}
}

// TestBatchRunsOnlyOnBatchRunners: every batch job on the `batch` label and
// nothing else on it, so batch work never takes a CI slot from a pull request.
func TestBatchRunsOnlyOnBatchRunners(t *testing.T) {
	wf := readFile(t, batchWorkflow)
	var jobs []string
	for _, m := range topKey.FindAllStringSubmatch(block(t, wf, "jobs"), -1) {
		jobs = append(jobs, m[1])
	}
	if !sameSet(jobs, []string{"fuzz", "race-full", "soak", "bench"}) {
		t.Errorf("batch.yml has jobs %v, want fuzz, race-full, soak and bench", jobs)
	}
	for _, j := range jobs {
		body := job(t, wf, j)
		got := runsOnLine.FindAllStringSubmatch(body, -1)
		if len(got) != 1 || got[0][1] != "batch" {
			t.Errorf("batch job %s runs on %v, want batch", j, got)
		}
		if n := needs(t, body); n != nil {
			t.Errorf("batch job %s needs %v; batch jobs are independent", j, n)
		}
	}
	for _, f := range workflowFiles(t) {
		if rel(t, f) == batchWorkflow {
			continue
		}
		for _, m := range runsOnLine.FindAllStringSubmatch(readFile(t, rel(t, f)), -1) {
			if m[1] == "batch" {
				t.Errorf("%s runs a job on the batch runners", rel(t, f))
			}
		}
	}
	if !regexp.MustCompile(`(?m)^    - batch$`).MatchString(readFile(t, ".github/actionlint.yaml")) {
		t.Error(".github/actionlint.yaml does not list the batch label; Lint reports it as unknown")
	}
}

// TestBatchIsNeverInAMergeGate: no other workflow names batch.yml or its jobs,
// so neither CI Gate, Full Gate nor the release gate can come to wait on it.
func TestBatchIsNeverInAMergeGate(t *testing.T) {
	for _, f := range workflowFiles(t) {
		if rel(t, f) == batchWorkflow {
			continue
		}
		text := readFile(t, rel(t, f))
		if strings.Contains(text, "batch.yml") || regexp.MustCompile(`needs\.(fuzz|race-full|soak|bench)\b`).MatchString(text) {
			t.Errorf("%s refers to the batch workflow", rel(t, f))
		}
		for _, n := range []string{"fuzz", "race-full", "soak", "bench"} {
			for _, g := range []string{"gate", "full-gate", "publish", "ci-gate"} {
				if strings.Contains(text, "\n  "+g+":\n") && contains(needs(t, job(t, text, g)), n) {
					t.Errorf("%s: %s needs batch job %s", rel(t, f), g, n)
				}
			}
		}
	}
}

// TestBatchGoVersionIsCIs: the batch suites test the toolchain CI tests.
func TestBatchGoVersionIsCIs(t *testing.T) {
	ci := goVersion.FindStringSubmatch(readFile(t, ".github/workflows/ci.yml"))
	batch := goVersion.FindStringSubmatch(readFile(t, batchWorkflow))
	if ci == nil || batch == nil {
		t.Fatalf("GO_VERSION not found: ci.yml %v, batch.yml %v", ci, batch)
	}
	if ci[1] != batch[1] {
		t.Errorf("batch.yml GO_VERSION %s, ci.yml %s; keep them in lockstep", batch[1], ci[1])
	}
}

// TestBatchSoakRunsTheContainerisedSuite: the integration suite writes host
// dm mappings and loop devices, so the soak runs it only through the make
// target that starts the privileged container, never bare on the runner, and
// with a state directory of its own so its reaper and CI's never read each
// other's ledgers.
func TestBatchSoakRunsTheContainerisedSuite(t *testing.T) {
	m := regexp.MustCompile(`(?m)^  SOAK_CMD: '([^']*)'`).FindStringSubmatch(readFile(t, batchWorkflow))
	if m == nil {
		t.Fatal("batch.yml has no SOAK_CMD")
	}
	cmd := m[1]
	if !strings.HasPrefix(cmd, "make docker-integration-test ") {
		t.Errorf("SOAK_CMD %q does not run make docker-integration-test", cmd)
	}
	if !strings.Contains(cmd, "TEST_STATE_DIR=") || strings.Contains(cmd, "TEST_STATE_DIR=/var/tmp/go-luks2-test-state") {
		t.Errorf("SOAK_CMD %q does not give the soak a state directory of its own", cmd)
	}
	if strings.Contains(cmd, "-tags=integration") || strings.Contains(cmd, "host-integration-test") {
		t.Errorf("SOAK_CMD %q runs the integration suite outside the container", cmd)
	}
}
