package workflows

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// runsOnLine is a job's runs-on key at job level; the capture is everything
// after the colon, trailing comments included.
var runsOnLine = regexp.MustCompile(`(?m)^    runs-on:(.*)$`)

// reusableUses is a job that calls a reusable workflow: it has no runs-on.
var reusableUses = regexp.MustCompile(`(?m)^    uses: `)

// runnerLabel is one literal runner label: no quotes, no expression, no list.
var runnerLabel = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// waiverComment is the waiver a self-hosted runs-on line carries.
var waiverComment = regexp.MustCompile(`#\s*self-hosted:(.*)$`)

// waiverCategories are the reasons a job may leave the hosted runner
// (ruling 999). hardware: the job needs specific hardware. oversize: it needs
// more than a standard hosted runner's 4 vCPU, 16 GB memory, about 14 GB of
// free disk or 6 hours. credential: a secret is mounted on one runner alone,
// and only the Codex review job may claim it.
var waiverCategories = map[string]bool{"hardware": true, "oversize": true, "credential": true}

// credentialJobs are the only jobs, by workflow file and job id, a
// credential waiver is valid on.
var credentialJobs = map[string]bool{"code-review.yml/review": true}

// runsOnViolation applies ruling 999's runner rule to one job's runs-on value
// (the text after `runs-on:`, comments included). It returns "" when the line
// is allowed and the reason otherwise.
func runsOnViolation(file, jobID, line string) string {
	value, comment, _ := strings.Cut(line, "#")
	if comment != "" {
		comment = "#" + comment
	}
	value = strings.TrimSpace(value)
	switch {
	case value == hostedRunner:
		return ""
	case value == "":
		return "runs-on has no inline label (a list or a mapping)"
	case strings.Contains(value, "${{"):
		return "runs-on is an expression"
	case strings.HasPrefix(value, "[") || strings.Contains(value, ","):
		return "runs-on is a label list"
	case !runnerLabel.MatchString(value):
		return "runs-on is not one literal label"
	}
	m := waiverComment.FindStringSubmatch(comment)
	if m == nil {
		return "self-hosted label " + value + " has no `# self-hosted: <category>: <reason>` waiver"
	}
	category, reason, ok := strings.Cut(m[1], ":")
	category, reason = strings.TrimSpace(category), strings.TrimSpace(reason)
	switch {
	case !ok || category == "":
		return "waiver on " + value + " names no category"
	case !waiverCategories[category]:
		return "waiver on " + value + " names unknown category " + category
	case reason == "":
		return "waiver on " + value + " gives no reason"
	case category == "credential" && !credentialJobs[file+"/"+jobID]:
		return "credential waiver is allowed only on the Codex review job, not " + file + "/" + jobID
	}
	return ""
}

func TestRunsOnViolation(t *testing.T) {
	for _, c := range []struct {
		name, file, job, line string
		ok                    bool
	}{
		{"hosted", "ci.yml", "lint", " ubuntu-latest", true},
		{"hosted with comment", "ci.yml", "lint", " ubuntu-latest  # plain note", true},
		{"bare self-hosted label", "ci.yml", "lint", " bigdisk", false},
		{"self-hosted with unrelated comment", "ci.yml", "lint", " qwen  # CUSTOMIZE: the host", false},
		{"label list", "ci.yml", "lint", " [self-hosted, linux]", false},
		{"label list waived", "ci.yml", "lint", " [self-hosted, gpu]  # self-hosted: hardware: the GPU", false},
		{"no inline label", "ci.yml", "lint", "", false},
		{"expression", "ci.yml", "lint", ` ${{ github.server_url == 'https://github.com' && 'ubuntu-latest' || 'bigdisk' }}`, false},
		{"expression waived", "ci.yml", "lint", ` ${{ inputs.runner }}  # self-hosted: hardware: the GPU`, false},
		{"quoted label", "ci.yml", "lint", ` 'ubuntu-latest'`, false},
		{"bare waiver, no category", "ci.yml", "lint", " qwen  # self-hosted:", false},
		{"waiver with reason, no category", "ci.yml", "lint", " qwen  # self-hosted: the GPU host", false},
		{"empty category", "ci.yml", "lint", " qwen  # self-hosted: : the GPU host", false},
		{"unknown category", "ci.yml", "lint", " qwen  # self-hosted: speed: it is faster", false},
		{"empty reason", "ci.yml", "lint", " qwen  # self-hosted: hardware:", false},
		{"blank reason", "ci.yml", "lint", " qwen  # self-hosted: hardware:   ", false},
		{"credential on a non-review job", "code-review.yml", "gate", " codex  # self-hosted: credential: the token", false},
		{"credential in another workflow", "ci.yml", "review", " codex  # self-hosted: credential: the token", false},
		{"hardware", "code-review.yml", "review-opencode", " qwen  # CUSTOMIZE: the label # self-hosted: hardware: the GPU host that serves the model", true},
		{"oversize", "nightly.yml", "trivy", " bigdisk  # self-hosted: oversize: needs 60 GB of free disk", true},
		{"credential on review", "code-review.yml", "review", " codex  # lab-string-ok: the label # self-hosted: credential: the reviewer token is mounted on this runner alone", true},
	} {
		got := runsOnViolation(c.file, c.job, c.line)
		if (got == "") != c.ok {
			t.Errorf("%s: runsOnViolation(%q, %q, %q) = %q, want ok=%v", c.name, c.file, c.job, c.line, got, c.ok)
		}
	}
}

// TestEveryJobRunsOnHostedOrWaived: ruling 999's runner rule holds for every
// job of every workflow. A job runs on ubuntu-latest, or on one self-hosted
// label whose runs-on line carries a categorised waiver.
func TestEveryJobRunsOnHostedOrWaived(t *testing.T) {
	for _, f := range workflowFiles(t) {
		src, present := readUnlessStripped(t, rel(t, f))
		if !present {
			continue
		}
		name := filepath.Base(f)
		for _, id := range jobIDs(t, src) {
			j := job(t, src, id)
			lines := runsOnLine.FindAllStringSubmatch(j, -1)
			if len(lines) == 0 && reusableUses.MatchString(j) {
				continue
			}
			if len(lines) != 1 {
				t.Errorf("%s job %s has %d runs-on lines, want 1", name, id, len(lines))
				continue
			}
			if why := runsOnViolation(name, id, lines[0][1]); why != "" {
				t.Errorf("%s job %s: %s (ruling 999)", name, id, why)
			}
		}
	}
}
