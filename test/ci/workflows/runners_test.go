package workflows

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// runsOnLine is a job's runs-on key at job-property indentation, bare,
// single- or double-quoted; the capture is everything after the colon,
// trailing comments included.
var runsOnLine = regexp.MustCompile(`^    (?:runs-on|'runs-on'|"runs-on")[ \t]*:(.*)$`)

// reusableUses is a job that calls a reusable workflow: it has no runs-on.
var reusableUses = regexp.MustCompile(`(?m)^    (?:uses|'uses'|"uses")[ \t]*: `)

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

// runsOnViolation applies ruling 999's runner rule to one job's runs-on key
// line (the text after `runs-on:`, comments included). It returns "" when the
// line is allowed and the reason otherwise. It fails closed: only one plain or
// quoted label on the key line itself is read, so a value that needs a YAML
// decoder (block or flow collection, block scalar, anchor, alias or tag) is a
// violation; waiverViolations rejects a value continued on a later line.
func runsOnViolation(file, jobID, line string) string {
	if line != "" && line[0] != ' ' && line[0] != '\t' {
		return "runs-on key is not followed by a space"
	}
	value, comment := line, ""
	for i := 1; i < len(line); i++ {
		if line[i] == '#' && (line[i-1] == ' ' || line[i-1] == '\t') {
			value, comment = line[:i], line[i:]
			break
		}
	}
	value, why := runsOnLabel(strings.TrimSpace(value))
	switch {
	case why != "":
		return why
	case value == hostedRunner:
		return ""
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

// runsOnLabel reads a runs-on value, comment removed, as one runner label: a
// plain scalar or one single- or double-quoted scalar around a literal label.
// It returns the label, or "" and the reason it is not one.
func runsOnLabel(value string) (string, string) {
	switch {
	case value == "":
		return "", "runs-on has no value on its key line (a list, a mapping or a block scalar below it)"
	case strings.Contains(value, "${{"):
		return "", "runs-on is an expression"
	case strings.HasPrefix(value, "|") || strings.HasPrefix(value, ">"):
		return "", "runs-on is a block scalar"
	case strings.HasPrefix(value, "{"):
		return "", "runs-on is a flow mapping"
	case strings.HasPrefix(value, "[") || strings.Contains(value, ","):
		return "", "runs-on is a label list"
	case strings.ContainsAny(value[:1], "&*!"):
		return "", "runs-on carries a YAML anchor, alias or tag"
	}
	if q := value[0]; q == '\'' || q == '"' {
		if len(value) < 2 || value[len(value)-1] != q {
			return "", "runs-on is not one quoted label"
		}
		value = value[1 : len(value)-1]
	}
	if !runnerLabel.MatchString(value) {
		return "", "runs-on is not one literal label"
	}
	return value, ""
}

// runsOnLines returns the text after the colon of every runs-on key line of
// one job body, and a problem for each line that continues a runs-on value
// (any non-blank line indented deeper than the key before the next line at
// or above the key's indentation that is not a comment) and for each explicit
// (`? `) key at job-property indentation, which the scan cannot read.
func runsOnLines(body string) (values, problems []string) {
	lines := strings.Split(body, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "    ? ") || l == "    ?" {
			problems = append(problems, fmt.Sprintf("explicit key %q cannot be read", l))
			continue
		}
		m := runsOnLine.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		values = append(values, m[1])
	scan:
		for _, next := range lines[i+1:] {
			trimmed := strings.TrimLeft(next, " ")
			switch {
			case strings.TrimSpace(next) == "":
				continue
			case len(next)-len(trimmed) > 4:
				problems = append(problems, fmt.Sprintf("runs-on value continues on a later line: %q", next))
				continue
			case strings.HasPrefix(trimmed, "#"):
				continue
			}
			break scan
		}
	}
	return values, problems
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
		{"single-quoted hosted", "ci.yml", "lint", ` 'ubuntu-latest'`, true},
		{"double-quoted hosted", "ci.yml", "lint", ` "ubuntu-latest"  # a note`, true},
		{"quoted self-hosted, waived", "ci.yml", "lint", ` 'qwen'  # self-hosted: hardware: the GPU`, true},
		{"quoted self-hosted, unwaived", "ci.yml", "lint", ` "qwen"`, false},
		{"quoted, trailing text", "ci.yml", "lint", ` 'ubuntu-latest' x`, false},
		{"unterminated quote", "ci.yml", "lint", ` 'ubuntu-latest`, false},
		{"mismatched quotes", "ci.yml", "lint", ` 'ubuntu-latest"`, false},
		{"quoted expression", "ci.yml", "lint", ` '${{ inputs.runner }}'`, false},
		{"empty", "ci.yml", "lint", " ", false},
		{"comment only", "ci.yml", "lint", "  # self-hosted: hardware: the GPU", false},
		{"literal block scalar", "ci.yml", "lint", " |", false},
		{"stripped literal block scalar", "ci.yml", "lint", " |-", false},
		{"folded block scalar", "ci.yml", "lint", " >", false},
		{"indented kept block scalar", "ci.yml", "lint", " >+2", false},
		{"block scalar waived", "ci.yml", "lint", " |  # self-hosted: hardware: the GPU", false},
		{"flow mapping", "ci.yml", "lint", " {group: big}", false},
		{"flow mapping waived", "ci.yml", "lint", " {group: big}  # self-hosted: hardware: the GPU", false},
		{"anchor", "ci.yml", "lint", " &r ubuntu-latest", false},
		{"alias", "ci.yml", "lint", " *r", false},
		{"core tag", "ci.yml", "lint", " !!str ubuntu-latest", false},
		{"local tag waived", "ci.yml", "lint", " !x qwen  # self-hosted: hardware: the GPU", false},
		{"hash inside the scalar", "ci.yml", "lint", " ubuntu-latest#x", false},
		{"no space after the colon", "ci.yml", "lint", "ubuntu-latest", false},
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
// label whose runs-on line carries a waiver that names its category.
func TestEveryJobRunsOnHostedOrWaived(t *testing.T) {
	for _, f := range workflowFiles(t) {
		src, present := readUnlessStripped(t, rel(t, f))
		if !present {
			continue
		}
		for _, why := range waiverViolations(t, filepath.Base(f), src) {
			t.Errorf("%s (ruling 999)", why)
		}
	}
}

// waiverViolations applies ruling 999's runner rule to every job of one
// workflow and returns one line per violation.
func waiverViolations(t *testing.T, name, src string) []string {
	t.Helper()
	jobs, out := workflowJobs(src)
	for i := range out {
		out[i] = name + ": " + out[i]
	}
	for _, j := range jobs {
		lines, problems := runsOnLines(j.body)
		for _, p := range problems {
			out = append(out, fmt.Sprintf("%s job %s: %s", name, j.id, p))
		}
		if len(lines) == 0 && reusableUses.MatchString(j.body) {
			continue
		}
		if len(lines) != 1 {
			out = append(out, fmt.Sprintf("%s job %s has %d runs-on lines, want 1", name, j.id, len(lines)))
			continue
		}
		if why := runsOnViolation(name, j.id, lines[0]); why != "" {
			out = append(out, fmt.Sprintf("%s job %s: %s", name, j.id, why))
		}
	}
	return out
}

// workflowJob is one entry of a workflow's jobs mapping: its id, unquoted,
// and the lines under its key.
type workflowJob struct {
	id, body string
}

// jobsKeyLine is the top-level jobs key, a block mapping with nothing after
// the colon but a comment.
var jobsKeyLine = regexp.MustCompile(`^jobs:\s*(#.*)?$`)

// jobKeyLine is one job key at job indentation: bare, single- or
// double-quoted, with nothing after the colon but a comment.
var jobKeyLine = regexp.MustCompile(`^  (?:([A-Za-z0-9_-]+)|'([A-Za-z0-9_-]+)'|"([A-Za-z0-9_-]+)")\s*:\s*(#.*)?$`)

// workflowJobs enumerates the jobs mapping of a workflow without a YAML
// decoder, and fails closed: any line under `jobs:` it cannot read as
// a comment, a job key at two-space indentation or a line of a job's body is
// returned as a problem, so a job the scan cannot see is never let through.
func workflowJobs(src string) ([]workflowJob, []string) {
	var (
		jobs     []workflowJob
		problems []string
		body     []string
		in, seen bool
	)
	flush := func() {
		if len(jobs) > 0 {
			jobs[len(jobs)-1].body = strings.Join(body, "\n")
		}
		body = nil
	}
	for n, l := range strings.Split(src, "\n") {
		trimmed := strings.TrimLeft(l, " ")
		indent := len(l) - len(trimmed)
		if !in {
			if strings.HasPrefix(l, "jobs:") {
				if seen {
					problems = append(problems, fmt.Sprintf("line %d: a second jobs key", n+1))
				} else if !jobsKeyLine.MatchString(l) {
					problems = append(problems, fmt.Sprintf("line %d: jobs is not a block mapping: %q", n+1, l))
				}
				in, seen = true, true
			}
			continue
		}
		switch {
		case strings.TrimSpace(l) == "" || strings.HasPrefix(trimmed, "#"):
			body = append(body, l)
		case indent == 0:
			in = false
		case indent >= 4 && len(jobs) > 0:
			body = append(body, l)
		case indent == 2 && jobKeyLine.MatchString(l):
			flush()
			m := jobKeyLine.FindStringSubmatch(l)
			jobs = append(jobs, workflowJob{id: m[1] + m[2] + m[3]})
		default:
			problems = append(problems, fmt.Sprintf("line %d: not a job key or a job's line: %q", n+1, l))
		}
	}
	flush()
	if !seen || len(jobs) == 0 {
		problems = append(problems, "no jobs found")
	}
	return jobs, problems
}

func TestWaiverViolationsFindEveryJob(t *testing.T) {
	const hosted = "  ok:\n    runs-on: ubuntu-latest\n"
	for _, c := range []struct {
		name, jobs string
		bad        bool
	}{
		{"runs-on continued on a deeper line", hosted + "  extra:\n    runs-on: ubuntu-latest\n      ${{ inputs.suffix }}\n", true},
		{"runs-on continued after a blank line", hosted + "  extra:\n    runs-on: ubuntu-latest\n\n      -gpu\n", true},
		{"runs-on continued after a comment line", hosted + "  extra:\n    runs-on: ubuntu-latest\n    # a note\n      -gpu\n", true},
		{"waived label continued", hosted + "  extra:\n    runs-on: qwen  # self-hosted: hardware: the GPU\n      ${{ inputs.suffix }}\n", true},
		{"deeper comment under runs-on", hosted + "  extra:\n    runs-on: ubuntu-latest\n      # a note\n", true},
		{"literal block runs-on", hosted + "  extra:\n    runs-on: |\n      ubuntu-latest\n", true},
		{"folded block runs-on", hosted + "  extra:\n    runs-on: >-\n      ubuntu-latest\n", true},
		{"flow mapping runs-on", hosted + "  extra:\n    runs-on: {group: big}\n", true},
		{"group mapping runs-on", hosted + "  extra:\n    runs-on:\n      group: big\n", true},
		{"group and labels runs-on", hosted + "  extra:\n    runs-on:\n      group: big\n      labels: ubuntu-latest\n", true},
		{"block list runs-on", hosted + "  extra:\n    runs-on:\n      - ubuntu-latest\n", true},
		{"anchored runs-on", hosted + "  extra:\n    runs-on: &r ubuntu-latest\n", true},
		{"aliased runs-on", hosted + "  extra:\n    runs-on: *r\n", true},
		{"tagged runs-on", hosted + "  extra:\n    runs-on: !!str ubuntu-latest\n", true},
		{"explicit runs-on key", hosted + "  extra:\n    ? runs-on\n    : ubuntu-latest\n", true},
		{"double-quoted runs-on key, hosted", hosted + "  extra:\n    \"runs-on\": ubuntu-latest\n", false},
		{"single-quoted runs-on key, waived", hosted + "  extra:\n    'runs-on': qwen  # self-hosted: hardware: the GPU\n", false},
		{"quoted uses key", hosted + "  call:\n    \"uses\": ./.github/workflows/x.yml\n", false},
		{"next property after runs-on", hosted + "  extra:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n", false},
		{"hosted only", hosted, false},
		{"waived", hosted + "  gpu:\n    runs-on: qwen  # self-hosted: hardware: the GPU\n", false},
		{"commented key between jobs", hosted + "  # a note\n  gpu:\n    runs-on: ubuntu-latest\n", false},
		{"plain key, unwaived", hosted + "  extra:\n    runs-on: qwen\n", true},
		{"inline-commented key, unwaived", hosted + "  extra: # GPU work\n    runs-on: qwen\n", true},
		{"single-quoted key, unwaived", hosted + "  'extra':\n    runs-on: qwen\n", true},
		{"double-quoted key, unwaived", hosted + "  \"extra\":\n    runs-on: qwen\n", true},
		{"quoted, commented key, unwaived", hosted + "  \"extra\":   # GPU work\n    runs-on: qwen\n", true},
		{"flow-mapping job", hosted + "  extra: {runs-on: qwen}\n", true},
		{"unknown line at job indentation", hosted + "  ? extra\n  : {runs-on: qwen}\n", true},
		{"deeper job indentation", "   extra:\n     runs-on: qwen\n", true},
		{"quoted runs-on key", hosted + "  extra:\n    \"runs-on\": qwen\n", true},
		{"no jobs", "", true},
		{"second jobs key", hosted + "env: {}\njobs:\n  extra:\n    runs-on: qwen\n", true},
		{"block scalar in a step", "  ok:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          echo hi\n\n          echo there\n", false},
	} {
		src := "name: x\non: push\njobs:\n" + c.jobs
		got := waiverViolations(t, "x.yml", src)
		if (len(got) > 0) != c.bad {
			t.Errorf("%s: waiverViolations = %q, want violation=%v", c.name, got, c.bad)
		}
	}
}
