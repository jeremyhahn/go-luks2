package workflows

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// runsOnLine is a job's unquoted runs-on key at job-property indentation (the
// strict subset rejects a quoted one); the capture is everything after the
// colon, trailing comments included.
var runsOnLine = regexp.MustCompile(`^    runs-on[ \t]*:(.*)$`)

// reusableUses is a job that calls a reusable workflow: it has no runs-on.
var reusableUses = regexp.MustCompile(`(?m)^    uses[ \t]*: `)

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
	if file == "ci.yml" && jobID == "preflight" && strings.TrimSpace(value) == preflightRunsOn {
		// ci-template v1.49: preflight alone may run on the bigdisk pool on
		// github.com, by this exact form; the runner-labels step checks it
		// with CI_PREFLIGHT_RUNS_ON unset and set to its fallback.
		return ""
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

// templateRoutingExpression is the handbook code-review.yml template's
// runs-on for its scope and gate jobs (v5.12.5, owner ruling 1012). On
// GitHub it resolves to ubuntu-latest. Only this exact string is accepted;
// any other expression is still refused.
const templateRoutingExpression = "${{ github.server_url == 'https://github.com' && 'ubuntu-latest' || 'bigdisk' }}"

// runsOnLabel reads a runs-on value, comment removed, as one runner label: a
// plain scalar or one single- or double-quoted scalar around a literal label.
// It returns the label, or "" and the reason it is not one.
// The template routing expression reads as ubuntu-latest.
func runsOnLabel(value string) (string, string) {
	switch {
	case value == "":
		return "", "runs-on has no value on its key line (a list, a mapping or a block scalar below it)"
	case value == templateRoutingExpression:
		return hostedRunner, ""
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
		{"v1.52 preflight form", "ci.yml", "preflight", " " + preflightRunsOn + "   # v1.52", true},
		{"v1.52 preflight form on another job", "ci.yml", "lint", " " + preflightRunsOn, false},
		{"v1.52 preflight form outside ci.yml", "batch.yml", "preflight", " " + preflightRunsOn, false},
		{"v1.52 preflight form, other default", "ci.yml", "preflight", " " + strings.Replace(preflightRunsOn, `"bigdisk"]`, `"bigdisk-docker"]`, 1), false},
		{"self-hosted with unrelated comment", "ci.yml", "lint", " qwen  # CUSTOMIZE: the host", false},
		{"label list", "ci.yml", "lint", " [self-hosted, linux]", false},
		{"label list waived", "ci.yml", "lint", " [self-hosted, gpu]  # self-hosted: hardware: the GPU", false},
		{"no inline label", "ci.yml", "lint", "", false},
		{"template routing expression", "code-review.yml", "gate", ` ${{ github.server_url == 'https://github.com' && 'ubuntu-latest' || 'bigdisk' }}`, true},
		{"template routing expression with comment", "code-review.yml", "scope", ` ${{ github.server_url == 'https://github.com' && 'ubuntu-latest' || 'bigdisk' }}  # a note`, true},
		{"routing expression, labels swapped", "code-review.yml", "gate", ` ${{ github.server_url == 'https://github.com' && 'bigdisk' || 'ubuntu-latest' }}`, false},
		{"routing expression, other label", "code-review.yml", "gate", ` ${{ github.server_url == 'https://github.com' && 'qwen' || 'bigdisk' }}`, false},
		{"routing expression, other spacing", "code-review.yml", "gate", ` ${{github.server_url == 'https://github.com' && 'ubuntu-latest' || 'bigdisk'}}`, false},
		{"routing expression quoted", "code-review.yml", "gate", ` '${{ github.server_url == 'https://github.com' && 'ubuntu-latest' || 'bigdisk' }}'`, false},
		{"other expression", "ci.yml", "lint", ` ${{ inputs.runner }}`, false},
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

// jobKeyLine is one job key at job indentation, unquoted, with nothing after
// the colon but a comment.
var jobKeyLine = regexp.MustCompile(`^  ([A-Za-z0-9_-]+):\s*(#.*)?$`)

// documentMarker is a YAML document start or end marker. A workflow is one
// document: a marker anywhere fails, so a second document is never skipped.
var documentMarker = regexp.MustCompile(`^(?:---|\.\.\.)(?:[ \t]|$)`)

// topKeyLine is a plain top-level key: the only column-0 line allowed after
// `jobs:` besides blanks and comments.
var topKeyLine = regexp.MustCompile(`^[A-Za-z0-9_.-]+:(?:[ \t]|$)`)

// workflowJobs enumerates the jobs mapping of a workflow without a YAML
// decoder, and fails closed: any line under `jobs:` it cannot read as
// a comment, a job key at two-space indentation or a line of a job's body is
// returned as a problem, so a job the scan cannot see is never let through.
// Every line of the file, from line 1 and top level included, must also fit
// the strict YAML subset of subsetScanner, and the file must hold exactly one
// top-level `jobs:` key, so a quoted or escaped key, an unclosed quote or a
// plain multi-line scalar anywhere cannot make GitHub read a job differently
// from the scan.
func workflowJobs(src string) ([]workflowJob, []string) {
	var (
		jobs     []workflowJob
		problems []string
		body     []string
		in       bool
		jobsKeys int
		subset   = newSubsetScanner(false)
	)
	flush := func() {
		if len(jobs) > 0 {
			jobs[len(jobs)-1].body = strings.Join(body, "\n")
		}
		body = nil
	}
	for n, l := range strings.Split(src, "\n") {
		if documentMarker.MatchString(l) {
			problems = append(problems, fmt.Sprintf("line %d: a YAML document marker: %q", n+1, l))
			continue
		}
		if why := subset.line(l); why != "" {
			problems = append(problems, fmt.Sprintf("line %d: %s: %q", n+1, why, l))
		}
		trimmed := strings.TrimLeft(l, " ")
		indent := len(l) - len(trimmed)
		if jobsKeys > 0 && l != "" && l[0] != ' ' && l[0] != '#' && strings.TrimSpace(l) != "" && !topKeyLine.MatchString(l) {
			problems = append(problems, fmt.Sprintf("line %d: a column-0 line after jobs that is not a plain top-level key: %q", n+1, l))
		}
		if strings.HasPrefix(l, "jobs:") {
			jobsKeys++
			switch {
			case jobsKeys > 1:
				problems = append(problems, fmt.Sprintf("line %d: a second top-level jobs key", n+1))
				in = false
				continue
			case !jobsKeyLine.MatchString(l):
				problems = append(problems, fmt.Sprintf("line %d: jobs is not a block mapping: %q", n+1, l))
			}
			in = true
			continue
		}
		if !in {
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
			jobs = append(jobs, workflowJob{id: m[1]})
		default:
			problems = append(problems, fmt.Sprintf("line %d: not a job key or a job's line: %q", n+1, l))
		}
	}
	flush()
	if jobsKeys == 0 || len(jobs) == 0 {
		problems = append(problems, "no jobs found")
	}
	return jobs, problems
}

// subsetKey matches a mapping key line of the strict YAML subset: an unquoted
// key of [A-Za-z0-9_.-], a colon, then whitespace and the value or the end of
// the line. A quoted key, or one written with an escape, does not match, so
// it is rejected rather than decoded.
var subsetKey = regexp.MustCompile(`^([A-Za-z0-9_.-]+):(?:[ \t]+|$)(.*)$`)

// blockIndicators are the block scalar headers the subset reads: no explicit
// indentation indicator.
var blockIndicators = map[string]bool{"|": true, ">": true, "|-": true, ">-": true, "|+": true, ">+": true}

// subsetScanner is an allowlist of a strict YAML subset, fed every line of a
// workflow file, from line 1, one at a time. Each line must be blank, a full-line comment, a
// `key: value` or `key:` line, or a `- ` sequence item holding one of those
// or a scalar. A quoted scalar or a flow collection must close on its line;
// no value carries an anchor, alias or tag.
// A line deeper than the last one is allowed only after an empty value (a
// nested mapping or sequence) or inside a block scalar; deeper after a
// non-empty value is a plain multi-line scalar and fails. What the subset
// does not cover fails closed: the runs-on reader never meets YAML it would
// read differently from GitHub.
type subsetScanner struct {
	col    int  // column of the last content line's innermost node
	deeper bool // the last content line opened a nested block
	block  int  // parent column of the open block scalar, or -1
}

// newSubsetScanner starts a scan at column 0. With nested false the first
// content line must be at column 0 (a whole file); with nested true it may
// be deeper (the lines under a key).
func newSubsetScanner(nested bool) *subsetScanner {
	return &subsetScanner{deeper: nested, block: -1}
}

// line checks one line and returns why it is outside the subset, or "".
func (s *subsetScanner) line(l string) string {
	trimmed := strings.TrimLeft(l, " ")
	indent := len(l) - len(trimmed)
	if s.block >= 0 {
		if strings.TrimSpace(l) == "" || indent > s.block {
			return ""
		}
		s.block = -1
	}
	switch {
	case strings.TrimSpace(l) == "":
		return ""
	case strings.HasPrefix(trimmed, "\t"):
		return "a tab in the indentation"
	case strings.HasPrefix(trimmed, "#"):
		return ""
	case indent > s.col && !s.deeper:
		return "a deeper line after a non-empty value (a multi-line scalar)"
	}
	col, rest, parent, item := indent, trimmed, indent, false
	for rest == "-" || strings.HasPrefix(rest, "- ") {
		after := strings.TrimLeft(rest[1:], " ")
		parent, col, rest, item = col, col+len(rest)-len(after), after, true
	}
	if strings.HasPrefix(rest, "\t") {
		return "a tab after a sequence indicator"
	}
	value := rest
	if m := subsetKey.FindStringSubmatch(rest); m != nil {
		parent, value = col, m[2]
	} else if !item {
		return "not an unquoted `key: value` line (a quoted or escaped key, or a multi-line scalar)"
	}
	empty, block, why := subsetValue(value)
	if why != "" {
		return why
	}
	s.col, s.deeper = col, empty
	if block {
		s.block = parent
	}
	return ""
}

// subsetValue reads the value after a key or a sequence indicator: empty (a
// nested block follows), a block scalar header, or a scalar that ends on
// this line.
func subsetValue(v string) (empty, block bool, why string) {
	v = strings.TrimLeft(v, " \t")
	switch {
	case v == "" || v[0] == '#':
		return true, false, ""
	case v[0] == '&' || v[0] == '*' || v[0] == '!':
		return false, false, "a YAML anchor, alias or tag"
	case v[0] == '|' || v[0] == '>':
		header, rest := v, ""
		if i := strings.IndexAny(v, " \t"); i >= 0 {
			header, rest = v[:i], v[i:]
		}
		if !blockIndicators[header] || !commentOrBlank(rest) {
			return false, false, "a block scalar header outside the subset"
		}
		return false, true, ""
	case v[0] == '\'' || v[0] == '"':
		end := quotedEnd(v, 0)
		if end < 0 {
			return false, false, "a quoted scalar does not close on its line"
		}
		if !commentOrBlank(v[end+1:]) {
			return false, false, "text after a quoted scalar"
		}
	case v[0] == '[' || v[0] == '{':
		if why := flowClosed(v); why != "" {
			return false, false, why
		}
	}
	return false, false, ""
}

// commentOrBlank reports whether s is empty, blank, or whitespace and then a
// comment.
func commentOrBlank(s string) bool {
	t := strings.TrimLeft(s, " \t")
	return t == "" || (t[0] == '#' && len(t) < len(s))
}

// quotedEnd returns the index of the quote closing the scalar opened at
// v[i], or -1 when it does not close on this line.
func quotedEnd(v string, i int) int {
	q := v[i]
	for j := i + 1; j < len(v); j++ {
		switch {
		case q == '"' && v[j] == '\\':
			j++
		case v[j] == q && q == '\'' && j+1 < len(v) && v[j+1] == '\'':
			j++
		case v[j] == q:
			return j
		}
	}
	return -1
}

// flowClosed returns "" when the flow collection opening v closes on this
// line, with only a comment after it and no anchor, alias or tag inside it,
// and the reason otherwise.
func flowClosed(v string) string {
	const open = "a flow collection does not close on its line"
	depth := 0
	for i := 0; i < len(v); i++ {
		switch c := v[i]; c {
		case '\'', '"':
			if i > 0 && !strings.ContainsRune("[{,: \t", rune(v[i-1])) {
				continue
			}
			if i = quotedEnd(v, i); i < 0 {
				return open
			}
		case '&', '*', '!':
			if strings.ContainsRune("[{, \t", rune(v[i-1])) {
				return "a YAML anchor, alias or tag in a flow collection"
			}
		case '[', '{':
			depth++
		case ']', '}':
			if depth--; depth == 0 {
				if !commentOrBlank(v[i+1:]) {
					return "text after a flow collection"
				}
				return ""
			}
		case '#':
			if v[i-1] == ' ' || v[i-1] == '\t' {
				return open
			}
		}
	}
	return open
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
		{"double-quoted runs-on key, hosted", hosted + "  extra:\n    \"runs-on\": ubuntu-latest\n", true},
		{"single-quoted runs-on key, waived", hosted + "  extra:\n    'runs-on': qwen  # self-hosted: hardware: the GPU\n", true},
		{"quoted uses key", hosted + "  call:\n    \"uses\": ./.github/workflows/x.yml\n", true},
		{"codex: multi-line name hides an escaped runs-on key", hosted + "  extra:\n    name: 'decoy\n    runs-on: ubuntu-latest\n    end'\n    \"runs\\u002don\": qwen\n    steps:\n      - run: echo ok\n", true},
		{"quoted key in a step", hosted + "  extra:\n    runs-on: ubuntu-latest\n    steps:\n      - 'run': echo ok\n", true},
		{"escaped key", hosted + "  extra:\n    runs-on: ubuntu-latest\n    \"tim\\x65out-minutes\": 5\n", true},
		{"unclosed double quote", hosted + "  extra:\n    runs-on: ubuntu-latest\n    env:\n      A: \"open\n      B: x\"\n", true},
		{"plain multi-line value", hosted + "  extra:\n    runs-on: ubuntu-latest\n    name: a\n      b\n", true},
		{"flow list not closed on its line", hosted + "  extra:\n    runs-on: ubuntu-latest\n    needs: [ok,\n      ok]\n", true},
		{"second document holds an unwaived job", hosted + "--- \n  extra:\n    runs-on: qwen\n", true},
		{"document end marker, then an unwaived job", hosted + "...\n  extra:\n    runs-on: qwen\n", true},
		{"stray column-0 line", hosted + "extra\n  gpu:\n    runs-on: qwen\n", true},
		{"top-level key after jobs", hosted + "env:\n  A: b\n", false},
		{"anchor on a value", hosted + "  extra:\n    runs-on: ubuntu-latest\n    timeout-minutes: &t 5\n", true},
		{"alias value", hosted + "  extra:\n    runs-on: ubuntu-latest\n    timeout-minutes: *t\n", true},
		{"tagged value", hosted + "  extra:\n    runs-on: ubuntu-latest\n    timeout-minutes: !!int 5\n", true},
		{"alias in a flow list", hosted + "  extra:\n    runs-on: ubuntu-latest\n    needs: [ok, *j]\n", true},
		{"tab-indented line", hosted + "  extra:\n    runs-on: ubuntu-latest\n\tname: x\n", true},
		{"subset forms", hosted + "  extra:\n    runs-on: ubuntu-latest  # note\n    needs: [ok]\n    env: {A: 'x', B: \"y # z\"}\n    if: \"github.event_name == 'push'\"\n    strategy:\n      matrix:\n        os:\n          - a\n          - 'b'\n    steps:\n      -\n        name: it's plain\n      - uses: x/y@v1\n        with:\n          script: >-\n            one\n\n            two\n      - run: |\n          echo 'unclosed\n", false},
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

// TestWaiverViolationsWholeFile: the strict subset holds from line 1, top
// level included, and the file has exactly one top-level jobs key.
func TestWaiverViolationsWholeFile(t *testing.T) {
	const job = "  ok:\n    runs-on: ubuntu-latest\n"
	for _, c := range []struct {
		name, src string
		bad       bool
	}{
		{"codex: quoted jobs key, decoy jobs inside a multi-line name", "\"jobs\":\n  real:\n    runs-on: qwen\n    steps:\n      - run: echo hi\nname: \"decoy\njobs:\n  fake:\n    runs-on: ubuntu-latest\n    x: end\"\non: push\n", true},
		{"two top-level jobs keys", "name: x\non: push\njobs:\n" + job + "jobs:\n" + job, true},
		{"no jobs key", "name: x\non: push\n", true},
		{"plain multi-line top-level value", "name: a\n  jobs\non: push\njobs:\n" + job, true},
		{"quoted top-level key", "'name': x\non: push\njobs:\n" + job, true},
		{"anchor at the top level", "name: x\non: &o push\njobs:\n" + job, true},
		{"leading document marker", "---\nname: x\non: push\njobs:\n" + job, true},
		{"indented first line", "  name: x\non: push\njobs:\n" + job, true},
		{"block scalar at the top level", "name: x\nrun-name: |\n  jobs:\n    evil:\njobs:\n" + job, false},
		{"one jobs key with top-level context", "# c\nname: x\non:\n  push:\n    branches: [main]\n  schedule:\n    - cron: '0 3 * * *'\npermissions: {}\njobs:\n" + job + "env:\n  A: b\n", false},
	} {
		got := waiverViolations(t, "x.yml", c.src)
		if (len(got) > 0) != c.bad {
			t.Errorf("%s: waiverViolations = %q, want violation=%v", c.name, got, c.bad)
		}
	}
}
