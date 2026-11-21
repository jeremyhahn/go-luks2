package workflows

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// maxRunChars bounds a step's `run:` script. GitHub refuses a run value over
// 21,000 characters in some contexts; a script that long belongs in a file
// under .github/scripts, where it can be read, linted and tested (Codex P1 on
// PR #495, Resume 23).
const maxRunChars = 20000

var runKey = regexp.MustCompile(`^( *)(?:- +)?run: *(.*)$`)

// runValues returns each `run:` value in a workflow, by 1-based line, as the
// runner gets it: a block scalar dedented by its first non-blank line's
// indentation, a plain value as written.
func runValues(text string) map[int]string {
	out := map[int]string{}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		m := runKey.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		head := strings.TrimSpace(m[2])
		if head != "" && (head[0] == '"' || head[0] == '\'') {
			// A quoted value runs to its closing quote, across lines.
			out[i+1] = quotedValue(lines[i:], head)
			continue
		}
		if head == "" || (head[0] != '|' && head[0] != '>') {
			out[i+1] = head
			continue
		}
		keyIndent := len(m[1])
		var body []string
		indent := -1
		for _, l := range lines[i+1:] {
			if strings.TrimSpace(l) == "" {
				body = append(body, "")
				continue
			}
			n := len(l) - len(strings.TrimLeft(l, " "))
			if n <= keyIndent {
				break
			}
			if indent < 0 {
				indent = n
			}
			if n < indent {
				break
			}
			body = append(body, l[indent:])
		}
		out[i+1] = strings.TrimRight(strings.Join(body, "\n"), "\n") + "\n"
	}
	return out
}

// quotedValue returns a quoted `run:` value that starts in head (the text
// after `run:` on lines[0]) and runs to its closing quote, folded as YAML
// folds a flow scalar: a line break between two lines is a space, a blank
// line a newline. Unclosed, it runs to the end of the text (measured whole).
func quotedValue(lines []string, head string) string {
	q := head[0]
	var parts []string
	for k, text := 0, head[1:]; k < len(lines); k++ {
		if k > 0 {
			text = strings.TrimSpace(lines[k])
		}
		if end := closingQuote(text, q); end >= 0 {
			parts = append(parts, strings.TrimLeft(text[:end], " \t"))
			break
		}
		parts = append(parts, strings.TrimSpace(text))
	}
	var b strings.Builder
	for j, p := range parts {
		if j > 0 && p == "" {
			b.WriteString("\n")
			continue
		}
		if j > 0 && parts[j-1] != "" {
			b.WriteString(" ")
		}
		b.WriteString(p)
	}
	return b.String()
}

// closingQuote returns the index in s of the quote q that closes a scalar
// (a backslash escapes in double quotes, ” is a quote in single), or -1.
func closingQuote(s string, q byte) int {
	for i := 0; i < len(s); i++ {
		switch {
		case q == '"' && s[i] == '\\':
			i++
		case s[i] == q && q == '\'' && i+1 < len(s) && s[i+1] == '\'':
			i++
		case s[i] == q:
			return i
		}
	}
	return -1
}

func TestRunValuesMeasureTheDedentedScript(t *testing.T) {
	wf := "jobs:\n  a:\n    steps:\n      - run: echo hi\n      - name: x\n        run: |\n          one\n\n            two\n      - name: y\n"
	got := runValues(wf)
	if got[4] != "echo hi" || got[6] != "one\n\n  two\n" {
		t.Errorf("runValues = %v", got)
	}
}

func TestRunValuesMeasureAQuotedValueWhole(t *testing.T) {
	long := strings.Repeat("x", maxRunChars)
	wf := "jobs:\n  a:\n    steps:\n      - name: q\n        run: \"echo one\n          " + long + "\n\n          two \\\" end\"\n      - name: s\n        run: 'it''s'\n"
	got := runValues(wf)
	if want := "echo one " + long + "\ntwo \\\" end"; got[5] != want {
		t.Errorf("the quoted value is %d characters, want %d", len(got[5]), len(want))
	}
	if got[10] != "it''s" {
		t.Errorf("runValues[10] = %q, want %q", got[10], "it''s")
	}
	errs := runSizeFindings(map[string]string{"x.yml": wf}, nil)
	if len(errs) != 1 || !strings.Contains(errs[0], "x.yml:5:") {
		t.Errorf("a quoted run value over the limit on its later lines gives %q, want one finding at x.yml:5", errs)
	}
}

func TestRunSizeExemptionCeiling(t *testing.T) {
	exempt := map[string]runExemption{"x.yml: big": {"a template step", 56000}}
	for _, c := range []struct {
		n    int
		want bool
	}{{56000, false}, {56001, true}} {
		wf := "jobs:\n  a:\n    steps:\n      - name: big\n        run: |\n          " + strings.Repeat("x", c.n-1) + "\n"
		errs := runSizeFindings(map[string]string{"x.yml": wf}, exempt)
		over := len(errs) == 1 && strings.Contains(errs[0], "over its exemption's ceiling")
		if (c.want && !over) || (!c.want && len(errs) != 0) {
			t.Errorf("an exempt step of %d characters gives %q; a finding wanted: %v", c.n, errs, c.want)
		}
	}
	if errs := runSizeFindings(map[string]string{"x.yml": "jobs:\n  a:\n    steps:\n      - name: big\n        run: echo\n"}, exempt); len(errs) != 1 || !strings.Contains(errs[0], "no longer exceeds") {
		t.Errorf("a stale exemption gives %q, want one finding", errs)
	}
}

// runSizeFindings checks the run values of the workflows (file base name ->
// text) against maxRunChars and the exemptions: an exempt step may exceed
// the limit up to its ceiling, and an exemption for a present workflow that
// no step needs is stale.
func runSizeFindings(files map[string]string, exempt map[string]runExemption) []string {
	var errs []string
	exempted := map[string]bool{}
	for file, text := range files {
		lines := strings.Split(text, "\n")
		for line, v := range runValues(text) {
			n := len([]rune(v))
			if n <= maxRunChars {
				continue
			}
			key := file + ": " + stepNameAt(lines, line-1)
			if e, ok := exempt[key]; ok {
				exempted[key] = true
				if n > e.ceiling {
					errs = append(errs, fmt.Sprintf("%s:%d: the exempt run block is %d characters, over its exemption's ceiling %d (%s)", file, line, n, e.ceiling, e.why))
				}
				continue
			}
			errs = append(errs, fmt.Sprintf("%s:%d: the run block is %d characters after dedent, over %d; move the script to .github/scripts", file, line, n, maxRunChars))
		}
	}
	for key := range exempt {
		// The published tree leaves out export-ignore workflows (code-review.yml);
		// an exemption for a workflow that is not there is not stale.
		file, _, _ := strings.Cut(key, ": ")
		if _, present := files[file]; present && !exempted[key] {
			errs = append(errs, fmt.Sprintf("%q is exempt from the run-size limit but no longer exceeds it (or was renamed); drop the exemption", key))
		}
	}
	sort.Strings(errs)
	return errs
}

// TestNoRunBlockOverTheLimit: no workflow step runs a script over
// maxRunChars characters after dedent, but an exempt one up to its ceiling.
func TestNoRunBlockOverTheLimit(t *testing.T) {
	files := map[string]string{}
	seen := 0
	for _, path := range workflowFiles(t) {
		text := readFile(t, rel(t, path))
		files[filepath.Base(path)] = text
		seen += len(runValues(text))
	}
	if seen == 0 {
		t.Fatal("no run: value found in any workflow; the check checked nothing")
	}
	for _, e := range runSizeFindings(files, runSizeExempt) {
		t.Error(e)
	}
}

type runExemption struct {
	why     string
	ceiling int // the most characters the step may hold
}

// runSizeExempt names the steps (file: step name) whose oversized run block
// is a handbook template's step, carried verbatim, each with a ceiling of
// the template step's size plus 2,000 characters. Moving the template's
// part is the template's change to make: this repository's copy runs from
// the trusted base, and a local fork of the script would drift from the next
// template. Each entry must still exceed the limit, or the test fails; a
// step past its ceiling fails too (a local addition belongs in a file).
var runSizeExempt = map[string]runExemption{
	"code-review.yml: Check the container, the request, the head and any standing verdict": {
		"code-review-template v5.12.6's step (54,725 characters) plus 2,000", 56725},
}

// stepNameAt returns the name of the step whose key is on line i (0-based):
// the nearest `- name:` line at or above it.
func stepNameAt(lines []string, i int) string {
	for ; i >= 0; i-- {
		s := strings.TrimSpace(lines[i])
		if name, ok := strings.CutPrefix(s, "- name: "); ok {
			return name
		}
		if i < len(lines)-1 && strings.HasPrefix(s, "- ") {
			return ""
		}
	}
	return ""
}
