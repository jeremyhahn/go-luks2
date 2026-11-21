package workflows

import (
	"path/filepath"
	"regexp"
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

func TestRunValuesMeasureTheDedentedScript(t *testing.T) {
	wf := "jobs:\n  a:\n    steps:\n      - run: echo hi\n      - name: x\n        run: |\n          one\n\n            two\n      - name: y\n"
	got := runValues(wf)
	if got[4] != "echo hi" || got[6] != "one\n\n  two\n" {
		t.Errorf("runValues = %v", got)
	}
}

// TestNoRunBlockOverTheLimit: no workflow step runs a script over
// maxRunChars characters after dedent.
func TestNoRunBlockOverTheLimit(t *testing.T) {
	seen := 0
	exempted := map[string]bool{}
	for _, path := range workflowFiles(t) {
		text := readFile(t, rel(t, path))
		lines := strings.Split(text, "\n")
		for line, v := range runValues(text) {
			seen++
			n := len([]rune(v))
			if n <= maxRunChars {
				continue
			}
			key := filepath.Base(path) + ": " + stepNameAt(lines, line-1)
			if _, ok := runSizeExempt[key]; ok {
				exempted[key] = true
				continue
			}
			t.Errorf("%s:%d: the run block is %d characters after dedent, over %d; move the script to .github/scripts", filepath.Base(path), line, n, maxRunChars)
		}
	}
	if seen == 0 {
		t.Fatal("no run: value found in any workflow; the check checked nothing")
	}
	for key := range runSizeExempt {
		if !exempted[key] {
			t.Errorf("%q is exempt from the run-size limit but no longer exceeds it (or was renamed); drop the exemption", key)
		}
	}
}

// runSizeExempt names the steps (file: step name) whose oversized run block
// is a handbook template's own, carried as the template ships it. Moving it
// is the template's change to make: this repository's copy runs from the
// trusted base, and a local fork of the script would drift from the next
// template. Each entry must still exceed the limit, or the test fails.
var runSizeExempt = map[string]string{
	"code-review.yml: Check the container, the request, the head and any standing verdict": "code-review-template's review gate script",
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
