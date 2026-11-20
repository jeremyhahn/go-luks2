package workflows

import (
	"regexp"
	"strings"
	"testing"
)

// TestRevertStepsNameCISteps: every alternative in revert-red-main.yml's
// REVERT_STEPS names at least one step of ci.yml, so a step renamed in a
// template merge (ci-template v1.48, #494) cannot leave a deterministic stage
// that no longer reverts a red main.
func TestRevertStepsNameCISteps(t *testing.T) {
	m := regexp.MustCompile(`(?m)^\s*REVERT_STEPS: '\^\((.*)\)\$'$`).FindStringSubmatch(readFile(t, ".github/workflows/revert-red-main.yml"))
	if m == nil {
		t.Fatal("revert-red-main.yml defines no REVERT_STEPS of the form '^(a|b|...)$'")
	}
	var steps []string
	for _, s := range regexp.MustCompile(`(?m)^\s*- name: (.+)$`).FindAllStringSubmatch(readFile(t, ".github/workflows/ci.yml"), -1) {
		steps = append(steps, strings.TrimSpace(s[1]))
	}
	for _, alt := range strings.Split(m[1], "|") {
		re, err := regexp.Compile(`^(?:` + alt + `)$`)
		if err != nil {
			t.Errorf("REVERT_STEPS alternative %q: %v", alt, err)
			continue
		}
		hit := false
		for _, s := range steps {
			if re.MatchString(s) {
				hit = true
				break
			}
		}
		if !hit {
			t.Errorf("REVERT_STEPS alternative %q names no ci.yml step", alt)
		}
	}
}
