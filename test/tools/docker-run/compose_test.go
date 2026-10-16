package main

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The integration stage also runs as a compose service
// (build/docker/devcontainer/compose.yaml), which `make integration-test` and
// CI use. Two spellings of one security-critical invocation is how one of them
// grows a flag the other lacks, so this holds the service to privileges(),
// flag for flag: nothing missing and nothing added.

const composeFile = "../../../build/docker/devcontainer/compose.yaml"

// The keys the integration service may carry. Anything else -- privileged,
// a host network, a user, extra mounts -- is a privilege the launcher does
// not grant, or a change this test must be taught about first.
var composeKeys = map[string]bool{
	"image": true, "pull_policy": true, "cap_drop": true, "cap_add": true,
	"security_opt": true, "devices": true, "device_cgroup_rules": true,
	"volumes": true,
}

var composeVar = regexp.MustCompile(`\$\{(GO_LUKS2_[A-Z_]+):\?[^}]*\}`)

// composeIntegrationFlags reads the integration service and spells it as the
// docker run flags it is equivalent to, with each interpolated value replaced
// by the variable's name. It returns the flags and the service's keys.
func composeIntegrationFlags(t *testing.T) ([]string, []string) {
	t.Helper()
	raw, err := os.ReadFile(composeFile)
	if err != nil {
		t.Fatal(err)
	}
	flagFor := map[string]string{
		"cap_drop": "--cap-drop", "cap_add": "--cap-add", "security_opt": "--security-opt",
		"devices": "--device", "device_cgroup_rules": "--device-cgroup-rule", "volumes": "-v",
	}
	var flags, keys []string
	inService, key := false, ""
	for _, line := range strings.Split(string(raw), "\n") {
		switch {
		case strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#"):
			continue
		case line == "  integration:":
			inService = true
			continue
		case !strings.HasPrefix(line, "    "):
			inService = false
			continue
		case !inService:
			continue
		}
		body := strings.TrimPrefix(line, "    ")
		if !strings.HasPrefix(body, " ") {
			k, _, _ := strings.Cut(body, ":")
			key = k
			keys = append(keys, k)
			continue
		}
		item, ok := strings.CutPrefix(strings.TrimSpace(body), "- ")
		if !ok {
			t.Fatalf("compose.yaml: %q under %s is not a list item", line, key)
		}
		item = composeVar.ReplaceAllString(strings.Trim(item, `"`), "$1")
		if f, ok := flagFor[key]; ok {
			flags = append(flags, f, item)
		}
	}
	return flags, keys
}

// pairs turns a flag list into sorted "flag value" strings, so the two sets
// compare without depending on the order either file lists them in.
func pairs(flags []string) []string {
	var out []string
	for i := 0; i+1 < len(flags); i += 2 {
		out = append(out, flags[i]+" "+flags[i+1])
	}
	sort.Strings(out)
	return out
}

func TestComposeIntegrationServiceHasTheLaunchersPrivileges(t *testing.T) {
	got, keys := composeIntegrationFlags(t)
	want := privileges("GO_LUKS2_SECCOMP_PROFILE", "GO_LUKS2_DM_MAJOR", "GO_LUKS2_TEST_STATE_DIR")
	if g, w := strings.Join(pairs(got), "\n"), strings.Join(pairs(want), "\n"); g != w {
		t.Errorf("compose.yaml's integration service and privileges() differ\ncompose:\n%s\n\nlauncher:\n%s", g, w)
	}
	if len(keys) == 0 {
		t.Fatal("compose.yaml has no integration service; the check checked nothing")
	}
	for _, k := range keys {
		if !composeKeys[k] {
			t.Errorf("compose.yaml's integration service carries %q, which the launcher does not set", k)
		}
	}
}

// The parser above is what the parity check stands on, so it must see an
// added privilege rather than skip it.
func TestComposeParityCatchesAnAddedFlag(t *testing.T) {
	got, _ := composeIntegrationFlags(t)
	want := privileges("GO_LUKS2_SECCOMP_PROFILE", "GO_LUKS2_DM_MAJOR", "GO_LUKS2_TEST_STATE_DIR")
	grown := append(append([]string{}, got...), "--cap-add", "NET_ADMIN")
	if strings.Join(pairs(grown), "\n") == strings.Join(pairs(want), "\n") {
		t.Error("an added capability compares equal to the launcher's set")
	}
	if len(got) != len(want) {
		t.Errorf("parsed %d flag words from compose.yaml, the launcher has %d", len(got), len(want))
	}
}
