package makefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// raceDocker stands in for docker in the image build targets. Its build prints
// one progress line and then does what FAKE_BUILD says: "ok" succeeds,
// "exists" fails the way BuildKit refuses the slower of two exports of one tag,
// and anything else fails the way an ordinary build error does. Every failed
// build leaves the tag behind ($log.built), so `docker image inspect` finds it
// afterwards when FAKE_INSPECT=after; before any build it finds nothing, so a
// target that checks for a held tag first still builds.
const raceDocker = `#!/bin/sh
log="$FAKE_DOCKER_LOG"
printf '%s\n' "$*" >> "$log"
case "$1" in
build)
	tag=; prev=
	for a in "$@"; do [ "$prev" != -t ] || tag="$a"; prev="$a"; done
	touch "$log.built"
	echo "#1 building $tag"
	case "${FAKE_BUILD:-ok}" in
	ok) exit 0 ;;
	exists) echo "ERROR: failed to solve: image \"docker.io/library/$tag\": already exists" >&2; exit 1 ;;
	*) echo "ERROR: failed to solve: process \"/bin/sh -c go mod download\" did not complete successfully: exit code: 1" >&2; exit 1 ;;
	esac ;;
image)
	case "$2" in
	inspect) [ "${FAKE_INSPECT:-}" = after ] && [ -e "$log.built" ] || exit 1 ;;
	esac ;;
esac
exit 0
`

func raceDockerEnv(t *testing.T, set map[string]string) (env []string, log string) {
	t.Helper()
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(raceDocker), 0o700); err != nil { // #nosec G306 -- an executable test fixture under t.TempDir()
		t.Fatalf("writing the docker stand-in: %v", err)
	}
	log = filepath.Join(t.TempDir(), "docker.log")
	all := map[string]string{
		"PATH":            bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"FAKE_DOCKER_LOG": log,
	}
	for k, v := range set {
		all[k] = v
	}
	drop := []string{"GOPRIVATE", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0",
		"MODULE_ENV_FILE", "TOOLCHAIN_IMAGE", "ITEST_IMAGE", "ITEST_ID"}
	return environ(drop, all), log
}

// Two jobs of one run can build the same content-addressed image tag at once
// on one daemon. Each starts while the tag is not there, and BuildKit refuses
// the slower export because the tag "already exists". The tag is a hash of the
// inputs, so the image the faster job left under it is the image the slower
// one would have made: the target passes, and says so. It passes only when the
// failure is that exact refusal AND the tag now resolves; every other failure
// fails the target, with the build's own output.
func TestImageBuildToleratesAConcurrentBuildOfItsContentTag(t *testing.T) {
	mef := filepath.Join(t.TempDir(), "gomodauth.env")
	if err := os.WriteFile(mef, []byte("GOPRIVATE=example.com/private\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	targets := []struct {
		name string
		args []string
	}{
		{"docker-build-toolchain", []string{"docker-build-toolchain"}},
		{"docker-build-toolchain with MODULE_ENV_FILE", []string{"docker-build-toolchain", "MODULE_ENV_FILE=" + mef}},
		{"docker-build-integration", []string{"docker-build-integration", "MODULE_ENV_FILE=" + mef, "ITEST_IMAGE=go-luks2-ci-it:raced"}},
	}
	cases := []struct {
		name    string
		build   string
		inspect string
		wantOK  bool
	}{
		{"(a) already exists, tag resolves", "exists", "after", true},
		{"(b) already exists, tag does not resolve", "exists", "", false},
		{"(c) any other error, tag resolves", "other", "after", false},
		{"(c) any other error, tag does not resolve", "other", "", false},
	}
	for _, tg := range targets {
		for _, tc := range cases {
			env, log := raceDockerEnv(t, map[string]string{"FAKE_BUILD": tc.build, "FAKE_INSPECT": tc.inspect})
			stdout, stderr, err := runMakeErr(t, env, append([]string{"-s"}, tg.args...)...)
			if _, built := called(logLines(t, log), "build "); !built {
				t.Fatalf("%s %s: docker build never ran:\n%s", tg.name, tc.name, readLog(t, log))
			}
			out := stdout + stderr
			switch {
			case tc.wantOK && err != nil:
				t.Errorf("%s %s: failed although another job built the same content: %v\n%s", tg.name, tc.name, err, out)
			case tc.wantOK && !strings.Contains(out, "was built concurrently"):
				t.Errorf("%s %s: the success does not say why:\n%s", tg.name, tc.name, out)
			case !tc.wantOK && err == nil:
				t.Errorf("%s %s: a failed build passed:\n%s", tg.name, tc.name, out)
			case !tc.wantOK && !strings.Contains(out, "ERROR: failed to solve"):
				t.Errorf("%s %s: the failure does not carry the build's output:\n%s", tg.name, tc.name, out)
			case !tc.wantOK && strings.Contains(out, "was built concurrently"):
				t.Errorf("%s %s: a failure claims a concurrent build:\n%s", tg.name, tc.name, out)
			}
		}
	}
}

// A content tag the toolchain target is handed by name, not computed from the
// inputs, is not known to be a hash of them: an "already exists" refusal of
// it is a failure like any other.
func TestToolchainBuildRaceOnlyForTheComputedTag(t *testing.T) {
	env, log := raceDockerEnv(t, map[string]string{"FAKE_BUILD": "exists", "FAKE_INSPECT": "after"})
	stdout, stderr, err := runMakeErr(t, env, "-s", "docker-build-toolchain", "TOOLCHAIN_IMAGE=go-luks2-toolchain:named")
	if _, built := called(logLines(t, log), "build "); !built {
		t.Fatalf("docker build never ran:\n%s", readLog(t, log))
	}
	if err == nil {
		t.Errorf("a refused export of a named, not content-computed, tag passed:\n%s%s", stdout, stderr)
	}
}
