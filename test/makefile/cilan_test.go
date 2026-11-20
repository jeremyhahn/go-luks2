package makefile

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ci-template v1.44 (ruling 887) and v1.45 (ruling 888): ci-mask-lan and
// ci-image-history are the template's scripts/ci-mask-lan.sh and
// scripts/ci-image-history.sh as Makefile recipes (#211: no shell scripts).
// These tests hold the recipes to the scripts' behavior and messages.

// bareEnv is a job environment holding only PATH, HOME and set, so no
// variable of the host running the tests reaches the recipe.
func bareEnv(path string, set map[string]string) []string {
	env := []string{"PATH=" + path, "HOME=" + os.Getenv("HOME")}
	for k, v := range set {
		env = append(env, k+"="+v)
	}
	return env
}

func maskLines(t *testing.T, set map[string]string) []string {
	t.Helper()
	stdout, stderr, err := runMakeErr(t, bareEnv(os.Getenv("PATH"), set), "-s", "ci-mask-lan")
	if err != nil {
		t.Fatalf("make -s ci-mask-lan: %v\n%s", err, stderr)
	}
	if stderr != "" {
		t.Errorf("make -s ci-mask-lan wrote to stderr: %q", stderr)
	}
	lines := strings.Fields(stdout)
	sort.Strings(lines)
	return lines
}

func TestCIMaskLANMasksThePrivateEntries(t *testing.T) {
	got := maskLines(t, map[string]string{
		"DEVCACHE_APK":      "http://10.0.0.5:3142/alpine",
		"GOPROXY":           "http://192.168.1.9:3000|https://proxy.golang.org,direct",
		"CI_REGISTRY":       "172.20.0.1:5000",
		"CI_IMAGE_REGISTRY": "172.31.255.1",
		"RELEASE_REGISTRY":  "ghcr.io/owner",
		"GITHUB_SERVER_URL": "https://github.com",
		// Not a variable the template reads, and not private.
		"OTHER_PROXY":      "http://10.9.9.9:80",
		"DEVCACHE_GOPROXY": "http://172.32.0.1:80 http://11.0.0.1 off",
	})
	want := []string{
		"::add-mask::10.0.0.5",
		"::add-mask::10.0.0.5:3142",
		"::add-mask::172.20.0.1",
		"::add-mask::172.20.0.1:5000",
		"::add-mask::172.31.255.1",
		"::add-mask::192.168.1.9",
		"::add-mask::192.168.1.9:3000",
		"::add-mask::http://10.0.0.5:3142/alpine",
		"::add-mask::http://192.168.1.9:3000",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("make -s ci-mask-lan printed\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestCIMaskLANPrintsNothingOnAPublicEnvironment(t *testing.T) {
	if got := maskLines(t, map[string]string{
		"GOPROXY":           "https://proxy.golang.org,direct",
		"GITHUB_SERVER_URL": "https://github.com",
	}); len(got) != 0 {
		t.Errorf("make -s ci-mask-lan printed %q on a public environment, want nothing", got)
	}
}

// historyDocker is a docker stand-in for ci-image-history: `docker history`
// prints <dir>/history-<image>, `docker image inspect` <dir>/config-<image>,
// and either fails when its file is missing. Every call is logged.
func historyDocker(t *testing.T, images map[string][2]string) (path, log string) {
	t.Helper()
	bin := t.TempDir()
	log = filepath.Join(bin, "calls")
	script := fmt.Sprintf(`#!/bin/sh
echo "$*" >> %q
for a do last=$a; done
f=%q/$1-$last
[ -f "$f" ] || exit 1
cat "$f"
`, log, bin)
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o700); err != nil { // #nosec G306 -- an executable test fixture under t.TempDir()
		t.Fatalf("writing the docker stand-in: %v", err)
	}
	for img, hc := range images {
		for i, kind := range []string{"history", "image"} {
			if hc[i] == "-" {
				continue
			}
			if err := os.WriteFile(filepath.Join(bin, kind+"-"+img), []byte(hc[i]), 0o600); err != nil {
				t.Fatalf("writing the stand-in's %s: %v", kind, err)
			}
		}
	}
	return bin + string(os.PathListSeparator) + os.Getenv("PATH"), log
}

func imageHistory(t *testing.T, images map[string][2]string, arg string) (stdout, stderr, log string, err error) {
	t.Helper()
	path, log := historyDocker(t, images)
	stdout, stderr, err = runMakeErr(t, bareEnv(path, nil), "-s", "ci-image-history", "IMAGES="+arg)
	return stdout, stderr, log, err
}

func TestCIImageHistoryNeedsAnImage(t *testing.T) {
	for _, arg := range []string{"", "  "} {
		_, stderr, _, err := imageHistory(t, nil, arg)
		if err == nil || !strings.Contains(stderr, "usage: make ci-image-history IMAGES='<image>...'\n") {
			t.Errorf("IMAGES=%q: err %v, stderr %q; want the usage line and a failure", arg, err, stderr)
		}
	}
}

func TestCIImageHistoryPassesAnImageWithNoPrivateAddress(t *testing.T) {
	stdout, stderr, log, err := imageHistory(t, map[string][2]string{
		"clean": {"RUN apk add go 1.10.2.3 \n|1 GOPROXY=https://172.32.0.1 \nADD file:abc in / buildkit.dockerfile.v0\n",
			`{"Env":["PATH=/usr/bin","V=11.0.0.1"],"Labels":{"v":"110.1.2.3"}}`},
	}, "clean")
	if err != nil || stdout != "" || stderr != "" {
		t.Fatalf("make -s ci-image-history = %q, %q, %v; want a silent pass", stdout, stderr, err)
	}
	calls, _ := os.ReadFile(log) // #nosec G304 -- the stand-in's log under t.TempDir()
	for _, want := range []string{
		"history --no-trunc --format {{.CreatedBy}} {{.Comment}} clean\n",
		"image inspect --format {{json .Config}} clean\n",
	} {
		if !strings.Contains(string(calls), want) {
			t.Errorf("docker was not called as %q; calls:\n%s", want, calls)
		}
	}
}

func TestCIImageHistoryNamesTheImageAndEntryNeverTheAddress(t *testing.T) {
	_, stderr, _, err := imageHistory(t, map[string][2]string{
		"good": {"RUN true\n", `{"Env":[]}`},
		"bad": {"RUN true\nRUN wget http://10.1.2.3:3142/x\nRUN true\n|1 P=192.168.0.7 /bin/sh\n",
			`{"Env":["GOPROXY=http://172.16.0.1:3000"]}`},
	}, "good bad")
	if err == nil {
		t.Fatal("make -s ci-image-history passed an image carrying private addresses")
	}
	want := "ci-image-history: bad: history entry 2 carries a private address\n" +
		"ci-image-history: bad: history entry 4 carries a private address\n" +
		"ci-image-history: bad: its config (env, labels, command) carries a private address\n"
	// make adds its own "*** ... Error 1" line after the recipe's.
	if !strings.HasPrefix(stderr, want) {
		t.Errorf("stderr\n%s\nwant\n%s", stderr, want)
	}
	for _, addr := range []string{"10.1.2.3", "192.168.0.7", "172.16.0.1"} {
		if strings.Contains(stderr, addr) {
			t.Errorf("the message names the address %s", addr)
		}
	}
}

func TestCIImageHistoryFailsOnAnImageItCannotRead(t *testing.T) {
	for name, hc := range map[string][2]string{
		"no history": {"-", `{"Env":[]}`},
		"no config":  {"RUN true\n", "-"},
	} {
		_, stderr, _, err := imageHistory(t, map[string][2]string{"img": hc}, "img")
		if err == nil || !strings.Contains(stderr, "ci-image-history: cannot read img\n") {
			t.Errorf("%s: err %v, stderr %q; want a failure naming the image", name, err, stderr)
		}
	}
}
