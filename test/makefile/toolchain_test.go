// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package makefile

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// fakeGoRecorder stands in for the go command: it records GOPROXY and its
// arguments in log and exits with status.
func fakeGoRecorder(t *testing.T, status string) (goPath, log string) {
	t.Helper()
	dir := t.TempDir()
	log = filepath.Join(dir, "go.log")
	goPath = filepath.Join(dir, "go")
	script := "#!/bin/sh\ncase \"$1\" in\nenv) echo /nonexistent-gopath; exit 0 ;;\nesac\n" +
		"printf 'GOPROXY=%s ARGS=%s\\n' \"$GOPROXY\" \"$*\" >> " + log + "\nexit " + status + "\n"
	if err := os.WriteFile(goPath, []byte(script), 0o700); err != nil { // #nosec G306 -- an executable test fixture under t.TempDir()
		t.Fatalf("writing the fake go: %v", err)
	}
	return goPath, log
}

func readLog(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(name) // #nosec G304 -- a path under t.TempDir()
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(data)
}

// deps-check runs the checker and takes its proxy from DEPS_CHECK_GOPROXY, the
// one target allowed to ask a module host while the image has GOPROXY=off.
func TestDepsCheckRunsTheCheckerThroughDEPS_CHECK_GOPROXY(t *testing.T) {
	fakeGo, log := fakeGoRecorder(t, "0")
	env := environ(nil, map[string]string{"GOPROXY": "off"})
	runMake(t, env, "-s", "deps-check", "GO="+fakeGo, "DEPS_CHECK_GOPROXY=https://proxy.example.test")
	got := readLog(t, log)
	if !strings.Contains(got, "GOPROXY=https://proxy.example.test ARGS=run ./test/tools/depscheck") {
		t.Errorf("deps-check did not run the checker through DEPS_CHECK_GOPROXY:\n%s", got)
	}
}

// Without DEPS_CHECK_GOPROXY the environment's GOPROXY stands.
func TestDepsCheckKeepsTheEnvironmentProxyWhenUnset(t *testing.T) {
	fakeGo, log := fakeGoRecorder(t, "0")
	env := environ([]string{"DEPS_CHECK_GOPROXY"}, map[string]string{"GOPROXY": "https://env.example.test"})
	runMake(t, env, "-s", "deps-check", "GO="+fakeGo)
	if got := readLog(t, log); !strings.Contains(got, "GOPROXY=https://env.example.test ARGS=run ./test/tools/depscheck") {
		t.Errorf("deps-check did not keep the environment's GOPROXY:\n%s", got)
	}
}

// A failing checker fails the target: deps-check is a gate that can fail.
func TestDepsCheckFailsWhenTheCheckerFails(t *testing.T) {
	fakeGo, _ := fakeGoRecorder(t, "1")
	stdout, stderr, err := runMakeErr(t, environ(nil, nil), "-s", "deps-check", "GO="+fakeGo)
	if err == nil {
		t.Fatalf("the checker failed and deps-check passed:\n%s%s", stdout, stderr)
	}
	if strings.Contains(stdout, "Every module is at its latest release") {
		t.Errorf("deps-check reported success after the checker failed:\n%s", stdout)
	}
}

var toolchainTag = regexp.MustCompile(`^go-luks2-toolchain:[0-9a-f]{16}\n$`)

// The toolchain image's tag is a hash of its inputs: the same inputs name the
// same image, and a changed input names a new one.
func TestToolchainImageTagIsAHashOfItsInputs(t *testing.T) {
	stdout, stderr := runMake(t, environ(nil, nil), "-s", "toolchain-image")
	if !toolchainTag.MatchString(stdout) {
		t.Fatalf("toolchain-image printed %q, want go-luks2-toolchain:<16 hex>\n%s", stdout, stderr)
	}

	dir := t.TempDir()
	a, b, c := filepath.Join(dir, "a"), filepath.Join(dir, "b"), filepath.Join(dir, "c")
	for name, content := range map[string]string{a: "pins v1\n", b: "pins v1\n", c: "pins v2\n"} {
		if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	tag := func(input string) string {
		out, _ := runMake(t, environ(nil, nil), "-s", "toolchain-image", "TOOLCHAIN_INPUTS="+input)
		return out
	}
	if tag(a) != tag(b) {
		t.Errorf("identical inputs named different images: %q, %q", tag(a), tag(b))
	}
	if tag(a) == tag(c) {
		t.Errorf("a changed input named the same image %q", tag(a))
	}
}

// Both images are stages of the one devcontainer Dockerfile (devcontainer.md
// §1): there is no second CI image.
func TestImagesAreStagesOfTheDevcontainerDockerfile(t *testing.T) {
	for target, stage := range map[string]string{
		"docker-build-toolchain":   "--target toolchain",
		"docker-build-integration": "--target integration",
		"devcontainer":             "--target toolchain",
	} {
		stdout, stderr := runMake(t, environ(nil, nil), "-n", target)
		for _, want := range []string{"-f build/docker/devcontainer/Dockerfile", stage} {
			if !strings.Contains(stdout, want) {
				t.Errorf("make -n %s does not contain %q:\n%s%s", target, want, stdout, stderr)
			}
		}
	}
}

// toolchain-run refuses an empty CMD before anything is built.
func TestToolchainRunRefusesAnEmptyCMD(t *testing.T) {
	bin, marker := dockerInvocationMarker(t)
	env := environ(nil, map[string]string{"PATH": bin + string(os.PathListSeparator) + os.Getenv("PATH")})
	stdout, stderr, err := runMakeErr(t, env, "-s", "toolchain-run", "CMD=")
	if err == nil {
		t.Fatalf("toolchain-run passed with no CMD:\n%s%s", stdout, stderr)
	}
	if !strings.Contains(stdout, `make toolchain-run CMD=`) {
		t.Errorf("the failure does not show the usage:\n%s%s", stdout, stderr)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Errorf("docker was invoked for an empty CMD:\n%s%s", stdout, stderr)
	}
}

// toolchain-run builds the toolchain stage, then runs CMD in it as the
// invoking uid with HOME=/tmp over this checkout (devcontainer.md §5).
func TestToolchainRunBuildsThenRunsCMDInTheImage(t *testing.T) {
	bin := t.TempDir()
	log := filepath.Join(bin, "docker.log")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + log + "\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o700); err != nil { // #nosec G306 -- an executable test fixture under t.TempDir()
		t.Fatalf("writing the docker stand-in: %v", err)
	}
	env := environ(nil, map[string]string{"PATH": bin + string(os.PathListSeparator) + os.Getenv("PATH")})
	runMake(t, env, "-s", "toolchain-run", "CMD=make test", "TOOLCHAIN_IMAGE=go-luks2-toolchain:test")

	calls := strings.Split(strings.TrimSpace(readLog(t, log)), "\n")
	if len(calls) != 2 {
		t.Fatalf("want a build then a run, got %d docker calls:\n%s", len(calls), strings.Join(calls, "\n"))
	}
	for _, want := range []string{"build ", "--target toolchain", "-t go-luks2-toolchain:test"} {
		if !strings.Contains(calls[0], want) {
			t.Errorf("the build %q does not contain %q", calls[0], want)
		}
	}
	for _, want := range []string{"run --rm", "--user", "HOME=/tmp", "go-luks2-toolchain:test bash -c make test"} {
		if !strings.Contains(calls[1], want) {
			t.Errorf("the run %q does not contain %q", calls[1], want)
		}
	}
}
