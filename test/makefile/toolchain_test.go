// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package makefile

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
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

// The base stage runs `go mod download`, and go.mod pins a private module: a
// devcontainer build without the credentials staging and the build-time proxy
// dies on it, as a bare `docker build` did.
func TestDevcontainerBuildGetsModuleCredentials(t *testing.T) {
	for _, target := range []string{"devcontainer", "docker-build-toolchain"} {
		stdout, stderr := runMake(t, environ(nil, nil), "-n", target)
		for _, want := range []string{"--secret id=gomodauth,src=", "--build-arg GO_BUILD_PROXY", "gomodauth.XXXXXX"} {
			if !strings.Contains(stdout, want) {
				t.Errorf("make -n %s does not contain %q:\n%s%s", target, want, stdout, stderr)
			}
		}
	}
}

// devcontainer.json opens the image `make devcontainer` builds, so VS Code
// gets the same credentials staging instead of a build of its own without it.
func TestDevcontainerJSONOpensTheImageMakeDevcontainerBuilds(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), ".devcontainer", "devcontainer.json")) // #nosec G304 -- the repository's own devcontainer definition
	if err != nil {
		t.Fatalf("reading devcontainer.json: %v", err)
	}
	var dc struct {
		InitializeCommand string          `json:"initializeCommand"`
		Image             string          `json:"image"`
		Build             json.RawMessage `json:"build"`
	}
	if err := json.Unmarshal(raw, &dc); err != nil {
		t.Fatalf("parsing devcontainer.json: %v", err)
	}
	if dc.Build != nil {
		t.Errorf("devcontainer.json builds the image itself, without the credentials staging: %s", dc.Build)
	}
	if !strings.Contains(dc.InitializeCommand, "make") || !strings.HasSuffix(dc.InitializeCommand, " devcontainer") {
		t.Errorf("initializeCommand %q does not run make devcontainer", dc.InitializeCommand)
	}
	stdout, stderr := runMake(t, environ(nil, nil), "-n", "devcontainer")
	if dc.Image == "" || !strings.Contains(stdout, "-t "+dc.Image+" ") {
		t.Errorf("devcontainer.json opens %q, which make devcontainer does not tag:\n%s%s", dc.Image, stdout, stderr)
	}
}

// devcontainer.json enables the language server and the toolchain image sets
// GOPROXY=off, so gopls must be in the image, at a pin of the one pin file.
func TestToolchainInstallsThePinnedGopls(t *testing.T) {
	root := repoRoot(t)
	pins, err := os.ReadFile(filepath.Join(root, "build/docker/devcontainer/tool-pins.env")) // #nosec G304 -- the repository's own tool pin file
	if err != nil {
		t.Fatalf("reading tool-pins.env: %v", err)
	}
	if !regexp.MustCompile(`(?m)^GOPLS_VERSION=v\d+\.\d+\.\d+$`).Match(pins) {
		t.Errorf("tool-pins.env carries no GOPLS_VERSION=vX.Y.Z pin")
	}
	dockerfile, err := os.ReadFile(filepath.Join(root, "build/docker/devcontainer/Dockerfile")) // #nosec G304 -- the repository's own Dockerfile
	if err != nil {
		t.Fatalf("reading the devcontainer Dockerfile: %v", err)
	}
	if !strings.Contains(string(dockerfile), `go install "golang.org/x/tools/gopls@${GOPLS_VERSION}"`) {
		t.Errorf("the devcontainer Dockerfile does not install gopls at the pin")
	}
}

// TestToolchainBuildsGosecAgainstThePinnedXTools: gosec v2.29.0's go.mod names
// an x/tools that cannot read Go 1.27's export data, so in the image every
// import failed to type-check and gosec exited 1 with no finding. The image
// builds it in a throwaway module with x/tools raised to the pin, and keeps the
// -X flag that makes it report GOSEC_VERSION.
func TestToolchainBuildsGosecAgainstThePinnedXTools(t *testing.T) {
	root := repoRoot(t)
	pins, err := os.ReadFile(filepath.Join(root, "build/docker/devcontainer/tool-pins.env")) // #nosec G304 -- the repository's own tool pin file
	if err != nil {
		t.Fatalf("reading tool-pins.env: %v", err)
	}
	if !regexp.MustCompile(`(?m)^XTOOLS_VERSION=v\d+\.\d+\.\d+$`).Match(pins) {
		t.Errorf("tool-pins.env carries no XTOOLS_VERSION=vX.Y.Z pin")
	}
	dockerfile, err := os.ReadFile(filepath.Join(root, "build/docker/devcontainer/Dockerfile")) // #nosec G304 -- the repository's own Dockerfile
	if err != nil {
		t.Fatalf("reading the devcontainer Dockerfile: %v", err)
	}
	for _, want := range []string{
		`go mod init gosec-build`,
		`go get "github.com/securego/gosec/v2/cmd/gosec@${GOSEC_VERSION}" "golang.org/x/tools@${XTOOLS_VERSION}"`,
		`go install -ldflags "-X main.Version=${GOSEC_VERSION}" github.com/securego/gosec/v2/cmd/gosec;`,
	} {
		if !strings.Contains(string(dockerfile), want) {
			t.Errorf("the devcontainer Dockerfile does not build gosec against the x/tools pin: missing %q", want)
		}
	}
	// No install path may build gosec at its own x/tools: not the image, not
	// the Makefile's install hint, not a workflow.
	workflows, err := filepath.Glob(filepath.Join(root, ".github/workflows/*.yml"))
	if err != nil || len(workflows) == 0 {
		t.Fatalf("listing the workflows: %v", err)
	}
	bare := regexp.MustCompile(`go install [^\n]*gosec/v2/cmd/gosec@`)
	for _, rel := range append([]string{"build/docker/devcontainer/Dockerfile", "Makefile"}, workflows...) {
		path := rel
		if !filepath.IsAbs(path) {
			path = filepath.Join(root, rel)
		}
		data, err := os.ReadFile(path) // #nosec G304 -- the repository's own build files
		if err != nil {
			t.Fatalf("reading %s: %v", rel, err)
		}
		if bare.Match(data) {
			t.Errorf("%s still installs gosec at its own x/tools", rel)
		}
	}
}

// TestToolchainDoesNotStampVCSIntoTheReadOnlyModuleCache: with tags in the
// checkout, go build resolves the main module's version and writes a stat
// cache under GOMODCACHE, which in the image is root's and only readable to
// the stage uid; every build printed "writing stat cache: permission denied".
func TestToolchainDoesNotStampVCSIntoTheReadOnlyModuleCache(t *testing.T) {
	dockerfile, err := os.ReadFile(filepath.Join(repoRoot(t), "build/docker/devcontainer/Dockerfile")) // #nosec G304 -- the repository's own Dockerfile
	if err != nil {
		t.Fatalf("reading the devcontainer Dockerfile: %v", err)
	}
	if !strings.Contains(string(dockerfile), `GOFLAGS="-mod=readonly -buildvcs=false"`) {
		t.Errorf("the devcontainer image's GOFLAGS is not -mod=readonly -buildvcs=false")
	}
}

// TestMakeAsksGOPATHOnlyOfAGoThatExists: a CI job container that hands a
// target to the toolchain image has no go, and the parse-time `$(GO) env
// GOPATH` made make print "No such file or directory" on every such step.
func TestMakeAsksGOPATHOnlyOfAGoThatExists(t *testing.T) {
	_, stderr := runMake(t, environ(nil, nil), "-s", "GO="+filepath.Join(t.TempDir(), "go"), "toolchain-image")
	if strings.Contains(stderr, "No such file or directory") {
		t.Errorf("make ran a go that does not exist:\n%s", stderr)
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

// The install hint `make gosec` prints without gosec is the image's recipe,
// with the x/tools pin filled in from tool-pins.env.
func TestGosecInstallHintBuildsAgainstThePinnedXTools(t *testing.T) {
	root := repoRoot(t)
	pins, err := os.ReadFile(filepath.Join(root, "build/docker/devcontainer/tool-pins.env")) // #nosec G304 -- the repository's own tool pin file
	if err != nil {
		t.Fatalf("reading tool-pins.env: %v", err)
	}
	m := regexp.MustCompile(`(?m)^XTOOLS_VERSION=(\S+)$`).FindSubmatch(pins)
	if m == nil {
		t.Fatal("tool-pins.env carries no XTOOLS_VERSION")
	}
	env := environ([]string{"TOOLS_REQUIRED"}, map[string]string{"PATH": "/usr/bin:/bin"})
	out, _ := runMake(t, env, "-s", "gosec", "GOBIN="+t.TempDir())
	for _, want := range []string{
		"go mod init gosec-build",
		"golang.org/x/tools@" + string(m[1]),
		`go install -ldflags "-X main.Version=`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the gosec install hint lacks %q:\n%s", want, out)
		}
	}
}

// The toolchain image proves at build time that gosec was built by the
// image's own Go against XTOOLS_VERSION, that the build cache is keyed by that
// Go, and that the module cache is where ci-toolchain-run reads it from.
func TestToolchainProvesWhichGoBuiltGosec(t *testing.T) {
	stage := toolchainStage(t)
	for _, want := range []string{
		`--mount=type=bind,source=build/docker/devcontainer/tool-pins.env,target=/tmp/tool-pins.env`,
		`gover="$(go env GOVERSION)"`,
		`test "$gover" = "go${GOLANG_VERSION}"`,
		`test "$(go env GOCACHE)" = "/tmp/.cache/go-build-$gover"`,
		`test "$(go env GOMODCACHE)" = /go/pkg/mod`,
		`built="$(go version -m "$(command -v gosec)")"`,
		`head -n 1 | grep -qx ".*: $gover"`,
		`dep[[:space:]]+golang\.org/x/tools[[:space:]]+${XTOOLS_VERSION}[[:space:]]`,
	} {
		if !strings.Contains(stage, want) {
			t.Errorf("the toolchain stage does not check %q", want)
		}
	}
	if strings.Index(stage, "go version -m") < strings.Index(stage, "COPY --from=tools") {
		t.Error("the gosec check runs before the toolchain stage has gosec")
	}
}

// The build cache under HOME=/tmp is keyed by the Go version, so no build
// cache another Go wrote can reach a tool of this one.
func TestToolchainKeysTheBuildCacheByGoVersion(t *testing.T) {
	stage := toolchainStage(t)
	if !strings.Contains(stage, "GOCACHE=/tmp/.cache/go-build-go${GOLANG_VERSION}") {
		t.Error("the toolchain stage does not set GOCACHE per Go version")
	}
	// Go creates the directory on first use as the uid that runs, 0755. A
	// directory made here would be root's, or opened to every uid.
	if regexp.MustCompile(`(chmod|mkdir|install -d)[^\n]*/tmp/\.cache`).MatchString(stage) {
		t.Error("the toolchain stage makes or opens the build cache directory itself")
	}
}

// toolchainStage returns the toolchain stage of the devcontainer Dockerfile.
func toolchainStage(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "build/docker/devcontainer/Dockerfile")) // #nosec G304 -- the repository's own Dockerfile
	if err != nil {
		t.Fatalf("reading the devcontainer Dockerfile: %v", err)
	}
	s := string(data)
	start := strings.Index(s, "FROM base AS toolchain")
	end := strings.Index(s, "FROM base AS integration")
	if start < 0 || end < start {
		t.Fatal("the Dockerfile has no toolchain stage before the integration stage")
	}
	return s[start:end]
}

// integrationStage is the Dockerfile's integration stage, to its end.
func integrationStage(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "build/docker/devcontainer/Dockerfile")) // #nosec G304 -- the repository's own Dockerfile
	if err != nil {
		t.Fatalf("reading the devcontainer Dockerfile: %v", err)
	}
	s := string(data)
	start := strings.Index(s, "FROM base AS integration")
	if start < 0 {
		t.Fatal("the Dockerfile has no integration stage")
	}
	return s[start:]
}

// The Go base image ships curl, libcurl and git to fetch modules. The
// integration image uses none of them and purges them, so their fixable
// advisories never reach trivy image. Installing one again needs a reason
// stated next to the install, and this test changed with it.
func TestIntegrationImagePurgesCurl(t *testing.T) {
	stage := integrationStage(t)
	curl := []string{"curl", "libcurl4t64", "libcurl3t64-gnutls"}
	purge := regexp.MustCompile(`apt-get purge -y --auto-remove ([^;\\]+)`).FindStringSubmatch(stage)
	if purge == nil {
		t.Fatal("the integration stage purges nothing")
	}
	purged := strings.Fields(purge[1])
	for _, pkg := range curl {
		if !slices.Contains(purged, pkg) {
			t.Errorf("the integration stage does not purge %s", pkg)
		}
	}
	for _, m := range regexp.MustCompile(`apt-get install[^;]*`).FindAllString(stage, -1) {
		for _, f := range strings.Fields(strings.ReplaceAll(m, "\\", " ")) {
			if slices.Contains(curl, f) || f == "git" || strings.HasPrefix(f, "libcurl") {
				t.Errorf("the integration stage installs %s", f)
			}
		}
	}
	if !strings.Contains(stage, `curl, libcurl or git is still installed`) {
		t.Error("the integration stage does not fail its build when curl, libcurl or git survives the purge")
	}
}

// The toolchain keeps curl, for `make trivy-install` in the devcontainer, and
// git, which fetches the first-party module over https through
// libcurl3t64-gnutls. It takes all three packages at Debian's security update
// and fails its build if any is missing or older than the release that fixes
// the curl advisories.
func TestToolchainImageFloorsCurl(t *testing.T) {
	stage := toolchainStage(t)
	if strings.Contains(stage, "apt-get purge") || strings.Contains(stage, "apt-get remove") {
		t.Error("the toolchain stage removes packages; it keeps curl and libcurl for the devcontainer")
	}
	floor := regexp.MustCompile(`for p in ([^;]+); do \\\n\s*v="\$\(dpkg-query -W -f '\$\{Version\}' "\$p"\)" \|\| \{[^}]*exit 1; \}; \\\n\s*dpkg --compare-versions "\$v" ge 8\.14\.1-2\+deb13u7 \|\|`).FindStringSubmatch(stage)
	if floor == nil {
		t.Fatal("the toolchain stage does not fail its build on a missing or pre-8.14.1-2+deb13u7 curl")
	}
	for _, pkg := range []string{"curl", "libcurl4t64", "libcurl3t64-gnutls"} {
		if !slices.Contains(strings.Fields(floor[1]), pkg) {
			t.Errorf("the toolchain stage's version floor does not cover %s", pkg)
		}
	}
}

// The toolchain image is the devcontainer, where a developer runs the
// Makefile's installers. Each downloads with a tool the recipe names; the
// toolchain stage must install that tool and fail its build without it, or the
// target breaks in the devcontainer while passing on any host that has it.
func TestToolchainImageHasTheMakefileDownloadTools(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "Makefile")) // #nosec G304 -- the repository's own Makefile
	if err != nil {
		t.Fatalf("reading the Makefile: %v", err)
	}
	stage := toolchainStage(t)
	install := regexp.MustCompile(`apt-get install[^;]*`).FindAllString(stage, -1)
	installed := []string{}
	for _, m := range install {
		installed = append(installed, strings.Fields(strings.ReplaceAll(m, "\\", " "))...)
	}
	asserted := regexp.MustCompile(`for c in ([^;]+); do \\\n\s*command -v "\$c"`).FindStringSubmatch(stage)
	downloader := regexp.MustCompile(`(?:^|[\s;(|&])(curl|wget|aria2c)\s`)
	for _, target := range []string{"trivy-install"} {
		recipe := makeRecipe(t, string(data), target)
		tools := map[string]bool{}
		for _, m := range downloader.FindAllStringSubmatch(recipe, -1) {
			tools[m[1]] = true
		}
		if len(tools) == 0 {
			t.Errorf("%s's recipe names no download tool; this test no longer reads it right", target)
		}
		for tool := range tools {
			if !slices.Contains(installed, tool) {
				t.Errorf("%s downloads with %s, which the toolchain stage does not install", target, tool)
			}
			if asserted == nil || !slices.Contains(strings.Fields(asserted[1]), tool) {
				t.Errorf("%s downloads with %s, and the toolchain stage's build does not fail without it", target, tool)
			}
		}
	}
}

// makeRecipe is the recipe of the Makefile rule whose `##` line declares
// target: the tab-indented lines that follow it.
func makeRecipe(t *testing.T, makefile, target string) string {
	t.Helper()
	lines := strings.Split(makefile, "\n")
	for i, line := range lines {
		if !strings.HasPrefix(line, target+":") || !strings.Contains(line, "##") {
			continue
		}
		var b strings.Builder
		for _, l := range lines[i+1:] {
			if !strings.HasPrefix(l, "\t") {
				break
			}
			b.WriteString(l + "\n")
		}
		return b.String()
	}
	t.Fatalf("the Makefile has no %s rule", target)
	return ""
}

// make verify must never pass over a module cache that holds no module
// sources. `go mod verify` checks only the zips already cached: given the
// go.mod files it needs to load the graph and nothing else -- what an empty
// cache holds after the graph loads through an open GOPROXY, as in CI's
// security step -- it verified nothing and printed "all modules verified".
func TestVerifyFailsOnAModuleCacheWithoutSources(t *testing.T) {
	goBin := lookPath(t, "go")
	out, err := exec.Command(goBin, "env", "GOMODCACHE").Output() // #nosec G204 -- the go tool on PATH
	if err != nil {
		t.Fatalf("go env GOMODCACHE: %v", err)
	}
	cache := modFilesOnly(t, filepath.Join(strings.TrimSpace(string(out)), "cache", "download"))
	env := environ(nil, map[string]string{"GOMODCACHE": cache, "GOPROXY": "off", "GOFLAGS": "-mod=readonly"})

	// The fixture is the vacuous case: bare `go mod verify` passes on it.
	bare := exec.Command(goBin, "mod", "verify") // #nosec G204 -- the go tool on PATH
	bare.Dir, bare.Env = repoRoot(t), env
	if got, err := bare.CombinedOutput(); err != nil || !strings.Contains(string(got), "all modules verified") {
		t.Fatalf("the fixture does not reproduce the vacuous pass: %v\n%s", err, got)
	}

	stdout, stderr, err := runMakeErr(t, env, "-s", "verify")
	if err == nil {
		t.Fatalf("make verify passed over a cache without module sources:\n%s%s", stdout, stderr)
	}
	if strings.Contains(stdout, "all modules verified") {
		t.Errorf("go mod verify ran over the cache without sources:\n%s", stdout)
	}
}

// modFilesOnly copies the go.mod files of the download cache at src into a new
// module cache and returns it: enough to load the module graph, no sources.
func modFilesOnly(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	copied := 0
	err := filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".mod" || filepath.Base(filepath.Dir(path)) != "@v" {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path) // #nosec G304 -- a go.mod file in the module cache
		if err != nil {
			return err
		}
		to := filepath.Join(dst, "cache", "download", rel)
		if err := os.MkdirAll(filepath.Dir(to), 0o750); err != nil {
			return err
		}
		copied++
		return os.WriteFile(to, data, 0o600)
	})
	if err != nil || copied == 0 {
		t.Fatalf("copying the go.mod files of %s: %d copied, %v", src, copied, err)
	}
	return dst
}
