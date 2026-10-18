package makefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The CI recipes -- ci-toolchain-run, ci-reap-stacks and the compose
// integration stage -- run against a recording docker stand-in: what they ask
// the daemon to do is the behavior, and a real daemon would only add a way
// for these tests to touch the machine.

// ciDocker is a docker stand-in that appends each invocation to
// $FAKE_DOCKER_LOG and answers the calls the CI recipes make:
//
//   - `cp -a - NAME:/src` lists the tar stream it is handed into
//     $FAKE_DOCKER_LOG.tar, numeric owners included;
//   - `cp SRC DST` writes a profile to DST unless FAKE_CP=fail;
//   - `start` exits FAKE_START_RC, `compose ... run` exits FAKE_RUN_RC and
//     records the GO_LUKS2_* values it was started with;
//   - `rm`, `network rm` and `volume rm` exit FAKE_RM_RC;
//   - `ps`, `inspect`, `network ls` and `volume ls` answer from the reaper
//     fixture: see TestCIReapStacks.
const ciDocker = `#!/bin/sh
log="$FAKE_DOCKER_LOG"
printf '%s\n' "$*" >> "$log"
[ -z "${FAKE_DOCKER_FAIL:-}" ] || { echo "Cannot connect to the Docker daemon" >&2; exit 1; }
old=2000-01-01T00:00:00Z
new=$(date -u +%Y-%m-%dT%H:%M:%SZ)
never=0001-01-01T00:00:00Z
case "$1" in
cp)
	if [ "$2" = -a ]; then tar -tv --numeric-owner -f - > "$log.tar"; exit 0; fi
	[ "${FAKE_CP:-ok}" = ok ] || { echo "Error response from daemon: No such container" >&2; exit 1; }
	printf 'mode: atomic\nexample.com/fake/f.go:1.1,2.2 1 1\n' > "$3" ;;
start) exit "${FAKE_START_RC:-0}" ;;
rm) exit "${FAKE_RM_RC:-0}" ;;
compose)
	case " $* " in *" run "*)
		printf 'env image=%s seccomp=%s major=%s state=%s\n' "$GO_LUKS2_IT_IMAGE" \
			"$GO_LUKS2_SECCOMP_PROFILE" "$GO_LUKS2_DM_MAJOR" "$GO_LUKS2_TEST_STATE_DIR" >> "$log"
		exit "${FAKE_RUN_RC:-0}" ;;
	esac ;;
network|volume)
	case "$2" in
	rm) exit "${FAKE_RM_RC:-0}" ;;
	ls)
		case "$5" in
		name=*) printf '%s\n' go-luks2-ci-cache-pr-gomod go-luks2-ci-cache-pr-gobuild \
			go-luks2-ci-cache-main-gobuild go-luks2-ci-cache-main-golangci notours-go-luks2-ci-cache-pr-gobuild ;;
		*) echo "$1-${5#label=com.docker.compose.project=}" ;;
		esac ;;
	esac ;;
run)
	case "$*" in *"--entrypoint du "*)
		[ -z "${FAKE_DU_FAIL:-}" ] || exit 1
		case "$*" in
		*cache-pr-gomod:*) kib=20971520 ;;
		*cache-pr-gobuild:*) kib=15728640 ;;
		*cache-main-gobuild:*) kib=10485760 ;;
		*cache-main-golangci:*) kib=1048576 ;;
		*) exit 1 ;;
		esac
		printf '%s\t/c\n' "$kib" ;;
	esac ;;
inspect)
	case "$4" in
	c1|c3|c6|c7|c10) echo "exited $old $old" ;;
	c2) echo "created $never $old" ;;
	c4|c8) echo "running $never $old" ;;
	c5) echo "exited $new $old" ;;
	*) exit 1 ;;
	esac ;;
ps)
	case "$*" in
	*-aq*)
		case "$*" in
		*=go-luks2-ci-old) echo c1; echo c2 ;;
		*=go-luks2-ci-live) echo c3; echo c4 ;;
		*=go-luks2-ci-fresh) echo c5 ;;
		*=other-old) echo c6 ;;
		*volume=go-luks2-ci-cache-pr-gomod) echo c11 ;;
		esac ;;
	*name=*)
		echo "c7 go-luks2-ci-tc-1 "
		echo "c8 go-luks2-ci-tc-2 "
		echo "c9 go-luks2-ci-old-integration-1 go-luks2-ci-old"
		echo "c10 notours-go-luks2-ci-x " ;;
	*)
		printf '%s\n' go-luks2-ci-old go-luks2-ci-live go-luks2-ci-fresh other-old go-luks2-ci-old ;;
	esac ;;
esac
exit 0
`

// ciDockerEnv installs ciDocker first on PATH and returns the environment the
// recipes run under (with set added) and the log the stand-in writes.
func ciDockerEnv(t *testing.T, set map[string]string) (env []string, log string) {
	t.Helper()
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(ciDocker), 0o700); err != nil { // #nosec G306 -- an executable test fixture under t.TempDir()
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
		"IN_IMAGE_NETWORK", "REAP_MIN_AGE", "REAP_DRY_RUN", "MODULE_ENV_FILE", "CI_OUT", "CI_OUT_DIR",
		"CI_CACHE", "CI_CACHE_CLASS", "CI_CACHE_MAX_GIB"}
	return environ(drop, all), log
}

// logLines is the stand-in's log, one invocation per line, or nothing when
// docker was never called.
func logLines(t *testing.T, log string) []string {
	t.Helper()
	if _, err := os.Stat(log); os.IsNotExist(err) {
		return nil
	}
	return strings.Split(strings.TrimSpace(readLog(t, log)), "\n")
}

// called reports the first logged invocation that starts with prefix.
func called(lines []string, prefix string) (string, bool) {
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			return l, true
		}
	}
	return "", false
}

func TestCIToolchainRunCopiesTheCheckoutInAndRunsCMDWithNoNetwork(t *testing.T) {
	env, log := ciDockerEnv(t, map[string]string{"GIT_CONFIG_VALUE_0": "secret-token-value"})
	runMake(t, env, "-s", "ci-toolchain-run", "CMD=make build", "TOOLCHAIN_IMAGE=example/toolchain:t")
	lines := logLines(t, log)

	create, ok := called(lines, "create ")
	if !ok {
		t.Fatalf("no docker create:\n%s", strings.Join(lines, "\n"))
	}
	for _, want := range []string{
		"--name go-luks2-ci-tc-", "--init", "--cap-drop ALL",
		"--security-opt no-new-privileges:true", "--pids-limit 4096",
		"--ulimit memlock=67108864:67108864", "--network none",
		"--user 10001:10001", "--workdir /src", "--env HOME=/tmp",
		"example/toolchain:t sh -c make build",
	} {
		if !strings.Contains(create, want) {
			t.Errorf("docker create lacks %q:\n%s", want, create)
		}
	}
	for _, never := range []string{"GOPROXY", "GOMODCACHE", "GOPATH", "GIT_CONFIG", "secret-token-value"} {
		if strings.Contains(create, never) {
			t.Errorf("a no-network run passes %s:\n%s", never, create)
		}
	}

	name := strings.Fields(create[strings.Index(create, "--name ")+len("--name "):])[0]
	var order []string
	for _, prefix := range []string{"run --rm --network none --cap-drop ALL --cap-add CHOWN ", "create ", "cp -a - " + name + ":/src", "start -a " + name, "rm -f -v " + name} {
		if _, ok := called(lines, prefix); !ok {
			t.Errorf("no %q in the run:\n%s", prefix, strings.Join(lines, "\n"))
		}
		order = append(order, prefix)
	}
	for i, l := range lines {
		if i < len(order) && !strings.HasPrefix(l, order[i]) {
			t.Errorf("call %d is %q, want %q first", i, l, order[i])
		}
	}

	// The checkout goes in owned by the uid the container runs as, and that is
	// the uid the Dockerfile gives /src.
	listing := readLog(t, log+".tar")
	if !strings.Contains(listing, "10001/10001") || !strings.Contains(listing, "Makefile") {
		t.Errorf("the checkout was not streamed in as 10001:10001:\n%.400s", listing)
	}
	if strings.Contains(listing, " 0/0 ") {
		t.Error("a file in the stream is owned by root")
	}
	dockerfile := readLog(t, filepath.Join(repoRoot(t), "build", "docker", "devcontainer", "Dockerfile"))
	if !strings.Contains(dockerfile, "install -d -m 0755 -o 10001 -g 10001 /src") {
		t.Error("the Dockerfile does not give /src to the uid ci-toolchain-run runs as")
	}
}

// Bridge mode opens the network for the stages that need one and passes the
// module credentials by name, so no token ever appears on a command line.
func TestCIToolchainRunBridgePassesCredentialsByName(t *testing.T) {
	env, log := ciDockerEnv(t, map[string]string{
		"GOPRIVATE":          "example.com/private",
		"GIT_CONFIG_COUNT":   "1",
		"GIT_CONFIG_KEY_0":   "url.https://user:secret-token-value@example.com/.insteadOf",
		"GIT_CONFIG_VALUE_0": "https://example.com/",
	})
	runMake(t, env, "-s", "ci-toolchain-run", "CMD=make deps-check",
		"TOOLCHAIN_IMAGE=example/toolchain:t", "IN_IMAGE_NETWORK=bridge")
	create, ok := called(logLines(t, log), "create ")
	if !ok {
		t.Fatal("no docker create")
	}
	for _, want := range []string{
		"--network bridge",
		// The baked module cache first, read-only, so verify checks the
		// modules the image was built with; deps-check asks the network.
		"--env GOPROXY=file:///go/pkg/mod/cache/download,https://proxy.golang.org,direct ",
		"--env DEPS_CHECK_GOPROXY=https://proxy.golang.org,direct ",
		"--env GOMODCACHE=/cache/gomod", "--env GOPRIVATE ", "--env GIT_CONFIG_COUNT ",
		"--env GIT_CONFIG_KEY_0 ", "--env GIT_CONFIG_VALUE_0 ",
	} {
		if !strings.Contains(create, want) {
			t.Errorf("a bridge run lacks %q:\n%s", want, create)
		}
	}
	if strings.Contains(create, "secret-token-value") || strings.Contains(create, "example.com/private") {
		t.Errorf("a credential's value reached the command line:\n%s", create)
	}
}

// The go command caches the checksum database under $GOPATH/pkg/sumdb, not in
// the module cache. The image's GOPATH is root's /go and a stage runs as the CI
// uid, so a networked stage that leaves GOPATH there cannot open that cache and
// every public module's lookup fails. Bridge mode must put GOPATH on the
// writable tmpfs, name the module cache explicitly, and never switch the
// checksum database off to get past it.
func TestCIToolchainRunBridgeKeepsTheSumDBCacheWritable(t *testing.T) {
	env, log := ciDockerEnv(t, nil)
	runMake(t, env, "-s", "ci-toolchain-run", "CMD=make deps-check",
		"TOOLCHAIN_IMAGE=example/toolchain:t", "IN_IMAGE_NETWORK=bridge")
	create, ok := called(logLines(t, log), "create ")
	if !ok {
		t.Fatal("no docker create")
	}
	if !strings.Contains(create, "--tmpfs /tmp:rw,") {
		t.Fatalf("/tmp is not a writable tmpfs:\n%s", create)
	}
	vars := map[string]string{}
	fields := strings.Fields(create)
	for i, f := range fields {
		if f == "--env" && i+1 < len(fields) {
			if k, v, ok := strings.Cut(fields[i+1], "="); ok {
				vars[k] = v
			}
		}
	}
	gopath := vars["GOPATH"]
	if !strings.HasPrefix(gopath, "/tmp/") {
		t.Errorf("a bridge run leaves GOPATH, and with it the checksum database cache, on the image's root-owned /go (unset means /go): GOPATH=%q\n%s",
			gopath, create)
	}
	if mc := vars["GOMODCACHE"]; mc != "/cache/gomod" {
		t.Errorf("a bridge run does not name the writable module cache volume: GOMODCACHE=%q", mc)
	}
	for _, never := range []string{"GOSUMDB", "GONOSUMDB=", "GONOSUMCHECK", "GOINSECURE", "-insecure"} {
		if strings.Contains(create, never) {
			t.Errorf("a bridge run weakens checksum verification with %s:\n%s", never, create)
		}
	}
}

func TestCIToolchainRunRefusesBadInput(t *testing.T) {
	for name, args := range map[string][]string{
		"no command":   {"TOOLCHAIN_IMAGE=example/toolchain:t"},
		"bad network":  {"CMD=make test", "TOOLCHAIN_IMAGE=example/toolchain:t", "IN_IMAGE_NETWORK=host"},
		"absolute out": {"CMD=make test", "TOOLCHAIN_IMAGE=example/toolchain:t", "CI_OUT=/etc/passwd"},
		"out above":    {"CMD=make test", "TOOLCHAIN_IMAGE=example/toolchain:t", "CI_OUT=a ../b"},
	} {
		t.Run(name, func(t *testing.T) {
			env, log := ciDockerEnv(t, nil)
			stdout, stderr, err := runMakeErr(t, env, append([]string{"-s", "ci-toolchain-run"}, args...)...)
			if err == nil {
				t.Fatalf("the target passed:\n%s%s", stdout, stderr)
			}
			if lines := logLines(t, log); len(lines) != 0 {
				t.Errorf("docker was called anyway:\n%s", strings.Join(lines, "\n"))
			}
		})
	}
}

// CMD's failure is the target's failure, and the container goes either way.
func TestCIToolchainRunPropagatesFailureAndStillRemoves(t *testing.T) {
	env, log := ciDockerEnv(t, map[string]string{"FAKE_START_RC": "3"})
	stdout, stderr, err := runMakeErr(t, env, "-s", "ci-toolchain-run", "CMD=make test", "TOOLCHAIN_IMAGE=example/toolchain:t")
	if err == nil {
		t.Fatalf("CMD failed and the target passed:\n%s%s", stdout, stderr)
	}
	if _, ok := called(logLines(t, log), "rm -f -v go-luks2-ci-tc-"); !ok {
		t.Errorf("the failed run's container was not removed:\n%s", readLog(t, log))
	}
}

// CI_OUT copies what CMD wrote back out after it exits, pass or fail, before
// the container goes; a passing run that left one of them behind fails.
func TestCIToolchainRunCopiesCIOutBack(t *testing.T) {
	for _, tc := range []struct {
		name     string
		set      map[string]string
		wantPass bool
	}{
		{"CMD passes", nil, true},
		{"CMD fails", map[string]string{"FAKE_START_RC": "3"}, false},
		{"a file is missing", map[string]string{"FAKE_CP": "fail"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, log := ciDockerEnv(t, tc.set)
			out := t.TempDir()
			stdout, stderr, err := runMakeErr(t, env, "-s", "ci-toolchain-run", "CMD=make security",
				"TOOLCHAIN_IMAGE=example/toolchain:t", "CI_OUT=gosec.sarif sub/coverage.out", "CI_OUT_DIR="+out)
			if (err == nil) != tc.wantPass {
				t.Fatalf("passed = %v, want %v:\n%s%s", err == nil, tc.wantPass, stdout, stderr)
			}
			lines := logLines(t, log)
			var order []string
			for _, l := range lines {
				for _, prefix := range []string{"start -a ", "cp go-luks2-ci-tc-", "rm -f -v "} {
					if strings.HasPrefix(l, prefix) {
						order = append(order, l)
					}
				}
			}
			if len(order) != 4 || !strings.HasPrefix(order[0], "start -a ") || !strings.HasPrefix(order[3], "rm -f -v ") {
				t.Fatalf("want start, two copies, then rm:\n%s", strings.Join(lines, "\n"))
			}
			for i, f := range []string{"gosec.sarif", "sub/coverage.out"} {
				if want := ":/src/" + f + " " + filepath.Join(out, f); !strings.HasSuffix(order[i+1], want) {
					t.Errorf("copy %d is %q, want it to end %q", i+1, order[i+1], want)
				}
				if _, statErr := os.Stat(filepath.Join(out, f)); (statErr == nil) != (tc.set["FAKE_CP"] != "fail") {
					t.Errorf("%s copied back: %v", f, statErr)
				}
			}
		})
	}
}

// envVars is every --env K=V a docker call passes.
func envVars(call string) map[string]string {
	vars := map[string]string{}
	fields := strings.Fields(call)
	for i, f := range fields {
		if f == "--env" && i+1 < len(fields) {
			if k, v, ok := strings.Cut(fields[i+1], "="); ok {
				vars[k] = v
			}
		}
	}
	return vars
}

// ci-template v1.22 (in-toolchain-image.sh v2, ci-standard.md §6): every
// stage keeps its build and golangci-lint caches in this repository's named
// volumes of its trust class, a bridge stage its module cache too, and a
// helper holding CHOWN alone gives a new volume to the run's uid first.
func TestCIToolchainRunMountsTheCacheVolumesOfItsTrustClass(t *testing.T) {
	for _, tc := range []struct {
		name, network, class, want string
	}{
		{"pull request, no network", "none", "", "pr"},
		{"push to main, no network", "none", "main", "main"},
		{"pull request, bridge", "bridge", "pr", "pr"},
		{"push to main, bridge", "bridge", "main", "main"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set := map[string]string{}
			if tc.class != "" {
				set["CI_CACHE_CLASS"] = tc.class
			}
			env, log := ciDockerEnv(t, set)
			runMake(t, env, "-s", "ci-toolchain-run", "CMD=make build",
				"TOOLCHAIN_IMAGE=example/toolchain:t", "IN_IMAGE_NETWORK="+tc.network)
			lines := logLines(t, log)
			vols := "go-luks2-ci-cache-" + tc.want

			helper, ok := called(lines, "run ")
			if !ok {
				t.Fatalf("no helper gives the volumes to the uid:\n%s", strings.Join(lines, "\n"))
			}
			for _, want := range []string{
				"--rm --network none --cap-drop ALL --cap-add CHOWN --security-opt no-new-privileges:true --user 0:0",
				"-v " + vols + "-gobuild:/c/gobuild", "-v " + vols + "-golangci:/c/golangci", "-v " + vols + "-gomod:/c/gomod",
				"example/toolchain:t sh -c ", "chown 10001:10001",
			} {
				if !strings.Contains(helper, want) {
					t.Errorf("the helper lacks %q:\n%s", want, helper)
				}
			}

			create, ok := called(lines, "create ")
			if !ok {
				t.Fatal("no docker create")
			}
			for _, want := range []string{
				"-v " + vols + "-gobuild:/cache/gobuild --env GOCACHE=/cache/gobuild",
				"-v " + vols + "-golangci:/cache/golangci --env GOLANGCI_LINT_CACHE=/cache/golangci",
			} {
				if !strings.Contains(create, want) {
					t.Errorf("docker create lacks %q:\n%s", want, create)
				}
			}
			gomod := "-v " + vols + "-gomod:/cache/gomod"
			mc := envVars(create)["GOMODCACHE"]
			if tc.network == "bridge" {
				if !strings.Contains(create, gomod) || mc != "/cache/gomod" {
					t.Errorf("a bridge stage does not use the module cache volume (GOMODCACHE=%q):\n%s", mc, create)
				}
			} else if strings.Contains(create, "-gomod:") || mc != "" {
				t.Errorf("a no-network stage leaves the image's read-only module cache:\n%s", create)
			}
			other := map[string]string{"pr": "main", "main": "pr"}[tc.want]
			if strings.Contains(helper+create, "cache-"+other+"-") {
				t.Errorf("a %s run mounts the %s caches:\n%s\n%s", tc.want, other, helper, create)
			}
		})
	}
}

func TestCIToolchainRunCacheOffMountsNone(t *testing.T) {
	env, log := ciDockerEnv(t, map[string]string{"CI_CACHE": "off"})
	runMake(t, env, "-s", "ci-toolchain-run", "CMD=make deps-check",
		"TOOLCHAIN_IMAGE=example/toolchain:t", "IN_IMAGE_NETWORK=bridge")
	lines := logLines(t, log)
	if _, ok := called(lines, "run "); ok {
		t.Errorf("CI_CACHE=off still runs the volume helper:\n%s", strings.Join(lines, "\n"))
	}
	create, _ := called(lines, "create ")
	if strings.Contains(create, " -v ") || strings.Contains(create, "CACHE=/cache/") {
		t.Errorf("CI_CACHE=off still mounts a cache:\n%s", create)
	}
	if mc := envVars(create)["GOMODCACHE"]; mc != "/tmp/gomodcache" {
		t.Errorf("CI_CACHE=off bridge module cache is %q, want /tmp/gomodcache", mc)
	}
}

func TestCIToolchainRunRefusesABadCacheSetting(t *testing.T) {
	for _, set := range []map[string]string{
		{"CI_CACHE_CLASS": "release"},
		{"CI_CACHE_CLASS": "pr main"},
		{"CI_CACHE": "yes"},
	} {
		env, log := ciDockerEnv(t, set)
		if stdout, stderr, err := runMakeErr(t, env, "-s", "ci-toolchain-run", "CMD=make test",
			"TOOLCHAIN_IMAGE=example/toolchain:t"); err == nil {
			t.Errorf("%v was accepted:\n%s%s", set, stdout, stderr)
		}
		if lines := logLines(t, log); len(lines) != 0 {
			t.Errorf("%v: docker was called:\n%s", set, strings.Join(lines, "\n"))
		}
	}
}

// volumeRemovals is every volume `docker volume rm` was asked to remove.
func volumeRemovals(lines []string) []string {
	var out []string
	for _, l := range lines {
		if v, ok := strings.CutPrefix(l, "volume rm "); ok {
			out = append(out, v)
		}
	}
	return out
}

// trim-ci-caches.sh v1 (ci-template v1.22): the fake host holds 46 GiB of
// this repository's cache volumes, the 20 GiB module cache in use. Over the
// 32 GiB default the largest unused volume goes whole, and that is enough.
func TestCITrimCachesRemovesTheLargestUnusedVolumeUnderTheBound(t *testing.T) {
	env, log := ciDockerEnv(t, nil)
	stdout, _ := runMake(t, env, "-s", "ci-trim-caches", "TOOLCHAIN_IMAGE=example/toolchain:t")
	lines := logLines(t, log)
	if got := volumeRemovals(lines); len(got) != 1 || got[0] != "go-luks2-ci-cache-pr-gobuild" {
		t.Errorf("removed %v, want only go-luks2-ci-cache-pr-gobuild", got)
	}
	for _, want := range []string{
		"caches: 46 GiB of 32 GiB for prefix 'go-luks2-ci-'",
		"keep  go-luks2-ci-cache-pr-gomod (20480 MiB, in use)",
		"trim  go-luks2-ci-cache-pr-gobuild (15360 MiB)",
		"trim: 1 volume(s), 31 GiB left for prefix 'go-luks2-ci-'",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the trim does not report %q:\n%s", want, stdout)
		}
	}
	du, ok := called(lines, "run ")
	if !ok {
		t.Fatal("no volume was measured")
	}
	for _, want := range []string{
		"--rm --network none --cap-drop ALL --security-opt no-new-privileges:true --user 10001:10001",
		":/c:ro --entrypoint du example/toolchain:t -sk /c",
	} {
		if !strings.Contains(du, want) {
			t.Errorf("the measurement lacks %q:\n%s", want, du)
		}
	}
	for _, l := range lines {
		if strings.Contains(l, "--cap-add") || strings.Contains(l, "notours-") {
			t.Errorf("the trim made a call it must not: %s", l)
		}
	}
}

func TestCITrimCachesBound(t *testing.T) {
	for _, tc := range []struct {
		max  string
		want []string
	}{
		{"64", nil},
		{"8", []string{"go-luks2-ci-cache-pr-gobuild", "go-luks2-ci-cache-main-gobuild", "go-luks2-ci-cache-main-golangci"}},
	} {
		env, log := ciDockerEnv(t, map[string]string{"CI_CACHE_MAX_GIB": tc.max})
		runMake(t, env, "-s", "ci-trim-caches", "TOOLCHAIN_IMAGE=example/toolchain:t")
		if got := volumeRemovals(logLines(t, log)); strings.Join(got, " ") != strings.Join(tc.want, " ") {
			t.Errorf("CI_CACHE_MAX_GIB=%s removed %v, want %v", tc.max, got, tc.want)
		}
	}
}

func TestCITrimCachesDryRunRemovesNothing(t *testing.T) {
	env, log := ciDockerEnv(t, nil)
	stdout, _ := runMake(t, env, "-s", "ci-trim-caches", "TOOLCHAIN_IMAGE=example/toolchain:t", "REAP_DRY_RUN=1")
	if got := volumeRemovals(logLines(t, log)); len(got) != 0 {
		t.Errorf("a dry run removed %v", got)
	}
	if !strings.Contains(stdout, "dry   docker volume rm go-luks2-ci-cache-pr-gobuild (15360 MiB)") {
		t.Errorf("a dry run does not say what it would remove:\n%s", stdout)
	}
}

func TestCITrimCachesNeverFailsTheJob(t *testing.T) {
	for _, tc := range []struct {
		set  map[string]string
		want string
	}{
		{map[string]string{"FAKE_RM_RC": "1"}, "warn  go-luks2-ci-cache-pr-gobuild not removed"},
		{map[string]string{"FAKE_DU_FAIL": "1"}, "warn  go-luks2-ci-cache-pr-gomod: size not read"},
		{map[string]string{"FAKE_DOCKER_FAIL": "1"}, "trim: 0 volume(s)"},
	} {
		env, _ := ciDockerEnv(t, tc.set)
		stdout, stderr, err := runMakeErr(t, env, "-s", "ci-trim-caches", "TOOLCHAIN_IMAGE=example/toolchain:t")
		if err != nil {
			t.Errorf("%v failed the job: %v\n%s%s", tc.set, err, stdout, stderr)
		}
		if !strings.Contains(stdout, tc.want) {
			t.Errorf("%v: no %q:\n%s", tc.set, tc.want, stdout)
		}
	}

	for _, bad := range []string{"32G", "-1", "1 2"} {
		env, log := ciDockerEnv(t, nil)
		if stdout, stderr, err := runMakeErr(t, env, "-s", "ci-trim-caches",
			"TOOLCHAIN_IMAGE=example/toolchain:t", "CI_CACHE_MAX_GIB="+bad); err == nil {
			t.Errorf("CI_CACHE_MAX_GIB=%q was accepted:\n%s%s", bad, stdout, stderr)
		}
		if lines := logLines(t, log); len(lines) != 0 {
			t.Errorf("docker was called with CI_CACHE_MAX_GIB=%q:\n%s", bad, strings.Join(lines, "\n"))
		}
	}
}

// removals is every logged call that removes something.
func removals(lines []string) []string {
	var out []string
	for _, l := range lines {
		if strings.HasPrefix(l, "rm ") || strings.HasPrefix(l, "network rm ") || strings.HasPrefix(l, "volume rm ") {
			out = append(out, l)
		}
	}
	return out
}

// The fixture in ciDocker: go-luks2-ci-old is all stale (c1 exited, c2 created
// and never started, both long ago); go-luks2-ci-live has a running container;
// go-luks2-ci-fresh stopped a moment ago; other-old is stale but another
// project's. Outside compose, c7 is ours and stale, c8 ours and running, c9 a
// compose container the project pass owns, and c10 a name that merely contains
// the prefix.
func TestCIReapStacksRemovesOnlyThisRepositorysStaleStacks(t *testing.T) {
	env, log := ciDockerEnv(t, nil)
	stdout, _ := runMake(t, env, "-s", "ci-reap-stacks")
	got := strings.Join(removals(logLines(t, log)), "\n")
	want := strings.Join([]string{
		"rm -v c1 c2",
		"network rm network-go-luks2-ci-old",
		"volume rm volume-go-luks2-ci-old",
		"rm -v c7",
	}, "\n")
	if got != want {
		t.Errorf("removed:\n%s\nwant:\n%s\noutput:\n%s", got, want, stdout)
	}
	if !strings.Contains(stdout, "reaper: 1 compose project(s) removed for prefix 'go-luks2-ci-'") {
		t.Errorf("no summary:\n%s", stdout)
	}
	for _, kept := range []string{"keep  go-luks2-ci-live", "keep  go-luks2-ci-fresh"} {
		if !strings.Contains(stdout, kept) {
			t.Errorf("the output does not say %q:\n%s", kept, stdout)
		}
	}
	if strings.Contains(readLog(t, log), "=other-old") {
		t.Error("the reaper inspected another project's stack")
	}
}

func TestCIReapStacksDryRunRemovesNothing(t *testing.T) {
	env, log := ciDockerEnv(t, nil)
	stdout, _ := runMake(t, env, "-s", "ci-reap-stacks", "REAP_DRY_RUN=1")
	if got := removals(logLines(t, log)); len(got) != 0 {
		t.Errorf("a dry run removed:\n%s", strings.Join(got, "\n"))
	}
	for _, want := range []string{"dry   docker rm -v c1 c2", "dry   docker rm -v c7", "would be removed"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the dry run does not say %q:\n%s", want, stdout)
		}
	}
}

// A failed removal is reported and never fails the job; a malformed age is a
// caller's error and does.
func TestCIReapStacksNeverFailsTheJob(t *testing.T) {
	env, _ := ciDockerEnv(t, map[string]string{"FAKE_RM_RC": "1"})
	stdout, _ := runMake(t, env, "-s", "ci-reap-stacks")
	if !strings.Contains(stdout, "warn  go-luks2-ci-old: container removal failed") ||
		!strings.Contains(stdout, "warn  container go-luks2-ci-tc-1 not removed") {
		t.Errorf("failed removals were not reported:\n%s", stdout)
	}

	env, log := ciDockerEnv(t, nil)
	if stdout, stderr, err := runMakeErr(t, env, "-s", "ci-reap-stacks", "REAP_MIN_AGE=3h"); err == nil {
		t.Errorf("REAP_MIN_AGE=3h was accepted:\n%s%s", stdout, stderr)
	}
	if lines := logLines(t, log); len(lines) != 0 {
		t.Errorf("docker was called with a malformed age:\n%s", strings.Join(lines, "\n"))
	}
}

// integrationRun is `make integration-test` against ciDocker, with every name
// and path the recipe takes pinned to the test. It returns the, the log, the directory the run's files are under and make's error.
func integrationRun(t *testing.T, devices string, set map[string]string) (out, log, dir string, err error) {
	t.Helper()
	dir = t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if werr := os.WriteFile(p, []byte(body), 0o600); werr != nil {
			t.Fatal(werr)
		}
		return p
	}
	fakeGo := filepath.Join(dir, "go")
	if werr := os.WriteFile(fakeGo, []byte(fakeGoForCI), 0o700); werr != nil { // #nosec G306 -- an executable test fixture under t.TempDir()
		t.Fatalf("writing the fake go: %v", werr)
	}
	state := filepath.Join(dir, "state")
	if werr := os.Mkdir(state, 0o700); werr != nil {
		t.Fatal(werr)
	}
	env, log := ciDockerEnv(t, set)
	stdout, stderr, err := runMakeErr(t, env, "-s", "integration-test", "GO="+fakeGo,
		"PROC_DEVICES="+write("devices", devices),
		"MODULE_ENV_FILE="+write("gomodauth.env", "GOPRIVATE=example.com/private\n"),
		"COVERAGE_INTEGRATION="+filepath.Join(dir, "integration.out"),
		"TEST_STATE_DIR="+state,
		"IT_PROJECT=go-luks2-ci-t", "ITEST_CONTAINER=go-luks2-ci-t-itest", "ITEST_IMAGE=go-luks2-ci-it:t")
	return stdout + stderr, log, dir, err
}

const procDevices = "Character devices:\n  1 mem\n\nBlock devices:\n  7 loop\n253 device-mapper\n"

// teardown checks the trap removed the container, the project and the image.
func teardown(t *testing.T, lines []string) {
	t.Helper()
	for _, want := range []string{
		"rm -f go-luks2-ci-t-itest",
		"compose -f build/docker/devcontainer/compose.yaml -p go-luks2-ci-t down --volumes",
		"image rm -f go-luks2-ci-it:t",
	} {
		if _, ok := called(lines, want); !ok {
			t.Errorf("no teardown call %q:\n%s", want, strings.Join(lines, "\n"))
		}
	}
}

func TestIntegrationTestRunsTheComposeServiceWithTheLaunchersValues(t *testing.T) {
	out, log, dir, err := integrationRun(t, procDevices, nil)
	if err != nil {
		t.Fatalf("make integration-test failed: %v\n%s", err, out)
	}
	lines := logLines(t, log)

	build, ok := called(lines, "build ")
	if !ok || !strings.Contains(build, "--secret id=gomodauth,src="+filepath.Join(dir, "gomodauth.env")) ||
		!strings.Contains(build, "--target integration") || !strings.Contains(build, "-t go-luks2-ci-it:t") {
		t.Errorf("the integration image was not built from MODULE_ENV_FILE:\n%s", build)
	}
	if _, serr := os.Stat(filepath.Join(dir, "gomodauth.env")); serr != nil {
		t.Errorf("the target removed the caller's MODULE_ENV_FILE: %v", serr)
	}

	if _, ok := called(lines, "compose -f build/docker/devcontainer/compose.yaml -p go-luks2-ci-t run --name go-luks2-ci-t-itest integration"); !ok {
		t.Errorf("the integration service was not run under the project:\n%s", strings.Join(lines, "\n"))
	}
	// The launcher's rule: a ledger an ordinary user owns gets a root-ledger
	// subdirectory, a root-owned one is used as it is.
	state := filepath.Join(dir, "state")
	if os.Getuid() != 0 {
		state = filepath.Join(state, "root-ledger")
	}
	wantEnv := "env image=go-luks2-ci-it:t seccomp=" + filepath.Join(repoRoot(t), "test", "integration", "seccomp.json") +
		" major=253 state=" + state
	if got, _ := called(lines, "env "); got != wantEnv {
		t.Errorf("compose ran with\n%s\nwant\n%s", got, wantEnv)
	}
	if data := readLog(t, filepath.Join(dir, "integration.out")); !strings.HasPrefix(data, "mode: ") {
		t.Errorf("the profile was not copied out: %q", data)
	}
	teardown(t, lines)
}

func TestIntegrationTestFailsWithoutADeviceMapperMajor(t *testing.T) {
	out, log, _, err := integrationRun(t, "Block devices:\n  7 loop\n", nil)
	if err == nil {
		t.Fatalf("no device-mapper major and the target passed:\n%s", out)
	}
	if !strings.Contains(out, "no device-mapper line") {
		t.Errorf("the failure does not say what was missing:\n%s", out)
	}
	lines := logLines(t, log)
	if _, ok := called(lines, "env "); ok {
		t.Error("the service started with no device-mapper rule")
	}
	teardown(t, lines)
}

// The same pass/fail rule as docker-integration-test: a passing run whose
// profile cannot be copied fails; a failing run is the failure, its profile
// copied when it can be.
func TestIntegrationTestCoverageRule(t *testing.T) {
	out, log, _, err := integrationRun(t, procDevices, map[string]string{"FAKE_CP": "fail"})
	if err == nil || !strings.Contains(out, "the container passed and left no") {
		t.Errorf("a passing run with no profile: err=%v\n%s", err, out)
	}
	teardown(t, logLines(t, log))

	out, log, _, err = integrationRun(t, procDevices, map[string]string{"FAKE_RUN_RC": "3"})
	if err == nil {
		t.Fatalf("the suite failed and the target passed:\n%s", out)
	}
	lines := logLines(t, log)
	if _, ok := called(lines, "cp go-luks2-ci-t-itest:/app/"); !ok {
		t.Errorf("a failed run's profile was not copied out:\n%s", strings.Join(lines, "\n"))
	}
	teardown(t, lines)
}

func TestModuleEnvFileThatIsNotAFileFailsTheBuild(t *testing.T) {
	env, log := ciDockerEnv(t, nil)
	missing := filepath.Join(t.TempDir(), "absent.env")
	stdout, stderr, err := runMakeErr(t, env, "-s", "docker-build-integration",
		"MODULE_ENV_FILE="+missing, "ITEST_IMAGE=go-luks2-ci-it:t")
	if err == nil {
		t.Fatalf("a missing MODULE_ENV_FILE built anyway:\n%s%s", stdout, stderr)
	}
	if !strings.Contains(stderr, "is not a file") {
		t.Errorf("the failure does not name the problem:\n%s", stderr)
	}
	if _, ok := called(logLines(t, log), "build "); ok {
		t.Error("docker build ran without the credentials file")
	}
}
