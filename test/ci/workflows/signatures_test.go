package workflows

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The Signatures job's verifier is a bash script in ci.yml. These tests run
// that script, extracted from the workflow, against throwaway repositories
// whose commits are signed with throwaway SSH keys, with a fake curl standing
// in for the GitHub API. They need bash, git, ssh-keygen and jq, which the CI
// toolchain image has; a missing tool fails the test, it never skips.

const signaturesStep = "- name: Verify commit signatures against .github/allowed_signers"

// signaturesScript returns the step's `run: |` block, dedented.
func signaturesScript(t *testing.T) string {
	t.Helper()
	text := job(t, readFile(t, ".github/workflows/ci.yml"), "signatures")
	lines := strings.Split(text, "\n")
	i := 0
	for i < len(lines) && strings.TrimSpace(lines[i]) != signaturesStep {
		i++
	}
	for i < len(lines) && strings.TrimSpace(lines[i]) != "run: |" {
		i++
	}
	if i >= len(lines) {
		t.Fatalf("signatures job has no step %q with a `run: |` script", signaturesStep)
	}
	const indent = "          "
	var b strings.Builder
	for _, l := range lines[i+1:] {
		if strings.TrimSpace(l) == "" {
			b.WriteString("\n")
			continue
		}
		if !strings.HasPrefix(l, indent) {
			break
		}
		b.WriteString(strings.TrimPrefix(l, indent) + "\n")
	}
	if b.Len() == 0 {
		t.Fatal("the signatures step's script is empty")
	}
	return b.String()
}

func requireSignatureTools(t *testing.T) {
	t.Helper()
	var missing []string
	for _, tool := range []string{"bash", "git", "ssh-keygen", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			missing = append(missing, tool)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("the Signatures verifier tests need %s on PATH (the CI toolchain image has them)", strings.Join(missing, ", "))
	}
}

// sigRepo is a work repository with a bare origin, a hermetic git
// configuration and a fake curl.
type sigRepo struct {
	t      *testing.T
	root   string
	work   string
	script string
	env    []string
}

func newSigRepo(t *testing.T) *sigRepo {
	t.Helper()
	requireSignatureTools(t)
	root := t.TempDir()
	r := &sigRepo{t: t, root: root, work: filepath.Join(root, "work")}
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	curl := "#!/bin/sh\nif [ -n \"${FAKE_CURL_FAIL:-}\" ]; then exit 22; fi\nprintf '%s\\n' \"${FAKE_CURL_JSON:-}\"\n"
	if err := os.WriteFile(filepath.Join(bin, "curl"), []byte(curl), 0o755); err != nil {
		t.Fatal(err)
	}
	gitconfig := filepath.Join(root, "gitconfig")
	if err := os.WriteFile(gitconfig, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "GIT_") || k == "HOME" || k == "PATH" || strings.HasPrefix(k, "FAKE_CURL_") {
			continue
		}
		r.env = append(r.env, kv)
	}
	r.env = append(r.env,
		"HOME="+root,
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+gitconfig,
	)
	r.script = filepath.Join(root, "verify.sh")
	if err := os.WriteFile(r.script, []byte(signaturesScript(t)), 0o644); err != nil {
		t.Fatal(err)
	}
	r.run(root, "git", "init", "-q", "--bare", "origin.git")
	r.run(root, "git", "init", "-q", "-b", "main", "work")
	r.git("remote", "add", "origin", filepath.Join(root, "origin.git"))
	return r
}

func (r *sigRepo) run(dir string, name string, args ...string) string {
	r.t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = r.env
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func (r *sigRepo) git(args ...string) string {
	r.t.Helper()
	return r.run(r.work, "git", args...)
}

// key makes an ed25519 key and returns the private key path and the public key.
func (r *sigRepo) key(name string) (string, string) {
	r.t.Helper()
	path := filepath.Join(r.root, "key-"+name)
	r.run(r.root, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", path)
	pub, err := os.ReadFile(path + ".pub")
	if err != nil {
		r.t.Fatal(err)
	}
	f := strings.Fields(string(pub))
	return path, f[0] + " " + f[1]
}

// commit writes content to file and commits it as email, signed with key
// unless key is empty, and returns the commit's sha.
func (r *sigRepo) commit(file, content, email, key string) string {
	r.t.Helper()
	p := filepath.Join(r.work, file)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		r.t.Fatal(err)
	}
	r.git("add", file)
	args := []string{"-c", "user.name=Test", "-c", "user.email=" + email}
	if key != "" {
		args = append(args, "-c", "gpg.format=ssh", "-c", "user.signingkey="+key, "commit", "-q", "-S")
	} else {
		args = append(args, "commit", "-q")
	}
	r.git(append(args, "-m", "change "+file)...)
	return r.git("rev-parse", "HEAD")
}

// verify runs the step's script in the work repository and returns its
// output and exit status.
func (r *sigRepo) verify(env ...string) (string, int) {
	r.t.Helper()
	cmd := exec.Command("bash", r.script)
	cmd.Dir = r.work
	cmd.Env = append(append([]string{}, r.env...),
		"REPO=example/repo", "API=https://api.github.invalid", "GH_TOKEN=test-token",
		"RUNNER_TEMP="+r.t.TempDir())
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &ee):
		return string(out), ee.ExitCode()
	}
	r.t.Fatalf("running the signatures script: %v\n%s", err, out)
	return "", -1
}

func pr(base, head string) []string {
	return []string{"EVENT=pull_request", "BASE_SHA=" + base, "HEAD_SHA=" + head, "BEFORE="}
}

func push(before, head string) []string {
	return []string{"EVENT=push", "BASE_SHA=", "HEAD_SHA=" + head, "BEFORE=" + before}
}

func expect(t *testing.T, out string, code, wantCode int, wantLines ...string) {
	t.Helper()
	if code != wantCode {
		t.Errorf("exit status %d, want %d\n%s", code, wantCode, out)
	}
	for _, w := range wantLines {
		if !strings.Contains(out, w) {
			t.Errorf("output lacks %q\n%s", w, out)
		}
	}
}

const alice, bob = "alice@example.com", "bob@example.com"

// registered returns a repository whose base commit holds a registry with
// alice's key, signed by alice, and alice's key path and the base sha.
func registered(t *testing.T) (*sigRepo, string, string) {
	r := newSigRepo(t)
	key, pub := r.key("alice")
	base := r.commit(".github/allowed_signers", alice+" "+pub+"\n", alice, key)
	r.git("push", "-q", "origin", "main")
	return r, key, base
}

func short(sha string) string { return sha[:12] }

func TestSignaturesAllSignedByARegisteredKeyPass(t *testing.T) {
	r, key, base := registered(t)
	c1 := r.commit("a", "1", alice, key)
	c2 := r.commit("b", "2", alice, key)
	out, code := r.verify(pr(base, c2)...)
	expect(t, out, code, 0,
		"registry: .github/allowed_signers at "+short(base),
		"checking 2 commit(s)",
		"OK   "+short(c1)+" signed by "+alice,
		"OK   "+short(c2)+" signed by "+alice)
}

func TestSignaturesUnsignedCommitInTheMiddleFails(t *testing.T) {
	r, key, base := registered(t)
	c1 := r.commit("a", "1", alice, key)
	mid := r.commit("b", "2", alice, "")
	c3 := r.commit("c", "3", alice, key)
	out, code := r.verify(pr(base, c3)...)
	expect(t, out, code, 1,
		"OK   "+short(c1),
		"FAIL "+short(mid)+" unsigned, committer "+alice,
		"OK   "+short(c3))
}

func TestSignaturesUnregisteredKeyFails(t *testing.T) {
	r, _, base := registered(t)
	other, _ := r.key("mallory")
	c := r.commit("a", "1", alice, other)
	out, code := r.verify(pr(base, c)...)
	expect(t, out, code, 1, "FAIL "+short(c)+" signed by a key not in the registry")
}

func TestSignaturesPrincipalMismatchFails(t *testing.T) {
	r, key, base := registered(t)
	c := r.commit("a", "1", bob, key)
	out, code := r.verify(pr(base, c)...)
	expect(t, out, code, 1,
		"FAIL "+short(c)+" principal mismatch: the key is registered to "+alice+", the committer is an address not in the registry")
	if strings.Contains(out, bob) {
		t.Errorf("output prints an email outside the registry\n%s", out)
	}
}

func TestSignaturesGitHubMadeCommit(t *testing.T) {
	cases := []struct {
		name string
		env  []string
		code int
		want string
	}{
		{"verified web-flow", []string{`FAKE_CURL_JSON={"commit":{"verification":{"verified":true,"reason":"valid"}},"committer":{"login":"web-flow"}}`}, 0, "GitHub web-flow, verified"},
		{"not verified", []string{`FAKE_CURL_JSON={"commit":{"verification":{"verified":false,"reason":"unsigned"}},"committer":{"login":"web-flow"}}`}, 1, "committed as GitHub but not verified (verified=false reason=unsigned committer=web-flow)"},
		{"API unreadable", []string{"FAKE_CURL_FAIL=1"}, 1, "committed by GitHub, and the API could not be read"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _, base := registered(t)
			c := r.commit("a", "1", "noreply@github.com", "")
			out, code := r.verify(append(pr(base, c), tc.env...)...)
			prefix := "FAIL "
			if tc.code == 0 {
				prefix = "OK   "
			}
			expect(t, out, code, tc.code, prefix+short(c)+" "+tc.want)
		})
	}
}

func TestSignaturesRegistryIsReadFromTheBase(t *testing.T) {
	r, _, base := registered(t)
	ckey, cpub := r.key("carol")
	asf, err := os.ReadFile(filepath.Join(r.work, ".github/allowed_signers"))
	if err != nil {
		t.Fatal(err)
	}
	carol := "carol@example.com"
	c := r.commit(".github/allowed_signers", string(asf)+carol+" "+cpub+"\n", carol, ckey)
	out, code := r.verify(pr(base, c)...)
	expect(t, out, code, 1,
		"registry: .github/allowed_signers at "+short(base),
		"FAIL "+short(c)+" signed by a key not in the registry")
}

func TestSignaturesUnreadableBaseFailsClosed(t *testing.T) {
	const missing = "1234567890abcdef1234567890abcdef12345678"
	for name, env := range map[string]func(string) []string{
		"pull_request": func(head string) []string { return pr(missing, head) },
		"push":         func(head string) []string { return push(missing, head) },
	} {
		t.Run(name, func(t *testing.T) {
			// The head brings its own registry and key: it must not be read.
			r := newSigRepo(t)
			key, pub := r.key("mallory")
			r.commit("README", "x", alice, "")
			c := r.commit(".github/allowed_signers", alice+" "+pub+"\n", alice, key)
			out, code := r.verify(env(c)...)
			expect(t, out, code, 1, "FAIL the base "+short(missing)+" cannot be read, so neither the registry nor the range can be checked")
			if strings.Contains(out, "OK   ") || strings.Contains(out, "::warning::") {
				t.Errorf("an unreadable base fell back to the head's registry\n%s", out)
			}
		})
	}
}

func TestSignaturesFirstAdoptionReadsTheHead(t *testing.T) {
	r := newSigRepo(t)
	key, pub := r.key("alice")
	base := r.commit("README", "x", alice, key)
	r.git("push", "-q", "origin", "main")
	c := r.commit(".github/allowed_signers", alice+" "+pub+"\n", alice, key)
	out, code := r.verify(pr(base, c)...)
	expect(t, out, code, 0,
		"::warning::no registry at the base: .github/allowed_signers read from the head (first adoption only)",
		"checking 1 commit(s)",
		"OK   "+short(c)+" signed by "+alice)
}

func TestSignaturesPushWithZeroBeforeChecksTheHeadOnly(t *testing.T) {
	r, key, _ := registered(t)
	r.commit("a", "1", alice, "")
	c := r.commit("b", "2", alice, key)
	out, code := r.verify(push(strings.Repeat("0", 40), c)...)
	expect(t, out, code, 0,
		"checking 1 commit(s) in "+c+" -1",
		"OK   "+short(c)+" signed by "+alice)
	if strings.Contains(out, "unsigned") {
		t.Errorf("a push with no before checked more than the head\n%s", out)
	}
}
