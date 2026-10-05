// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Regression tests for #246 D5-D9: how a helper is found and what it
// inherits, a helper whose output outlives it, the FIDO2 device argument, two
// enrollments at once, and the FIDO2 requirements a token records.

// TestCommandKeyProviderRefusesAPathItWouldHaveToSearchFor is #246 D5. The
// doc said the helper is not searched for on PATH, and exec.CommandContext
// searches for any name without a slash: a helper named "fido2-assert" ran
// whatever the invoking user's PATH put first. Here PATH names a directory
// holding a helper that answers, and it must not be run.
func TestCommandKeyProviderRefusesAPathItWouldHaveToSearchFor(t *testing.T) {
	dir := filepath.Dir(helperScript(t, "substituted", "from-the-users-path\n"))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Chdir(dir)

	for _, name := range []string{"substituted", "./substituted", "sub/../substituted"} {
		p := &CommandKeyProvider{Path: name, Line: 1}
		credential, err := p.Passphrase(context.Background())
		if credential != nil {
			mustDestroy(t, credential)
		}
		if !errors.Is(err, ErrHelperPathNotAbsolute) || !errors.Is(err, ErrKeyProvider) {
			t.Fatalf("Passphrase() with helper %q = %v, want ErrHelperPathNotAbsolute", name, err)
		}
	}
}

// TestCommandKeyProviderGivesTheHelperAMinimalEnvironment is #246 D5's second
// half: the helper inherited this process's whole environment, so anything the
// invoking user exported -- LD_PRELOAD, a library's debug hook -- reached the
// program that produces the credential. It gets a system PATH and what the
// caller passes in Env, and nothing else.
func TestCommandKeyProviderGivesTheHelperAMinimalEnvironment(t *testing.T) {
	t.Setenv("LUKS2_TEST_INHERITED", "inherited")

	path := filepath.Join(t.TempDir(), "env")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n/usr/bin/env\n"), 0o700); err != nil { // #nosec G306 -- an executable test fixture under t.TempDir()
		t.Fatal(err)
	}
	p := &CommandKeyProvider{Path: path, Line: 0, Env: []string{"FIDO_DEBUG=1"}}
	out, err := p.Passphrase(context.Background())
	if err != nil {
		t.Fatalf("Passphrase() = %v", err)
	}
	defer mustDestroy(t, out)

	got := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(openSecret(t, out))), "\n") {
		got[line] = true
	}
	want := map[string]bool{helperBaseEnv[0]: true, "FIDO_DEBUG=1": true}
	// sh may export PWD, SHLVL and _ on its own; those are the shell's, not
	// this process's.
	for line := range got {
		name, _, _ := strings.Cut(line, "=")
		if want[line] || name == "PWD" || name == "SHLVL" || name == "_" || name == "OLDPWD" {
			continue
		}
		t.Errorf("the helper inherited %q", line)
	}
	for line := range want {
		if !got[line] {
			t.Errorf("the helper's environment lacks %q", line)
		}
	}
}

// lingeringHelper writes a helper that leaves a grandchild holding its stdout
// and stderr, writes its credential, says so on the returned FIFO, and then
// either exits or -- block -- waits as a helper waiting for a touch does. The
// grandchild lives for seconds, not forever, so a regression ends instead of
// hanging; it is killed when the test ends either way.
func lingeringHelper(t *testing.T, seconds int, block bool) (path, fifo string) {
	t.Helper()
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "grandchild.pid")
	fifo = filepath.Join(dir, "started")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, "lingering")
	script := "#!/bin/sh\nsleep " + strconv.Itoa(seconds) + " &\necho $! > " + shellQuote(pidFile) +
		"\necho the-credential\necho started > " + shellQuote(fifo) + "\n"
	if block {
		script += "exec sleep " + strconv.Itoa(seconds) + "\n"
	}
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { // #nosec G306 -- an executable test fixture under t.TempDir()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if b, err := os.ReadFile(pidFile); err == nil { // #nosec G304 -- under t.TempDir()
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})
	return path, fifo
}

// awaitStarted blocks until the helper has written its credential.
func awaitStarted(t *testing.T, fifo string) {
	t.Helper()
	b, err := os.ReadFile(fifo) // #nosec G304 -- under t.TempDir(); blocks until the helper writes
	if err != nil || strings.TrimSpace(string(b)) != "started" {
		t.Fatalf("the helper did not start: %q, %v", b, err)
	}
}

// shortHelperWait makes the post-exit wait short for the rest of the test.
// Not parallel: helperWaitDelay is package state.
func shortHelperWait(t *testing.T) {
	t.Helper()
	previous := helperWaitDelay
	helperWaitDelay = time.Millisecond
	t.Cleanup(func() { helperWaitDelay = previous })
}

// TestCommandKeyProviderEndsWhenItsContextDoes is #246 D6: the stdout read
// ignored ctx, so a helper whose grandchild kept stdout open held Passphrase
// past cancellation until the grandchild exited -- for ever, for a daemon.
// Here the helper is still waiting (for a touch, say) when ctx ends; the call
// returns the context's error. (A regression returns a helper failure once the
// grandchild exits, and fails.)
func TestCommandKeyProviderEndsWhenItsContextDoes(t *testing.T) {
	shortHelperWait(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	path, fifo := lingeringHelper(t, 20, true)
	p := &CommandKeyProvider{Path: path, Line: 1}
	done := make(chan error, 1)
	go func() {
		credential, err := p.Passphrase(ctx)
		if credential != nil {
			_ = credential.Destroy()
		}
		done <- err
	}()
	awaitStarted(t, fifo)
	cancel()

	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Passphrase() after cancel = %v, want context.Canceled", err)
	}
}

// TestCommandKeyProviderStopsWaitingForAnExitedHelpersOutput is D6 with no
// deadline in ctx at all -- what an unattended unlock at boot passes. The
// helper exited; a process it started still holds the pipe; the read is cut
// off after helperWaitDelay and refused, not trusted. (A regression returns
// the credential once the grandchild exits, and fails.)
func TestCommandKeyProviderStopsWaitingForAnExitedHelpersOutput(t *testing.T) {
	shortHelperWait(t)

	path, fifo := lingeringHelper(t, 20, false)
	p := &CommandKeyProvider{Path: path, Line: 1}
	done := make(chan error, 1)
	go func() {
		credential, err := p.Passphrase(context.Background())
		if credential != nil {
			_ = credential.Destroy()
		}
		done <- err
	}()
	awaitStarted(t, fifo)

	if err := <-done; !errors.Is(err, ErrHelperOutput) || !strings.Contains(err.Error(), "still held open") {
		t.Fatalf("Passphrase() = %v, want ErrHelperOutput naming the held pipe", err)
	}
}

// TestFIDO2HelpersRequireADeviceAndEndTheirOptions is #246 D7: an empty Device
// went to the helper as an empty-string argument, and a device was not
// separated from the options, so a name starting with "-" was parsed as one.
func TestFIDO2HelpersRequireADeviceAndEndTheirOptions(t *testing.T) {
	params := fido2TestParams(t)
	if _, err := NewFIDO2KeyProvider(params, ExecConfig{}); !errors.Is(err, ErrNoFIDO2Device) {
		t.Fatalf("NewFIDO2KeyProvider with no device = %v, want ErrNoFIDO2Device", err)
	}
	if _, err := NewFIDO2Credential(context.Background(), ExecConfig{}, FIDO2CredentialOptions{}); !errors.Is(err, ErrNoFIDO2Device) {
		t.Fatalf("NewFIDO2Credential with no device = %v, want ErrNoFIDO2Device", err)
	}

	p, err := NewFIDO2KeyProvider(params, ExecConfig{Device: "-r"})
	if err != nil {
		t.Fatal(err)
	}
	args := p.(*fido2Provider).cmd.Args
	if len(args) < 2 || args[len(args)-2] != "--" || args[len(args)-1] != "-r" {
		t.Fatalf("assert argv = %q, want it to end with -- and the device", args)
	}

	helper, argsFile, _ := echoingHelper(t, "fido2-cred", "1\n2\n3\n4\naWQ=\n")
	if _, err := NewFIDO2Credential(context.Background(), ExecConfig{FIDO2Cred: helper, Device: "-v"}, FIDO2CredentialOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := readFixture(t, argsFile); !strings.HasSuffix(got, "--\n-v\nes256\n") {
		t.Fatalf("cred argv = %q, want -- before the device", got)
	}
}

// TestFIDO2TokenRoundTripsEveryRequirement is #246 D9: fido2Token wrote only
// the user-presence requirement, so a binding enrolled with a PIN or user
// verification was rebuilt from its token -- ProviderFromToken, what an unlock
// from the header uses -- into one that asked for neither.
func TestFIDO2TokenRoundTripsEveryRequirement(t *testing.T) {
	for _, params := range []FIDO2Params{
		{CredentialID: []byte("c"), Salt: []byte("s"), ClientPin: true, UserVerification: true},
		{CredentialID: []byte("c"), Salt: []byte("s"), UserPresence: true},
	} {
		token := fido2Token(params)
		encoded, err := json.Marshal(token)
		if err != nil {
			t.Fatal(err)
		}
		var back Token
		if err := json.Unmarshal(encoded, &back); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{`"fido2-clientPin-required":` + strconv.FormatBool(params.ClientPin), `"fido2-uv-required":` + strconv.FormatBool(params.UserVerification)} {
			if !strings.Contains(string(encoded), field) {
				t.Errorf("token %s does not record %s", encoded, field)
			}
		}

		round, err := fido2ParamsFromToken(&back)
		if err != nil {
			t.Fatal(err)
		}
		if round.ClientPin != params.ClientPin || round.UserVerification != params.UserVerification || round.UserPresence != params.UserPresence {
			t.Fatalf("round trip = %+v, want the requirements of %+v", round, params)
		}

		p, err := ProviderFromToken(&back, ExecConfig{Device: "/dev/hidraw9"})
		if err != nil {
			t.Fatal(err)
		}
		args := strings.Join(p.(*fido2Provider).cmd.Args, " ")
		if strings.Contains(args, "pin=true") != params.ClientPin || strings.Contains(args, " -v") != params.UserVerification {
			t.Fatalf("argv from the token = %q, want the requirements of %+v", args, params)
		}
	}
}

// TestConcurrentEnrollmentsKeepBothTokens is #246 D8. The token slot was
// chosen before the keyslot was written, and each step took the device lock on
// its own, so a second enrollment running while the first had written its
// keyslot but not yet its token found the same slot free -- and one token
// overwrote the other, leaving a keyslot nothing describes.
//
// The interleaving is forced rather than hoped for: the first enrollment is
// held at its token write, the second is started, and the first is released
// only once the second has opened the device for writing. Under one lock the
// second waits there for the first; without it, it has already chosen the
// first's token slot.
func TestConcurrentEnrollmentsKeepBothTokens(t *testing.T) {
	image := newImage(t, "concurrent-enroll.img")
	formatWithLibrary(t, image)

	// The existing credential both enrollments unlock with is made cheap
	// first -- a minimum-cost keyslot, and the formatted one removed -- so
	// the test pays one full derivation rather than one per enrollment.
	opener, err := AddRecoveryKey(image, []byte(conformancePassphrase), &RecoveryKeyOptions{KDFType: KDFTypePBKDF2, PBKDFIterations: recoveryTestIterations})
	if err != nil {
		t.Fatal(err)
	}
	existing, err := opener.FormattedString()
	opener.Clear()
	if err != nil {
		t.Fatal(err)
	}
	if err := KillKeyslot(image, 0); err != nil {
		t.Fatal(err)
	}
	if err := RemoveToken(image, opener.TokenID); err != nil {
		t.Fatal(err)
	}

	held := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	previousImport := importToken
	importToken = func(dev *keyslotDevice, id int, token *Token) error {
		first := false
		once.Do(func() { first = true })
		if first {
			close(held)
			<-release
		}
		return previousImport(dev, id, token)
	}
	t.Cleanup(func() { importToken = previousImport })

	var armed sync.Once
	opened := make(chan struct{})
	watching := make(chan struct{})
	previousOpen := openFileFunc
	openFileFunc = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		select {
		case <-watching:
			if name == image && flag&(os.O_RDWR|os.O_WRONLY) != 0 {
				armed.Do(func() { close(opened) })
			}
		default:
		}
		return previousOpen(name, flag, perm)
	}
	t.Cleanup(func() { openFileFunc = previousOpen })

	// Enrolled through AddRecoveryKey, which shares enrollWithToken with
	// EnrollKeyProvider and, holding a credential this package drew, may use
	// the minimum iteration count: the subject is the token slot, not the KDF.
	enroll := func(string) (int, int, error) {
		key, err := AddRecoveryKey(image, []byte(existing), &RecoveryKeyOptions{KDFType: KDFTypePBKDF2, PBKDFIterations: recoveryTestIterations})
		if err != nil {
			return -1, -1, err
		}
		defer key.Clear()
		return key.Keyslot, key.TokenID, nil
	}

	type result struct {
		slot, token int
		err         error
	}
	first := make(chan result, 1)
	go func() {
		s, tok, err := enroll("first-credential")
		first <- result{s, tok, err}
	}()
	<-held

	close(watching)
	second := make(chan result, 1)
	go func() {
		s, tok, err := enroll("second-credential")
		second <- result{s, tok, err}
	}()
	<-opened
	close(release)

	a, b := <-first, <-second
	if a.err != nil || b.err != nil {
		t.Fatalf("enrollments failed: %v / %v", a.err, b.err)
	}
	if a.token == b.token {
		t.Fatalf("both enrollments were given token %d", a.token)
	}
	tokens, err := ListTokens(image)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []result{a, b} {
		tok := tokens[r.token]
		if tok == nil || len(tok.Keyslots) != 1 || tok.Keyslots[0] != strconv.Itoa(r.slot) {
			t.Fatalf("token %d = %+v, want it to name keyslot %d (all tokens: %+v)", r.token, tok, r.slot, tokens)
		}
	}
}

// TestEnrollmentRefusesATokenSlotTakenUnderItsLock: the locked token write
// will not overwrite a slot it finds occupied, and refuses what ImportToken
// refuses.
func TestEnrollmentRefusesATokenSlotTakenUnderItsLock(t *testing.T) {
	defer parallel(t)()

	image := newImage(t, "taken.img")
	formatWithLibrary(t, image)
	if err := ImportToken(image, 0, &Token{Type: "x-existing", Keyslots: []string{"0"}}); err != nil {
		t.Fatal(err)
	}

	// The locked helpers act only on a device pinned to its locked descriptor
	// (#255); there is no device without one to hand them.
	dev := lockedDevice(t, image)
	if err := importTokenLocked(dev, 0, &Token{Type: "x-new"}); !errors.Is(err, ErrNoFreeTokenSlot) {
		t.Fatalf("importTokenLocked over a taken slot = %v, want ErrNoFreeTokenSlot", err)
	}
	if err := importTokenLocked(dev, MaxTokenSlots, &Token{Type: "x-new"}); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("importTokenLocked out of range = %v, want ErrInvalidHeader", err)
	}
	if err := importTokenLocked(dev, 1, nil); !errors.Is(err, ErrUnsupportedTokenType) {
		t.Fatalf("importTokenLocked of no token = %v, want ErrUnsupportedTokenType", err)
	}
	if err := killKeyslotLocked(dev, 7); !errors.Is(err, ErrInvalidKeyslot) {
		t.Fatalf("killKeyslotLocked of an absent slot = %v, want ErrInvalidKeyslot", err)
	}
	if _, _, err := lockKeyslotDevice(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("a device that does not exist was locked and pinned")
	}
}

// TestEnrollmentRollbackStaysOnTheEnrolledDevice: the rollback of a keyslot
// whose token could not be written removes it through the locked descriptor
// the enrollment wrote with. Here the path is retargeted at the moment the
// token write fails; a rollback that reopened the path would act on the
// replacement and leave the new credential live, orphaned, on the original.
func TestEnrollmentRollbackStaysOnTheEnrolledDevice(t *testing.T) {
	dir := t.TempDir()
	image := filepath.Join(dir, "enrolled.img")
	if err := os.WriteFile(image, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(image, conformanceImageSize); err != nil {
		t.Fatal(err)
	}
	formatWithLibrary(t, image)
	before, err := ListKeyslots(image)
	if err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(dir, "moved.img")
	pristine, err := os.ReadFile(image) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}

	previous := importToken
	importToken = func(*keyslotDevice, int, *Token) error {
		if err := os.Rename(image, moved); err != nil {
			return err
		}
		if err := os.WriteFile(image, pristine, 0o600); err != nil {
			return err
		}
		return errors.New("the header could not be written")
	}
	t.Cleanup(func() { importToken = previous })

	_, err = AddRecoveryKey(image, []byte(conformancePassphrase), &RecoveryKeyOptions{KDFType: KDFTypePBKDF2, PBKDFIterations: recoveryTestIterations})
	if err == nil || errors.Is(err, ErrOrphanedKeyslot) {
		t.Fatalf("AddRecoveryKey = %v, want a rolled-back failure", err)
	}
	after, err := ListKeyslots(moved)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("the enrolled device has %d keyslots after the rollback, want %d: the rollback acted on the path, not the descriptor", len(after), len(before))
	}
	if got, _ := os.ReadFile(image); !bytes.Equal(got, pristine) { // #nosec G304 -- under t.TempDir()
		t.Fatal("the rollback wrote to the file that replaced the path")
	}
}
