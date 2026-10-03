// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Tests for the external key providers.
//
// NOTHING HERE TOUCHES A PHYSICAL AUTHENTICATOR, and that is a hard constraint
// rather than a convenience: a production security key is attached to the
// machine these run on, and enrolling against it is forbidden. Every helper is
// a script written into t.TempDir that emits fixture lines in the documented
// format.
//
// That is not a mock of the system under test. The system under test is the
// EXEC SEAM -- run a program, take a line of its output, decode it, refuse it
// when it is wrong -- and a script is the honest way to drive it. What is not
// covered by it is whether a real authenticator emits those exact lines, which
// is recorded at fido2AssertSecretLine and cannot be settled here.

// helperScript writes an executable shell script that prints body verbatim on
// stdout and returns it.
func helperScript(t *testing.T, name, body string) string {
	t.Helper()
	return helperScriptWith(t, name, body, "", 0)
}

// helperScriptWith writes an executable shell script emitting stdout, then
// stderr, then exiting with code.
func helperScriptWith(t *testing.T, name, stdout, stderr string, code int) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	script := "#!/bin/sh\n"
	if stdout != "" {
		script += fmt.Sprintf("printf '%%s' %s\n", shellQuote(stdout))
	}
	if stderr != "" {
		script += fmt.Sprintf("printf '%%s' %s >&2\n", shellQuote(stderr))
	}
	script += fmt.Sprintf("exit %d\n", code)

	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { // #nosec G306 -- an executable test fixture under t.TempDir()
		t.Fatalf("failed to write helper %s: %v", path, err)
	}
	return path
}

// shellQuote renders s as a single-quoted shell word.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// echoingHelper writes a script that records its stdin and arguments, so a test
// can assert on the protocol the package speaks rather than only on what it
// reads back.
func echoingHelper(t *testing.T, name, stdout string) (path, argsFile, stdinFile string) {
	t.Helper()

	dir := t.TempDir()
	path = filepath.Join(dir, name)
	argsFile = filepath.Join(dir, "args")
	stdinFile = filepath.Join(dir, "stdin")

	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$@\" > %s\ncat > %s\nprintf '%%s' %s\n",
		shellQuote(argsFile), shellQuote(stdinFile), shellQuote(stdout))
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { // #nosec G306 -- an executable test fixture under t.TempDir()
		t.Fatalf("failed to write helper %s: %v", path, err)
	}
	return path, argsFile, stdinFile
}

func readFixture(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	return string(b)
}

func TestCommandKeyProviderTakesTheSelectedLine(t *testing.T) {
	tests := []struct {
		name   string
		stdout string
		line   int
		want   string
	}{
		{
			name:   "first line",
			stdout: "alpha\nbeta\ngamma\n",
			line:   1,
			want:   "alpha",
		},
		{
			name:   "fifth line, the fido2-cred credential id",
			stdout: "one\ntwo\nthree\nfour\nY3JlZA==\nsix\n",
			line:   fido2CredIDLine,
			want:   "Y3JlZA==",
		},
		{
			name:   "last line without a terminator",
			stdout: "one\ntwo",
			line:   2,
			want:   "two",
		},
		{
			name:   "a carriage return is not part of the credential",
			stdout: "one\r\ntwo\r\n",
			line:   1,
			want:   "one",
		},
		{
			// Line 0 is the whole of stdout VERBATIM. The trailing newline is
			// kept deliberately -- see the CommandKeyProvider doc comment and
			// the cryptsetup --key-file measurement it refers to.
			name:   "line zero keeps the trailing newline",
			stdout: "secret\n",
			line:   0,
			want:   "secret\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &CommandKeyProvider{
				Path: helperScript(t, "helper", tt.stdout),
				Line: tt.line,
			}

			got, err := p.Passphrase(context.Background())
			if err != nil {
				t.Fatalf("Passphrase() error = %v", err)
			}
			defer mustDestroy(t, got)

			if s := string(openSecret(t, got)); s != tt.want {
				t.Errorf("credential = %q, want %q", s, tt.want)
			}
		})
	}
}

func TestCommandKeyProviderRefusesUnusableOutput(t *testing.T) {
	tests := []struct {
		name    string
		provide func(t *testing.T) *CommandKeyProvider
		want    error
	}{
		{
			name: "no command configured",
			provide: func(*testing.T) *CommandKeyProvider {
				return &CommandKeyProvider{Line: 1}
			},
			want: ErrHelperNotConfigured,
		},
		{
			name: "negative line",
			provide: func(t *testing.T) *CommandKeyProvider {
				return &CommandKeyProvider{Path: helperScript(t, "helper", "x\n"), Line: -1}
			},
			want: ErrHelperOutput,
		},
		{
			name: "fewer lines than the protocol promises",
			provide: func(t *testing.T) *CommandKeyProvider {
				return &CommandKeyProvider{Path: helperScript(t, "helper", "one\ntwo\n"), Line: 5}
			},
			want: ErrHelperOutput,
		},
		{
			name: "the selected line is empty",
			provide: func(t *testing.T) *CommandKeyProvider {
				return &CommandKeyProvider{Path: helperScript(t, "helper", "one\n\nthree\n"), Line: 2}
			},
			want: ErrHelperOutput,
		},
		{
			name: "no output at all",
			provide: func(t *testing.T) *CommandKeyProvider {
				return &CommandKeyProvider{Path: helperScript(t, "helper", ""), Line: 0}
			},
			want: ErrHelperOutput,
		},
		{
			name: "the helper refused",
			provide: func(t *testing.T) *CommandKeyProvider {
				return &CommandKeyProvider{
					Path: helperScriptWith(t, "helper", "", "FIDO_ERR_NO_CREDENTIALS", 1),
					Line: 1,
				}
			},
			want: ErrHelperFailed,
		},
		{
			name: "the helper does not exist",
			provide: func(t *testing.T) *CommandKeyProvider {
				return &CommandKeyProvider{Path: filepath.Join(t.TempDir(), "absent"), Line: 1}
			},
			want: ErrKeyProvider,
		},
		{
			name: "output larger than the bound is refused, not truncated",
			provide: func(t *testing.T) *CommandKeyProvider {
				body := strings.Repeat("A", maxHelperOutput+1)
				return &CommandKeyProvider{Path: helperScript(t, "helper", body), Line: 0}
			},
			want: ErrHelperOutput,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := tt.provide(t)

			got, err := p.Passphrase(context.Background())
			if err == nil {
				mustDestroy(t, got)
				t.Fatalf("Passphrase() succeeded, want %v", tt.want)
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("Passphrase() error = %v, want errors.Is(_, %v)", err, tt.want)
			}
			if !errors.Is(err, ErrKeyProvider) {
				t.Errorf("Passphrase() error = %v, want it to match ErrKeyProvider too", err)
			}
		})
	}
}

// TestHelperErrorCarriesWhatTheHelperSaid pins the one thing an operator
// actually needs out of a refused assertion: the authenticator's own sentence.
func TestHelperErrorCarriesWhatTheHelperSaid(t *testing.T) {
	p := &CommandKeyProvider{
		Path: helperScriptWith(t, "helper", "", "FIDO_ERR_PIN_INVALID", 1),
		Line: 1,
	}

	_, err := p.Passphrase(context.Background())
	if err == nil {
		t.Fatal("Passphrase() succeeded, want a refusal")
	}

	var helperErr *HelperError
	if !errors.As(err, &helperErr) {
		t.Fatalf("error = %v, want a *HelperError", err)
	}
	if helperErr.ExitCode != 1 {
		t.Errorf("ExitCode = %d, want 1", helperErr.ExitCode)
	}
	if !strings.Contains(helperErr.Stderr, "FIDO_ERR_PIN_INVALID") {
		t.Errorf("Stderr = %q, want it to carry the helper's diagnostic", helperErr.Stderr)
	}
	if !strings.Contains(helperErr.Error(), "FIDO_ERR_PIN_INVALID") {
		t.Errorf("Error() = %q, want it to carry the helper's diagnostic", helperErr.Error())
	}
}

// TestCommandKeyProviderHonorsContext proves the unattended case: a helper
// waiting for a touch that never comes has to end.
func TestCommandKeyProviderHonorsContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocking")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nsleep 60\n"), 0o700); err != nil { // #nosec G306 -- an executable test fixture under t.TempDir()
		t.Fatalf("failed to write helper: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p := &CommandKeyProvider{Path: path, Line: 1}
	if _, err := p.Passphrase(ctx); err == nil {
		t.Fatal("Passphrase() succeeded with a canceled context, want a refusal")
	}
}

// TestCommandKeyProviderRefusesOverlongOutputWithoutDeadlocking pins the
// LIVENESS half of the output bound, which the bounded-output case above cannot
// reach.
//
// That case writes maxHelperOutput+1 bytes: readFullish fills dst, peeks the one
// extra byte and refuses -- and the helper has already exited, because its whole
// output fit in the pipe. Nothing is left writing. A helper that overruns by more
// than a pipe buffer is a different situation: readFullish stops reading for good
// the moment it refuses, so the helper blocks in write(2) on a pipe nobody will
// drain again, and cmd.Wait() blocks waiting for a process that cannot exit.
// StdoutPipe's read end is closed by Wait, i.e. only AFTER the exit that is not
// coming.
//
// With a deadline-carrying context CommandContext eventually kills the helper and
// the deadlock unwedges. With context.Background() -- what an unattended
// UnlockWithProvider at boot typically passes, and what this test uses on purpose
// -- nothing ever interrupts it: Passphrase never returns, holding the child and
// maxHelperOutput bytes of locked memory. An unlock that hangs forever is strictly
// worse than one that fails.
func TestCommandKeyProviderRefusesOverlongOutputWithoutDeadlocking(t *testing.T) {
	// Comfortably past maxHelperOutput + 1 + a full pipe buffer (64 KiB on
	// Linux), so the helper is certainly still blocked in write(2) when
	// readFullish gives up.
	const flood = 4 * maxHelperOutput

	path := filepath.Join(t.TempDir(), "flood")
	script := fmt.Sprintf("#!/bin/sh\nyes A | head -c %d\n", flood)
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { // #nosec G306 -- an executable test fixture under t.TempDir()
		t.Fatalf("failed to write helper: %v", err)
	}

	// Called directly, with no wall-clock guard (#233). A deadlock here does
	// not return, and the test binary's -timeout -- UNIT_TEST_TIMEOUT in the
	// Makefile -- ends the run with every goroutine's stack, naming this test.
	// A 30-second select was a second, load-sensitive copy of that bound.
	p := &CommandKeyProvider{Path: path, Line: 0}
	credential, err := p.Passphrase(context.Background())
	if credential != nil {
		mustDestroy(t, credential)
	}
	if !errors.Is(err, ErrHelperOutput) {
		t.Errorf("Passphrase() error = %v, want errors.Is(_, ErrHelperOutput)", err)
	}
	if !errors.Is(err, ErrKeyProvider) {
		t.Errorf("Passphrase() error = %v, want it to match ErrKeyProvider too", err)
	}
}

// TestNormalizeFIDO2SecretIsCanonicalBase64 is the single-source-of-truth
// assertion for the encoding.
//
// It states the property directly -- what is enrolled is
// base64.StdEncoding.EncodeToString(secret) -- rather than comparing against a
// hardcoded string, so if fido2SecretEncoding is ever changed because hardware
// disproved the inference, this test changes with it in exactly one place.
func TestNormalizeFIDO2SecretIsCanonicalBase64(t *testing.T) {
	secret := make([]byte, FIDO2SecretLength)
	for i := range secret {
		secret[i] = byte(i)
	}
	encoded := base64.StdEncoding.EncodeToString(secret)

	got, err := normalizeFIDO2Secret([]byte(encoded))
	if err != nil {
		t.Fatalf("normalizeFIDO2Secret() error = %v", err)
	}
	defer mustDestroy(t, got)

	if s := string(openSecret(t, got)); s != encoded {
		t.Errorf("enrolled credential = %q, want %q", s, encoded)
	}

	// It is TEXT that is enrolled, not the raw bytes. Getting this backwards
	// produces a keyslot systemd-cryptsetup can never open.
	if s := string(openSecret(t, got)); s == string(secret) {
		t.Error("the raw secret was enrolled; systemd enrolls its base64 text")
	}
}

func TestNormalizeFIDO2SecretRefusesWhatItCannotDecode(t *testing.T) {
	secret := make([]byte, FIDO2SecretLength)
	std := base64.StdEncoding.EncodeToString(secret)

	tests := []struct {
		name string
		line string
	}{
		{name: "not base64 at all", line: "!!! not base64 !!!"},
		{name: "unpadded", line: strings.TrimRight(std, "=")},
		{name: "empty", line: ""},
		{name: "url-safe alphabet", line: base64.URLEncoding.EncodeToString([]byte{0xfb, 0xff, 0xfe})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeFIDO2Secret([]byte(tt.line))
			if err == nil {
				mustDestroy(t, got)
				t.Fatal("normalizeFIDO2Secret() accepted output it cannot decode")
			}
			if !errors.Is(err, ErrHelperOutput) {
				t.Errorf("error = %v, want errors.Is(_, ErrHelperOutput)", err)
			}
		})
	}
}

// assertOutput renders the stdout of a non-resident `fido2-assert -G -h` run,
// with secret as the hmac-secret field.
//
// The field ORDER is the assumption under test everywhere below; it is written
// once, here, so there is one place to change if hardware disproves it.
func assertOutput(secret string) string {
	return strings.Join([]string{
		base64.StdEncoding.EncodeToString([]byte("client data hash")), // 1
		DefaultFIDO2RelyingParty,                               // 2
		base64.StdEncoding.EncodeToString([]byte("authdata")),  // 3
		base64.StdEncoding.EncodeToString([]byte("signature")), // 4
		secret, // 5
	}, "\n") + "\n"
}

func fido2TestParams(t *testing.T) FIDO2Params {
	t.Helper()

	salt, err := NewFIDO2Salt()
	if err != nil {
		t.Fatalf("NewFIDO2Salt() error = %v", err)
	}
	if len(salt) != FIDO2SaltLength {
		t.Fatalf("salt length = %d, want %d", len(salt), FIDO2SaltLength)
	}
	return FIDO2Params{
		CredentialID: []byte("credential-id-bytes"),
		Salt:         salt,
		UserPresence: true,
	}
}

func TestFIDO2ProviderEnrollsTheBase64OfTheSecret(t *testing.T) {
	secret := make([]byte, FIDO2SecretLength)
	for i := range secret {
		secret[i] = byte(255 - i)
	}
	encoded := base64.StdEncoding.EncodeToString(secret)

	helper, argsFile, stdinFile := echoingHelper(t, "fido2-assert", assertOutput(encoded))
	params := fido2TestParams(t)

	p, err := NewFIDO2KeyProvider(params, ExecConfig{FIDO2Assert: helper, Device: "/dev/hidraw9"})
	if err != nil {
		t.Fatalf("NewFIDO2KeyProvider() error = %v", err)
	}

	credential, err := p.Passphrase(context.Background())
	if err != nil {
		t.Fatalf("Passphrase() error = %v", err)
	}
	defer mustDestroy(t, credential)

	if s := string(openSecret(t, credential)); s != encoded {
		t.Errorf("credential = %q, want the base64 text %q", s, encoded)
	}

	// The invocation itself is interop-critical. -h is what enables
	// hmac-secret on the assertion; without it no secret is ever returned.
	args := readFixture(t, argsFile)
	for _, want := range []string{"-G\n", "-h\n", "up=true\n", "/dev/hidraw9\n"} {
		if !strings.Contains(args, want) {
			t.Errorf("argv = %q, want it to contain %q", args, want)
		}
	}
	if strings.Contains(args, "-r\n") {
		t.Error("argv asked for a resident assertion; the secret's line number assumes it did not")
	}

	// The input fields, in the order fido2-assert(1) documents.
	stdin := strings.Split(strings.TrimRight(readFixture(t, stdinFile), "\n"), "\n")
	if len(stdin) != 4 {
		t.Fatalf("stdin had %d fields, want 4: %q", len(stdin), stdin)
	}
	if stdin[1] != DefaultFIDO2RelyingParty {
		t.Errorf("stdin[1] = %q, want the relying party %q", stdin[1], DefaultFIDO2RelyingParty)
	}
	if stdin[2] != base64.StdEncoding.EncodeToString(params.CredentialID) {
		t.Errorf("stdin[2] = %q, want the base64 credential id", stdin[2])
	}
	if stdin[3] != base64.StdEncoding.EncodeToString(params.Salt) {
		t.Errorf("stdin[3] = %q, want the base64 salt", stdin[3])
	}
}

// TestFIDO2ProviderRefusesAFieldThatIsNotTheSecret is the backstop for
// fido2AssertSecretLine.
//
// If an authenticator ever emits a user id for a single-entry allow list, the
// package reads the signature instead of the secret. That field decodes as
// base64 perfectly well, so only its LENGTH distinguishes it -- and enrolling
// it would produce a keyslot that opens nothing, discovered months later.
func TestFIDO2ProviderRefusesAFieldThatIsNotTheSecret(t *testing.T) {
	signature := base64.StdEncoding.EncodeToString(make([]byte, 71))

	helper := helperScript(t, "fido2-assert", assertOutput(signature))
	p, err := NewFIDO2KeyProvider(fido2TestParams(t), ExecConfig{FIDO2Assert: helper})
	if err != nil {
		t.Fatalf("NewFIDO2KeyProvider() error = %v", err)
	}

	got, err := p.Passphrase(context.Background())
	if err == nil {
		mustDestroy(t, got)
		t.Fatal("Passphrase() accepted a field that is not a 32-byte hmac-secret")
	}
	if !errors.Is(err, ErrHelperOutput) {
		t.Errorf("error = %v, want errors.Is(_, ErrHelperOutput)", err)
	}
}

func TestNewFIDO2KeyProviderRefusesAnIncompleteBinding(t *testing.T) {
	tests := []struct {
		name   string
		params FIDO2Params
	}{
		{name: "no credential id", params: FIDO2Params{Salt: []byte("salt")}},
		{name: "no salt", params: FIDO2Params{CredentialID: []byte("cred")}},
		{name: "nothing at all", params: FIDO2Params{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewFIDO2KeyProvider(tt.params, ExecConfig{}); !errors.Is(err, ErrInvalidFIDO2Binding) {
				t.Errorf("error = %v, want errors.Is(_, ErrInvalidFIDO2Binding)", err)
			}
		})
	}
}

func TestNewFIDO2CredentialReadsTheCredentialID(t *testing.T) {
	credID := []byte("a credential identifier")
	stdout := strings.Join([]string{
		base64.StdEncoding.EncodeToString([]byte("client data hash")), // 1
		DefaultFIDO2RelyingParty, // 2
		"packed",                 // 3
		base64.StdEncoding.EncodeToString([]byte("authdata")),    // 4
		base64.StdEncoding.EncodeToString(credID),                // 5
		base64.StdEncoding.EncodeToString([]byte("attestation")), // 6
	}, "\n") + "\n"

	helper, argsFile, stdinFile := echoingHelper(t, "fido2-cred", stdout)

	got, err := NewFIDO2Credential(context.Background(), ExecConfig{FIDO2Cred: helper, Device: "/dev/hidraw9"},
		FIDO2CredentialOptions{UserName: "operator"})
	if err != nil {
		t.Fatalf("NewFIDO2Credential() error = %v", err)
	}
	if string(got) != string(credID) {
		t.Errorf("credential id = %q, want %q", got, credID)
	}

	// -h at CREATION is what gives the credential an hmac-secret at all. A
	// credential made without it can never produce a secret, however the
	// assertion is phrased.
	args := readFixture(t, argsFile)
	for _, want := range []string{"-M\n", "-h\n", "es256\n", "/dev/hidraw9\n"} {
		if !strings.Contains(args, want) {
			t.Errorf("argv = %q, want it to contain %q", args, want)
		}
	}

	stdin := strings.Split(strings.TrimRight(readFixture(t, stdinFile), "\n"), "\n")
	if len(stdin) != 4 {
		t.Fatalf("stdin had %d fields, want 4: %q", len(stdin), stdin)
	}
	if stdin[2] != "operator" {
		t.Errorf("stdin[2] = %q, want the user name", stdin[2])
	}
}

func TestNewFIDO2CredentialRefusesUnusableOutput(t *testing.T) {
	helper := helperScript(t, "fido2-cred", "one\ntwo\nthree\nfour\n!!! not base64 !!!\n")

	if _, err := NewFIDO2Credential(context.Background(), ExecConfig{FIDO2Cred: helper}, FIDO2CredentialOptions{}); !errors.Is(err, ErrHelperOutput) {
		t.Errorf("error = %v, want errors.Is(_, ErrHelperOutput)", err)
	}
}

func TestProviderFromTokenBuildsTheBindingTheHeaderRecords(t *testing.T) {
	params := fido2TestParams(t)
	token := fido2Token(params)

	if token.Type != fido2TokenType {
		t.Fatalf("token type = %q, want %q", token.Type, fido2TokenType)
	}

	round, err := fido2ParamsFromToken(token)
	if err != nil {
		t.Fatalf("fido2ParamsFromToken() error = %v", err)
	}
	if string(round.CredentialID) != string(params.CredentialID) {
		t.Errorf("credential id = %q, want %q", round.CredentialID, params.CredentialID)
	}
	if string(round.Salt) != string(params.Salt) {
		t.Errorf("salt = %x, want %x", round.Salt, params.Salt)
	}
	if round.relyingParty() != DefaultFIDO2RelyingParty {
		t.Errorf("relying party = %q, want %q", round.relyingParty(), DefaultFIDO2RelyingParty)
	}

	if _, err := ProviderFromToken(token, ExecConfig{}); err != nil {
		t.Errorf("ProviderFromToken() error = %v", err)
	}
}

func TestProviderFromTokenRefusesWhatItCannotDrive(t *testing.T) {
	tests := []struct {
		name  string
		token *Token
		want  error
	}{
		{name: "no token", token: nil, want: ErrNoKeyProvider},
		{
			name:  "a token type this package cannot drive",
			token: &Token{Type: "systemd-tpm2"},
			want:  ErrUnsupportedTokenType,
		},
		{
			name:  "a credential id that is not base64",
			token: &Token{Type: fido2TokenType, FIDO2Credential: "!!!", FIDO2Salt: "AAAA"},
			want:  ErrInvalidFIDO2Binding,
		},
		{
			name:  "a salt that is not base64",
			token: &Token{Type: fido2TokenType, FIDO2Credential: "AAAA", FIDO2Salt: "!!!"},
			want:  ErrInvalidFIDO2Binding,
		},
		{
			name:  "a binding with no salt",
			token: &Token{Type: fido2TokenType, FIDO2Credential: "AAAA"},
			want:  ErrInvalidFIDO2Binding,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ProviderFromToken(tt.token, ExecConfig{}); !errors.Is(err, tt.want) {
				t.Errorf("error = %v, want errors.Is(_, %v)", err, tt.want)
			}
		})
	}
}

// TestEnrollKeyProviderWritesTheKeyslotAndTheTokenThatNamesIt is the
// end-to-end statement, against a real container and checked with cryptsetup.
//
// The credential the provider hands back must open the volume for the THIRD
// PARTY, not merely for this package: a keyslot only this library can use is
// exactly the failure the conformance suite exists to catch.
func TestEnrollKeyProviderWritesTheKeyslotAndTheTokenThatNamesIt(t *testing.T) {
	defer parallel(t)()

	requireCryptsetup(t)

	image := newImage(t, "enroll.img")
	formatWithLibrary(t, image)

	const credential = "a-credential-from-somewhere-else"
	provider := &CommandKeyProvider{
		Path: helperScript(t, "helper", credential+"\n"),
		Line: 1,
		Meta: &Token{Type: fido2TokenType, FIDO2Credential: "AAAA", FIDO2Salt: "AAAA"},
	}

	slot, tokenID, err := EnrollKeyProvider(context.Background(), image, []byte(conformancePassphrase), provider, cheapAddKeyOptions())
	if err != nil {
		t.Fatalf("EnrollKeyProvider() error = %v", err)
	}
	if slot < 0 {
		t.Fatalf("keyslot = %d, want a real slot", slot)
	}

	// The token names the slot that was actually used -- read from where addKey
	// chose it, not inferred from the header afterwards (#42).
	token, err := GetToken(image, tokenID)
	if err != nil {
		t.Fatalf("GetToken(%d) error = %v", tokenID, err)
	}
	if len(token.Keyslots) != 1 || token.Keyslots[0] != strconv.Itoa(slot) {
		t.Errorf("token keyslots = %v, want [%d]", token.Keyslots, slot)
	}
	if token.Type != fido2TokenType {
		t.Errorf("token type = %q, want %q", token.Type, fido2TokenType)
	}

	// cryptsetup, not this package, decides whether the credential works.
	if code, out := runCryptsetup(t, credential, "luksOpen", "--test-passphrase", image); code != 0 {
		t.Fatalf("cryptsetup rejected the enrolled credential (exit %d): %s", code, out)
	}

	// And the credential the caller started with still opens it: enrolling adds
	// a keyslot, it does not replace one.
	if code, out := runCryptsetup(t, conformancePassphrase, "luksOpen", "--test-passphrase", image); code != 0 {
		t.Fatalf("cryptsetup rejected the original passphrase (exit %d): %s", code, out)
	}
}

// TestEnrollKeyProviderWithoutATokenAddsOnlyTheKeyslot covers the anonymous
// provider: no token means no token slot is consumed.
func TestEnrollKeyProviderWithoutATokenAddsOnlyTheKeyslot(t *testing.T) {
	defer parallel(t)()

	requireCryptsetup(t)

	image := newImage(t, "anonymous.img")
	formatWithLibrary(t, image)

	provider := &CommandKeyProvider{
		Path: helperScript(t, "helper", "anonymous-credential\n"),
		Line: 1,
	}

	slot, tokenID, err := EnrollKeyProvider(context.Background(), image, []byte(conformancePassphrase), provider, cheapAddKeyOptions())
	if err != nil {
		t.Fatalf("EnrollKeyProvider() error = %v", err)
	}
	if slot < 0 {
		t.Fatalf("keyslot = %d, want a real slot", slot)
	}
	if tokenID != -1 {
		t.Errorf("token id = %d, want -1 for a provider with no token", tokenID)
	}

	count, err := CountTokens(image)
	if err != nil {
		t.Fatalf("CountTokens() error = %v", err)
	}
	if count != 0 {
		t.Errorf("token count = %d, want 0", count)
	}
}

// TestEnrollKeyProviderRollsBackAKeyslotItCannotIdentify is the orphan
// guarantee: a keyslot whose token could not be written must not survive.
func TestEnrollKeyProviderRollsBackAKeyslotItCannotIdentify(t *testing.T) {
	defer parallel(t)()

	requireCryptsetup(t)

	image := newImage(t, "rollback.img")
	formatWithLibrary(t, image)

	const credential = "a-credential-that-must-not-survive"
	provider := &CommandKeyProvider{
		Path: helperScript(t, "helper", credential+"\n"),
		Line: 1,
		// ImportToken refuses a token with no type, which is the failure this
		// arranges: the keyslot is already written by then.
		Meta: &Token{},
	}

	before, err := ListKeyslots(image)
	if err != nil {
		t.Fatalf("ListKeyslots() error = %v", err)
	}

	_, _, err = EnrollKeyProvider(context.Background(), image, []byte(conformancePassphrase), provider, cheapAddKeyOptions())
	if err == nil {
		t.Fatal("EnrollKeyProvider() succeeded with an unwritable token")
	}
	if errors.Is(err, ErrOrphanedKeyslot) {
		t.Fatalf("the keyslot was orphaned rather than rolled back: %v", err)
	}

	after, err := ListKeyslots(image)
	if err != nil {
		t.Fatalf("ListKeyslots() error = %v", err)
	}
	if len(after) != len(before) {
		t.Errorf("keyslot count = %d, want %d: the rollback left a slot behind", len(after), len(before))
	}

	// The decisive check: the credential must no longer open the volume.
	if code, _ := runCryptsetup(t, credential, "luksOpen", "--test-passphrase", image); code == 0 {
		t.Error("the rolled-back credential still opens the volume")
	}
}

// TestEnrollKeyProviderReportsAnOrphanItCannotRemove covers the one outcome
// that needs a human.
func TestEnrollKeyProviderReportsAnOrphanItCannotRemove(t *testing.T) {
	requireCryptsetup(t)

	image := newImage(t, "orphan.img")
	formatWithLibrary(t, image)

	original := killKeyslot
	killKeyslot = func(string, int) error { return errors.New("device is read-only") }
	t.Cleanup(func() { killKeyslot = original })

	provider := &CommandKeyProvider{
		Path: helperScript(t, "helper", "orphaned-credential\n"),
		Line: 1,
		Meta: &Token{},
	}

	slot, _, err := EnrollKeyProvider(context.Background(), image, []byte(conformancePassphrase), provider, cheapAddKeyOptions())
	if err == nil {
		t.Fatal("EnrollKeyProvider() succeeded, want an orphan report")
	}
	if !errors.Is(err, ErrOrphanedKeyslot) {
		t.Fatalf("error = %v, want errors.Is(_, ErrOrphanedKeyslot)", err)
	}

	var orphan *OrphanedKeyslotError
	if !errors.As(err, &orphan) {
		t.Fatalf("error = %v, want an *OrphanedKeyslotError", err)
	}
	if orphan.Keyslot != slot {
		t.Errorf("orphan keyslot = %d, want %d", orphan.Keyslot, slot)
	}
	// The slot number is the only record of the credential that exists, so the
	// message has to carry it.
	if !strings.Contains(orphan.Error(), strconv.Itoa(slot)) {
		t.Errorf("Error() = %q, want it to name keyslot %d", orphan.Error(), slot)
	}
}

func TestEnrollKeyProviderRefusesBadInput(t *testing.T) {
	image := newImage(t, "refuse.img")
	formatWithLibrary(t, image)

	t.Run("no provider", func(t *testing.T) {
		if _, _, err := EnrollKeyProvider(context.Background(), image, []byte(conformancePassphrase), nil, nil); !errors.Is(err, ErrNoKeyProvider) {
			t.Errorf("error = %v, want errors.Is(_, ErrNoKeyProvider)", err)
		}
	})

	t.Run("no device", func(t *testing.T) {
		provider := &CommandKeyProvider{Path: helperScript(t, "helper", "x\n"), Line: 1}
		if _, _, err := EnrollKeyProvider(context.Background(), "", []byte(conformancePassphrase), provider, nil); err == nil {
			t.Error("EnrollKeyProvider() accepted an empty device path")
		}
	})

	t.Run("the helper refused", func(t *testing.T) {
		provider := &CommandKeyProvider{
			Path: helperScriptWith(t, "helper", "", "FIDO_ERR_NO_CREDENTIALS", 1),
			Line: 1,
		}
		if _, _, err := EnrollKeyProvider(context.Background(), image, []byte(conformancePassphrase), provider, nil); !errors.Is(err, ErrHelperFailed) {
			t.Errorf("error = %v, want errors.Is(_, ErrHelperFailed)", err)
		}
	})

	t.Run("the wrong existing passphrase", func(t *testing.T) {
		provider := &CommandKeyProvider{Path: helperScript(t, "helper", "x\n"), Line: 1}
		if _, _, err := EnrollKeyProvider(context.Background(), image, []byte(conformanceWrongPassphrase), provider, cheapAddKeyOptions()); !errors.Is(err, ErrKeyProvider) {
			t.Errorf("error = %v, want errors.Is(_, ErrKeyProvider)", err)
		}
	})
}

func TestUnlockWithProviderRefusesBadInput(t *testing.T) {
	t.Run("no provider", func(t *testing.T) {
		if err := UnlockWithProvider(context.Background(), "/dev/null", "name", nil); !errors.Is(err, ErrNoKeyProvider) {
			t.Errorf("error = %v, want errors.Is(_, ErrNoKeyProvider)", err)
		}
	})

	t.Run("the helper refused", func(t *testing.T) {
		provider := &CommandKeyProvider{
			Path: helperScriptWith(t, "helper", "", "no device found", 1),
			Line: 1,
		}
		err := UnlockWithProvider(context.Background(), "/dev/null", "name", provider)
		if !errors.Is(err, ErrHelperFailed) {
			t.Errorf("error = %v, want errors.Is(_, ErrHelperFailed)", err)
		}
	})
}

// cheapAddKeyOptions keeps the keyslot KDF at the cost the fixtures use, so
// these tests stay in the tens of milliseconds rather than the seconds argon2id
// would cost.
func cheapAddKeyOptions() *AddKeyOptions {
	return &AddKeyOptions{KDFType: KDFTypePBKDF2, Hash: "sha512", PBKDFIterTime: 1}
}

// TestKeyProviderErrorVocabulary covers what a CALLER does with these errors:
// match a sentinel without knowing the type, reach the cause through Unwrap,
// and read a message that says which step failed.
func TestKeyProviderErrorVocabulary(t *testing.T) {
	cause := errors.New("the underlying reason")

	t.Run("KeyProviderError", func(t *testing.T) {
		err := &KeyProviderError{Op: "enroll", Err: cause}

		if !errors.Is(err, ErrKeyProvider) {
			t.Error("a KeyProviderError does not match ErrKeyProvider")
		}
		if !errors.Is(err, cause) {
			t.Error("the cause is not reachable through Unwrap")
		}
		if !strings.Contains(err.Error(), "enroll") || !strings.Contains(err.Error(), cause.Error()) {
			t.Errorf("Error() = %q, want the step and the cause", err.Error())
		}
	})

	t.Run("HelperError", func(t *testing.T) {
		err := &HelperError{Path: "/usr/bin/fido2-assert", ExitCode: 1, Err: cause}

		if !errors.Is(err, ErrKeyProvider) {
			t.Error("a HelperError does not match ErrKeyProvider")
		}
		if !errors.Is(err, cause) {
			t.Error("the cause is not reachable through Unwrap")
		}
		// With no stderr there is nothing to append, and the message must not
		// end in a dangling colon.
		if strings.HasSuffix(err.Error(), ": ") {
			t.Errorf("Error() = %q", err.Error())
		}
	})

	t.Run("OrphanedKeyslotError", func(t *testing.T) {
		err := &OrphanedKeyslotError{Keyslot: 3, Err: cause, Cause: errors.New("read-only")}

		if !errors.Is(err, ErrOrphanedKeyslot) {
			t.Error("an OrphanedKeyslotError does not match ErrOrphanedKeyslot")
		}
		if !errors.Is(err, ErrKeyProvider) {
			t.Error("an OrphanedKeyslotError does not match ErrKeyProvider")
		}
		if !errors.Is(err, cause) {
			t.Error("the token-write failure is not reachable through Unwrap")
		}
		// The remedy has to be in the message: this slot number is the only
		// record of the credential that exists anywhere.
		if !strings.Contains(err.Error(), "killslot") {
			t.Errorf("Error() = %q, want it to say how to remove the slot", err.Error())
		}
	})
}

// TestFIDO2ProviderCarriesItsToken: EnrollKeyProvider writes what this returns,
// so a provider that forgot to carry it would enroll an unidentifiable keyslot.
func TestFIDO2ProviderCarriesItsToken(t *testing.T) {
	params := fido2TestParams(t)

	p, err := NewFIDO2KeyProvider(params, ExecConfig{})
	if err != nil {
		t.Fatalf("NewFIDO2KeyProvider() error = %v", err)
	}

	token := p.Token()
	if token == nil {
		t.Fatal("the FIDO2 provider carries no token")
	}
	if token.Type != fido2TokenType {
		t.Errorf("token type = %q, want %q", token.Type, fido2TokenType)
	}
	if token.FIDO2Salt != base64.StdEncoding.EncodeToString(params.Salt) {
		t.Error("the token does not carry the salt the provider asserts with")
	}
}

// TestExecConfigDefaultsToTheInstalledHelpers: an ExecConfig that names nothing
// must still reach the libfido2 tools, and must do so by ABSOLUTE PATH -- a
// PATH lookup would let whoever controls the environment decide what produces
// the credential.
func TestExecConfigDefaultsToTheInstalledHelpers(t *testing.T) {
	var cfg ExecConfig

	if cfg.credPath() != DefaultFIDO2CredPath {
		t.Errorf("credPath() = %q, want %q", cfg.credPath(), DefaultFIDO2CredPath)
	}
	if cfg.assertPath() != DefaultFIDO2AssertPath {
		t.Errorf("assertPath() = %q, want %q", cfg.assertPath(), DefaultFIDO2AssertPath)
	}
	for _, path := range []string{DefaultFIDO2CredPath, DefaultFIDO2AssertPath} {
		if !strings.HasPrefix(path, "/") {
			t.Errorf("%q is not an absolute path", path)
		}
	}

	set := ExecConfig{FIDO2Cred: "/opt/fido2-cred", FIDO2Assert: "/opt/fido2-assert"}
	if set.credPath() != "/opt/fido2-cred" || set.assertPath() != "/opt/fido2-assert" {
		t.Error("an explicit helper path was not used")
	}
}

// TestFIDO2EncodingNameDescribesTheAlphabet: this string is what a field report
// says when a credential does not decode, and the whole encoding question is
// unverified against hardware -- so the message has to name what was expected.
func TestFIDO2EncodingNameDescribesTheAlphabet(t *testing.T) {
	original := fido2SecretEncoding
	t.Cleanup(func() { fido2SecretEncoding = original })

	tests := []struct {
		encoding *base64.Encoding
		want     string
	}{
		{encoding: base64.StdEncoding, want: "standard, padded"},
		{encoding: base64.RawStdEncoding, want: "standard, unpadded"},
		{encoding: base64.URLEncoding, want: "URL-safe, padded"},
		{encoding: base64.RawURLEncoding, want: "URL-safe, unpadded"},
		{encoding: base64.NewEncoding("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/"), want: "the configured"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			fido2SecretEncoding = tt.encoding
			if got := fido2EncodingName(); got != tt.want {
				t.Errorf("fido2EncodingName() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestChangingTheEncodingChangesWhatIsEnrolled is the point of having one
// variable: if hardware ever disproves the standard-padded inference, this is
// the whole change.
func TestChangingTheEncodingChangesWhatIsEnrolled(t *testing.T) {
	original := fido2SecretEncoding
	t.Cleanup(func() { fido2SecretEncoding = original })

	secret := make([]byte, FIDO2SecretLength)
	for i := range secret {
		secret[i] = byte(i * 7)
	}

	fido2SecretEncoding = base64.RawStdEncoding
	got, err := normalizeFIDO2Secret([]byte(base64.RawStdEncoding.EncodeToString(secret)))
	if err != nil {
		t.Fatalf("normalizeFIDO2Secret() error = %v", err)
	}
	defer mustDestroy(t, got)

	if s := string(openSecret(t, got)); s != base64.RawStdEncoding.EncodeToString(secret) {
		t.Errorf("enrolled = %q, want the unpadded encoding", s)
	}
}

// TestFIDO2ArgumentsFollowTheRequirementFlags: what the authenticator demands
// of the user is expressed in argv, and each flag has its own branch.
//
// These are not cosmetic. `-t pin=true` makes the helper prompt on its own
// controlling terminal, which is precisely what an unattended unlock must not
// do, and `-v` asks the authenticator for user verification. A provider built
// from a token that requires them and invoked without them gets a DIFFERENT
// assertion -- or none.
func TestFIDO2ArgumentsFollowTheRequirementFlags(t *testing.T) {
	tests := []struct {
		name    string
		params  FIDO2Params
		want    []string
		notWant []string
	}{
		{
			name:    "nothing required",
			params:  FIDO2Params{CredentialID: []byte("c"), Salt: []byte("s")},
			want:    []string{"-G", "-h"},
			notWant: []string{"up=true", "pin=true", "-v"},
		},
		{
			name:    "user presence",
			params:  FIDO2Params{CredentialID: []byte("c"), Salt: []byte("s"), UserPresence: true},
			want:    []string{"up=true"},
			notWant: []string{"pin=true", "-v"},
		},
		{
			name:    "client pin",
			params:  FIDO2Params{CredentialID: []byte("c"), Salt: []byte("s"), ClientPin: true},
			want:    []string{"pin=true"},
			notWant: []string{"up=true"},
		},
		{
			name:   "user verification",
			params: FIDO2Params{CredentialID: []byte("c"), Salt: []byte("s"), UserVerification: true},
			want:   []string{"-v"},
		},
		{
			name: "everything",
			params: FIDO2Params{
				CredentialID: []byte("c"), Salt: []byte("s"),
				UserPresence: true, ClientPin: true, UserVerification: true,
			},
			want: []string{"-G", "-h", "up=true", "pin=true", "-v"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewFIDO2KeyProvider(tt.params, ExecConfig{FIDO2Assert: "/usr/bin/fido2-assert"})
			if err != nil {
				t.Fatalf("NewFIDO2KeyProvider() error = %v", err)
			}

			args := strings.Join(p.(*fido2Provider).cmd.Args, " ")
			for _, want := range tt.want {
				if !strings.Contains(args, want) {
					t.Errorf("argv = %q, want it to contain %q", args, want)
				}
			}
			for _, notWant := range tt.notWant {
				if strings.Contains(args, notWant) {
					t.Errorf("argv = %q, want it NOT to contain %q", args, notWant)
				}
			}
		})
	}
}

func TestNewFIDO2CredentialArgumentsFollowTheOptions(t *testing.T) {
	credID := base64.StdEncoding.EncodeToString([]byte("id"))
	stdout := "1\n2\n3\n4\n" + credID + "\n6\n"

	tests := []struct {
		name    string
		opts    FIDO2CredentialOptions
		want    []string
		notWant []string
	}{
		{
			name:    "defaults",
			opts:    FIDO2CredentialOptions{},
			want:    []string{"-M\n", "-h\n", "es256\n"},
			notWant: []string{"-r\n", "-v\n"},
		},
		{
			name: "resident and verified",
			opts: FIDO2CredentialOptions{Resident: true, UserVerification: true, UserID: []byte("a user id")},
			want: []string{"-r\n", "-v\n"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			helper, argsFile, stdinFile := echoingHelper(t, "fido2-cred", stdout)

			if _, err := NewFIDO2Credential(context.Background(), ExecConfig{FIDO2Cred: helper}, tt.opts); err != nil {
				t.Fatalf("NewFIDO2Credential() error = %v", err)
			}

			args := readFixture(t, argsFile)
			for _, want := range tt.want {
				if !strings.Contains(args, want) {
					t.Errorf("argv = %q, want it to contain %q", args, want)
				}
			}
			for _, notWant := range tt.notWant {
				if strings.Contains(args, notWant) {
					t.Errorf("argv = %q, want it NOT to contain %q", args, notWant)
				}
			}

			// A relying party is always sent, defaulted when the caller gave
			// none: systemd-cryptsetup looks the credential up by it.
			stdin := strings.Split(strings.TrimRight(readFixture(t, stdinFile), "\n"), "\n")
			if stdin[1] != DefaultFIDO2RelyingParty {
				t.Errorf("relying party = %q, want %q", stdin[1], DefaultFIDO2RelyingParty)
			}
		})
	}
}

// TestUnlockWithProviderPassesTheCredentialToUnlock: the helper succeeded, so
// what comes back must be the LIBRARY's verdict on the volume rather than a
// provider error.
func TestUnlockWithProviderPassesTheCredentialToUnlock(t *testing.T) {
	image := newImage(t, "unlock.img") // not a LUKS container: Unlock must refuse it

	provider := &CommandKeyProvider{
		Path: helperScript(t, "helper", "a-credential\n"),
		Line: 1,
	}

	err := UnlockWithProvider(context.Background(), image, "a-name", provider)
	if err == nil {
		t.Fatal("UnlockWithProvider() opened a file that is not a LUKS container")
	}
	if errors.Is(err, ErrKeyProvider) {
		t.Errorf("error = %v, want the library's refusal rather than a provider error", err)
	}
}

// TestHelperDiagnosticsAreBounded: a helper that writes without end must not
// grow this process through a failure path.
func TestHelperDiagnosticsAreBounded(t *testing.T) {
	noisy := helperScriptWith(t, "helper", "", strings.Repeat("E", maxHelperStderr*3), 1)

	p := &CommandKeyProvider{Path: noisy, Line: 1}
	_, err := p.Passphrase(context.Background())
	if err == nil {
		t.Fatal("Passphrase() succeeded, want a refusal")
	}

	var helperErr *HelperError
	if !errors.As(err, &helperErr) {
		t.Fatalf("error = %v, want a *HelperError", err)
	}
	if len(helperErr.Stderr) > maxHelperStderr {
		t.Errorf("kept %d bytes of stderr, want at most %d", len(helperErr.Stderr), maxHelperStderr)
	}
	if len(helperErr.Stderr) == 0 {
		t.Error("no stderr was kept at all; the operator gets no reason")
	}
}

// TestTooFewLinesWithoutATrailingNewline covers the other shape of the same
// refusal: a helper whose last line has no terminator.
func TestTooFewLinesWithoutATrailingNewline(t *testing.T) {
	p := &CommandKeyProvider{
		Path: helperScript(t, "helper", "one\ntwo\nthree"),
		Line: 6,
	}

	_, err := p.Passphrase(context.Background())
	if !errors.Is(err, ErrHelperOutput) {
		t.Fatalf("error = %v, want errors.Is(_, ErrHelperOutput)", err)
	}
	// The message says how many lines there actually were, which is the one
	// fact that tells a protocol mismatch from a broken helper.
	if !strings.Contains(err.Error(), "3 line") {
		t.Errorf("error = %v, want it to report 3 lines", err)
	}
}
