// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/fips140"
	"errors"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// Tests for the KDF options `create` and `recovery add` share (#237).
//
// The resolution is tested through resolveFor, which takes the mode and the
// library default as parameters, so both modes' answers are checked in every
// run. The command-level tests assert what the commands do in THIS process's
// mode; the nightly FIPS lane runs them in the other.

// kdfFlagsFrom parses args as the KDF options of a command, as the commands
// themselves do.
func kdfFlagsFrom(t *testing.T, args ...string) *kdfFlags {
	t.Helper()
	o := newOptions("create")
	f := declareKDFFlags(o)
	if rest, err := o.parse(args); err != nil || len(rest) != 0 {
		t.Fatalf("parse(%q) = %v, %v; want no error and no positional arguments", args, rest, err)
	}
	return f
}

func TestKDFFlagsResolveForChoosesTheKDF(t *testing.T) {
	const (
		fipsDefault  = luks2.KDFTypePBKDF2SHA512
		otherDefault = luks2.KDFTypeArgon2id
	)

	tests := []struct {
		name       string
		args       []string
		fipsMode   bool
		defaultKDF string
		want       kdfChoice
	}{
		{
			name: "no option outside FIPS mode is the library default, Argon2id",
			args: nil, fipsMode: false, defaultKDF: otherDefault,
			want: kdfChoice{KDFType: luks2.KDFTypeArgon2id, Label: "Argon2id"},
		},
		{
			name: "no option in FIPS mode is the library default, PBKDF2-SHA512",
			args: nil, fipsMode: true, defaultKDF: fipsDefault,
			want: kdfChoice{KDFType: luks2.KDFTypePBKDF2SHA512, Label: "PBKDF2-SHA512"},
		},
		{
			name: "a PBKDF2 default keeps the hash it names",
			args: nil, fipsMode: true, defaultKDF: luks2.KDFTypePBKDF2SHA256,
			want: kdfChoice{KDFType: luks2.KDFTypePBKDF2SHA256, Label: "PBKDF2-SHA256"},
		},
		{
			name: "--pbkdf pbkdf2 outside FIPS mode defaults to SHA-512",
			args: []string{"--pbkdf", "pbkdf2"}, fipsMode: false, defaultKDF: otherDefault,
			want: kdfChoice{KDFType: luks2.KDFTypePBKDF2SHA512, Label: "PBKDF2-SHA512"},
		},
		{
			name: "--hash chooses the PBKDF2 hash, in any case",
			args: []string{"--pbkdf", "pbkdf2", "--hash", "SHA256"}, fipsMode: false, defaultKDF: otherDefault,
			want: kdfChoice{KDFType: luks2.KDFTypePBKDF2SHA256, Label: "PBKDF2-SHA256"},
		},
		{
			name:     "PBKDF2 costs in FIPS mode, with --pbkdf left to the default",
			args:     []string{"--hash", "sha384", "--iter-time", "500", "--pbkdf-force-iterations", "300000"},
			fipsMode: true, defaultKDF: fipsDefault,
			want: kdfChoice{
				KDFType: luks2.KDFTypePBKDF2SHA384, Label: "PBKDF2-SHA384",
				PBKDFIterTime: 500, PBKDFIterations: 300000,
			},
		},
		{
			name:     "Argon2id costs outside FIPS mode",
			args:     []string{"--pbkdf", "argon2id", "--pbkdf-force-iterations", "3", "--pbkdf-memory", "65536", "--pbkdf-parallel", "2"},
			fipsMode: false, defaultKDF: otherDefault,
			want: kdfChoice{
				KDFType: luks2.KDFTypeArgon2id, Label: "Argon2id",
				Argon2Time: 3, Argon2Memory: 65536, Argon2Parallel: 2,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := kdfFlagsFrom(t, tt.args...).resolveFor(tt.fipsMode, tt.defaultKDF)
			if err != nil {
				t.Fatalf("resolveFor = %v", err)
			}
			if got != tt.want {
				t.Fatalf("resolveFor = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestKDFFlagsResolveForRefusesArgon2idInFIPSMode: the typed library error,
// before anything else is looked at -- including costs that would themselves
// be refused.
func TestKDFFlagsResolveForRefusesArgon2idInFIPSMode(t *testing.T) {
	for _, args := range [][]string{
		{"--pbkdf", "argon2id"},
		{"--pbkdf", "argon2id", "--pbkdf-memory", "65536"},
		{"--pbkdf", "argon2id", "--hash", "sha512"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			_, err := kdfFlagsFrom(t, args...).resolveFor(true, luks2.KDFTypePBKDF2SHA512)
			if !errors.Is(err, luks2.ErrFIPSNotApproved) {
				t.Fatalf("resolveFor in FIPS mode = %v, want ErrFIPSNotApproved", err)
			}
			var cryptoErr *luks2.CryptoError
			if !errors.As(err, &cryptoErr) || cryptoErr.Op != "argon2id" {
				t.Fatalf("resolveFor in FIPS mode = %#v, want a *luks2.CryptoError for argon2id", err)
			}
		})
	}

	// The same request outside FIPS mode is accepted.
	if _, err := kdfFlagsFrom(t, "--pbkdf", "argon2id").resolveFor(false, luks2.KDFTypeArgon2id); err != nil {
		t.Fatalf("--pbkdf argon2id outside FIPS mode = %v, want it accepted", err)
	}
}

func TestKDFFlagsResolveForRefusesWhatItCannotHonor(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		fipsMode bool
		mention  string
	}{
		{"an unknown KDF", []string{"--pbkdf", "argon2i"}, false, "--pbkdf"},
		{"an unknown hash", []string{"--pbkdf", "pbkdf2", "--hash", "md5"}, false, "--hash"},
		{"SHA-1, which nothing new is written with", []string{"--pbkdf", "pbkdf2", "--hash", "sha1"}, false, "--hash"},
		{"--hash on Argon2id", []string{"--hash", "sha512"}, false, "--hash"},
		{"--iter-time on Argon2id", []string{"--pbkdf", "argon2id", "--iter-time", "500"}, false, "--iter-time"},
		{"--pbkdf-memory on PBKDF2", []string{"--pbkdf", "pbkdf2", "--pbkdf-memory", "65536"}, false, "--pbkdf-memory"},
		{"--pbkdf-parallel on the FIPS default", []string{"--pbkdf-parallel", "2"}, true, "--pbkdf-parallel"},
		{"a zero iteration time", []string{"--pbkdf", "pbkdf2", "--iter-time", "0"}, false, "--iter-time"},
		{"a negative iteration count", []string{"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "-5"}, false, "--pbkdf-force-iterations"},
		{"a cost that is not a number", []string{"--pbkdf", "argon2id", "--pbkdf-memory", "lots"}, false, "--pbkdf-memory"},
		{"a zero parallelism", []string{"--pbkdf", "argon2id", "--pbkdf-parallel", "0"}, false, "--pbkdf-parallel"},
		{"an empty iteration count, inline", []string{"--pbkdf", "pbkdf2", "--pbkdf-force-iterations="}, false, "--pbkdf-force-iterations"},
		{"an empty iteration count, separate", []string{"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", ""}, false, "--pbkdf-force-iterations"},
		{"an empty memory cost on PBKDF2", []string{"--pbkdf", "pbkdf2", "--pbkdf-memory="}, false, "--pbkdf-memory"},
		{"an empty parallelism", []string{"--pbkdf", "argon2id", "--pbkdf-parallel", ""}, false, "--pbkdf-parallel"},
		{"an empty iteration time", []string{"--pbkdf", "pbkdf2", "--iter-time="}, false, "--iter-time"},
		{"an empty hash", []string{"--pbkdf", "pbkdf2", "--hash", ""}, false, "--hash"},
		{"an empty KDF", []string{"--pbkdf="}, true, "--pbkdf"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defaultKDF := luks2.KDFTypeArgon2id
			if tt.fipsMode {
				defaultKDF = luks2.KDFTypePBKDF2SHA512
			}
			_, err := kdfFlagsFrom(t, tt.args...).resolveFor(tt.fipsMode, defaultKDF)
			if !errors.Is(err, ErrUsage) {
				t.Fatalf("resolveFor(%q) = %v, want ErrUsage", tt.args, err)
			}
			if !strings.Contains(err.Error(), tt.mention) {
				t.Fatalf("resolveFor(%q) = %q, want it to name %s", tt.args, err, tt.mention)
			}
		})
	}
}

// TestKDFFlagsResolveUsesTheProcessMode: the commands' resolve is resolveFor
// with this process's mode and the library's default for it, and with no
// option the KDF is exactly that default.
func TestKDFFlagsResolveUsesTheProcessMode(t *testing.T) {
	got, err := kdfFlagsFrom(t).resolve()
	if err != nil {
		t.Fatalf("resolve with no option = %v", err)
	}
	if got.KDFType != luks2.DefaultKDFType() {
		t.Fatalf("resolve with no option chose %q, want the library default %q", got.KDFType, luks2.DefaultKDFType())
	}

	_, err = kdfFlagsFrom(t, "--pbkdf", "argon2id").resolve()
	if fips140.Enabled() != errors.Is(err, luks2.ErrFIPSNotApproved) {
		t.Fatalf("resolve(--pbkdf argon2id) = %v with fips140.Enabled() = %v", err, fips140.Enabled())
	}
}

// formatRecorder is a MockLuksOperations for create that records the options
// Format was called with.
func formatRecorder(calls *[]luks2.FormatOptions) *MockLuksOperations {
	ops := (&createRecorder{}).ops(nil, nil, nil)
	ops.FormatFunc = func(opts luks2.FormatOptions) error {
		*calls = append(*calls, opts)
		return nil
	}
	return ops
}

// TestCreatePassesTheKDFChoiceToFormat covers both create paths: a file and
// a block device.
func TestCreatePassesTheKDFChoiceToFormat(t *testing.T) {
	dir := t.TempDir()
	keyFile := writeFile(t, dir, "key", "create-passphrase")
	kdfArgs := []string{"--pbkdf", "pbkdf2", "--hash", "sha256", "--iter-time", "500", "--pbkdf-force-iterations", "250000"}

	for name, target := range map[string][]string{
		"file":         {filepath.Join(dir, "vol.luks"), "32M", "ext4"},
		"block device": {"/dev/sdz9"},
	} {
		t.Run(name, func(t *testing.T) {
			args := append([]string{"luks2", "create", "--key-file", keyFile}, kdfArgs...)
			cli, stdout, stderr := newTestCLI(append(args, target...))
			var calls []luks2.FormatOptions
			cli.Luks = formatRecorder(&calls)

			if code := cli.Run(); code != 0 {
				t.Fatalf("create exited %d: %s", code, stderr.String())
			}
			if len(calls) != 1 {
				t.Fatalf("Format was called %d times, want 1", len(calls))
			}
			got := calls[0]
			if got.KDFType != luks2.KDFTypePBKDF2SHA256 || got.PBKDFIterTime != 500 || got.PBKDFIterations != 250000 {
				t.Fatalf("Format got KDF %q, iter-time %d, iterations %d; want pbkdf2-sha256, 500, 250000",
					got.KDFType, got.PBKDFIterTime, got.PBKDFIterations)
			}
			if !strings.Contains(stdout.String(), "KDF: PBKDF2-SHA256") {
				t.Errorf("stdout does not name the KDF it used:\n%s", stdout.String())
			}
		})
	}
}

// TestCreateWithNoKDFOptionUsesTheModeDefault is the defect: create
// hard-coded Argon2id, which FIPS mode refuses.
func TestCreateWithNoKDFOptionUsesTheModeDefault(t *testing.T) {
	cli, stdout, stderr, _ := newCreateCLI(t)
	var calls []luks2.FormatOptions
	cli.Luks = formatRecorder(&calls)

	if code := cli.Run(); code != 0 {
		t.Fatalf("create exited %d: %s", code, stderr.String())
	}
	if len(calls) != 1 || calls[0].KDFType != luks2.DefaultKDFType() {
		t.Fatalf("Format calls = %+v, want one with the library default KDF %q", calls, luks2.DefaultKDFType())
	}

	label := "KDF: Argon2id"
	if fips140.Enabled() {
		label = "KDF: PBKDF2-SHA512"
	}
	if !strings.Contains(stdout.String(), label) {
		t.Errorf("stdout lacks %q:\n%s", label, stdout.String())
	}
}

// TestCreateRefusesAnArgon2idRequestUpFrontInFIPSMode: in FIPS mode nothing
// happens -- no prompt, no file, no Format. Outside it the request is honored.
func TestCreateRefusesAnArgon2idRequestUpFrontInFIPSMode(t *testing.T) {
	cli, stdout, stderr := newTestCLI([]string{"luks2", "create", "--pbkdf", "argon2id",
		filepath.Join(t.TempDir(), "vol.luks"), "32M"})
	terminal := &MockTerminal{Password: []byte("testpassword")}
	cli.Terminal = terminal
	var calls []luks2.FormatOptions
	cli.Luks = formatRecorder(&calls)
	createErr := errors.New("create must not be reached")
	cli.FS = &MockFileSystem{Files: make(map[string]bool), CreateErr: createErr}

	code := cli.Run()

	if !fips140.Enabled() {
		// The filesystem refuses the file, which shows create got that far.
		if !strings.Contains(stderr.String(), createErr.Error()) {
			t.Fatalf("outside FIPS mode create did not proceed: exit %d, stderr %q", code, stderr.String())
		}
		return
	}

	if code != 1 {
		t.Fatalf("create --pbkdf argon2id in FIPS mode exited %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), luks2.ErrFIPSNotApproved.Error()) ||
		!strings.Contains(stderr.String(), "--pbkdf pbkdf2") {
		t.Fatalf("stderr = %q, want the FIPS refusal and what to use instead", stderr.String())
	}
	if strings.Contains(stderr.String(), createErr.Error()) || len(calls) != 0 || terminal.Reads != 0 {
		t.Fatalf("the refusal was not up front: file created %v, Format calls %d, passphrase reads %d",
			strings.Contains(stderr.String(), createErr.Error()), len(calls), terminal.Reads)
	}
	if strings.Contains(stdout.String(), "Creating") {
		t.Errorf("stdout announced a create that was refused:\n%s", stdout.String())
	}
}

func TestCreateRefusesAnUnusableKDFOption(t *testing.T) {
	cli, _, stderr := newTestCLI([]string{"luks2", "create", "--pbkdf", "scrypt", "/dev/sdz9"})
	var calls []luks2.FormatOptions
	cli.Luks = formatRecorder(&calls)

	if code := cli.Run(); code != 1 {
		t.Fatalf("create --pbkdf scrypt exited %d, want 1", code)
	}
	if len(calls) != 0 || !strings.Contains(stderr.String(), "--pbkdf must be") {
		t.Fatalf("Format calls %d, stderr %q; want no Format and the reason", len(calls), stderr.String())
	}
}

func TestCreateUsageListsTheKDFOptions(t *testing.T) {
	cli, stdout, _ := newTestCLI([]string{"luks2", "create"})
	cli.Run()
	for _, flag := range []string{"--pbkdf", "--hash", "--iter-time", "--pbkdf-force-iterations", "--pbkdf-memory", "--pbkdf-parallel"} {
		if !strings.Contains(stdout.String(), flag) {
			t.Errorf("create usage lacks %s:\n%s", flag, stdout.String())
		}
	}
}

// recoveryAddRecorder records the options AddRecoveryKey was called with.
func recoveryAddRecorder(calls *[]luks2.RecoveryKeyOptions) *MockLuksOperations {
	return &MockLuksOperations{
		AddRecoveryKeyFunc: func(_ string, _ []byte, opts *luks2.RecoveryKeyOptions) (*luks2.RecoveryKey, error) {
			*calls = append(*calls, *opts)
			return luks2.GenerateRecoveryKey(opts.Length, opts.Format)
		},
	}
}

func TestRecoveryAddPassesTheKDFChoiceThrough(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want luks2.RecoveryKeyOptions
	}{
		{
			name: "no option is the library's policy",
			want: luks2.RecoveryKeyOptions{KDFType: luks2.DefaultKDFType()},
		},
		{
			name: "PBKDF2 with a hash, a budget and a count",
			args: []string{"--pbkdf", "pbkdf2", "--hash", "sha384", "--iter-time", "300", "--pbkdf-force-iterations", "1000"},
			want: luks2.RecoveryKeyOptions{KDFType: luks2.KDFTypePBKDF2SHA384, PBKDFIterTime: 300, PBKDFIterations: 1000},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"recovery", "add"}, tt.args...)
			cli, _, stderr := runCLI(t, "passphrase\n", append(args, "/dev/sdb1")...)
			var calls []luks2.RecoveryKeyOptions
			cli.Luks = recoveryAddRecorder(&calls)

			if code := cli.Run(); code != 0 {
				t.Fatalf("recovery add exited %d: %s", code, stderr.String())
			}
			if len(calls) != 1 {
				t.Fatalf("AddRecoveryKey was called %d times, want 1", len(calls))
			}
			got := calls[0]
			if got.KDFType != tt.want.KDFType || got.PBKDFIterTime != tt.want.PBKDFIterTime ||
				got.PBKDFIterations != tt.want.PBKDFIterations || got.Argon2Memory != 0 {
				t.Fatalf("AddRecoveryKey got KDF %q, iter-time %d, iterations %d, memory %d; want %+v",
					got.KDFType, got.PBKDFIterTime, got.PBKDFIterations, got.Argon2Memory, tt.want)
			}
		})
	}
}

// TestRecoveryAddPassesArgon2CostsThrough: outside FIPS mode the Argon2 costs
// reach the library; in FIPS mode the request is refused before the
// passphrase is read and the library is not called.
func TestRecoveryAddPassesArgon2CostsThrough(t *testing.T) {
	cli, _, stderr := runCLI(t, "passphrase\n", "recovery", "add", "--pbkdf", "argon2id",
		"--pbkdf-force-iterations", "2", "--pbkdf-memory", "65536", "--pbkdf-parallel", "1", "/dev/sdb1")
	terminal := &MockTerminal{Password: []byte("testpassword")}
	cli.Terminal = terminal
	var calls []luks2.RecoveryKeyOptions
	cli.Luks = recoveryAddRecorder(&calls)

	code := cli.Run()

	if fips140.Enabled() {
		if code != 1 || !strings.Contains(stderr.String(), luks2.ErrFIPSNotApproved.Error()) {
			t.Fatalf("recovery add --pbkdf argon2id in FIPS mode: exit %d, stderr %q; want 1 and the FIPS refusal", code, stderr.String())
		}
		if len(calls) != 0 || terminal.Reads != 0 {
			t.Fatalf("the refusal was not up front: AddRecoveryKey calls %d, passphrase reads %d", len(calls), terminal.Reads)
		}
		return
	}

	if code != 0 {
		t.Fatalf("recovery add exited %d: %s", code, stderr.String())
	}
	if len(calls) != 1 {
		t.Fatalf("AddRecoveryKey was called %d times, want 1", len(calls))
	}
	got := calls[0]
	if got.KDFType != luks2.KDFTypeArgon2id || got.Argon2Time != 2 || got.Argon2Memory != 65536 || got.Argon2Parallel != 1 {
		t.Fatalf("AddRecoveryKey got %q %d/%d/%d, want argon2id 2/65536/1",
			got.KDFType, got.Argon2Time, got.Argon2Memory, got.Argon2Parallel)
	}
}

func TestRecoveryAddRefusesAnUnusableKDFOption(t *testing.T) {
	cli, _, stderr := runCLI(t, "passphrase\n", "recovery", "add", "--pbkdf", "pbkdf2", "--pbkdf-memory", "1", "/dev/sdb1")
	var calls []luks2.RecoveryKeyOptions
	cli.Luks = recoveryAddRecorder(&calls)

	if code := cli.Run(); code != 1 {
		t.Fatalf("recovery add exited %d, want 1", code)
	}
	if len(calls) != 0 || !strings.Contains(stderr.String(), "--pbkdf-memory") {
		t.Fatalf("AddRecoveryKey calls %d, stderr %q; want none and the reason", len(calls), stderr.String())
	}
}

func TestRecoveryUsageListsTheKDFOptions(t *testing.T) {
	cli, stdout, _ := runCLI(t, "", "recovery")
	cli.Run()
	for _, flag := range []string{"--pbkdf", "--hash", "--iter-time", "--pbkdf-force-iterations", "--pbkdf-memory", "--pbkdf-parallel"} {
		if !strings.Contains(stdout.String(), flag) {
			t.Errorf("recovery usage lacks %s:\n%s", flag, stdout.String())
		}
	}
}

// TestRecoveryAddWritesAPBKDF2KeyslotCryptsetupOpens runs the real library:
// `recovery add --pbkdf pbkdf2` writes a PBKDF2-SHA512 keyslot that cryptsetup
// opens with the printed key, in either mode.
func TestRecoveryAddWritesAPBKDF2KeyslotCryptsetupOpens(t *testing.T) {
	defer parallel(t)()
	// Fails rather than skips: what this test holds is that cryptsetup opens
	// the keyslot, and a run without cryptsetup has verified nothing.
	if _, err := exec.LookPath("cryptsetup"); err != nil {
		t.Fatalf("cryptsetup is not installed: %v", err)
	}

	dir := t.TempDir()
	passphrase := writeFile(t, dir, "pw", "the-existing-passphrase")
	image := newLUKSImage(t, passphrase)

	cli, stdout, stderr := runCLI(t, "", "recovery", "add", "--key-file", passphrase,
		"--pbkdf", "pbkdf2", "--iter-time", "50", image)
	cli.Luks = &DefaultLuksOperations{}

	if code := cli.Run(); code != 0 {
		t.Fatalf("recovery add exited %d: %s", code, stderr.String())
	}

	_, metadata, err := luks2.ReadHeader(image)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	slot := -1
	for id, keyslot := range metadata.Keyslots {
		if id != "0" {
			if keyslot.KDF.Type != luks2.KDFTypePBKDF2 || keyslot.KDF.Hash != "sha512" {
				t.Fatalf("keyslot %s KDF = %s/%s, want pbkdf2/sha512", id, keyslot.KDF.Type, keyslot.KDF.Hash)
			}
			n, err := strconv.Atoi(id)
			if err != nil {
				t.Fatalf("keyslot ID %q is not a number: %v", id, err)
			}
			slot = n
		}
	}
	if slot < 0 {
		t.Fatal("recovery add wrote no keyslot")
	}

	keyFile := writeFile(t, dir, "printed", printedRecoveryKey(t, stdout.String()))
	if code, out := runCryptsetupCLI(t, "open", "--test-passphrase", "--key-slot", strconv.Itoa(slot),
		image, "--key-file", keyFile); code != 0 {
		t.Fatalf("cryptsetup rejected the recovery key in keyslot %d (exit %d): %s", slot, code, out)
	}
}
