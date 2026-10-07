// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/filesystem"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// This file closes coverage gaps left by the command-level tests: the
// real host wrappers (never reached through a fake), small helpers whose
// error branches need a dedicated fixture, and parser functions exercised
// end-to-end by only one of their branches elsewhere.

func TestRealHostWrappersDelegate(t *testing.T) {
	ctx := context.Background()

	// None of these need root or a real device: every one is given a
	// path or name that cannot exist, so the real package underneath
	// returns an error quickly. The point is covering the delegation
	// itself, not exercising dmcrypt/loop/filesystem's own logic, which
	// is those packages' own test suites' job.
	if _, err := (realActivator{}).activate(ctx, nil, nil, "does-not-exist"); err == nil {
		t.Error("realActivator.activate: want an error for a nil Volume")
	}
	if err := (realActivator{}).deactivate(ctx, "cli-coverage-does-not-exist"); err == nil {
		t.Error("realActivator.deactivate: want an error for a mapping that does not exist")
	}
	if _, err := (realActivator{}).lookup(ctx, "cli-coverage-does-not-exist"); err == nil {
		t.Error("realActivator.lookup: want an error for a mapping that does not exist")
	}

	if _, err := (realLooper{}).attach(ctx, "/nonexistent/cli-coverage.img"); err == nil {
		t.Error("realLooper.attach: want an error for a file that does not exist")
	}
	if _, err := (realLooper{}).detach(ctx, loopDevice{devPath: "/dev/cli-coverage-does-not-exist"}); err == nil {
		t.Error("realLooper.detach: want an error for a loop device that does not exist")
	}

	target := filepath.Join(t.TempDir(), "mnt")
	if err := (realMounter{}).mount(ctx, filesystem.MountParams{Source: "/nonexistent", Target: target}); err == nil {
		t.Error("realMounter.mount: want an error for a nonexistent source")
	}
	if err := (realMounter{}).unmount(ctx, "/nonexistent/cli-coverage-mnt", 0); err == nil {
		t.Error("realMounter.unmount: want an error for a path that is not mounted")
	}
	if _, err := (realMounter{}).isMounted(ctx, "/nonexistent/cli-coverage-mnt"); err != nil {
		// IsMounted on an absent path reports false, not an error; either
		// is fine here -- only the delegation needs covering.
		_ = err
	}
	if _, err := (realMounter{}).deviceMounted(ctx, 0, 0); err != nil {
		_ = err
	}
	if _, err := (realMounter{}).detect(ctx, "/nonexistent/cli-coverage.img"); err == nil {
		t.Error("realMounter.detect: want an error for a nonexistent device")
	}
	if err := (realMounter{}).make(ctx, "/nonexistent/cli-coverage.img", filesystem.Ext4, filesystem.MakeParams{}); err == nil {
		t.Error("realMounter.make: want an error for a nonexistent device")
	}
}

func TestParseSizeSuffixes(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"1", 1},
		{"1K", 1 << 10},
		{"1k", 1 << 10},
		{"2M", 2 << 20},
		{"1G", 1 << 30},
		{"1T", 1 << 40},
	}
	for _, c := range cases {
		got, err := parseSize("create", c.in)
		if err != nil {
			t.Errorf("parseSize(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseSize(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestParseSizeRejectsInvalid(t *testing.T) {
	for _, in := range []string{"", "0", "-1", "+1", "abc", "1.5G", "9223372036854775807T"} {
		if _, err := parseSize("create", in); err == nil {
			t.Errorf("parseSize(%q): want an error", in)
		}
	}
}

func TestRemoveCreatedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "created.img")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer func() { _ = f.Close() }()

	if err := removeCreatedFile(path, f); err != nil {
		t.Fatalf("removeCreatedFile: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("Stat after removal = %v, want IsNotExist", err)
	}
}

func TestRemoveCreatedFileRefusesAReplacedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "created.img")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer func() { _ = f.Close() }()

	// Someone else's file now occupies the path: removeCreatedFile must
	// refuse to remove it and must put it back.
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := os.WriteFile(path, []byte("someone else's file"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := removeCreatedFile(path, f); err == nil {
		t.Fatal("removeCreatedFile: want an error when the path no longer names the created file")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the replaced file should have been put back: %v", err)
	}
}

func TestDetachAndReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vol.luks")
	e, _, _, _, stderr := newTestEnv(&bytes.Buffer{})
	lp := e.host.looper.(*fakeLooper)

	if err := detachAndReport(context.Background(), e, loopDevice{devPath: "/dev/loop0"}, path, errSentinel); !errors.Is(err, errSentinel) {
		t.Errorf("detachAndReport = %v, want the cause returned", err)
	}
	if len(lp.detached) != 1 {
		t.Errorf("detached = %v, want one call", lp.detached)
	}
	if stderr.Len() == 0 {
		t.Error("stderr should report the failure")
	}

	stderr.Reset()
	lp.detachErr = errSentinel
	if err := detachAndReport(context.Background(), e, loopDevice{devPath: "/dev/loop0"}, path, errSentinel); !errors.Is(err, errSentinel) {
		t.Errorf("detachAndReport = %v, want the cause returned even when detach also fails", err)
	}
}

var errSentinel = errors.New("cli: coverage test sentinel")

func TestPromptLabelFromTerminal(t *testing.T) {
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString(""))
	term := &fakeTerminal{isTerm: true}
	e.term = term
	e.getStdinFd = func() int { return 0 }
	e.stdin = bytes.NewBufferString("my-label\n")

	label := promptLabel(e, keySource{})
	if label != "my-label" {
		t.Errorf("promptLabel = %q, want %q", label, "my-label")
	}
}

func TestPromptLabelSkippedWithKeyFile(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	e.term = &fakeTerminal{isTerm: true}
	e.getStdinFd = func() int { return 0 }

	label := promptLabel(e, keySource{path: "/some/key/file"})
	if label != "" {
		t.Errorf("promptLabel = %q, want empty when --key-file was given", label)
	}
}

func TestReportKDFRefusalPrintsFIPSHint(t *testing.T) {
	e, _, _, _, stderr := newTestEnv(&bytes.Buffer{})
	reportKDFRefusal(e, luks2.ErrFIPSNotApproved)
	if stderr.Len() == 0 {
		t.Error("reportKDFRefusal: want a FIPS hint on stderr")
	}

	stderr.Reset()
	reportKDFRefusal(e, errSentinel)
	if stderr.Len() != 0 {
		t.Errorf("reportKDFRefusal: want nothing printed for a non-FIPS error, got %q", stderr.String())
	}
}

func TestParseAddKeyKDFEveryBranch(t *testing.T) {
	cases := []struct {
		name     string
		wantType luks2.KDFType
		wantHash crypto.Hash
		wantErr  bool
	}{
		{"", "", 0, false},
		{"argon2id", luks2.KDFArgon2id, 0, false},
		{"argon2i", luks2.KDFArgon2i, 0, false},
		{"pbkdf2", luks2.KDFPBKDF2, crypto.SHA256, false},
		{"pbkdf2-sha256", luks2.KDFPBKDF2, crypto.SHA256, false},
		{"pbkdf2-sha384", luks2.KDFPBKDF2, crypto.SHA384, false},
		{"pbkdf2-sha512", luks2.KDFPBKDF2, crypto.SHA512, false},
		{"pbkdf2-sha1", "", 0, true},
		{"nonsense", "", 0, true},
	}
	for _, c := range cases {
		got, err := parseAddKeyKDF("addkey", c.name)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseAddKeyKDF(%q): want an error", c.name)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseAddKeyKDF(%q): %v", c.name, err)
			continue
		}
		if got.Type != c.wantType || got.Hash != c.wantHash {
			t.Errorf("parseAddKeyKDF(%q) = %+v, want Type=%q Hash=%v", c.name, got, c.wantType, c.wantHash)
		}
	}
}

func TestHashFromNameEveryBranch(t *testing.T) {
	cases := map[string]crypto.Hash{"sha256": crypto.SHA256, "sha384": crypto.SHA384, "sha512": crypto.SHA512}
	for name, want := range cases {
		got, err := hashFromName(name)
		if err != nil {
			t.Errorf("hashFromName(%q): %v", name, err)
		}
		if got != want {
			t.Errorf("hashFromName(%q) = %v, want %v", name, got, want)
		}
	}
	if _, err := hashFromName("sha1"); err == nil {
		t.Error("hashFromName(\"sha1\"): want an error")
	}
}

func TestKDFFlagsResolveRejectsCrossFamilyOptions(t *testing.T) {
	f := newFlags("create")
	kdf := declareKDFFlags(f)
	if _, err := f.parse([]string{"--pbkdf", "argon2id", "--hash", "sha256"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, _, err := kdf.resolve(); err == nil {
		t.Fatal("resolve: want an error for --hash with --pbkdf argon2id")
	}

	f2 := newFlags("create")
	kdf2 := declareKDFFlags(f2)
	if _, err := f2.parse([]string{"--pbkdf", "pbkdf2", "--pbkdf-memory", "65536"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, _, err := kdf2.resolve(); err == nil {
		t.Fatal("resolve: want an error for --pbkdf-memory with --pbkdf pbkdf2")
	}

	f3 := newFlags("create")
	kdf3 := declareKDFFlags(f3)
	if _, err := f3.parse([]string{"--pbkdf", "nonsense"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, _, err := kdf3.resolve(); err == nil {
		t.Fatal("resolve: want an error for an unknown --pbkdf value")
	}

	f4 := newFlags("create")
	kdf4 := declareKDFFlags(f4)
	if _, err := f4.parse([]string{"--pbkdf-force-iterations", "not-a-number"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, _, err := kdf4.resolve(); err == nil {
		t.Fatal("resolve: want an error for a non-numeric --pbkdf-force-iterations")
	}
}

func TestTokenDeviceAndIDMissingArgs(t *testing.T) {
	if _, _, err := tokenDeviceAndID("token show", []string{"/dev/sdb1"}); err == nil {
		t.Fatal("tokenDeviceAndID: want an error with a missing id")
	}
}

func TestRunTokenExportAndImportThroughFiles(t *testing.T) {
	path := newTestVolumeImage(t, "token-files.img")
	tokenPath := filepath.Join(t.TempDir(), "token.json")

	importE, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	if err := os.WriteFile(tokenPath, []byte(`{"type":"user-defined","keyslots":["0"]}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := runTokenImport(context.Background(), importE, []string{"--file", tokenPath, path, "0"}); err != nil {
		t.Fatalf("runTokenImport: %v", err)
	}

	exportPath := filepath.Join(t.TempDir(), "exported.json")
	exportE, _, _, exportStdout, _ := newTestEnv(&bytes.Buffer{})
	if err := runTokenExport(context.Background(), exportE, []string{"--file", exportPath, path, "0"}); err != nil {
		t.Fatalf("runTokenExport: %v", err)
	}
	if exportStdout.Len() == 0 {
		t.Error("stdout should confirm the file was written")
	}
	if _, err := os.Stat(exportPath); err != nil {
		t.Errorf("exported file should exist: %v", err)
	}
}

func TestRunTokenShowMissingArgs(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	if err := runTokenShow(context.Background(), e, nil); err == nil {
		t.Fatal("runTokenShow: want a usage error with no arguments")
	}
}
