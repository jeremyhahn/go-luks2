// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/jeremyhahn/go-luks2/internal/header"
	"github.com/jeremyhahn/go-luks2/pkg/dmcrypt"
	"github.com/jeremyhahn/go-luks2/pkg/filesystem"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// The tests in this file pin rows of the CLI SPEC (docs/*/cli.md) that no
// other test in the package names.

// assertHeaderIntact fails t unless the LUKS2 header at path still parses:
// a refusal must come before anything is destroyed.
func assertHeaderIntact(t *testing.T, path string) {
	t.Helper()
	v, err := luks2.Open(context.Background(), path, luks2.WithReadOnly())
	if err != nil {
		t.Fatalf("Open after a refused wipe: %v", err)
	}
	defer func() { _ = v.Close() }()
	if _, err := v.Header(context.Background()); err != nil {
		t.Fatalf("Header after a refused wipe: %v, want the header intact", err)
	}
}

// docs/wipe/cli.md: options may come before or after <device>, a relative
// path is resolved against the working directory, and --yes skips the
// question as --batch-mode does.
func TestRunWipeOptionsAfterTheDeviceOnARelativePath(t *testing.T) {
	path := newPlainImage(t, "wipe-relative.img")
	t.Chdir(filepath.Dir(path))
	e, _, _, stdout, _ := newTestEnv(&bytes.Buffer{})

	if err := runWipe(context.Background(), e, []string{filepath.Base(path), "--full", "--yes"}); err != nil {
		t.Fatalf("runWipe <relative device> --full --yes: %v", err)
	}
	if !strings.Contains(stdout.String(), path) {
		t.Errorf("stdout = %q, want the device resolved to %s", stdout.String(), path)
	}
}

// docs/wipe/cli.md: --passes is 1 to 100 and the whole value must be a
// number; anything else is a usage error (exit 1) before anything is wiped.
func TestRunWipeRefusesPassesOutsideOneToAHundred(t *testing.T) {
	for _, passes := range []string{"0", "101", "-1", "2x", " 1", ""} {
		path := newTestVolumeImage(t, "wipe-passes.img")
		e, _, _, _, _ := newTestEnv(bytes.NewBufferString("YES\n"))

		err := runWipe(context.Background(), e, []string{"--full", "--passes", passes, path})
		var ue *UsageError
		if !errors.As(err, &ue) {
			t.Fatalf("runWipe --passes %q = %v, want a *UsageError", passes, err)
		}
		if got := exitCode(err); got != 1 {
			t.Errorf("runWipe --passes %q: exit %d, want 1", passes, got)
		}
		assertHeaderIntact(t, path)
	}
}

// docs/wipe/cli.md: any answer but YES, end of input or a read error prints
// "Wipe canceled" and exits 1, on both the header-only and the full wipe.
func TestRunWipeCanceledExitsOne(t *testing.T) {
	stdins := map[string]func() *env{
		"other answer": func() *env { e, _, _, _, _ := newTestEnv(bytes.NewBufferString("yes\n")); return e },
		"end of input": func() *env { e, _, _, _, _ := newTestEnv(&bytes.Buffer{}); return e },
		"read error": func() *env {
			e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
			e.stdin = iotest.ErrReader(errors.New("stdin read failed"))
			return e
		},
	}
	for name, newEnv := range stdins {
		for _, mode := range [][]string{nil, {"--full"}} {
			path := newTestVolumeImage(t, "wipe-cancel.img")
			e := newEnv()
			stderr := &bytes.Buffer{}
			e.stderr = stderr

			err := runWipe(context.Background(), e, append(append([]string{}, mode...), path))
			var ce *ConfirmationError
			if !errors.As(err, &ce) {
				t.Fatalf("%s %v: runWipe = %v, want *ConfirmationError", name, mode, err)
			}
			if got := exitCode(err); got != 1 {
				t.Errorf("%s %v: exit %d, want 1", name, mode, got)
			}
			if !strings.Contains(stderr.String(), "Wipe canceled") {
				t.Errorf("%s %v: stderr = %q, want \"Wipe canceled\"", name, mode, stderr.String())
			}
			assertHeaderIntact(t, path)
		}
	}
}

// docs/tokens/cli.md: export --file - writes to standard output; exists
// answers in its exit status (0 present, 1 absent) while other failures keep
// their own; remove deletes the token only, so its keyslot still opens.
func TestRunTokenExportExistsAndRemoveRows(t *testing.T) {
	ctx := context.Background()
	path := newTestVolumeImage(t, "token-rows.img")
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString(`{"type":"user-defined","keyslots":["0"]}`))
	if err := runTokenImport(ctx, e, []string{"--file", "-", path, "0"}); err != nil {
		t.Fatalf("runTokenImport: %v", err)
	}

	e, _, _, stdout, _ := newTestEnv(&bytes.Buffer{})
	if err := runTokenExport(ctx, e, []string{path, "0", "--file", "-"}); err != nil {
		t.Fatalf("runTokenExport --file -: %v", err)
	}
	if !strings.Contains(stdout.String(), "user-defined") {
		t.Errorf("export --file - stdout = %q, want the token JSON", stdout.String())
	}

	e, _, _, _, _ = newTestEnv(&bytes.Buffer{})
	if got := exitCode(runTokenExists(ctx, e, []string{path, "0"})); got != 0 {
		t.Errorf("exists on a present token: exit %d, want 0", got)
	}
	e, _, _, _, _ = newTestEnv(&bytes.Buffer{})
	if got := exitCode(runTokenExists(ctx, e, []string{path, "5"})); got != 1 {
		t.Errorf("exists on an absent token: exit %d, want 1", got)
	}
	e, _, _, _, _ = newTestEnv(&bytes.Buffer{})
	if got := exitCode(runTokenExists(ctx, e, []string{newPlainImage(t, "not-luks.img"), "0"})); got != 4 {
		t.Errorf("exists on a non-LUKS2 device: exit %d, want 4 (its own status, not absent)", got)
	}

	e, _, _, _, _ = newTestEnv(&bytes.Buffer{})
	if err := runTokenRemove(ctx, e, []string{path, "0"}); err != nil {
		t.Fatalf("runTokenRemove: %v", err)
	}
	e, _, _, _, _ = newTestEnv(bytes.NewBufferString(testPassphrase + "\n"))
	if err := runTestKey(ctx, e, []string{path}); err != nil {
		t.Errorf("testkey after token remove: %v, want keyslot 0 still to open the volume", err)
	}
}

// docs/filesystems/cli.md: without -t, a mapping on which Detect finds no
// filesystem, more than one signature or a non-filesystem is refused with
// exit 1, and nothing is mounted.
func TestRunMountRefusesAnUndetectedFilesystem(t *testing.T) {
	e, act, mnt, _, _ := newTestEnv(&bytes.Buffer{})
	act.mapping = mapping{name: "myvolume"}
	mnt.detectErr = &filesystem.Error{Kind: filesystem.ErrNotDetected, Detail: "no signature"}

	err := runMount(context.Background(), e, []string{"myvolume", filepath.Join(t.TempDir(), "mnt")})
	if !errors.Is(err, filesystem.ErrNotDetected) {
		t.Fatalf("runMount = %v, want ErrNotDetected", err)
	}
	if got := exitCode(err); got != 1 {
		t.Errorf("exit %d, want 1", got)
	}
	if len(mnt.mountCalls) != 0 {
		t.Errorf("mountCalls = %v, want none", mnt.mountCalls)
	}
}

// docs/volumes/cli.md (mount): an empty --type, or --type and -t naming
// different types, is a usage error, and nothing is mounted. Both naming the
// same type is accepted.
func TestRunMountRefusesAnEmptyOrConflictingType(t *testing.T) {
	for _, args := range [][]string{
		{"--type", ""},
		{"--type="},
		{"-t", ""},
		{"--type", "xfs", "-t", "ext4"},
	} {
		e, act, mnt, _, _ := newTestEnv(&bytes.Buffer{})
		act.mapping = mapping{name: "myvolume"}

		err := runMount(context.Background(), e, append(append([]string{}, args...), "myvolume", filepath.Join(t.TempDir(), "mnt")))
		var ue *UsageError
		if !errors.As(err, &ue) {
			t.Fatalf("runMount %q = %v, want a *UsageError", args, err)
		}
		if got := exitCode(err); got != 1 {
			t.Errorf("runMount %q: exit %d, want 1", args, got)
		}
		if len(mnt.mountCalls) != 0 {
			t.Errorf("runMount %q: mountCalls = %v, want none", args, mnt.mountCalls)
		}
	}

	e, act, mnt, _, _ := newTestEnv(&bytes.Buffer{})
	act.mapping = mapping{name: "myvolume"}
	if err := runMount(context.Background(), e, []string{"--type", "xfs", "-t", "xfs", "myvolume", filepath.Join(t.TempDir(), "mnt")}); err != nil {
		t.Fatalf("runMount --type xfs -t xfs: %v", err)
	}
	if len(mnt.mountCalls) != 1 || mnt.mountCalls[0].Type != filesystem.XFS {
		t.Errorf("mountCalls = %v, want one xfs mount", mnt.mountCalls)
	}
}

// docs/volumes/cli.md (info): keyslot or token entries written as JSON null
// are listed on stderr, and info still succeeds.
func TestRunInfoListsNullEntriesOnStderr(t *testing.T) {
	path := newTestVolumeImage(t, "info-null.img")
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open the image: %v", err)
	}
	hdr, metadata, err := header.ReadHeaderCopyFrom(f, 0)
	if err != nil {
		t.Fatalf("ReadHeaderCopyFrom: %v", err)
	}
	metadata.Tokens = map[string]*header.Token{"3": nil}
	jsonData, area, err := header.EncodeMetadata(hdr, metadata)
	if err != nil {
		t.Fatalf("EncodeMetadata: %v", err)
	}
	if err := header.WriteEncodedHeader(f, hdr, jsonData, area, (*os.File).Sync); err != nil {
		t.Fatalf("WriteEncodedHeader: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close the image: %v", err)
	}

	e, _, _, stdout, stderr := newTestEnv(&bytes.Buffer{})
	if err := runInfo(context.Background(), e, []string{path}); err != nil {
		t.Fatalf("runInfo: %v", err)
	}
	if !strings.Contains(stderr.String(), "JSON null") || !strings.Contains(stderr.String(), "3") {
		t.Errorf("stderr = %q, want the null token 3 listed", stderr.String())
	}
	if !strings.Contains(stdout.String(), "Volume is valid and accessible") {
		t.Errorf("stdout = %q, want the summary", stdout.String())
	}
}

// docs/volumes/cli.md (create, key input limits): a new passphrase must be 8
// to 512 bytes. Outside that, create exits 2 (ErrInvalidCredential) and the
// file it made is deleted.
func TestRunCreateRefusesANewPassphraseOutsideEightTo512Bytes(t *testing.T) {
	for _, n := range []int{7, 513} {
		dir := t.TempDir()
		keyFile := filepath.Join(dir, "new.key")
		if err := os.WriteFile(keyFile, bytes.Repeat([]byte("k"), n), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		path := filepath.Join(dir, "vol.luks")
		e, act, _, _, _ := newTestEnv(&bytes.Buffer{})

		args := append(append([]string{}, fastKDFArgs...), "--key-file", keyFile, path, "24M")
		err := runCreate(context.Background(), e, args)
		if !errors.Is(err, luks2.ErrInvalidCredential) {
			t.Fatalf("%d-byte passphrase: runCreate = %v, want ErrInvalidCredential", n, err)
		}
		if got := exitCode(err); got != 2 {
			t.Errorf("%d-byte passphrase: exit %d, want 2", n, got)
		}
		if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
			t.Errorf("%d-byte passphrase: Lstat(%s) = %v, want the file deleted", n, path, statErr)
		}
		if len(act.deactivated) != 0 {
			t.Errorf("%d-byte passphrase: deactivated = %v, want nothing activated", n, act.deactivated)
		}
	}
}

// docs/volumes/cli.md (create, step 2): a symlink at the path is refused and
// the file it points at is left alone.
func TestRunCreateRefusesASymlinkAtThePath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	link := filepath.Join(dir, "vol.luks")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString(testPassphrase + "\n"))

	args := append(append([]string{}, fastKDFArgs...), link, "24M")
	if err := runCreate(context.Background(), e, args); err == nil {
		t.Fatal("runCreate on a symlink: want an error")
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "keep" {
		t.Errorf("symlink target = %q, %v, want it unchanged", got, err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("Lstat(link) = %v, %v, want the symlink left in place", fi, err)
	}
}

// keyslotIDs returns the keyslot numbers in the header at path.
func keyslotIDs(t *testing.T, path string) []int {
	t.Helper()
	v, err := luks2.Open(context.Background(), path, luks2.WithReadOnly())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = v.Close() }()
	hdr, err := v.Header(context.Background())
	if err != nil {
		t.Fatalf("Header: %v", err)
	}
	var ids []int
	for _, s := range hdr.Keyslots() {
		ids = append(ids, s.ID)
	}
	return ids
}

// docs/keyslots/cli.md (addkey): the new passphrase goes into --slot <n>.
func TestRunAddKeyIntoTheNamedSlot(t *testing.T) {
	path := newTestVolumeImage(t, "addkey-slot.img")
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString(testPassphrase + "\nsecond-pass\n"))
	if err := runAddKey(context.Background(), e, append(append([]string{}, fastKDFArgs...), "--slot", "5", path)); err != nil {
		t.Fatalf("runAddKey --slot 5: %v", err)
	}
	if got := keyslotIDs(t, path); len(got) != 2 || got[0] != 0 || got[1] != 5 {
		t.Errorf("keyslots = %v, want [0 5]", got)
	}
}

// docs/keyslots/cli.md (killslot): the slot number is printed before it
// acts; the slot is removed from every token in the same write, and a token
// left naming no slot stays.
func TestRunKillSlotEchoesTheSlotAndDropsItFromTokens(t *testing.T) {
	ctx := context.Background()
	path := newTwoSlotVolumeImage(t, "killslot-token.img")
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString(`{"type":"user-defined","keyslots":["1"]}`))
	if err := runTokenImport(ctx, e, []string{"--file", "-", path, "0"}); err != nil {
		t.Fatalf("runTokenImport: %v", err)
	}

	e, _, _, stdout, _ := newTestEnv(bytes.NewBufferString(testPassphrase + "\n"))
	if err := runKillSlot(ctx, e, []string{path, "1"}); err != nil {
		t.Fatalf("runKillSlot: %v", err)
	}
	out := stdout.String()
	before, after := strings.Index(out, "Removing keyslot 1"), strings.Index(out, "Keyslot 1 removed")
	if before < 0 || after < 0 || before > after {
		t.Errorf("stdout = %q, want the slot named before it is removed", out)
	}

	e, _, _, stdout, _ = newTestEnv(&bytes.Buffer{})
	if err := runTokenExport(ctx, e, []string{path, "0"}); err != nil {
		t.Fatalf("runTokenExport after killslot: %v, want the token kept", err)
	}
	var tok struct {
		Keyslots []string `json:"keyslots"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &tok); err != nil {
		t.Fatalf("token JSON %q: %v", stdout.String(), err)
	}
	if len(tok.Keyslots) != 0 {
		t.Errorf("token keyslots = %v, want slot 1 dropped", tok.Keyslots)
	}
}

// docs/keyslots/cli.md: removing the last slot that can open the volume is
// refused, and the volume still opens.
func TestRunKillSlotRefusesTheLastSlot(t *testing.T) {
	path := newTestVolumeImage(t, "killslot-last.img")
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString(testPassphrase + "\n"))
	if err := runKillSlot(context.Background(), e, []string{path, "0"}); err == nil {
		t.Fatal("runKillSlot on the last slot: want a refusal")
	}
	e, _, _, _, _ = newTestEnv(bytes.NewBufferString(testPassphrase + "\n"))
	if err := runTestKey(context.Background(), e, []string{path}); err != nil {
		t.Errorf("testkey after the refused killslot: %v, want slot 0 to still open", err)
	}
}

// recoveryKeyLine returns the line between the RECOVERY KEY banners.
func recoveryKeyLine(t *testing.T, out string) string {
	t.Helper()
	lines := strings.Split(out, "\n")
	for i, l := range lines {
		if strings.Contains(l, "RECOVERY KEY") && i+1 < len(lines) {
			return lines[i+1]
		}
	}
	t.Fatalf("no recovery key in %q", out)
	return ""
}

// docs/recovery-keys/cli.md: dashed, hex and base64 render 32 bytes as 74,
// 64 and 44 characters.
func TestRunRecoveryGenerateFormatLengths(t *testing.T) {
	for format, want := range map[string]int{"dashed": 74, "hex": 64, "base64": 44} {
		e, _, _, stdout, _ := newTestEnv(&bytes.Buffer{})
		if err := runRecoveryGenerate(context.Background(), e, []string{"--format", format}); err != nil {
			t.Fatalf("generate --format %s: %v", format, err)
		}
		if got := len(recoveryKeyLine(t, stdout.String())); got != want {
			t.Errorf("--format %s: %d characters, want %d", format, got, want)
		}
	}
}

// docs/recovery-keys/cli.md: any other --format, an empty one included, is a
// usage error raised before the passphrase is read.
func TestRunRecoveryAddRefusesABadFormatBeforeThePassphrase(t *testing.T) {
	path := newTestVolumeImage(t, "recovery-format.img")
	for _, format := range []string{"nope", ""} {
		stdin := bytes.NewBufferString(testPassphrase + "\n")
		e, _, _, _, _ := newTestEnv(stdin)
		err := runRecoveryAdd(context.Background(), e, append(append([]string{}, fastKDFArgs...), "--format", format, path))
		var ue *UsageError
		if !errors.As(err, &ue) {
			t.Fatalf("add --format %q = %v, want a *UsageError", format, err)
		}
		if stdin.Len() != len(testPassphrase)+1 {
			t.Errorf("add --format %q: the passphrase was read before the refusal", format)
		}
	}
	if got := keyslotIDs(t, path); len(got) != 1 {
		t.Errorf("keyslots = %v, want only slot 0", got)
	}
}

// docs/recovery-keys/cli.md (add): a systemd-recovery token names the slot,
// --output refuses an existing path, and verify --recovery-file takes the
// first line that is not blank or a comment, whitespace stripped.
func TestRunRecoveryAddTokenOutputAndRecoveryFileRows(t *testing.T) {
	ctx := context.Background()
	path := newTestVolumeImage(t, "recovery-rows.img")

	existing := filepath.Join(t.TempDir(), "exists.txt")
	if err := os.WriteFile(existing, []byte("keep"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	e, _, _, stdout, _ := newTestEnv(bytes.NewBufferString(testPassphrase + "\n"))
	err := runRecoveryAdd(ctx, e, append(append([]string{}, fastKDFArgs...), "--output", existing, path))
	if err == nil {
		t.Fatal("recovery add --output <existing>: want a failure")
	}
	if got, _ := os.ReadFile(existing); string(got) != "keep" {
		t.Errorf("existing output = %q, want it not overwritten", got)
	}
	key := recoveryKeyLine(t, stdout.String())

	e, _, _, stdout, _ = newTestEnv(&bytes.Buffer{})
	if err := runTokenList(ctx, e, []string{path}); err != nil {
		t.Fatalf("token list: %v", err)
	}
	if !strings.Contains(stdout.String(), "systemd-recovery") {
		t.Errorf("token list = %q, want a systemd-recovery token", stdout.String())
	}

	recoveryFile := filepath.Join(t.TempDir(), "key.txt")
	if err := os.WriteFile(recoveryFile, []byte("# a comment\n\n   \n  "+key+"  \n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	e, _, _, _, _ = newTestEnv(&bytes.Buffer{})
	if err := runRecoveryVerify(ctx, e, []string{"--recovery-file", recoveryFile, path}); err != nil {
		t.Errorf("verify --recovery-file with comments, blanks and padding: %v", err)
	}
}

// damagePrimary zeroes the start of the primary header copy.
func damagePrimary(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteAt(make([]byte, 512), 0); err != nil {
		t.Fatalf("zero the primary: %v", err)
	}
}

// docs/header/cli.md (restore): a damaged primary is rebuilt from the
// secondary without --force once YES is typed, or with --yes; any other
// answer, end of input or a read error exits 1 and writes nothing.
func TestRunHeaderRestoreRows(t *testing.T) {
	ctx := context.Background()
	for name, stdin := range map[string]*bytes.Buffer{"YES": bytes.NewBufferString("YES\n"), "--yes": {}} {
		path := newTestVolumeImage(t, "restore-damaged.img")
		damagePrimary(t, path)
		args := []string{path}
		if name == "--yes" {
			args = []string{"--yes", path}
		}
		e, _, _, _, _ := newTestEnv(stdin)
		if err := runHeaderRestore(ctx, e, args); err != nil {
			t.Fatalf("%s: restore of a damaged primary: %v", name, err)
		}
		primary, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(primary[:6]) != "LUKS\xba\xbe" {
			t.Errorf("%s: primary magic = %q, want it rebuilt", name, primary[:6])
		}
		e, _, _, _, _ = newTestEnv(bytes.NewBufferString(testPassphrase + "\n"))
		if err := runTestKey(ctx, e, []string{path}); err != nil {
			t.Errorf("%s: testkey after restore: %v", name, err)
		}
	}

	for name, newEnv := range map[string]func() *env{
		"end of input": func() *env { e, _, _, _, _ := newTestEnv(&bytes.Buffer{}); return e },
		"read error": func() *env {
			e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
			e.stdin = iotest.ErrReader(errors.New("stdin read failed"))
			return e
		},
	} {
		path := newTestVolumeImage(t, "restore-cancel.img")
		damagePrimary(t, path)
		err := runHeaderRestore(ctx, newEnv(), []string{path})
		var ce *ConfirmationError
		if !errors.As(err, &ce) {
			t.Fatalf("%s: restore = %v, want *ConfirmationError", name, err)
		}
		if got := exitCode(err); got != 1 {
			t.Errorf("%s: exit %d, want 1", name, got)
		}
		primary, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(primary[:512], make([]byte, 512)) {
			t.Errorf("%s: the primary was written after a canceled restore", name)
		}
	}
}

// docs/volumes/cli.md (exit status) and docs/dm-crypt-activation/cli.md: the
// rows TestExitCodeTable does not name. ErrInvalidCredential is 2; an invalid
// mapping name, an unverified node, a keyring failure, a canceled
// confirmation and a FIPS refusal have no row of their own and exit 1.
func TestExitCodeRowsFromActivationAndKeyInput(t *testing.T) {
	for name, c := range map[string]struct {
		err  error
		want int
	}{
		"invalid credential":    {luks2.ErrInvalidCredential, 2},
		"invalid mapping name":  {dmcrypt.ErrInvalidName, 1},
		"node unverified":       {dmcrypt.ErrNodeUnverified, 1},
		"keyring unavailable":   {dmcrypt.ErrKeyringUnavailable, 1},
		"canceled confirmation": {&ConfirmationError{}, 1},
		"FIPS refuses the KDF":  {luks2.ErrFIPSNotApproved, 1},
	} {
		if got := exitCode(c.err); got != c.want {
			t.Errorf("%s: exitCode(%v) = %d, want %d", name, c.err, got, c.want)
		}
	}
}

// docs/loop-devices/cli.md, open: open takes a device and never attaches a
// loop device for it; an image file is refused by activation with "not a
// block device", which has no exit row of its own, so it exits 1.
func TestRunOpenNeverAttachesALoopDevice(t *testing.T) {
	path := newTestVolumeImage(t, "open-no-loop.img")
	e, act, _, _, _ := newTestEnv(bytes.NewBufferString(testPassphrase + "\n"))
	looper := e.host.looper.(*fakeLooper)
	act.activateErr = errors.Join(luks2.ErrInvalidArgument, errors.New("not a block device: "+path))

	err := runOpen(context.Background(), e, []string{path, "data"})
	if err == nil || !strings.Contains(err.Error(), "not a block device") {
		t.Fatalf("runOpen = %v, want the not-a-block-device refusal", err)
	}
	if got := exitCode(err); got != 1 {
		t.Errorf("exit status = %d, want 1", got)
	}
	if len(looper.attached) != 0 {
		t.Errorf("attached = %v, want no loop device attached by open", looper.attached)
	}
}

// docs/loop-devices/cli.md, close: close removes the mapping only; a loop
// device under it stays attached.
func TestRunCloseNeverDetachesALoopDevice(t *testing.T) {
	e, act, _, stdout, _ := newTestEnv(&bytes.Buffer{})
	looper := e.host.looper.(*fakeLooper)

	if err := runClose(context.Background(), e, []string{"luks-auto"}); err != nil {
		t.Fatalf("runClose: %v", err)
	}
	if len(act.deactivated) != 1 || act.deactivated[0] != "luks-auto" {
		t.Errorf("deactivated = %v, want [luks-auto]", act.deactivated)
	}
	if len(looper.detached) != 0 || len(looper.attached) != 0 {
		t.Errorf("looper attached %v, detached %v; want close to leave loop devices alone", looper.attached, looper.detached)
	}
	if !strings.Contains(stdout.String(), "Volume locked successfully: luks-auto") {
		t.Errorf("stdout = %q, want the close confirmation", stdout.String())
	}
}

// writeAt overwrites path at off with b.
func writeAt(t *testing.T, path string, off int64, b []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteAt(b, off); err != nil {
		t.Fatalf("write at %d: %v", off, err)
	}
}

// docs/header/cli.md, isluks: without --luks2 a LUKS1 header counts; with it,
// only a LUKS2 header that passes validation does. A LUKS2 header whose
// copies both fail validation is a no even though the magic is there, and a
// no exits 1, never 2 to 5.
func TestRunIsLUKSHeaderRows(t *testing.T) {
	luks1 := newPlainImage(t, "luks1.img")
	writeAt(t, luks1, 0, []byte{'L', 'U', 'K', 'S', 0xba, 0xbe, 0x00, 0x01})

	damaged := newTestVolumeImage(t, "isluks-damaged.img")
	garbage := bytes.Repeat([]byte{'#'}, 64)
	writeAt(t, damaged, 4096, garbage)       // the primary's JSON area
	writeAt(t, damaged, 16384+4096, garbage) // the secondary's

	for _, c := range []struct {
		name string
		args []string
		want int
		out  string
	}{
		{"LUKS1 counts without --luks2", []string{luks1}, 0, luks1 + " is a LUKS device"},
		{"LUKS1 is not LUKS2", []string{"--luks2", luks1}, 1, luks1 + " is not a LUKS2 device"},
		{"a header failing validation is a no", []string{damaged}, 1, damaged + " is not a LUKS device"},
		{"a header failing validation is not LUKS2", []string{"--luks2", damaged}, 1, damaged + " is not a LUKS2 device"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, _, _, stdout, _ := newTestEnv(&bytes.Buffer{})
			err := runIsLUKS(context.Background(), e, c.args)
			if got := exitCode(err); got != c.want {
				t.Fatalf("exit status = %d (%v), want %d", got, err, c.want)
			}
			if !strings.Contains(stdout.String(), c.out) {
				t.Errorf("stdout = %q, want %q", stdout.String(), c.out)
			}
		})
	}
}

// docs/header/cli.md, show and secondary: show prints every documented field
// of the current copy; secondary's header offset equals the header size; and
// when the primary is intact but older (a lower sequence ID), show prints the
// secondary, labeled as such, and says so on stderr.
func TestRunHeaderShowAndSecondaryRows(t *testing.T) {
	const hdrSize = 16384
	ctx := context.Background()

	t.Run("show prints every documented field", func(t *testing.T) {
		path := newTestVolumeImage(t, "show-fields.img")
		e, _, _, stdout, stderr := newTestEnv(&bytes.Buffer{})
		if err := runHeaderShow(ctx, e, []string{path}); err != nil {
			t.Fatalf("runHeaderShow: %v", err)
		}
		for _, want := range []string{
			"Primary header: " + path + "\n", "Version:        LUKS2\n", "UUID:           ", "Label:          ",
			"Subsystem:      ", "Header size:    16384 bytes\n", "Header offset:  0\n",
			"Checksum algo:  sha256\n", "Sequence ID:    ", "Keyslots:       1\n",
			"Tokens:         0\n", "Segments:       1\n",
		} {
			if !strings.Contains(stdout.String(), want) {
				t.Errorf("stdout = %q, want it to contain %q", stdout.String(), want)
			}
		}
		if stderr.Len() != 0 {
			t.Errorf("stderr = %q, want nothing for an intact primary", stderr.String())
		}
	})

	t.Run("secondary's offset is the header size", func(t *testing.T) {
		path := newTestVolumeImage(t, "secondary-offset.img")
		e, _, _, stdout, _ := newTestEnv(&bytes.Buffer{})
		if err := runHeaderSecondary(ctx, e, []string{path}); err != nil {
			t.Fatalf("runHeaderSecondary: %v", err)
		}
		for _, want := range []string{"Header size:    16384 bytes\n", "Header offset:  16384\n"} {
			if !strings.Contains(stdout.String(), want) {
				t.Errorf("stdout = %q, want it to contain %q", stdout.String(), want)
			}
		}
	})

	t.Run("show prints the secondary when the primary is older", func(t *testing.T) {
		// The one-slot volume's primary is an intact copy of the same volume
		// at a lower sequence ID than the two-slot volume's secondary.
		old, err := os.ReadFile(newTestVolumeImage(t, "older.img"))
		if err != nil {
			t.Fatal(err)
		}
		path := newTwoSlotVolumeImage(t, "stale-primary.img")
		writeAt(t, path, 0, old[:hdrSize])

		e, _, _, stdout, stderr := newTestEnv(&bytes.Buffer{})
		if err := runHeaderShow(ctx, e, []string{path}); err != nil {
			t.Fatalf("runHeaderShow: %v", err)
		}
		out := stdout.String()
		for _, want := range []string{"Secondary header: " + path + "\n", "Header offset:  16384\n", "Keyslots:       2\n"} {
			if !strings.Contains(out, want) {
				t.Errorf("stdout = %q, want it to contain %q", out, want)
			}
		}
		if !strings.Contains(stderr.String(), "older than the secondary; showing the secondary") {
			t.Errorf("stderr = %q, want a note that the secondary is shown", stderr.String())
		}
	})
}
