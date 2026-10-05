// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// Regression tests for #246 D10-D18: the CLI's destructive operations, the
// file a create makes, the paths it is given, and how it reads what it is
// told.

// formatCounter is a MockLuksOperations that counts Format calls.
func formatCounter(n *int) *MockLuksOperations {
	return &MockLuksOperations{FormatFunc: func(luks2.FormatOptions) error { *n++; return nil }}
}

// TestCreateOnABlockDeviceNeedsAnExplicitYes is #246 D10: `luks2 create
// /dev/X` formatted the device with no confirmation at all. It now asks for
// YES, and anything else -- end of input included -- exits non-zero without
// formatting.
func TestCreateOnABlockDeviceNeedsAnExplicitYes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		stdin   string
		args    []string
		formats int
		code    int
	}{
		{"YES", "YES\n\n", nil, 1, 0},
		{"end of input", "", nil, 0, 1},
		{"no", "no\n", nil, 0, 1},
		{"lowercase", "yes\n", nil, 0, 1},
		{"--batch-mode", "", []string{"--batch-mode"}, 1, 0},
		{"--yes", "", []string{"--yes"}, 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			formats := 0
			cli, _, stderr := newTestCLI(append(append([]string{"luks2", "create"}, tc.args...), "/dev/sdz9"))
			cli.Stdin = strings.NewReader(tc.stdin)
			cli.Luks = formatCounter(&formats)

			if code := cli.Run(); code != tc.code || formats != tc.formats {
				t.Fatalf("exit %d with %d formats, want %d with %d\n%s", code, formats, tc.code, tc.formats, stderr.String())
			}
		})
	}
}

// TestCreateRefusesADeviceThatHoldsData is D10's second half: a device with a
// LUKS header or a filesystem on it is refused without --force, and a device
// the kernel reports in use is refused whatever the flags.
func TestCreateRefusesADeviceThatHoldsData(t *testing.T) {
	for _, tc := range []struct {
		name    string
		found   string
		probe   error
		args    []string
		formats int
		code    int
		stderr  string
	}{
		{"a filesystem", "an ext2/3/4 filesystem", nil, []string{"--batch-mode"}, 0, 1, "--force"},
		{"a filesystem, forced", "an ext2/3/4 filesystem", nil, []string{"--batch-mode", "--force"}, 1, 0, ""},
		{"in use", "", luks2.ErrDeviceInUse, []string{"--batch-mode", "--force"}, 0, 1, "in use"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			formats := 0
			cli, _, stderr := newTestCLI(append(append([]string{"luks2", "create"}, tc.args...), "/dev/sdz9"))
			cli.Devices = &MockDeviceProber{Found: tc.found, FoundErr: tc.probe}
			cli.Luks = formatCounter(&formats)

			if code := cli.Run(); code != tc.code || formats != tc.formats {
				t.Fatalf("exit %d with %d formats, want %d with %d\n%s", code, formats, tc.code, tc.formats, stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.stderr) {
				t.Fatalf("stderr = %q, want it to mention %q", stderr.String(), tc.stderr)
			}
		})
	}
}

// TestCreateRefusesWhatIsNotABlockDeviceUnderDev: a /dev name that is not a
// block device is not created as a regular file, and a path that exists and
// is neither is not formatted.
func TestCreateRefusesWhatIsNotABlockDeviceUnderDev(t *testing.T) {
	for _, tc := range []struct {
		kind pathKind
		want string
	}{{pathAbsent, "no such block device"}, {pathOther, "File already exists"}, {pathRegular, "File already exists"}} {
		formats := 0
		cli, _, stderr := newTestCLI([]string{"luks2", "create", "--batch-mode", "/dev/sdz9", "10M"})
		fs := &MockFileSystem{Files: map[string]bool{}}
		cli.FS = fs
		cli.Devices = &MockDeviceProber{Kinds: map[string]pathKind{"/dev/sdz9": tc.kind}}
		cli.Luks = formatCounter(&formats)
		if code := cli.Run(); code != 1 || formats != 0 || len(fs.Files) != 0 || !strings.Contains(stderr.String(), tc.want) {
			t.Fatalf("kind %d: exit %d, %d formats, files %v, stderr %q", tc.kind, code, formats, fs.Files, stderr.String())
		}
	}

	cli, _, stderr := newTestCLI([]string{"luks2", "create", "/dev/sdz9"})
	cli.Devices = &MockDeviceProber{KindErr: os.ErrPermission}
	if code := cli.Run(); code != 1 || !strings.Contains(stderr.String(), "inspect") {
		t.Fatalf("an uninspectable path: exit %d, stderr %q", code, stderr.String())
	}
}

// TestCreateWithTheKeyOnStandardInputNeedsBatchMode: the whole of standard
// input cannot be both the key and the confirmation.
func TestCreateWithTheKeyOnStandardInputNeedsBatchMode(t *testing.T) {
	formats := 0
	cli, _, stderr := newTestCLI([]string{"luks2", "create", "--key-file", "-", "/dev/sdz9"})
	cli.Stdin = strings.NewReader("YES\n")
	cli.Luks = formatCounter(&formats)
	if code := cli.Run(); code != 1 || formats != 0 || !strings.Contains(stderr.String(), "--batch-mode") {
		t.Fatalf("exit %d, %d formats, stderr %q", code, formats, stderr.String())
	}
}

// TestFindSignatureNamesWhatIsThere covers every signature create refuses to
// format over, and the LUKS2 secondary copy a damaged primary leaves.
func TestFindSignatureNamesWhatIsThere(t *testing.T) {
	defer parallel(t)()

	for _, s := range knownSignatures {
		buf := make([]byte, signatureScanSize)
		copy(buf[s.offset:], s.magic)
		got, err := findSignature(bytes.NewReader(buf))
		if err != nil || got == "" {
			t.Errorf("%s at %d: found %q, %v", s.name, s.offset, got, err)
		}
	}

	secondary := make([]byte, 2<<20)
	copy(secondary[1<<20:], "SKUL\xba\xbe")
	if got, _ := findSignature(bytes.NewReader(secondary)); got != "a LUKS2 secondary header" {
		t.Errorf("a secondary copy at 1 MiB: found %q", got)
	}
	if got, err := findSignature(bytes.NewReader(make([]byte, 1<<20))); got != "" || err != nil {
		t.Errorf("an empty device: found %q, %v", got, err)
	}
	if _, err := findSignature(failingReaderAt{}); err == nil {
		t.Error("a read failure was not reported")
	}
}

type failingReaderAt struct{}

func (failingReaderAt) ReadAt([]byte, int64) (int, error) { return 0, unix.EIO }

// TestDefaultDeviceProberOnTheRealFilesystem: what Kind reports for each kind
// of path, and a signature read from a real file.
func TestDefaultDeviceProberOnTheRealFilesystem(t *testing.T) {
	defer parallel(t)()

	dir := t.TempDir()
	image := filepath.Join(dir, "image")
	content := make([]byte, signatureScanSize)
	copy(content[0:], "LUKS\xba\xbe")
	if err := os.WriteFile(image, content, 0o600); err != nil {
		t.Fatal(err)
	}

	p := DefaultDeviceProber{}
	for path, want := range map[string]pathKind{
		image:                         pathRegular,
		filepath.Join(dir, "missing"): pathAbsent,
		dir:                           pathOther,
		"/dev/null":                   pathOther,
	} {
		if got, err := p.Kind(path); got != want || err != nil {
			t.Errorf("Kind(%s) = %d, %v; want %d", path, got, err, want)
		}
	}
	if _, err := p.Kind(filepath.Join(image, "under-a-file")); err == nil {
		t.Error("Kind under a regular file did not fail")
	}

	got, release, err := p.Claim(image)
	if got != "a LUKS header" || err != nil {
		t.Errorf("Claim(image) = %q, %v", got, err)
	} else {
		release()
	}
	if _, _, err := p.Claim(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Claim(missing) = %v", err)
	}
	if _, _, err := p.Claim(dir); err == nil {
		t.Error("Claim of a directory succeeded")
	}
}

// TestCreateExclusiveRefusesWhatIsAlreadyThere is #246 D11: create used
// Stat-then-Create, which raced, followed a symlink planted at the path, and
// made the container 0644. The file is now created in one O_EXCL|O_NOFOLLOW
// step, mode 0600.
func TestCreateExclusiveRefusesWhatIsAlreadyThere(t *testing.T) {
	defer parallel(t)()

	dir := t.TempDir()
	fs := &DefaultFileSystem{}

	fresh := filepath.Join(dir, "fresh.luks")
	f, err := fs.CreateExclusive(fresh)
	if err != nil {
		t.Fatalf("CreateExclusive: %v", err)
	}
	st, err := f.Stat()
	_ = f.Close()
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("a new container's mode = %v (%v), want 0600", st.Mode().Perm(), err)
	}

	if _, err := fs.CreateExclusive(fresh); !errors.Is(err, os.ErrExist) {
		t.Fatalf("CreateExclusive over an existing file = %v, want ErrExist", err)
	}

	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link.luks")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.CreateExclusive(link); err == nil {
		t.Fatal("CreateExclusive followed a symlink planted at the path")
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the symlink's target was created")
	}
}

// TestRemoveCreatedRemovesOnlyThisRunsFile: a cleanup that removed by name
// would delete a file put in place of the one this run created.
func TestRemoveCreatedRemovesOnlyThisRunsFile(t *testing.T) {
	defer parallel(t)()

	dir := t.TempDir()
	fs := &DefaultFileSystem{}
	path := filepath.Join(dir, "vol.luks")
	created, err := fs.CreateExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = created.Close() }()

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("someone else's"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fs.RemoveCreated(path, created); err == nil {
		t.Fatal("RemoveCreated removed a file this run did not create")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the replacement is gone: %v", err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	again, err := fs.CreateExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = again.Close() }()
	if err := fs.RemoveCreated(path, again); err != nil {
		t.Fatalf("RemoveCreated of this run's file = %v", err)
	}
	if stillCreated(path, nil) {
		t.Fatal("stillCreated with no record reported true")
	}
	_ = again.Close()
	if stillCreated(path, again) {
		t.Fatal("stillCreated with a closed descriptor reported true")
	}
}

// TestCreateFileOnTheRealFilesystem: create on a path that exists leaves it
// untouched, and a failed format removes the file this run made.
func TestCreateFileOnTheRealFilesystem(t *testing.T) {
	defer parallel(t)()

	dir := t.TempDir()
	keyFile := writeFile(t, dir, "key", "create-passphrase")

	existing := writeFile(t, dir, "existing.luks", "precious")
	cli, _, stderr := newTestCLI([]string{"luks2", "create", "--key-file", keyFile, existing, "32M"})
	cli.FS = &DefaultFileSystem{}
	cli.Devices = DefaultDeviceProber{}
	if code := cli.Run(); code != 1 || !strings.Contains(stderr.String(), "already exists") {
		t.Fatalf("create over an existing file: exit %d, %q", code, stderr.String())
	}
	if got, _ := os.ReadFile(existing); string(got) != "precious" { // #nosec G304 -- under t.TempDir()
		t.Fatal("create touched an existing file")
	}

	volume := filepath.Join(dir, "new.luks")
	cli, _, _ = newTestCLI([]string{"luks2", "create", "--key-file", keyFile, volume, "32M"})
	cli.FS = &DefaultFileSystem{}
	cli.Devices = DefaultDeviceProber{}
	cli.Luks = &MockLuksOperations{FormatFunc: func(luks2.FormatOptions) error { return errors.New("format failed") }}
	if code := cli.Run(); code != 1 {
		t.Fatalf("create with a failing format exited %d", code)
	}
	if _, err := os.Lstat(volume); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the file this run created survived its failure: %v", err)
	}
}

// TestWipeAndRestoreExitNonZeroWhenNotConfirmed is #246 D12: a confirmation
// that read end of input, or failed to read, was "canceled" and exited 0, so
// a script checking the status read an unperformed wipe as done.
func TestWipeAndRestoreExitNonZeroWhenNotConfirmed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stdin io.Reader
		args  []string
		done  bool
	}{
		{"wipe, end of input", strings.NewReader(""), []string{"wipe", "/dev/sdz9"}, false},
		{"wipe, read error", iotestErrReader{}, []string{"wipe", "/dev/sdz9"}, false},
		{"wipe, YES at end of input", strings.NewReader("YES"), []string{"wipe", "/dev/sdz9"}, true},
		{"wipe, YES with CRLF", strings.NewReader("YES\r\n"), []string{"wipe", "/dev/sdz9"}, true},
		{"wipe, an overlong answer", strings.NewReader(strings.Repeat("Y", 200) + "\n"), []string{"wipe", "/dev/sdz9"}, false},
		{"wipe --batch-mode", strings.NewReader(""), []string{"wipe", "--batch-mode", "/dev/sdz9"}, true},
		{"restore, end of input", strings.NewReader(""), []string{"header", "restore", "/dev/sdz9"}, false},
		{"restore, read error", iotestErrReader{}, []string{"header", "restore", "/dev/sdz9"}, false},
		{"restore --yes", strings.NewReader(""), []string{"header", "restore", "--yes", "/dev/sdz9"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			done := false
			cli, _, stderr := runCLI(t, "", tc.args...)
			cli.Stdin = tc.stdin
			cli.Luks = &MockLuksOperations{
				WipeFunc:                 func(luks2.WipeOptions) error { done = true; return nil },
				RestorePrimaryHeaderFunc: func(string, luks2.RestoreHeaderOptions) error { done = true; return nil },
			}
			code := cli.Run()
			if done != tc.done || (code == 0) != tc.done {
				t.Fatalf("exit %d, performed %v; want performed %v and a matching status\n%s", code, done, tc.done, stderr.String())
			}
		})
	}
}

type iotestErrReader struct{}

func (iotestErrReader) Read([]byte) (int, error) { return 0, unix.EIO }

// TestConfirmationErrorsMatchTheSentinel: every way of not confirming is
// ErrNotConfirmed, and the read failure stays reachable.
func TestConfirmationErrorsMatchTheSentinel(t *testing.T) {
	for _, err := range []error{&ConfirmationError{Err: ErrNotConfirmed}, &ConfirmationError{Err: io.ErrUnexpectedEOF}} {
		if !errors.Is(err, ErrNotConfirmed) || err.Error() == "" {
			t.Errorf("%v does not match ErrNotConfirmed", err)
		}
	}
	if !errors.Is(&ConfirmationError{Err: unix.EIO}, unix.EIO) {
		t.Error("the read failure is not reachable")
	}
	if e := (&DevicePathError{Path: "/x", Op: "open", Err: unix.EIO}); !errors.Is(e, unix.EIO) || !strings.Contains(e.Error(), "open /x") {
		t.Errorf("DevicePathError = %v", e)
	}
}

// secondReadFails is a terminal that returns a passphrase and then fails.
type secondReadFails struct{ handed [][]byte }

func (s *secondReadFails) ReadPassword(int) ([]byte, error) {
	if len(s.handed) > 0 {
		return nil, unix.EIO
	}
	out := []byte("the-first-passphrase")
	s.handed = append(s.handed, out)
	return out, nil
}

func (s *secondReadFails) IsTerminal(int) bool { return true }

// TestAFailedConfirmationReadWipesTheFirstPassphrase is #246 D13: when the
// confirmation could not be read, the passphrase already read was returned to
// nobody and left on the heap unwiped.
func TestAFailedConfirmationReadWipesTheFirstPassphrase(t *testing.T) {
	cli, _, _ := newTestCLI([]string{"luks2"})
	term := &secondReadFails{}
	cli.Terminal = term

	if _, err := cli.promptPassphrase("p: ", true); err == nil {
		t.Fatal("promptPassphrase succeeded with a failing confirmation read")
	}
	if first := term.handed[0]; !bytes.Equal(first, make([]byte, len(first))) {
		t.Fatalf("the first passphrase was left readable: %q", first)
	}
}

// TestRelativePathsReachTheLibraryAbsolute is #246 D14: the library takes
// absolute paths only, the documentation shows relative ones, and every
// relative path failed. Each command resolves its path argument.
func TestRelativePathsReachTheLibraryAbsolute(t *testing.T) {
	want, err := filepath.Abs("vol.luks")
	if err != nil {
		t.Fatal(err)
	}

	var got []string
	record := func(device string) { got = append(got, device) }
	ops := &MockLuksOperations{
		UnlockFunc: func(d string, _ []byte, _ string) error { record(d); return nil },
		GetVolumeInfoFunc: func(d string) (*luks2.VolumeInfo, error) {
			record(d)
			return &luks2.VolumeInfo{Metadata: &luks2.LUKS2Metadata{}}, nil
		},
		WipeFunc:         func(o luks2.WipeOptions) error { record(o.Device); return nil },
		TestKeyFunc:      func(d string, _ []byte) error { record(d); return nil },
		AddKeyFunc:       func(d string, _, _ []byte, _ *luks2.AddKeyOptions) (int, error) { record(d); return 1, nil },
		RemoveKeyFunc:    func(d string, _ []byte, _ int) error { record(d); return nil },
		KillSlotFunc:     func(d string, _ []byte, _ int) error { record(d); return nil },
		ChangeKeyFunc:    func(d string, _, _ []byte, _ int) error { record(d); return nil },
		ListKeyslotsFunc: func(d string) ([]luks2.KeyslotInfo, error) { record(d); return []luks2.KeyslotInfo{{}}, nil },
		ListTokensFunc:   func(d string) (map[int]*luks2.Token, error) { record(d); return nil, nil },
		ReadHeaderFunc: func(d string) (*luks2.LUKS2BinaryHeader, *luks2.LUKS2Metadata, error) {
			record(d)
			return &luks2.LUKS2BinaryHeader{}, &luks2.LUKS2Metadata{}, nil
		},
		IsLUKSFunc: func(d string) (bool, error) { record(d); return true, nil },
	}

	for _, args := range [][]string{
		{"open", "vol.luks", "name"},
		{"info", "vol.luks"},
		{"wipe", "--batch-mode", "vol.luks"},
		{"testkey", "vol.luks"},
		{"removekey", "vol.luks", "1"},
		{"killslot", "vol.luks", "1"},
		{"keyslots", "vol.luks"},
		{"token", "list", "vol.luks"},
		{"header", "show", "vol.luks"},
		{"isluks", "vol.luks"},
	} {
		got = nil
		cli, _, stderr := runCLI(t, "a-passphrase\n", args...)
		cli.Luks = ops
		if code := cli.Run(); code != 0 || len(got) != 1 || got[0] != want {
			t.Errorf("%v: exit %d, library given %q, want %q\n%s", args, code, got, want, stderr.String())
		}
	}
}

// TestParseSizeTakesTheWholeStringOrNothing is #246 D15: Sscanf stopped at
// the first character it could not use, and the multiplication could wrap.
func TestParseSizeTakesTheWholeStringOrNothing(t *testing.T) {
	for in, want := range map[string]int64{"100M": 100 << 20, "1g": 1 << 30, "512": 512, "2T": 2 << 40, "4k": 4096} {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("ParseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "M", "10x", "10Mx", "1.5G", "-5M", "0", "+5M", " 5M", "9223372036854775807K", "8589934592G", "99999999999999999999"} {
		if got, err := ParseSize(in); !errors.Is(err, ErrUsage) {
			t.Errorf("ParseSize(%q) = %d, %v; want a usage error", in, got, err)
		}
	}
}

// TestWipePassesTakesTheWholeNumber: --passes 3x was three passes.
func TestWipePassesTakesTheWholeNumber(t *testing.T) {
	for _, passes := range []string{"3x", "0", "-1", "101", "99999999999999999999", ""} {
		wiped := false
		cli, _, stderr := runCLI(t, "", "wipe", "--batch-mode", "--passes", passes, "/dev/sdz9")
		cli.Luks = &MockLuksOperations{WipeFunc: func(luks2.WipeOptions) error { wiped = true; return nil }}
		if code := cli.Run(); code != 1 || wiped {
			t.Errorf("--passes %q: exit %d, wiped %v\n%s", passes, code, wiped, stderr.String())
		}
	}
	var got luks2.WipeOptions
	cli, _, _ := runCLI(t, "", "wipe", "--batch-mode", "--full", "--passes", "3", "/dev/sdz9")
	cli.Luks = &MockLuksOperations{WipeFunc: func(o luks2.WipeOptions) error { got = o; return nil }}
	if code := cli.Run(); code != 0 || got.Passes != 3 || got.HeaderOnly {
		t.Fatalf("--full --passes 3: exit %d, options %+v", code, got)
	}
}

// TestReadKeyLineWipesEveryBufferItOutgrows is #246 D16: the passphrase line
// grew by append, and every buffer it outgrew -- a prefix of the passphrase --
// was left on the heap for the collector.
func TestReadKeyLineWipesEveryBufferItOutgrows(t *testing.T) {
	var held [][]byte
	previous := newKeyBuffer
	newKeyBuffer = func(n int) []byte {
		b := previous(n)
		held = append(held, b[:cap(b)])
		return b
	}
	t.Cleanup(func() { newKeyBuffer = previous })

	secret := strings.Repeat("s", 1000)
	line, err := readKeyLine(strings.NewReader(secret + "\nnext"))
	if err != nil || string(line) != secret {
		t.Fatalf("readKeyLine = %q, %v", line, err)
	}
	if len(held) < 2 {
		t.Fatalf("readKeyLine allocated %d buffer(s) for a %d-byte line; it grew some other way", len(held), len(secret))
	}
	for _, b := range held {
		if &b[0] == &line[:1][0] {
			continue
		}
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Fatalf("an outgrown buffer of %d bytes still holds the passphrase", len(b))
		}
	}
}

// failingKeyWriter fails the write that carries the recovery key.
type failingKeyWriter struct {
	bytes.Buffer
	key string
}

func (w *failingKeyWriter) Write(p []byte) (int, error) {
	if w.key != "" && strings.Contains(string(p), w.key) {
		return 0, unix.EPIPE
	}
	return w.Buffer.Write(p)
}

// TestRecoveryAddRollsBackAKeyNobodySaw is #246 D17: a recovery key enrolled
// and then not shown -- the write to stdout failed -- was left live in its
// keyslot, a credential nobody holds. It is removed again; what cannot be
// removed is named.
func TestRecoveryAddRollsBackAKeyNobodySaw(t *testing.T) {
	for _, tc := range []struct {
		name               string
		killErr, removeErr error
		output             string
		wantKill           bool
		wantStderr         string
	}{
		{"rolled back", nil, nil, "", true, "removed again"},
		{"keyslot cannot be removed", unix.EROFS, nil, "", true, "luks2 killslot"},
		{"token cannot be removed", nil, unix.EROFS, "", true, "luks2 token remove"},
		{"saved to a file instead", nil, nil, "saved.txt", false, "saved to"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var killed, removed bool
			out := &failingKeyWriter{}
			args := []string{"recovery", "add", "--key-file", writeFile(t, t.TempDir(), "k", "existing"), "/dev/sdz9"}
			if tc.output != "" {
				args = append(args[:2], append([]string{"--output", tc.output}, args[2:]...)...)
			}
			cli, _, stderr := runCLI(t, "", args...)
			cli.Stdout = out
			cli.FS = &DefaultFileSystem{}
			cli.Luks = &MockLuksOperations{
				AddRecoveryKeyFunc: func(_ string, _ []byte, opts *luks2.RecoveryKeyOptions) (*luks2.RecoveryKey, error) {
					key, err := luks2.GenerateRecoveryKey(luks2.RecoveryKeyLength, luks2.RecoveryKeyFormatDashed)
					if err != nil {
						return nil, err
					}
					out.key, _ = key.FormattedString()
					key.Keyslot, key.TokenID = 3, 1
					return key, nil
				},
				KillSlotFunc: func(_ string, auth []byte, slot int) error {
					killed = string(auth) == "existing" && slot == 3
					return tc.killErr
				},
				RemoveTokenFunc: func(_ string, id int) error { removed = id == 1; return tc.removeErr },
			}

			if code := cli.Run(); code != 1 {
				t.Fatalf("exit %d, want 1: no key reached the operator", code)
			}
			if killed != tc.wantKill || (tc.wantKill && tc.killErr == nil && !removed) {
				t.Fatalf("killed %v removed %v", killed, removed)
			}
			if !strings.Contains(stderr.String(), tc.wantStderr) {
				t.Fatalf("stderr = %q, want %q", stderr.String(), tc.wantStderr)
			}
		})
	}
}

// TestAnEmptyKeyFilePathIsRefused is #246 D18: `--key-file ""` was "no key
// file", and the command fell back to the prompt or to standard input --
// quietly using a credential other than the one named.
func TestAnEmptyKeyFilePathIsRefused(t *testing.T) {
	for _, args := range [][]string{
		{"open", "--key-file", "", "/dev/sdz9", "name"},
		{"open", "--key-file=", "/dev/sdz9", "name"},
		{"addkey", "--key-file", "k", "--new-key-file", "", "/dev/sdz9"},
	} {
		touched := false
		dir := t.TempDir()
		for i, a := range args {
			if a == "k" {
				args[i] = writeFile(t, dir, "k", "existing")
			}
		}
		cli, _, stderr := runCLI(t, "from-standard-input\n", args...)
		cli.FS = &DefaultFileSystem{}
		cli.Luks = &MockLuksOperations{
			UnlockFunc: func(string, []byte, string) error { touched = true; return nil },
			AddKeyFunc: func(string, []byte, []byte, *luks2.AddKeyOptions) (int, error) { touched = true; return 0, nil },
		}
		if code := cli.Run(); code != 1 || touched || !strings.Contains(stderr.String(), ErrEmptyKeyFilePath.Error()) {
			t.Errorf("%v: exit %d, touched %v, stderr %q", args, code, touched, stderr.String())
		}
	}
}

// TestAbsPathRefusesAnEmptyPath.
func TestAbsPathRefusesAnEmptyPath(t *testing.T) {
	if _, err := absPath("open", ""); !errors.Is(err, ErrUsage) {
		t.Fatalf("absPath(\"\") = %v, want a usage error", err)
	}
	cli, _, _ := runCLI(t, "", "open", "", "name")
	if code := cli.Run(); code != 1 {
		t.Fatalf("open with an empty device exited %d", code)
	}
}

// claimWatchingTerminal reads a passphrase and records whether the device was
// claimed at that moment.
type claimWatchingTerminal struct {
	prober    *MockDeviceProber
	heldReads []bool
}

func (c *claimWatchingTerminal) ReadPassword(int) ([]byte, error) {
	c.heldReads = append(c.heldReads, c.prober.Held)
	return []byte("a-new-passphrase"), nil
}

func (c *claimWatchingTerminal) IsTerminal(int) bool { return true }

// TestCreateHoldsTheExclusiveClaimUntilFormat: the in-use probe is not a
// one-off check. Its O_EXCL claim is held through the confirmation and the
// passphrase prompt, so nothing can mount or map the device while the
// operator types, and it is given up only just before Format opens the device.
func TestCreateHoldsTheExclusiveClaimUntilFormat(t *testing.T) {
	prober := &MockDeviceProber{}
	term := &claimWatchingTerminal{prober: prober}
	heldAtFormat := true
	cli, _, stderr := newTestCLI([]string{"luks2", "create", "/dev/sdz9"})
	cli.Stdin = strings.NewReader("YES\n\n")
	cli.Devices = prober
	cli.Terminal = term
	cli.Luks = &MockLuksOperations{FormatFunc: func(luks2.FormatOptions) error { heldAtFormat = prober.Held; return nil }}

	if code := cli.Run(); code != 0 {
		t.Fatalf("create exited %d\n%s", code, stderr.String())
	}
	if len(term.heldReads) != 2 || !term.heldReads[0] || !term.heldReads[1] {
		t.Fatalf("claim held during the passphrase reads: %v, want held for both", term.heldReads)
	}
	if heldAtFormat || prober.Released != 1 {
		t.Fatalf("claim at Format = %v, released %d times; want released once, before Format", heldAtFormat, prober.Released)
	}

	prober = &MockDeviceProber{}
	cli, _, _ = newTestCLI([]string{"luks2", "create", "/dev/sdz9"})
	cli.Devices = prober
	if code := cli.Run(); code != 1 || prober.Released != 1 {
		t.Fatalf("an unconfirmed create: exit %d, released %d times; want 1 and 1", code, prober.Released)
	}
}

// TestCreateMakesAFileUnderDevShm: /dev/shm is an ordinary place for a file,
// so an absent path there is a file volume, not a missing block device.
func TestCreateMakesAFileUnderDevShm(t *testing.T) {
	if looksLikeADeviceName("/dev/shm/vol.luks") || looksLikeADeviceName("/dev/shm") || !looksLikeADeviceName("/dev/sdz9") {
		t.Fatal("looksLikeADeviceName misclassifies /dev/shm or /dev/sdz9")
	}
	formats := 0
	cli, _, stderr := newTestCLI([]string{"luks2", "create", "--key-file", writeFile(t, t.TempDir(), "k", "a-passphrase"), "/dev/shm/vol.luks", "32M"})
	cli.Devices = &MockDeviceProber{Kinds: map[string]pathKind{"/dev/shm/vol.luks": pathAbsent}}
	cli.Luks = formatCounter(&formats)
	cli.Run()
	if formats != 1 {
		t.Fatalf("create of /dev/shm/vol.luks formatted %d times\n%s", formats, stderr.String())
	}
}

// TestWipeNoVerifyReachesTheLibrary: --no-verify disables a standard's
// verification in the library, not only in the summary printed.
func TestWipeNoVerifyReachesTheLibrary(t *testing.T) {
	var got luks2.WipeOptions
	cli, _, _ := runCLI(t, "", "wipe", "--batch-mode", "--full", "--standard", "dod3", "--no-verify", "/dev/sdz9")
	cli.Luks = &MockLuksOperations{WipeFunc: func(o luks2.WipeOptions) error { got = o; return nil }}
	if code := cli.Run(); code != 0 || !got.NoVerify || got.Standard != luks2.StandardDoD3Pass {
		t.Fatalf("exit %d, options %+v; want NoVerify with dod3", code, got)
	}
}

// TestRemoveCreatedNeverRemovesByNameAlone: the path is moved aside before it
// is compared, so a file swapped in between check and unlink cannot be the
// one removed; and the move never overwrites what is already at its target.
func TestRemoveCreatedNeverRemovesByNameAlone(t *testing.T) {
	defer parallel(t)()

	dir := t.TempDir()
	path := filepath.Join(dir, "vol.luks")
	created, err := (&DefaultFileSystem{}).CreateExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = created.Close() }()

	blocker := path + ".luks2-cleanup-" + strconv.Itoa(os.Getpid())
	if err := os.WriteFile(blocker, []byte("in the way"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeCreated(path, created); err == nil {
		t.Fatal("removeCreated overwrote what was at its aside name")
	}
	if got, _ := os.ReadFile(blocker); string(got) != "in the way" { // #nosec G304 -- under t.TempDir()
		t.Fatal("the file at the aside name was replaced")
	}
	if !stillCreated(path, created) {
		t.Fatal("the created file was disturbed by a refused cleanup")
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	if err := removeCreated(path, created); err != nil {
		t.Fatalf("removeCreated = %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("left behind: %v", entries)
	}
	if err := removeCreated(path, created); err == nil {
		t.Fatal("removeCreated of an absent path succeeded")
	}
}
