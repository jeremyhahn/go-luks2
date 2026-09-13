// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Writing and reading the recovery-key file.
//
// A recovery key is the last-resort credential, reached for precisely when
// everything else has failed. Two properties follow, and neither held.
//
// SAVING must never damage what is already there. Building the whole file and
// writing it in one call, as this package originally did, had that property by
// accident. Streaming into a truncated file does not: the destination is
// emptied before the replacement exists, so a destroyed rendering, a refused
// borrow, a short write, a failed Sync or the process simply exiting leaves an
// empty or partial file where a valid credential used to be.
//
// LOADING must not scatter the credential through memory nobody can wipe.

// TestSaveRecoveryKeyDoesNotDamageAnExistingFile is the regression test.
//
// The destination is mode 0600 rather than 0400 on purpose: a 0400 file cannot
// be opened for writing at all, so it hid the defect behind a permission error.
// 0600 is what an operator's own earlier file, or one written by another tool,
// looks like -- and it is the case where the truncation actually happened.
func TestSaveRecoveryKeyDoesNotDamageAnExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "recovery.key")

	existing := []byte("# LUKS Recovery Key\n# an earlier, working key\nAABBCC-DDEEFF-112233-445566\n")
	if err := os.WriteFile(path, existing, 0o600); err != nil {
		t.Fatalf("failed to create the existing key file: %v", err)
	}

	// A save that fails PART WAY THROUGH: the preamble is writable, and the
	// credential is not. This is the "destroyed key.Credential" case, and it is
	// the one that used to leave a truncated file behind.
	key := failingRecoveryKey(t)

	if err := SaveRecoveryKey(key, path); err == nil {
		t.Fatal("SaveRecoveryKey reported success with an unreadable credential")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the existing recovery key file is gone: %v", err)
	}
	if !bytes.Equal(after, existing) {
		t.Fatalf("a failed save damaged the existing recovery key file:\n got %q\nwant %q", after, existing)
	}
}

// TestSaveRecoveryKeyLeavesNoPartialFile is the other half: with nothing at the
// destination, a failed save must not leave a truncated credential file behind
// for someone to find and trust.
func TestSaveRecoveryKeyLeavesNoPartialFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "recovery.key")

	key := failingRecoveryKey(t)

	if err := SaveRecoveryKey(key, path); err == nil {
		t.Fatal("SaveRecoveryKey reported success with an unreadable credential")
	}

	if _, err := os.Stat(path); err == nil {
		content, _ := os.ReadFile(path)
		t.Fatalf("a failed save left a partial file at the destination: %q", content)
	}

	// And no temp file is left lying around either. A stray file holding part
	// of a recovery key is the same problem under a different name.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read the directory: %v", err)
	}
	for _, e := range entries {
		t.Fatalf("a failed save left %q behind", e.Name())
	}
}

// TestSaveRecoveryKeyRefusesToReplaceAnExistingFile pins the semantics the
// atomic publish chose, so the choice is visible rather than incidental.
//
// The original code refused only when the existing file happened to be mode
// 0400 -- a side effect of opening it for writing, not a decision. Whether a
// recovery key could be silently overwritten therefore depended on the mode of
// the file that was already there. The rule is now the same either way: an
// existing file is never replaced. For a last-resort credential, refusing is
// the safe direction, and a caller that means to replace one removes it first.
func TestSaveRecoveryKeyRefusesToReplaceAnExistingFile(t *testing.T) {
	dir := t.TempDir()

	for _, mode := range []os.FileMode{0o400, 0o600, 0o644} {
		t.Run(mode.String(), func(t *testing.T) {
			path := filepath.Join(dir, "existing-"+mode.String()+".key")
			existing := []byte("AABBCC-DDEEFF\n")
			if err := os.WriteFile(path, existing, mode); err != nil {
				t.Fatalf("failed to create the existing file: %v", err)
			}

			key, err := GenerateRecoveryKey(32, RecoveryKeyFormatDashed)
			if err != nil {
				t.Fatalf("GenerateRecoveryKey failed: %v", err)
			}
			defer key.Clear()

			if err := SaveRecoveryKey(key, path); err == nil {
				t.Fatal("SaveRecoveryKey replaced an existing file")
			}

			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("the existing file is gone: %v", err)
			}
			if !bytes.Equal(after, existing) {
				t.Fatal("the existing file was modified")
			}
		})
	}
}

// TestSaveRecoveryKeyWritesADurableReadableFile is the control: the assertions
// above are all satisfied by a function that never writes anything.
func TestSaveRecoveryKeyWritesADurableReadableFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "good.key")

	key, err := GenerateRecoveryKey(32, RecoveryKeyFormatDashed)
	if err != nil {
		t.Fatalf("GenerateRecoveryKey failed: %v", err)
	}
	defer key.Clear()
	key.VolumeUUID = "a-volume-uuid"
	key.Keyslot = 3

	if err := SaveRecoveryKey(key, path); err != nil {
		t.Fatalf("SaveRecoveryKey failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("no file was written: %v", err)
	}
	if info.Mode().Perm() != 0o400 {
		t.Fatalf("recovery key file has mode %o, want 400", info.Mode().Perm())
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read back: %v", err)
	}
	for _, want := range []string{"LUKS Recovery Key", "a-volume-uuid", "Keyslot: 3", key.CredentialHash} {
		if !strings.Contains(string(content), want) {
			t.Errorf("the file does not carry %q", want)
		}
	}

	// And the key itself round-trips, which is the only assertion that matters
	// to whoever needs it.
	loaded, err := LoadRecoveryCredential(path)
	if err != nil {
		t.Fatalf("LoadRecoveryCredential failed: %v", err)
	}
	defer loaded.Destroy()

	if !key.Credential.EqualTo(openSecret(t, loaded)) {
		t.Fatal("the credential read back is not the credential written")
	}

	// The directory holds exactly the one file: no temp left over on success.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read the directory: %v", err)
	}
	if len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("expected one file, found %v", names)
	}
}

// TestLoadRecoveryKeyDoesNotMaterializeTheFileOnTheHeap is the custody test for
// the read path.
//
// The file used to be read with os.ReadFile into a plain []byte, converted to a
// string, and split -- so the credential existed in at least three places, two
// of them IMMUTABLE and therefore unwipeable no matter what the byte slice was
// cleared to. Nothing about that copy is forced by a validated primitive; it is
// this package's own choice of how to read a file, which is why the
// protected-memory mandate does not yield to it the way it does inside PBKDF2.
//
// runtime.MemStats.TotalAlloc is CUMULATIVE, so a buffer that has since been
// freed still shows, which makes this a deterministic measurement rather than a
// timing one. The padding is what gives it resolution: reading a whole 60 KiB
// file onto the heap and stringifying it costs over twice that, which cannot
// hide inside a delta budgeted at one file's worth.
func TestLoadRecoveryKeyDoesNotMaterializeTheFileOnTheHeap(t *testing.T) {
	const padding = 60 << 10

	dir := t.TempDir()
	path := filepath.Join(dir, "padded.key")

	var file bytes.Buffer
	file.WriteString("# LUKS Recovery Key\n")
	for file.Len() < padding {
		file.WriteString("# padding so that a whole-file heap copy is visible in the allocation delta\n")
	}
	file.WriteString("AABBCC-DDEEFF-112233-445566\n")

	if err := os.WriteFile(path, file.Bytes(), 0o600); err != nil {
		t.Fatalf("failed to write the fixture: %v", err)
	}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	key, err := LoadRecoveryKey(path)

	runtime.ReadMemStats(&after)

	if err != nil {
		t.Fatalf("LoadRecoveryKey failed: %v", err)
	}
	defer key.Destroy()

	if got := openSecret(t, key); len(got) != 12 {
		t.Fatalf("decoded %d bytes, want 12", len(got))
	}

	allocated := after.TotalAlloc - before.TotalAlloc
	if allocated >= padding {
		t.Fatalf("reading a %d-byte file allocated %d bytes of ordinary heap: the file is being materialized outside protected memory",
			file.Len(), allocated)
	}
	t.Logf("read a %d-byte recovery file using %d bytes of ordinary heap", file.Len(), allocated)
}

// TestParseRecoveryKeyNormalisesInsideProtectedMemory is the same property for
// the string boundary.
//
// The caller's string is unwipeable and cannot be helped -- a recovery key
// reaches a program by being typed, pasted or read out of a file. What CAN be
// helped is this package making four more of them: ReplaceAll and ToLower each
// yield a new string when they change anything, and both decoders took
// []byte(s) of the result.
//
// The budget is expressed as a MULTIPLE of the input, not an absolute, because
// the one unavoidable copy -- []byte(formatted), moving the key into locked
// memory -- costs one input's worth on its own and would otherwise swamp the
// signal. At one copy the delta tracks the input; at the four the old form
// made, it tracks three or four times it. A large input is what separates
// those: measured at this size, normalising through strings costs 8 KiB on top
// of the copy for a 4 KiB key, which a small fixture cannot distinguish from
// allocator noise.
func TestParseRecoveryKeyNormalisesInsideProtectedMemory(t *testing.T) {
	// Dashed and upper-case, so every normalisation step has work to do and
	// none of them can be skipped as a no-op.
	const hexDigits = 64 << 10

	var formatted strings.Builder
	for i := 0; i < hexDigits; i++ {
		if i > 0 && i%6 == 0 {
			formatted.WriteByte('-')
		}
		formatted.WriteByte("0123456789ABCDEF"[i%16])
	}
	input := "  " + formatted.String() + "  "

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	key, err := ParseRecoveryKey(input)

	runtime.ReadMemStats(&after)

	if err != nil {
		t.Fatalf("ParseRecoveryKey failed: %v", err)
	}
	defer key.Destroy()

	budget := uint64(2 * len(input))
	allocated := after.TotalAlloc - before.TotalAlloc
	if allocated >= budget {
		t.Fatalf("normalising a %d-byte key allocated %d bytes of ordinary heap, over the %d budget: it is being copied through strings",
			len(input), allocated, budget)
	}
	t.Logf("normalised a %d-byte key using %d bytes of ordinary heap (budget %d)", len(input), allocated, budget)
}

// TestParseRecoveryKeyStillAcceptsEveryFormat guards the rewrite above: moving
// the normalisation into an enclave must not change what parses.
func TestParseRecoveryKeyStillAcceptsEveryFormat(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		expectLen int
	}{
		{"dashed uppercase", "AABBCC-DDEEFF-112233-445566", 12},
		{"dashed lowercase", "aabbcc-ddeeff-112233-445566", 12},
		{"plain hex", "aabbccddeeff112233445566", 12},
		{"plain hex uppercase", "AABBCCDDEEFF112233445566", 12},
		{"base64", "qrvM3e7/ESIzRFVm", 12},
		{"surrounded by whitespace", "  aabbccddeeff  ", 6},
		{"a ragged final group", "010203-0405", 5},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ParseRecoveryKey(tc.input)
			if err != nil {
				t.Fatalf("ParseRecoveryKey(%q) failed: %v", tc.input, err)
			}
			defer key.Destroy()

			if key.Size() != tc.expectLen {
				t.Fatalf("decoded %d bytes, want %d", key.Size(), tc.expectLen)
			}
		})
	}

	for _, bad := range []string{"", "   ", "gghhii", "aabbc"} {
		t.Run("refuses "+bad, func(t *testing.T) {
			key, err := ParseRecoveryKey(bad)
			if err == nil {
				key.Destroy()
				t.Fatalf("ParseRecoveryKey(%q) succeeded", bad)
			}
		})
	}
}

// TestLoadRecoveryKeyRefusesAFileWithNoKey covers the parse, and the bound on
// how much of an untrusted path this will read into locked memory.
func TestLoadRecoveryKeyRefusesAFileWithNoKey(t *testing.T) {
	dir := t.TempDir()

	t.Run("comments only", func(t *testing.T) {
		path := filepath.Join(dir, "comments.key")
		if err := os.WriteFile(path, []byte("# nothing but a comment\n\n   \n"), 0o600); err != nil {
			t.Fatalf("failed to write the fixture: %v", err)
		}
		if key, err := LoadRecoveryKey(path); err == nil {
			key.Destroy()
			t.Fatal("a file with no key was accepted")
		}
	})

	t.Run("empty file", func(t *testing.T) {
		path := filepath.Join(dir, "empty.key")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatalf("failed to write the fixture: %v", err)
		}
		if key, err := LoadRecoveryKey(path); err == nil {
			key.Destroy()
			t.Fatal("an empty file was accepted")
		}
	})

	t.Run("absurdly large file", func(t *testing.T) {
		path := filepath.Join(dir, "huge.key")
		f, err := os.Create(path)
		if err != nil {
			t.Fatalf("failed to create the fixture: %v", err)
		}
		// Sparse: the point is the declared size, which is what would be
		// allocated in locked memory.
		if err := f.Truncate(maxRecoveryKeyFileSize + 1); err != nil {
			_ = f.Close()
			t.Fatalf("failed to size the fixture: %v", err)
		}
		_ = f.Close()

		key, err := LoadRecoveryKey(path)
		if err == nil {
			key.Destroy()
			t.Fatal("a file too large to be a recovery key file was read into locked memory")
		}
		if !errors.Is(err, ErrInvalidSize) {
			t.Fatalf("the refusal does not name the size: %v", err)
		}
	})
}

// failingRecoveryKey returns a RecoveryKey whose credential cannot be read, so a
// save fails after the preamble has been written.
func failingRecoveryKey(t *testing.T) *RecoveryKey {
	t.Helper()

	key, err := GenerateRecoveryKey(32, RecoveryKeyFormatDashed)
	if err != nil {
		t.Fatalf("GenerateRecoveryKey failed: %v", err)
	}
	t.Cleanup(key.Clear)

	key.Credential.Destroy()
	return key
}

// TestSaveRecoveryKeyAlwaysUnlinksTheStagingName covers the one path where the
// staging file outlived the function.
//
// Publication is os.Link, so between the link succeeding and the staging name
// being unlinked there are TWO names for one inode -- two complete copies of the
// recovery credential as far as anything walking the filesystem is concerned.
// The cleanup was gated on a `published` flag that disabled the deferred
// removal precisely once the second name existed, so a failing removal -- a
// concurrent permission change on the directory is the realistic case -- left
// `.recovery-key-*.tmp` behind for backup or scanning tooling to collect, at a
// path nobody expects.
//
// Unlinking the staging name cannot damage the published file. That is what a
// hard link guarantees: the inode survives while any name refers to it. So the
// removal is unconditional and the flag is gone, which also removes an
// invariant that was documented ("removed on every failure path") and untrue.
func TestSaveRecoveryKeyAlwaysUnlinksTheStagingName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "recovery.key")

	key, err := GenerateRecoveryKey(32, RecoveryKeyFormatDashed)
	if err != nil {
		t.Fatalf("GenerateRecoveryKey failed: %v", err)
	}
	defer key.Clear()

	// Fail the FIRST removal only. Failing every removal would leave nothing to
	// assert -- the point is that the deferred attempt still runs and still
	// succeeds, not that a doomed unlink is retried forever.
	failNextRemove(t)

	// Held in its own variable: the assertions below call functions that return
	// their own errors, and reusing err let one of them shadow this one -- which
	// then nil-dereferenced at err.Error(). The bug this whole branch is about,
	// in the test written to check it.
	saveErr := SaveRecoveryKey(key, path)
	if saveErr == nil {
		t.Fatal("SaveRecoveryKey did not report the failed cleanup")
	}

	// No second name for the credential survives. Asserted FIRST, because it is
	// the defect: the error being reported was never in question.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read the directory: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".recovery-key-") {
			t.Fatalf("the staging name survived as a second link to the credential: %s", e.Name())
		}
	}
	if len(entries) != 1 {
		t.Fatalf("expected only the published file, found %d entries", len(entries))
	}

	// The key WAS saved, and the error must say so: an operator reading it must
	// not conclude the credential was lost.
	if !strings.Contains(saveErr.Error(), path) {
		t.Fatalf("the error does not name the file that was written: %v", saveErr)
	}

	// The published file is intact and still the credential.
	loaded, err := LoadRecoveryCredential(path)
	if err != nil {
		t.Fatalf("the published recovery key is unreadable: %v", err)
	}
	defer loaded.Destroy()
	if !key.Credential.EqualTo(openSecret(t, loaded)) {
		t.Fatal("the published file is not the key that was generated")
	}
}

// failNextRemove makes the next file removal fail and every one after it
// succeed.
func failNextRemove(t *testing.T) {
	t.Helper()

	previous := removeFile
	t.Cleanup(func() { removeFile = previous })

	failed := false
	removeFile = func(name string) error {
		if !failed {
			failed = true
			return &os.PathError{Op: "remove", Path: name, Err: os.ErrPermission}
		}
		return previous(name)
	}
}
