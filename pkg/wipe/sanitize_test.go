// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package wipe

import (
	"bytes"
	"context"
	"crypto/aes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/device"
	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// baseSys is defaultSys with a short lock wait, so a test that contends for
// the lock resolves in milliseconds rather than DefaultLockWait.
func baseSys() sys {
	s := defaultSys()
	s.lockWait = 200 * time.Millisecond
	return s
}

// writeFixture writes a file of size bytes of fill and returns its path.
func writeFixture(t *testing.T, size int, fill byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wipe-fixture")
	if err := os.WriteFile(path, bytes.Repeat([]byte{fill}, size), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestResolvePatterns(t *testing.T) {
	for _, tc := range []struct {
		name         string
		params       Params
		wantPatterns []Pattern
		wantVerify   bool
	}{
		{"zero value defaults to a single zeros pass", Params{}, []Pattern{Zeros}, false},
		{"custom patterns, no verify", Params{Patterns: []Pattern{Ones, Zeros}}, []Pattern{Ones, Zeros}, false},
		{"custom patterns, verify always", Params{Patterns: []Pattern{Ones}, Verify: VerifyAlways}, []Pattern{Ones}, true},
		{"NIST", Params{Standard: NIST}, []Pattern{Random}, false},
		{"DoD3Pass verifies by default", Params{Standard: DoD3Pass}, []Pattern{Zeros, Ones, Random}, true},
		{"DoD7Pass verifies by default", Params{Standard: DoD7Pass},
			[]Pattern{Zeros, Ones, Random, Random, Zeros, Ones, Random}, true},
		{"standard overrides patterns", Params{Standard: NIST, Patterns: []Pattern{Zeros, Zeros, Zeros}}, []Pattern{Random}, false},
		{"VerifyAlways overrides a standard that would not verify", Params{Standard: NIST, Verify: VerifyAlways}, []Pattern{Random}, true},
		{"VerifyNever overrides a standard that would verify", Params{Standard: DoD3Pass, Verify: VerifyNever},
			[]Pattern{Zeros, Ones, Random}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			patterns, verify := resolvePatterns(tc.params)
			if !slices.Equal(patterns, tc.wantPatterns) {
				t.Errorf("patterns = %v, want %v", patterns, tc.wantPatterns)
			}
			if verify != tc.wantVerify {
				t.Errorf("verify = %v, want %v", verify, tc.wantVerify)
			}
		})
	}
}

// TestPassStreamFillsEachPattern: zeros and ones are what they say, and an
// unknown pattern is refused before anything is written.
func TestPassStreamFillsEachPattern(t *testing.T) {
	for _, tc := range []struct {
		pattern Pattern
		want    byte
	}{{Zeros, 0x00}, {Ones, 0xFF}} {
		s, err := newPassStream(tc.pattern)
		if err != nil {
			t.Fatalf("newPassStream(%s): %v", tc.pattern, err)
		}
		buf := bytes.Repeat([]byte{0xAA}, 1024)
		s.fill(buf, 4096)
		for i, b := range buf {
			if b != tc.want {
				t.Fatalf("%s: byte %d is 0x%02x, want 0x%02x", tc.pattern, i, b, tc.want)
			}
		}
	}

	if _, err := newPassStream(Pattern(99)); err == nil {
		t.Fatal("newPassStream(99) = nil, want an error")
	}
}

// TestRandomPassStreamIsReproducible is what makes a random pass verifiable
// (#246 D1): the stream at any chunk can be produced again on its own, a
// fresh pass gets a fresh key, and the output is not a constant.
func TestRandomPassStreamIsReproducible(t *testing.T) {
	s, err := newPassStream(Random)
	if err != nil {
		t.Fatalf("newPassStream: %v", err)
	}

	whole := make([]byte, 3*aes.BlockSize*64)
	s.fill(whole, 0)
	part := make([]byte, aes.BlockSize*64)
	s.fill(part, int64(aes.BlockSize*64))
	if !bytes.Equal(part, whole[aes.BlockSize*64:2*aes.BlockSize*64]) {
		t.Fatal("the stream regenerated at an offset differs from the stream written through it")
	}
	if bytes.Count(whole, []byte{0}) > len(whole)/16 {
		t.Fatal("the random stream is mostly zeros")
	}

	other, err := newPassStream(Random)
	if err != nil {
		t.Fatalf("newPassStream: %v", err)
	}
	again := make([]byte, len(whole))
	other.fill(again, 0)
	if bytes.Equal(again, whole) {
		t.Fatal("two random passes wrote the same stream: the key is not drawn per pass")
	}
}

// TestRandomPassStreamCarriesTheCounter: an IV whose low half is about to
// wrap carries into the high half, so the stream past the wrap is still the
// CTR stream and not a repeat of its start.
func TestRandomPassStreamCarriesTheCounter(t *testing.T) {
	s, err := newPassStream(Random)
	if err != nil {
		t.Fatalf("newPassStream: %v", err)
	}
	for i := 8; i < aes.BlockSize; i++ {
		s.iv[i] = 0xFF
	}

	whole := make([]byte, 4*aes.BlockSize)
	s.fill(whole, 0)
	tail := make([]byte, 2*aes.BlockSize)
	s.fill(tail, 2*aes.BlockSize)
	if !bytes.Equal(tail, whole[2*aes.BlockSize:]) {
		t.Fatal("the stream regenerated past the counter wrap differs from the stream written through it")
	}
}

// TestWritePassReportsAWriteFailure: a descriptor that cannot be written is a
// ErrIO error naming the caller's path, not a silent short wipe.
func TestWritePassReportsAWriteFailure(t *testing.T) {
	path := writeFixture(t, 16, 0xAA)
	ro, err := os.Open(path) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	s, _ := newPassStream(Zeros)
	err = writePass(context.Background(), ro, path, 16, s, nil, 1, 1)
	var e *Error
	if !errors.As(err, &e) || !errors.Is(err, errs.ErrIO) {
		t.Fatalf("writePass on a read-only descriptor = %v, want an ErrIO *Error", err)
	}
	if !strings.Contains(e.Detail, path) {
		t.Errorf("Detail = %q, want the caller's path %q", e.Detail, path)
	}
}

// recordingFile is a passFile that logs every write and sync in order.
type recordingFile struct {
	events  []string
	syncErr error
}

func (r *recordingFile) WriteAt(p []byte, off int64) (int, error) {
	r.events = append(r.events, "write")
	return len(p), nil
}

func (r *recordingFile) Sync() error {
	r.events = append(r.events, "sync")
	return r.syncErr
}

// TestWritePassSyncsAfterEveryPass is S1: a multi-pass wipe whose passes sit
// in the page cache together reaches the medium as only the last pattern, so
// each pass is flushed before the next one starts.
func TestWritePassSyncsAfterEveryPass(t *testing.T) {
	f := &recordingFile{}
	s, _ := newPassStream(Zeros)
	for pass := 1; pass <= 3; pass++ {
		if err := writePass(context.Background(), f, "dev", 2*chunk, s, nil, pass, 3); err != nil {
			t.Fatalf("writePass %d: %v", pass, err)
		}
	}
	want := []string{"write", "write", "sync", "write", "write", "sync", "write", "write", "sync"}
	if !slices.Equal(f.events, want) {
		t.Fatalf("events = %v, want a sync closing each pass: %v", f.events, want)
	}
}

// TestWritePassReportsASyncFailure: a pass that cannot be flushed has not
// reached the medium, so it fails the wipe.
func TestWritePassReportsASyncFailure(t *testing.T) {
	f := &recordingFile{syncErr: unix.EIO}
	s, _ := newPassStream(Zeros)
	err := writePass(context.Background(), f, "dev", chunk, s, nil, 1, 1)
	if !errors.Is(err, errs.ErrIO) || !errors.Is(err, unix.EIO) {
		t.Fatalf("writePass with a failing sync = %v, want ErrIO wrapping EIO", err)
	}
}

// TestSanitizeValidatesParamsBeforeWriting is S7: an unknown Standard or
// Pattern is refused before any byte lands, not turned into a zero pass or
// discovered halfway through the sequence.
func TestSanitizeValidatesParamsBeforeWriting(t *testing.T) {
	for name, p := range map[string]Params{
		"unknown standard": {Standard: Standard(99)},
		"unknown pattern":  {Patterns: []Pattern{Zeros, Pattern(99)}},
	} {
		path := writeFixture(t, 4096, 0xAA)
		err := sanitize(context.Background(), path, p, baseSys())
		if !errors.Is(err, errs.ErrInvalidArgument) {
			t.Fatalf("%s: Sanitize = %v, want ErrInvalidArgument", name, err)
		}
		got, _ := os.ReadFile(path) // #nosec G304 -- under t.TempDir()
		if !bytes.Equal(got, bytes.Repeat([]byte{0xAA}, 4096)) {
			t.Fatalf("%s: Sanitize wrote before refusing", name)
		}
	}
}

// TestSanitizeErrorsCarryOpAndPath is S12: the exported entry stamps Op and
// Path.
func TestSanitizeErrorsCarryOpAndPath(t *testing.T) {
	err := Sanitize(context.Background(), "/x", Params{Standard: Standard(99)})
	var e *Error
	if !errors.As(err, &e) || e.Op != "Sanitize" || e.Path != "/x" {
		t.Fatalf("Sanitize error = %#v, want Op Sanitize and Path /x", err)
	}
}

// TestWritePassReportsProgress tests the progress callback.
func TestWritePassReportsProgress(t *testing.T) {
	size := 2 * chunk
	path := writeFixture(t, size, 0)
	f, err := os.OpenFile(path, os.O_RDWR, 0o600) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	s, _ := newPassStream(Zeros)

	var calls []Progress
	if err := writePass(context.Background(), f, path, int64(size), s, func(p Progress) { calls = append(calls, p) }, 1, 3); err != nil {
		t.Fatalf("writePass failed: %v", err)
	}

	if len(calls) != 2 {
		t.Fatalf("got %d progress callbacks, want one per chunk (2)", len(calls))
	}
	first := calls[0]
	if first.Pass != 1 || first.Passes != 3 || first.Pattern != Zeros || first.Verifying {
		t.Errorf("first progress = %+v", first)
	}
	last := calls[len(calls)-1]
	if last.Written != int64(size) || last.Total != int64(size) {
		t.Errorf("last progress = %+v", last)
	}
}

// TestWritePassStopsAtTheChunkBoundaryOnCancellation: ctx is checked once per
// chunk, and a cancellation reports the kind and how far the
// pass got.
func TestWritePassStopsAtTheChunkBoundaryOnCancellation(t *testing.T) {
	size := 3 * chunk
	path := writeFixture(t, size, 0xAA)
	f, err := os.OpenFile(path, os.O_RDWR, 0o600) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	s, _ := newPassStream(Zeros)

	ctx, cancel := context.WithCancel(context.Background())
	chunks := 0
	err = writePass(ctx, f, path, int64(size), s, func(Progress) {
		chunks++
		if chunks == 1 {
			cancel()
		}
	}, 1, 1)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("writePass after cancellation = %v, want context.Canceled", err)
	}
	if chunks != 1 {
		t.Fatalf("writePass wrote %d chunks after cancellation, want exactly 1", chunks)
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("%d of %d bytes written", chunk, size)) {
		t.Fatalf("the error does not state how many bytes were written: %v", err)
	}
}

// busyClaimOpenFile fails every O_EXCL open of a /proc/self/fd entry with
// EBUSY -- what the kernel answers for a block device that is mounted,
// mapped or held -- and records whether one was attempted.
func busyClaimOpenFile(attempted *bool) device.OpenFunc {
	return func(name string, flag int, perm os.FileMode) (*os.File, error) {
		if strings.HasPrefix(name, "/proc/self/fd/") && flag&unix.O_EXCL != 0 {
			*attempted = true
			return nil, &os.PathError{Op: "open", Path: name, Err: unix.EBUSY}
		}
		return os.OpenFile(name, flag, perm)
	}
}

// TestSanitizeOpensTheDeviceExclusively is #246 D4. The kernel's O_EXCL claim
// is the in-use check; EBUSY from it is ErrDeviceInUse and nothing is
// written.
func TestSanitizeOpensTheDeviceExclusively(t *testing.T) {
	path := writeFixture(t, 64*1024, 0xAA)
	var attempted bool
	s := baseSys()
	s.openFile = busyClaimOpenFile(&attempted)

	err := sanitize(context.Background(), path, Params{}, s)
	if !attempted {
		t.Fatal("Sanitize did not open the device with O_EXCL")
	}
	if !errors.Is(err, ErrDeviceInUse) || !errors.Is(err, unix.EBUSY) {
		t.Fatalf("Sanitize of a busy device = %v, want ErrDeviceInUse wrapping EBUSY", err)
	}

	got, err := os.ReadFile(path) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bytes.Repeat([]byte{0xAA}, 64*1024)) {
		t.Fatal("Sanitize wrote to a device it reported busy")
	}
}

// TestSanitizeChecksCtxBeforeLocking: a caller that canceled before calling
// Sanitize does not spend the lock-wait budget, and nothing is written.
func TestSanitizeChecksCtxBeforeLocking(t *testing.T) {
	path := writeFixture(t, 4096, 0xAA)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := sanitize(ctx, path, Params{}, baseSys()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Sanitize with a canceled ctx = %v, want context.Canceled", err)
	}

	got, err := os.ReadFile(path) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bytes.Repeat([]byte{0xAA}, 4096)) {
		t.Fatal("Sanitize wrote with a ctx that was already canceled")
	}
}

// TestSanitizeRefusesAnEmptyDevice: "wiped zero bytes" is a success claim
// about nothing.
func TestSanitizeRefusesAnEmptyDevice(t *testing.T) {
	path := writeFixture(t, 0, 0)
	if err := sanitize(context.Background(), path, Params{}, baseSys()); err == nil {
		t.Fatal("Sanitize of an empty device = nil, want it refused for having no size")
	}
}

// TestSanitizePropagatesWhatItCannotOpen: a path that does not exist is
// reported as such, not masked by a different classification.
func TestSanitizePropagatesWhatItCannotOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent")
	if err := sanitize(context.Background(), path, Params{}, baseSys()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Sanitize(absent) = %v, want ErrNotExist", err)
	}
}

// TestSanitizeDefaultsToASingleZerosPass: the zero value of Params is a
// single Zeros pass with no verification and no discard. Exercised through
// the exported Sanitize, which builds the production sys for sanitize.
func TestSanitizeDefaultsToASingleZerosPass(t *testing.T) {
	path := writeFixture(t, 64*1024, 0xAA)
	if err := Sanitize(context.Background(), path, Params{}); err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	got, err := os.ReadFile(path) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, make([]byte, 64*1024)) {
		t.Fatal("the zero-value Params did not zero the device")
	}
}

// TestSanitizeCustomPatternSequence writes the sequence in order; the final
// pattern is what the device ends holding.
func TestSanitizeCustomPatternSequence(t *testing.T) {
	path := writeFixture(t, 64*1024, 0)
	var seen []Pattern
	p := Params{
		Patterns: []Pattern{Ones, Zeros, Ones},
		Progress: func(pr Progress) {
			if !pr.Verifying && pr.Written == pr.Total {
				seen = append(seen, pr.Pattern)
			}
		},
	}
	if err := sanitize(context.Background(), path, p, baseSys()); err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	if !slices.Equal(seen, []Pattern{Ones, Zeros, Ones}) {
		t.Fatalf("passes seen = %v, want [Ones Zeros Ones]", seen)
	}
	got, err := os.ReadFile(path) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bytes.Repeat([]byte{0xFF}, 64*1024)) {
		t.Fatal("the device does not hold the last pass's pattern")
	}
}

// TestSanitizeDiscardIsBestEffort: BLKDISCARD on a regular file fails, and
// Sanitize still reports success.
func TestSanitizeDiscardIsBestEffort(t *testing.T) {
	path := writeFixture(t, 4096, 0xAA)
	if err := sanitize(context.Background(), path, Params{Discard: true}, baseSys()); err != nil {
		t.Fatalf("Sanitize with Discard on a regular file: %v", err)
	}
}

// TestSanitizeVerifyAlwaysRunsEvenWithoutAStandard proves verification ran
// (rather than merely not objecting to a correct wipe) by making it fail: the
// medium is modeled as still holding the pre-wipe contents.
func TestSanitizeVerifyAlwaysRunsEvenWithoutAStandard(t *testing.T) {
	path := writeFixture(t, 16*1024, 0xAA)
	s := baseSys()
	s.openFile = staleMediumOpenFile(t, bytes.Repeat([]byte{0xAA}, 16*1024))

	err := sanitize(context.Background(), path, Params{Verify: VerifyAlways}, s)
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("Sanitize with a stale medium = %v, want ErrVerification", err)
	}
}

// TestSanitizeVerifyNeverSkipsAStandardsVerification: NoVerify's successor,
// VerifyNever, turns verification off even for a standard that requires it --
// the medium here would fail it if it ran.
func TestSanitizeVerifyNeverSkipsAStandardsVerification(t *testing.T) {
	path := writeFixture(t, 16*1024, 0xAA)
	s := baseSys()
	s.openFile = staleMediumOpenFile(t, bytes.Repeat([]byte{0xAA}, 16*1024))

	err := sanitize(context.Background(), path, Params{Standard: DoD3Pass, Verify: VerifyNever}, s)
	if err != nil {
		t.Fatalf("Sanitize dod3 with VerifyNever = %v, want no verification", err)
	}
}

// staleMediumOpenFile redirects every READ-ONLY open of a /proc/self/fd
// entry -- what ReadPastCache resolves the locked descriptor to -- to a
// fixed file holding stale contents, modeling a medium that still holds what
// a wipe pass overwrote in the page cache. The claim's own O_EXCL open of
// the same fd entry, and every open of the real device path, pass through
// unchanged, so the passes themselves still land on the device.
func staleMediumOpenFile(t *testing.T, stale []byte) device.OpenFunc {
	t.Helper()
	stalePath := writeFixture(t, len(stale), 0)
	if err := os.WriteFile(stalePath, stale, 0o600); err != nil {
		t.Fatal(err)
	}
	return func(name string, flag int, perm os.FileMode) (*os.File, error) {
		if strings.HasPrefix(name, "/proc/self/fd/") && flag&unix.O_EXCL == 0 {
			return os.OpenFile(stalePath, flag, perm)
		}
		return os.OpenFile(name, flag, perm)
	}
}
