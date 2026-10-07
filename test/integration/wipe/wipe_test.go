// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package wipe_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/header"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/jeremyhahn/go-luks2/pkg/wipe"
	"github.com/jeremyhahn/go-luks2/test/internal/harness"
)

// patternsOf returns passes copies of p, the shape wipe.Params.Patterns
// wants for what WipeOptions{Passes, Random} used to spell.
func patternsOf(passes int, random bool) []wipe.Pattern {
	p := wipe.Zeros
	if random {
		p = wipe.Random
	}
	out := make([]wipe.Pattern, passes)
	for i := range out {
		out[i] = p
	}
	return out
}

func formatTmp(t *testing.T, path string, size int64) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	if err := f.Truncate(size); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate: %v", err)
	}
	f.Close()

	if err := formatForTest(path, "test-password"); err != nil {
		t.Fatalf("Format failed: %v", err)
	}
}

// formatForTest formats path as a minimal PBKDF2 LUKS2 container, the way
// the pre-redesign library's luks2.Format(luks2.FormatOptions{...}) did
// before B.6 moved Format behind (*luks2.Volume).Format.
func formatForTest(path, passphrase string) error {
	ctx := context.Background()
	v, err := luks2.Open(ctx, path)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryEnclaveCopy([]byte(passphrase))
	if err != nil {
		return err
	}
	defer func() { _ = pass.Destroy() }()

	return v.Format(ctx, pass, luks2.FormatParams{
		KDF: luks2.KDFParams{Type: luks2.KDFPBKDF2, IterTime: time.Millisecond},
	})
}

// addKeyForTest adds a PBKDF2 keyslot, the way the pre-redesign library's
// luks2.AddKey(luks2.AddKeyOptions{...}) did before B.6 moved AddKey behind
// (*luks2.Volume).AddKeyslot.
func addKeyForTest(path, existing, newPassphrase string) error {
	ctx := context.Background()
	v, err := luks2.Open(ctx, path)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryEnclaveCopy([]byte(existing))
	if err != nil {
		return err
	}
	defer func() { _ = pass.Destroy() }()

	key, err := v.Unlock(ctx, pass)
	if err != nil {
		return err
	}
	defer key.Destroy()

	newCred, err := enclave.NewMemoryEnclaveCopy([]byte(newPassphrase))
	if err != nil {
		return err
	}
	defer func() { _ = newCred.Destroy() }()

	_, err = v.AddKeyslot(ctx, key, newCred, luks2.KeyslotParams{
		Priority: luks2.PriorityNormal,
		KDF:      luks2.KDFParams{Type: luks2.KDFPBKDF2, IterTime: time.Millisecond},
	})
	return err
}

func TestWipeHeader(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-header.img"
	defer os.Remove(tmpfile)
	formatTmp(t, tmpfile, 50*1024*1024)

	if _, _, err := harness.ReadHeader(tmpfile); err != nil {
		t.Fatalf("Header should be readable before wipe: %v", err)
	}

	v, err := luks2.Open(context.Background(), tmpfile)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if err := v.Erase(context.Background()); err != nil {
		t.Fatalf("Erase failed: %v", err)
	}
	_ = v.Close()

	if _, _, err := harness.ReadHeader(tmpfile); err == nil {
		t.Fatal("Header should not be readable after wipe")
	}
}

func TestWipeFull(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-full.img"
	defer os.Remove(tmpfile)
	formatTmp(t, tmpfile, 32*1024*1024)

	if err := wipe.Sanitize(context.Background(), tmpfile, wipe.Params{Patterns: patternsOf(1, true)}); err != nil {
		t.Fatalf("Sanitize failed: %v", err)
	}

	if _, err := os.Stat(tmpfile); err != nil {
		t.Fatal("File should still exist after wipe")
	}
	if _, _, err := harness.ReadHeader(tmpfile); err == nil {
		t.Fatal("Header should not be readable after full wipe")
	}
}

func TestWipeMultiplePasses(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-multi.img"
	defer os.Remove(tmpfile)
	formatTmp(t, tmpfile, 32*1024*1024)

	if err := wipe.Sanitize(context.Background(), tmpfile, wipe.Params{Patterns: patternsOf(3, true)}); err != nil {
		t.Fatalf("Sanitize with 3 passes failed: %v", err)
	}
}

func TestWipeKeyslot(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-keyslot.img"
	defer os.Remove(tmpfile)
	formatTmp(t, tmpfile, 50*1024*1024)

	// See wipe_integration_test.go (now moved): WipeKeyslot must refuse to
	// destroy a volume's only keyslot (#37, #71), the same last-keyslot
	// guard KillKeyslot already has.
	if err := harness.WipeKeyslot(tmpfile, 0); err == nil {
		t.Fatal("WipeKeyslot destroyed the only keyslot that can open this volume, and reported success")
	} else if !errors.Is(err, luks2.ErrLastKeyslot) {
		t.Fatalf("WipeKeyslot was refused for some other reason than the guard: %v", err)
	}

	func() {
		loopDev, err := harness.SetupLoopDevice(tmpfile)
		if err != nil {
			t.Fatalf("Failed to setup loop device: %v", err)
		}
		defer func() { _ = harness.DetachLoopDevice(loopDev) }()

		vol := runVolume(t, "test-wipe-keyslot")
		defer releaseVolume(t, vol)

		if err := Unlock(loopDev, []byte("test-password"), vol); err != nil {
			t.Fatalf("the volume no longer unlocks after a REFUSED WipeKeyslot: %v", err)
		}
	}()

	if err := addKeyForTest(tmpfile, "test-password", "second-password"); err != nil {
		t.Fatalf("AddKey failed: %v", err)
	}
	if err := harness.WipeKeyslot(tmpfile, 1); err != nil {
		t.Fatalf("WipeKeyslot refused a removal that leaves a working keyslot: %v", err)
	}
	if err := harness.TestKey(tmpfile, []byte("second-password")); err == nil {
		t.Fatal("the wiped credential still opens the volume")
	}
	if err := harness.TestKey(tmpfile, []byte("test-password")); err != nil {
		t.Fatalf("the surviving credential no longer opens the volume: %v", err)
	}
}

func TestWipeErrors(t *testing.T) {
	tests := []struct {
		name   string
		device string
		params wipe.Params
	}{
		{"nonexistent-device", "/nonexistent/device", wipe.Params{Patterns: patternsOf(1, false)}},
		{"zero-passes", "/tmp/test", wipe.Params{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := wipe.Sanitize(context.Background(), tt.device, tt.params); err == nil {
				t.Fatal("Expected error, got nil")
			}
		})
	}
}

func TestWipeWithTrimOnLoopDevice(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-trim-loop.img"
	defer os.Remove(tmpfile)
	formatTmp(t, tmpfile, 20*1024*1024)

	if err := wipe.Sanitize(context.Background(), tmpfile, wipe.Params{Patterns: patternsOf(1, true), Discard: true}); err != nil {
		t.Fatalf("Sanitize with discard failed: %v", err)
	}

	if _, err := os.Stat(tmpfile); err != nil {
		t.Fatal("File should still exist after wipe")
	}
	if _, _, err := harness.ReadHeader(tmpfile); err == nil {
		t.Fatal("Header should not be readable after wipe")
	}
}

func TestWipeWithTrimOnBlockDevice(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-trim-blk.img"
	defer os.Remove(tmpfile)

	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	if err := f.Truncate(30 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate: %v", err)
	}
	f.Close()

	loopDev, err := harness.SetupLoopDevice(tmpfile)
	if err != nil {
		t.Fatalf("Failed to setup loop device: %v", err)
	}
	defer harness.DetachLoopDevice(loopDev)

	if err := formatForTest(loopDev, "test-password"); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// TRIM might fail on loop device (depends on backing store) but the
	// wipe passes themselves must still succeed.
	if err := wipe.Sanitize(context.Background(), loopDev, wipe.Params{Patterns: patternsOf(1, false), Discard: true}); err != nil {
		t.Fatalf("Sanitize with discard failed: %v", err)
	}

	if _, _, err := harness.ReadHeader(loopDev); err == nil {
		t.Fatal("Header should not be readable after wipe")
	}
}

func TestWipeMultiplePassesWithTrim(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-multi-trim.img"
	defer os.Remove(tmpfile)
	formatTmp(t, tmpfile, 32*1024*1024)

	if err := wipe.Sanitize(context.Background(), tmpfile, wipe.Params{Patterns: patternsOf(3, true), Discard: true}); err != nil {
		t.Fatalf("Sanitize with 3 passes and discard failed: %v", err)
	}
}

func TestWipeHeaderOnlyNoTrim(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-header-no-trim.img"
	defer os.Remove(tmpfile)
	formatTmp(t, tmpfile, 50*1024*1024)

	// Erase (the old header-only Wipe's successor, B.6) has no discard
	// option at all: a crypto-erase never issued TRIM, exactly as the
	// original HeaderOnly path ignored Trim rather than erroring on it.
	v, err := luks2.Open(context.Background(), tmpfile)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if err := v.Erase(context.Background()); err != nil {
		t.Fatalf("Erase failed: %v", err)
	}
	_ = v.Close()

	if _, _, err := harness.ReadHeader(tmpfile); err == nil {
		t.Fatal("Header should not be readable after wipe")
	}
}

func TestWipeSecurityVerification(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-security.img"
	defer os.Remove(tmpfile)

	testSize := int64(10 * 1024 * 1024)
	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	pattern := []byte("SENSITIVE_DATA_MARKER_")
	buf := make([]byte, 1024*1024)
	for i := 0; i < len(buf); i += len(pattern) {
		copy(buf[i:], pattern)
	}
	for written := int64(0); written < testSize; {
		n, err := f.Write(buf)
		if err != nil {
			f.Close()
			t.Fatalf("Failed to write pattern: %v", err)
		}
		written += int64(n)
	}
	f.Close()

	if err := wipe.Sanitize(context.Background(), tmpfile, wipe.Params{Patterns: patternsOf(1, false)}); err != nil {
		t.Fatalf("Sanitize failed: %v", err)
	}

	result, err := os.ReadFile(tmpfile)
	if err != nil {
		t.Fatalf("Failed to read result: %v", err)
	}

	for i := 0; i <= len(result)-len(pattern); i++ {
		if string(result[i:i+len(pattern)]) == string(pattern) {
			t.Fatalf("Found sensitive pattern at offset %d - wipe failed!", i)
		}
	}
	for i, b := range result {
		if b != 0 {
			t.Fatalf("Non-zero byte at offset %d: 0x%02x", i, b)
		}
	}
}

func TestWipeRandomSecurityVerification(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-random-security.img"
	defer os.Remove(tmpfile)

	testSize := int64(5 * 1024 * 1024)
	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	zeros := make([]byte, 1024*1024)
	for written := int64(0); written < testSize; {
		n, err := f.Write(zeros)
		if err != nil {
			f.Close()
			t.Fatalf("Failed to write zeros: %v", err)
		}
		written += int64(n)
	}
	f.Close()

	if err := wipe.Sanitize(context.Background(), tmpfile, wipe.Params{Patterns: patternsOf(1, true)}); err != nil {
		t.Fatalf("Random sanitize failed: %v", err)
	}

	result, err := os.ReadFile(tmpfile)
	if err != nil {
		t.Fatalf("Failed to read result: %v", err)
	}

	nonZeroCount := 0
	for _, b := range result {
		if b != 0 {
			nonZeroCount++
		}
	}
	minExpected := len(result) / 10
	if nonZeroCount < minExpected {
		t.Fatalf("Too few non-zero bytes after random wipe: %d (expected at least %d)", nonZeroCount, minExpected)
	}
}

func TestWipeKeyslotWithTrim(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-keyslot-trim.img"
	defer os.Remove(tmpfile)
	formatTmp(t, tmpfile, 50*1024*1024)

	_, metadata, err := harness.ReadHeader(tmpfile)
	if err != nil {
		t.Fatalf("Failed to read header: %v", err)
	}
	if _, ok := metadata.Keyslots["0"]; !ok {
		t.Fatal("Keyslot 0 should exist")
	}

	if err := harness.WipeKeyslot(tmpfile, 0); err == nil {
		t.Fatal("WipeKeyslot destroyed the only keyslot that can open this volume, and reported success")
	} else if !errors.Is(err, luks2.ErrLastKeyslot) {
		t.Fatalf("WipeKeyslot was refused for some other reason than the guard: %v", err)
	}

	_, metadata, err = harness.ReadHeader(tmpfile)
	if err != nil {
		t.Fatalf("Failed to read header after the refusal: %v", err)
	}
	if _, ok := metadata.Keyslots["0"]; !ok {
		t.Fatal("WipeKeyslot was refused AND the keyslot was removed anyway")
	}

	if err := addKeyForTest(tmpfile, "test-password", "second-password"); err != nil {
		t.Fatalf("AddKey failed: %v", err)
	}
	if err := harness.WipeKeyslot(tmpfile, 1); err != nil {
		t.Fatalf("WipeKeyslot refused a removal that leaves a working keyslot: %v", err)
	}
	_, metadata, err = harness.ReadHeader(tmpfile)
	if err != nil {
		t.Fatalf("Failed to read header after wipe: %v", err)
	}
	if _, ok := metadata.Keyslots["1"]; ok {
		t.Fatal("Keyslot 1 should be wiped")
	}
}

func TestWipeWithDataVerification(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-e2e.img"
	defer os.Remove(tmpfile)
	formatTmp(t, tmpfile, 20*1024*1024)

	hdr, _, err := harness.ReadHeader(tmpfile)
	if err != nil {
		t.Fatalf("Failed to read header: %v", err)
	}
	if string(hdr.Magic[:]) != header.Magic {
		t.Fatalf("Invalid magic before wipe: %v", hdr.Magic)
	}

	if err := wipe.Sanitize(context.Background(), tmpfile, wipe.Params{Patterns: patternsOf(2, true), Discard: true}); err != nil {
		t.Fatalf("Sanitize failed: %v", err)
	}

	rf, err := os.Open(tmpfile)
	if err != nil {
		t.Fatalf("Failed to open wiped file: %v", err)
	}
	defer rf.Close()

	magic := make([]byte, 6)
	if _, err := rf.Read(magic); err != nil {
		t.Fatalf("Failed to read magic: %v", err)
	}
	if string(magic) == header.Magic {
		t.Fatal("LUKS2 magic should be wiped")
	}
}

func TestWipeConcurrentAccess(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-concurrent.img"
	defer os.Remove(tmpfile)
	formatTmp(t, tmpfile, 32*1024*1024)

	done := make(chan error, 2)

	go func() {
		done <- wipe.Sanitize(context.Background(), tmpfile, wipe.Params{Patterns: patternsOf(3, true)})
	}()
	go func() {
		done <- wipe.Sanitize(context.Background(), tmpfile, wipe.Params{Patterns: patternsOf(3, false)})
	}()

	err1 := <-done
	err2 := <-done

	successCount := 0
	if err1 == nil {
		successCount++
	}
	if err2 == nil {
		successCount++
	}
	if successCount == 0 {
		t.Fatalf("Both wipes failed: err1=%v, err2=%v", err1, err2)
	}
}
