// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"testing"
)

func TestTrimRight(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		cutset   string
		expected []byte
	}{
		{"empty input", []byte{}, "\x00", []byte{}},
		{"no trim needed", []byte("hello"), "\x00", []byte("hello")},
		{"single null byte", []byte("hello\x00"), "\x00", []byte("hello")},
		{"multiple null bytes", []byte("hello\x00\x00\x00"), "\x00", []byte("hello")},
		{"all null bytes", []byte("\x00\x00\x00"), "\x00", []byte{}},
		{"mixed cutset", []byte("hello   "), " ", []byte("hello")},
		{"multiple chars in cutset", []byte("hello \x00 \x00"), " \x00", []byte("hello")},
		{"no matching chars", []byte("hello"), "xyz", []byte("hello")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TrimRight(tt.input, tt.cutset)
			if string(result) != string(tt.expected) {
				t.Errorf("TrimRight() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestIsUnlocked_NonexistentVolume(t *testing.T) {
	// IsUnlocked should return false for non-existent volumes
	result := IsUnlocked("definitely-nonexistent-volume-12345")
	if result {
		t.Error("IsUnlocked() should return false for non-existent volume")
	}
}

func TestSafeUint64ToInt64(t *testing.T) {
	tests := []struct {
		name    string
		input   uint64
		want    int64
		wantErr bool
	}{
		{"zero", 0, 0, false},
		{"small positive", 100, 100, false},
		{"max int64", uint64(1<<63 - 1), 1<<63 - 1, false},
		{"overflow", 1 << 63, 0, true},
		{"max uint64", ^uint64(0), 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SafeUint64ToInt64(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("SafeUint64ToInt64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SafeUint64ToInt64() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSafeUint64ToInt(t *testing.T) {
	tests := []struct {
		name    string
		input   uint64
		want    int
		wantErr bool
	}{
		{"zero", 0, 0, false},
		{"small positive", 100, 100, false},
		{"medium value", 1000000, 1000000, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SafeUint64ToInt(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("SafeUint64ToInt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SafeUint64ToInt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSafeInt64ToUint64(t *testing.T) {
	tests := []struct {
		name    string
		input   int64
		want    uint64
		wantErr bool
	}{
		{"zero", 0, 0, false},
		{"positive", 100, 100, false},
		{"max int64", 1<<63 - 1, 1<<63 - 1, false},
		{"negative one", -1, 0, true},
		{"very negative", -1000000, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SafeInt64ToUint64(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("SafeInt64ToUint64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SafeInt64ToUint64() = %v, want %v", got, tt.want)
			}
		})
	}
}

// The two volume-state sentinels were declared and returned by nothing (#70).
// Both refusals already existed and were UNTYPED, so a caller could only tell
// them from any other failure by matching on message text.

// TestUnlockRefusesAMappingNameAlreadyInUse pins ErrVolumeAlreadyUnlocked.
//
// The refusal matters beyond tidiness: the target holding that name may map a
// DIFFERENT volume, so adopting it would hand the caller a plaintext device
// this call did not open.
func TestUnlockRefusesAMappingNameAlreadyInUse(t *testing.T) {
	device, passphrase := unlockableVolume(t)
	withDevDir(t, t.TempDir())

	fake := newFakeDeviceMapper()
	fake.targets["taken"] = "CRYPT-LUKS2-someone-elses-volume"
	fake.install(t)

	err := Unlock(device, passphrase, "taken")
	if err == nil {
		t.Fatal("Unlock adopted a device-mapper name that was already in use")
	}
	if !errors.Is(err, ErrVolumeAlreadyUnlocked) {
		t.Fatalf("Unlock = %v, want an error wrapping ErrVolumeAlreadyUnlocked", err)
	}

	// The damage plane: the existing target is untouched and no second one was
	// created. An error assertion alone cannot tell a refusal from a refusal
	// that trampled the mapping on its way out.
	if uuid := fake.targets["taken"]; uuid != "CRYPT-LUKS2-someone-elses-volume" {
		t.Fatalf("the pre-existing target was modified: %q", uuid)
	}
	if len(fake.created) != 0 {
		t.Fatalf("targets were created despite the refusal: %v", fake.created)
	}
	if len(fake.removed) != 0 {
		t.Fatalf("the pre-existing target was removed: %v", fake.removed)
	}
}

// TestLockRefusesANameNothingHasOpened pins ErrVolumeNotUnlocked.
//
// Closing a name nothing has opened used to surface as "failed to remove
// device-mapper: ...", which sends an operator to look at device-mapper when
// the actual state is that there was nothing to close.
func TestLockRefusesANameNothingHasOpened(t *testing.T) {
	withDevDir(t, t.TempDir())

	fake := newFakeDeviceMapper()
	fake.install(t)

	err := Lock("no-such-mapping")
	if err == nil {
		t.Fatal("Lock reported success for a mapping that does not exist")
	}
	if !errors.Is(err, ErrVolumeNotUnlocked) {
		t.Fatalf("Lock = %v, want an error wrapping ErrVolumeNotUnlocked", err)
	}
	// It must refuse BEFORE asking device-mapper to remove anything, or the
	// error is a diagnosis of someone else's failure.
	if len(fake.removed) != 0 {
		t.Fatalf("Lock asked device-mapper to remove %v despite there being nothing to close", fake.removed)
	}
}

// TestLockClosesAMappingThatIsOpen is the control that keeps the test above
// honest: the guard must not refuse the case it exists to let through.
func TestLockClosesAMappingThatIsOpen(t *testing.T) {
	withDevDir(t, t.TempDir())

	fake := newFakeDeviceMapper()
	fake.targets["open-mapping"] = "CRYPT-LUKS2-open"
	fake.install(t)

	if err := Lock("open-mapping"); err != nil {
		t.Fatalf("Lock refused a mapping that is open: %v", err)
	}
	if len(fake.removed) != 1 || fake.removed[0] != "open-mapping" {
		t.Fatalf("the open mapping was not removed; removals were %v", fake.removed)
	}
}
