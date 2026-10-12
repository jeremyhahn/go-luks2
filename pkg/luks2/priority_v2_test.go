// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"
)

// TestPriorityZeroValueIsDefault pins the shape of the enum: the zero value is
// "not asked for", so PriorityIgnore can only be reached by naming it.
func TestPriorityZeroValueIsDefault(t *testing.T) {
	var p KeyslotParams
	if p.Priority != PriorityDefault {
		t.Fatalf("zero KeyslotParams.Priority = %d, want PriorityDefault", p.Priority)
	}
	if PriorityIgnore == PriorityDefault || PriorityNormal == PriorityDefault || PriorityPrefer == PriorityDefault {
		t.Fatal("an explicit priority shares the zero value with PriorityDefault")
	}
}

// TestPriorityDiskMapping checks both directions of the on-disk mapping and
// that they are inverses for every declared value.
func TestPriorityDiskMapping(t *testing.T) {
	tests := []struct {
		p    Priority
		disk *int
		read Priority
	}{
		{PriorityDefault, nil, PriorityNormal},
		{PriorityIgnore, intPtr(keyslotPriorityIgnore), PriorityIgnore},
		{PriorityNormal, nil, PriorityNormal},
		{PriorityPrefer, intPtr(keyslotPriorityPrefer), PriorityPrefer},
	}
	for _, tt := range tests {
		got := onDiskPriority(tt.p)
		switch {
		case (got == nil) != (tt.disk == nil):
			t.Errorf("onDiskPriority(%d) = %v, want %v", tt.p, got, tt.disk)
		case got != nil && *got != *tt.disk:
			t.Errorf("onDiskPriority(%d) = %d, want %d", tt.p, *got, *tt.disk)
		}
		if r := priorityFromDisk(got); r != tt.read {
			t.Errorf("priorityFromDisk(onDiskPriority(%d)) = %d, want %d", tt.p, r, tt.read)
		}
	}
	if got := priorityFromDisk(intPtr(keyslotPriorityNormal)); got != PriorityNormal {
		t.Errorf("an explicit on-disk 1 reads as %d, want PriorityNormal", got)
	}
}

// TestVolumeAddKeyslotPriorityRoundTrips: every value a caller can name
// reaches disk as the LUKS2 encoding and reads back as itself; the default
// reads back as normal with no member written.
func TestVolumeAddKeyslotPriorityRoundTrips(t *testing.T) {
	defer parallel(t)()
	tests := []struct {
		name string
		p    Priority
		disk *int
		want Priority
	}{
		{"default", PriorityDefault, nil, PriorityNormal},
		{"ignore", PriorityIgnore, intPtr(0), PriorityIgnore},
		{"normal", PriorityNormal, nil, PriorityNormal},
		{"prefer", PriorityPrefer, intPtr(2), PriorityPrefer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := formattedVolumeImage(t, "addkeyslot-priority-"+tt.name+".img", "", "")
			v := txnVolume(t, path)
			key := txnKey(t, v)

			info, err := v.AddKeyslot(context.Background(), key, txnPassphrase(t, "priority "+tt.name), KeyslotParams{
				Priority: tt.p,
				KDF:      KDFParams{Type: KDFPBKDF2, IterTime: time.Millisecond},
			})
			if err != nil {
				t.Fatalf("AddKeyslot failed: %v", err)
			}
			if info.Priority != tt.want {
				t.Errorf("AddKeyslot returned Priority %d, want %d", info.Priority, tt.want)
			}
			assertOnDiskPriority(t, path, info.ID, tt.disk)
		})
	}
}

// TestVolumeChangeKeyslotIgnoreIsKeptAndChangeable: an explicit
// PriorityIgnore is written, PriorityDefault keeps it, and an explicit value
// replaces it.
func TestVolumeChangeKeyslotIgnoreIsKeptAndChangeable(t *testing.T) {
	defer parallel(t)()
	path := formattedVolumeImage(t, "changekeyslot-ignore.img", "", "")
	v := txnVolume(t, path)
	key := txnKey(t, v)
	ctx := context.Background()
	kdf := KDFParams{Type: KDFPBKDF2, IterTime: time.Millisecond}

	info, err := v.ChangeKeyslot(ctx, key, txnPassphrase(t, "an ignored slot"), KeyslotParams{Priority: PriorityIgnore, KDF: kdf})
	if err != nil {
		t.Fatalf("ChangeKeyslot(ignore) failed: %v", err)
	}
	if info.Priority != PriorityIgnore {
		t.Fatalf("ChangeKeyslot(ignore) returned %d", info.Priority)
	}
	assertOnDiskPriority(t, path, info.ID, intPtr(0))

	info, err = v.ChangeKeyslot(ctx, key, txnPassphrase(t, "still ignored"), KeyslotParams{KDF: kdf})
	if err != nil {
		t.Fatalf("ChangeKeyslot(default) failed: %v", err)
	}
	if info.Priority != PriorityIgnore {
		t.Fatalf("ChangeKeyslot with PriorityDefault changed ignore to %d", info.Priority)
	}
	assertOnDiskPriority(t, path, info.ID, intPtr(0))

	info, err = v.ChangeKeyslot(ctx, key, txnPassphrase(t, "preferred"), KeyslotParams{Priority: PriorityPrefer, KDF: kdf})
	if err != nil {
		t.Fatalf("ChangeKeyslot(prefer) failed: %v", err)
	}
	if info.Priority != PriorityPrefer {
		t.Fatalf("ChangeKeyslot(prefer) returned %d", info.Priority)
	}
	assertOnDiskPriority(t, path, info.ID, intPtr(2))

	info, err = v.ChangeKeyslot(ctx, key, txnPassphrase(t, "normal again"), KeyslotParams{Priority: PriorityNormal, KDF: kdf})
	if err != nil {
		t.Fatalf("ChangeKeyslot(normal) failed: %v", err)
	}
	if info.Priority != PriorityNormal {
		t.Fatalf("ChangeKeyslot(normal) returned %d", info.Priority)
	}
	assertOnDiskPriority(t, path, info.ID, nil)
}

// TestVolumeKeyslotWritesRefuseAnUndeclaredPriority: a Priority outside the
// declared values is refused on every write path, never written.
func TestVolumeKeyslotWritesRefuseAnUndeclaredPriority(t *testing.T) {
	path := formattedVolumeImage(t, "priority-undeclared.img", "", "")
	v := txnVolume(t, path)
	key := txnKey(t, v)
	ctx := context.Background()

	for _, bad := range []Priority{-1, PriorityPrefer + 1} {
		p := KeyslotParams{Priority: bad, KDF: KDFParams{Type: KDFPBKDF2, IterTime: time.Millisecond}}
		if _, err := v.AddKeyslot(ctx, key, txnPassphrase(t, "bad add"), p); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("AddKeyslot(Priority %d) error = %v, want ErrInvalidArgument", bad, err)
		}
		if _, err := v.ChangeKeyslot(ctx, key, txnPassphrase(t, "bad change"), p); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("ChangeKeyslot(Priority %d) error = %v, want ErrInvalidArgument", bad, err)
		}
		rk, err := NewRecoveryKey()
		if err != nil {
			t.Fatalf("NewRecoveryKey failed: %v", err)
		}
		_, err = v.AddRecoveryKey(ctx, key, rk, KeyslotParams{Priority: bad, KDF: argon2TestKDF()})
		rk.Destroy()
		if !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("AddRecoveryKey(Priority %d) error = %v, want ErrInvalidArgument", bad, err)
		}
	}

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	if got := len(metadata.Keyslots); got != 1 {
		t.Fatalf("keyslots after refused writes: %d, want 1", got)
	}
	assertOnDiskPriority(t, path, key.Keyslot(), nil)
}

// assertOnDiskPriority reads the header from path and checks keyslot id's raw
// priority member: nil means it must be absent.
// TestVolumeUnlockScanHonoursPriority: Unlock tries a prefer keyslot before a
// normal one and never tries an ignore keyslot, as cryptsetup's any-slot open
// does; UnlockKeyslot still opens the ignore keyslot by name.
func TestVolumeUnlockScanHonoursPriority(t *testing.T) {
	defer parallel(t)()
	ctx := context.Background()
	kdf := KDFParams{Type: KDFPBKDF2, IterTime: time.Millisecond}

	t.Run("prefer before normal", func(t *testing.T) {
		path := formattedVolumeImage(t, "scan-prefer.img", "", "")
		v := txnVolume(t, path)
		key := txnKey(t, v)

		// The same passphrase as keyslot 0, so ascending id order alone would
		// stop at keyslot 0.
		same := newTestPassphrase(t)
		t.Cleanup(func() { _ = same.Destroy() })
		info, err := v.AddKeyslot(ctx, key, same, KeyslotParams{Priority: PriorityPrefer, KDF: kdf})
		if err != nil {
			t.Fatalf("AddKeyslot(prefer) failed: %v", err)
		}
		if info.ID == 0 {
			t.Fatal("the preferred keyslot is keyslot 0; the fixture cannot tell priority from id order")
		}
		got := txnKey(t, v)
		if got.Keyslot() != info.ID {
			t.Fatalf("Unlock opened keyslot %d, want the preferred keyslot %d", got.Keyslot(), info.ID)
		}
	})

	t.Run("ignore is skipped by the scan", func(t *testing.T) {
		path := formattedVolumeImage(t, "scan-ignore.img", "", "")
		v := txnVolume(t, path)
		key := txnKey(t, v)

		info, err := v.AddKeyslot(ctx, key, txnPassphrase(t, "an ignored slot"), KeyslotParams{Priority: PriorityIgnore, KDF: kdf})
		if err != nil {
			t.Fatalf("AddKeyslot(ignore) failed: %v", err)
		}
		if k, err := v.Unlock(ctx, txnPassphrase(t, "an ignored slot")); !errors.Is(err, ErrWrongKey) {
			if k != nil {
				k.Destroy()
			}
			t.Fatalf("Unlock with only an ignore keyslot's passphrase: error = %v, want ErrWrongKey", err)
		}
		k, err := v.UnlockKeyslot(ctx, info.ID, txnPassphrase(t, "an ignored slot"))
		if err != nil {
			t.Fatalf("UnlockKeyslot on the ignore keyslot failed: %v", err)
		}
		k.Destroy()
	})

	t.Run("only ignore keyslots", func(t *testing.T) {
		path := formattedVolumeImage(t, "scan-only-ignore.img", "", "")
		v := txnVolume(t, path)
		key := txnKey(t, v)

		info, err := v.ChangeKeyslot(ctx, key, txnPassphrase(t, "the only slot"), KeyslotParams{Priority: PriorityIgnore, KDF: kdf})
		if err != nil {
			t.Fatalf("ChangeKeyslot(ignore) failed: %v", err)
		}
		if k, err := v.Unlock(ctx, txnPassphrase(t, "the only slot")); !errors.Is(err, ErrNoKeyslots) {
			if k != nil {
				k.Destroy()
			}
			t.Fatalf("Unlock with every keyslot ignore: error = %v, want ErrNoKeyslots", err)
		}
		k, err := v.UnlockKeyslot(ctx, info.ID, txnPassphrase(t, "the only slot"))
		if err != nil {
			t.Fatalf("UnlockKeyslot on the ignore keyslot failed: %v", err)
		}
		k.Destroy()
	})
}

func assertOnDiskPriority(t *testing.T, path string, id int, want *int) {
	t.Helper()
	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	ks, ok := metadata.Keyslots[strconv.Itoa(id)]
	if !ok {
		t.Fatalf("keyslot %d missing on disk", id)
	}
	switch {
	case want == nil && ks.Priority != nil:
		t.Errorf("keyslot %d on-disk priority = %d, want no member", id, *ks.Priority)
	case want != nil && ks.Priority == nil:
		t.Errorf("keyslot %d has no on-disk priority, want %d", id, *want)
	case want != nil && *ks.Priority != *want:
		t.Errorf("keyslot %d on-disk priority = %d, want %d", id, *ks.Priority, *want)
	}
}
