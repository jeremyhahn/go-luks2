// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// readRecorder is a device that fails the test if a byte of it is read.
type readRecorder struct {
	t     *testing.T
	reads int
}

func (r *readRecorder) ReadAt(p []byte, off int64) (int, error) {
	r.reads++
	r.t.Errorf("the scan read %d bytes at %d of a keyslot it must never try", len(p), off)
	return 0, errors.New("read refused by the test")
}

// A hostile header may declare luks2 keyslots at ids no LUKS2 implementation
// addresses: 32 and above, a negative id, a non-canonical spelling. The
// unlock scan never tries one (no read of its area, no derivation), and a
// header holding only such keyslots offers no way in: ErrNoKeyslots, not a
// credential verdict.
func TestUnlockScanNeverTriesAKeyslotOutsideZeroToThirtyOne(t *testing.T) {
	ids := []string{"32", "40", "-1", "01"}
	metadata := &header.Metadata{Keyslots: map[string]*header.Keyslot{}}
	for _, id := range ids {
		metadata.Keyslots[id] = &header.Keyslot{Type: "luks2", KeySize: 64}
	}
	dev := &readRecorder{t: t}

	_, _, err := getMasterKeySlot(context.Background(), dev, "test.img", []byte("passphrase"), metadata, ids, testVolumeSys())
	if !errors.Is(err, ErrNoKeyslots) {
		t.Fatalf("getMasterKeySlot = %v, want ErrNoKeyslots", err)
	}
	if errors.Is(err, ErrWrongKey) {
		t.Fatalf("getMasterKeySlot = %v: a keyslot that was never tried gave a credential verdict", err)
	}
	if dev.reads != 0 {
		t.Fatalf("the scan read the device %d times", dev.reads)
	}
}

// The listing agrees with the scan: a keyslot at an id outside 0-31 is not
// listed, so (*Header).Keyslots never reports a slot that cannot be opened.
func TestListKeyslotsOmitsIDsOutsideZeroToThirtyOne(t *testing.T) {
	metadata := &header.Metadata{Keyslots: map[string]*header.Keyslot{}}
	for _, id := range []string{"31", "32", "40", "-1", "01"} {
		metadata.Keyslots[id] = &header.Keyslot{Type: "luks2", KeySize: 64}
	}
	slots, _ := listKeyslotsFrom(metadata)
	if len(slots) != 1 || slots[0].ID != MaxKeyslots-1 {
		t.Fatalf("listKeyslotsFrom listed %+v, want only keyslot %d", slots, MaxKeyslots-1)
	}
}
