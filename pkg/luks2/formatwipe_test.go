// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// Format over an old volume wrote the new primary and then the new secondary
// over the old copies, which it never cleared. A crash between the two left
// the old secondary -- complete, valid, and at a higher sequence id than a
// fresh header's -- for a reader to choose over the new primary, or to find
// by probing when the new primary was torn: a header naming keyslots the
// format had already overwritten with random data. cryptsetup zeroes the
// header areas before it writes either copy (LUKS2_wipe_header_areas).
func TestFormatCrashAfterThePrimaryLeavesNoOldHeader(t *testing.T) {
	defer parallel(t)()
	errCrash := errors.New("the machine went down")
	for _, tc := range []struct {
		name string
		tear bool
	}{
		{name: "the new primary is durable"},
		{name: "the new primary is torn", tear: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := formattedVolumeImage(t, "reformat.img", "", "")
			// The old copies are one header write past a fresh format's.
			if err := setTokenForTest(path, 0, Token{Type: TokenTypeRecovery, Keyslots: []int{0}}); err != nil {
				t.Fatalf("SetToken: %v", err)
			}
			old, _, err := readHeaderForTest(path)
			if err != nil {
				t.Fatalf("ReadHeader: %v", err)
			}

			// The crash comes at the sync that makes the new primary durable,
			// before the secondary is written.
			sys := testVolumeSys()
			sys.syncDevice = func(f *os.File) error {
				primary, _, err := header.ReadHeaderCopyFrom(f, header.PrimaryHeaderOffset)
				if err != nil || primary.UUID == old.UUID {
					return f.Sync()
				}
				if tc.tear {
					if _, err := f.WriteAt([]byte("torn"), header.HeaderSize); err != nil {
						t.Fatal(err)
					}
				}
				return errCrash
			}
			v, err := Open(context.Background(), path, withTestSys(sys))
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer func() { _ = v.Close() }()
			pass := newTestPassphrase(t)
			defer func() { _ = pass.Destroy() }()
			if err := v.Format(context.Background(), pass, FormatParams{
				KDF: KDFParams{Type: KDFPBKDF2, IterTime: time.Millisecond},
			}); !errors.Is(err, errCrash) {
				t.Fatalf("Format: got %v, want the crash", err)
			}

			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			current, err := header.ReadCurrentHeader(f)
			switch {
			case tc.tear && err == nil:
				t.Fatalf("with the new primary torn, a reader chose the copy at %d (old UUID: %v), want no header",
					current.Offset, current.Header.UUID == old.UUID)
			case !tc.tear && err != nil:
				t.Fatalf("ReadCurrentHeader: %v", err)
			case !tc.tear && current.Header.UUID == old.UUID:
				t.Fatalf("a reader chose the old header at %d over the new primary", current.Offset)
			}
		})
	}
}
