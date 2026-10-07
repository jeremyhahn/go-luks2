// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package header

import (
	"errors"
	"os"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// containerAt writes a complete container -- both copies -- at sequence id
// seq, carrying label, and returns the open file.
func containerAt(t *testing.T, seq uint64, label string) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "current-*.img")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := f.Truncate(1 << 20); err != nil {
		t.Fatal(err)
	}
	hdr := newBinaryHeader(t)
	hdr.SequenceID = seq
	clear(hdr.Label[:])
	copy(hdr.Label[:], label)
	if err := WriteHeaderTo(f, hdr, metadataWithOneKeyslot(), zeroSync); err != nil {
		t.Fatalf("WriteHeaderTo: %v", err)
	}
	return f
}

// copyRegion copies n bytes at offset from src over dst: one header copy of a
// container written at another sequence id.
func copyRegion(t *testing.T, dst, src *os.File, offset int64, n int) {
	t.Helper()
	buf := make([]byte, n)
	if _, err := src.ReadAt(buf, offset); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.WriteAt(buf, offset); err != nil {
		t.Fatal(err)
	}
}

// tear overwrites a byte inside the JSON area of the copy at offset, so its
// checksum no longer matches: a header write interrupted part way.
func tear(t *testing.T, f *os.File, offset int64) {
	t.Helper()
	if _, err := f.WriteAt([]byte("torn"), offset+HeaderSize+10); err != nil {
		t.Fatal(err)
	}
}

// TestReadCurrentHeaderChoosesTheValidCopyWithTheHigherSequenceID is
// cryptsetup's LUKS2_disk_hdr_read: a copy failing magic, checksum or JSON
// validation is dropped, the valid copy with the higher seqid is used, and the
// primary wins a tie.
func TestReadCurrentHeaderChoosesTheValidCopyWithTheHigherSequenceID(t *testing.T) {
	const area = HeaderMinSize

	cases := []struct {
		name       string
		build      func(t *testing.T) *os.File
		wantOffset int64
		wantSeq    uint64
		wantLabel  string
		wantStale  bool
	}{
		{
			name:       "both copies agree",
			build:      func(t *testing.T) *os.File { return containerAt(t, 3, "current") },
			wantOffset: PrimaryHeaderOffset, wantSeq: 3, wantLabel: "current",
		},
		{
			name: "the primary is torn",
			build: func(t *testing.T) *os.File {
				f := containerAt(t, 3, "current")
				tear(t, f, PrimaryHeaderOffset)
				return f
			},
			wantOffset: area, wantSeq: 3, wantLabel: "current", wantStale: true,
		},
		{
			name: "the primary has no magic",
			build: func(t *testing.T) *os.File {
				f := containerAt(t, 3, "current")
				if _, err := f.WriteAt(make([]byte, HeaderSize), PrimaryHeaderOffset); err != nil {
					t.Fatal(err)
				}
				return f
			},
			wantOffset: area, wantSeq: 3, wantLabel: "current", wantStale: true,
		},
		{
			name: "the secondary is torn",
			build: func(t *testing.T) *os.File {
				f := containerAt(t, 3, "current")
				tear(t, f, area)
				return f
			},
			wantOffset: PrimaryHeaderOffset, wantSeq: 3, wantLabel: "current", wantStale: true,
		},
		{
			name: "the secondary is newer",
			build: func(t *testing.T) *os.File {
				f := containerAt(t, 3, "older")
				copyRegion(t, f, containerAt(t, 4, "newer"), area, area)
				return f
			},
			wantOffset: area, wantSeq: 4, wantLabel: "newer", wantStale: true,
		},
		{
			name: "the primary is newer",
			build: func(t *testing.T) *os.File {
				f := containerAt(t, 3, "older")
				copyRegion(t, f, containerAt(t, 4, "newer"), PrimaryHeaderOffset, area)
				return f
			},
			wantOffset: PrimaryHeaderOffset, wantSeq: 4, wantLabel: "newer", wantStale: true,
		},
		{
			// cryptsetup compares sequence ids only; at a tie the primary is used.
			name: "equal sequence ids with different content",
			build: func(t *testing.T) *os.File {
				f := containerAt(t, 3, "primary")
				copyRegion(t, f, containerAt(t, 3, "secondary"), area, area)
				return f
			},
			wantOffset: PrimaryHeaderOffset, wantSeq: 3, wantLabel: "primary",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReadCurrentHeader(tc.build(t))
			if err != nil {
				t.Fatalf("ReadCurrentHeader: %v", err)
			}
			if got.Offset != tc.wantOffset || got.Header.SequenceID != tc.wantSeq || got.Stale != tc.wantStale {
				t.Fatalf("chose offset %d at sequence %d (stale other copy: %v), want offset %d at %d (stale: %v)",
					got.Offset, got.Header.SequenceID, got.Stale, tc.wantOffset, tc.wantSeq, tc.wantStale)
			}
			if label := trimNUL(got.Header.Label[:]); label != tc.wantLabel {
				t.Fatalf("label %q, want %q", label, tc.wantLabel)
			}
			if got.Metadata == nil || len(got.Metadata.Keyslots) != 1 {
				t.Fatalf("metadata %+v, want the copy's one keyslot", got.Metadata)
			}
		})
	}
}

// TestReadCurrentHeaderRefusesWhenNeitherCopyIsValid: with no valid copy the
// read fails with the primary's error, so a device that is not LUKS2 at all
// still says so.
func TestReadCurrentHeaderRefusesWhenNeitherCopyIsValid(t *testing.T) {
	t.Run("both copies are torn", func(t *testing.T) {
		f := containerAt(t, 3, "current")
		tear(t, f, PrimaryHeaderOffset)
		tear(t, f, HeaderMinSize)
		if _, err := ReadCurrentHeader(f); !errors.Is(err, errs.ErrInvalidHeader) {
			t.Fatalf("got %v, want ErrInvalidHeader", err)
		}
	})

	t.Run("the device holds no header", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "blank-*.img")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		if err := f.Truncate(1 << 20); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadCurrentHeader(f); !errors.Is(err, errs.ErrInvalidHeader) {
			t.Fatalf("got %v, want ErrInvalidHeader", err)
		}
	})

	// A primary with the LUKS magic and another version is a LUKS1 (or a
	// future) container, not a damaged LUKS2 one: cryptsetup dispatches on the
	// primary's version before it reads either LUKS2 copy, so the secondary is
	// not consulted.
	t.Run("the primary is another LUKS version", func(t *testing.T) {
		f := containerAt(t, 3, "current")
		if _, err := f.WriteAt([]byte{0x00, 0x01}, 6); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadCurrentHeader(f); !errors.Is(err, ErrUnsupportedLUKSVersion) {
			t.Fatalf("got %v, want ErrUnsupportedLUKSVersion", err)
		}
	})
}

func trimNUL(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
