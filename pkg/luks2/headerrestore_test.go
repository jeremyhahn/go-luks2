// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"errors"
	"math"
	"os"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// RestorePrimaryHeader used to copy the secondary over the primary whatever
// either held (#248, B3). Header writes put the primary on the medium first, so
// an interrupted ChangeKey or RemoveKey can leave a NEWER primary -- the
// passphrase already revoked -- over an OLDER secondary that still lists it,
// and "restoring" that secondary brought the revoked passphrase back.

// writeBytesAt overwrites len(data) bytes of path at offset.
func writeBytesAt(t *testing.T, path string, offset int64, data []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteAt(data, offset); err != nil {
		t.Fatalf("write %d bytes at %d: %v", len(data), offset, err)
	}
}

// staleCopyVolume returns a container whose copy at staleOffset is one header
// write behind the other: a token was imported after the stale copy was saved.
func staleCopyVolume(t *testing.T, name string, staleOffset int64) string {
	t.Helper()
	path := newImage(t, name)
	formatWithLibrary(t, path)
	stale := readAreaBytes(t, path, staleOffset, header.HeaderMinSize)
	if err := setTokenForTest(path, 0, Token{Type: TokenTypeRecovery, Keyslots: []int{0}}); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	writeBytesAt(t, path, staleOffset, stale)
	return path
}

func TestRestorePrimaryHeaderDoesNotRollBackACurrentPrimary(t *testing.T) {
	defer parallel(t)()

	t.Run("the primary is newer", func(t *testing.T) {
		path := staleCopyVolume(t, "restore-newer-primary.img", header.HeaderMinSize)
		primary, _, err := readHeaderForTest(path)
		if err != nil {
			t.Fatalf("ReadHeader: %v", err)
		}
		before := readAreaBytes(t, path, 0, 2*header.HeaderMinSize)

		if err := restorePrimaryHeaderForTest(path); !errors.Is(err, ErrPrimaryHeaderCurrent) {
			t.Fatalf("RestorePrimaryHeader over a newer primary: got %v, want ErrPrimaryHeaderCurrent", err)
		}
		if !bytes.Equal(before, readAreaBytes(t, path, 0, 2*header.HeaderMinSize)) {
			t.Fatal("a refused restore changed the header")
		}

		// Forced, it rolls back -- and says so with a sequence id above both.
		if err := replacePrimaryHeaderForTest(path); err != nil {
			t.Fatalf("a forced restore: %v", err)
		}
		hdr, metadata, err := readHeaderForTest(path)
		if err != nil {
			t.Fatalf("ReadHeader after a forced restore: %v", err)
		}
		if hdr.SequenceID != primary.SequenceID+1 || len(metadata.Tokens) != 0 {
			t.Fatalf("after a forced restore: sequence %d with %d tokens, want %d with the secondary's none",
				hdr.SequenceID, len(metadata.Tokens), primary.SequenceID+1)
		}
	})

	t.Run("both copies are the same generation", func(t *testing.T) {
		path := newImage(t, "restore-same.img")
		formatWithLibrary(t, path)
		if err := restorePrimaryHeaderForTest(path); !errors.Is(err, ErrPrimaryHeaderCurrent) {
			t.Fatalf("RestorePrimaryHeader on an intact container: got %v, want ErrPrimaryHeaderCurrent", err)
		}
	})

	t.Run("the secondary is newer", func(t *testing.T) {
		path := staleCopyVolume(t, "restore-newer-secondary.img", 0)
		secondary, _, err := readSecondaryHeaderForTest(path)
		if err != nil {
			t.Fatalf("ReadSecondaryHeader: %v", err)
		}
		if err := restorePrimaryHeaderForTest(path); err != nil {
			t.Fatalf("RestorePrimaryHeader from a newer secondary: %v", err)
		}
		hdr, metadata, err := readHeaderForTest(path)
		if err != nil || hdr.SequenceID != secondary.SequenceID+1 || len(metadata.Tokens) != 1 {
			t.Fatalf("after the restore: %+v, %v; want the secondary's token at sequence %d", hdr, err, secondary.SequenceID+1)
		}
	})

	t.Run("the primary is torn", func(t *testing.T) {
		path := newImage(t, "restore-torn.img")
		formatWithLibrary(t, path)
		secondary, _, err := readSecondaryHeaderForTest(path)
		if err != nil {
			t.Fatalf("ReadSecondaryHeader: %v", err)
		}
		writeBytesAt(t, path, header.HeaderSize, []byte("torn"))
		if err := restorePrimaryHeaderForTest(path); err != nil {
			t.Fatalf("RestorePrimaryHeader over a torn primary: %v", err)
		}
		hdr, _, err := readHeaderForTest(path)
		if err != nil || hdr.SequenceID != secondary.SequenceID+1 {
			t.Fatalf("after the restore: %+v, %v; want sequence %d", hdr, err, secondary.SequenceID+1)
		}
	})

	t.Run("the secondary carries a damaged token", func(t *testing.T) {
		// A per-entry fault the reader tolerates does not stop the repair: the
		// restore reproduces the copy on the medium, damage and all.
		path := newImage(t, "restore-damaged-entry.img")
		formatWithLibrary(t, path)
		hdr, metadata, err := readHeaderForTest(path)
		if err != nil {
			t.Fatalf("ReadHeader: %v", err)
		}
		metadata.Tokens["0"] = &LegacyToken{Type: TokenTypeRecovery, Keyslots: []string{"7"}}
		if err := writeHeaderUnvalidated(path, hdr, metadata); err != nil {
			t.Fatalf("writeHeaderUnvalidated: %v", err)
		}
		writeBytesAt(t, path, header.HeaderSize, []byte("torn"))
		if err := restorePrimaryHeaderForTest(path); err != nil {
			t.Fatalf("RestorePrimaryHeader from a secondary with a damaged token: %v", err)
		}
		if _, restored, err := readHeaderForTest(path); err != nil || len(restored.Tokens) != 1 {
			t.Fatalf("after the restore: %v, %v; want the secondary's token back", restored, err)
		}
	})

	t.Run("the sequence id cannot advance", func(t *testing.T) {
		path := newImage(t, "restore-max.img")
		formatWithLibrary(t, path)
		hdr, metadata, err := readHeaderForTest(path)
		if err != nil {
			t.Fatalf("ReadHeader: %v", err)
		}
		hdr.SequenceID = math.MaxUint64
		if err := writeHeaderInternal(path, hdr, metadata); err != nil {
			t.Fatalf("writeHeaderInternal: %v", err)
		}
		writeBytesAt(t, path, header.HeaderSize, []byte("torn"))
		if err := restorePrimaryHeaderForTest(path); !errors.Is(err, ErrInvalidHeader) {
			t.Fatalf("RestorePrimaryHeader at the maximum sequence id: got %v, want ErrInvalidHeader", err)
		}
	})
}
