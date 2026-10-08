// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
	"os"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// csumAlgFieldOffset is where the 32-byte csum_alg field sits in a LUKS2
// binary header: magic(6), version(2), hdr_size(8), seqid(8), label(48).
const csumAlgFieldOffset = 72

// restampHeaderChecksum rewrites the csum_alg field of the primary header in
// path to claimed and the checksum to sum over the area, so a test can build a
// header whose checksum is internally consistent with whatever algorithm it
// chooses.
func restampHeaderChecksum(t *testing.T, path string, claimed []byte, sum func() hash.Hash) {
	t.Helper()

	f, err := os.OpenFile(path, os.O_RDWR, 0) // #nosec G304 -- a fixture under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	head := make([]byte, 16)
	if _, err := f.ReadAt(head, 0); err != nil {
		t.Fatal(err)
	}
	area := make([]byte, binary.BigEndian.Uint64(head[8:16]))
	if _, err := f.ReadAt(area, 0); err != nil {
		t.Fatal(err)
	}

	field := area[csumAlgFieldOffset : csumAlgFieldOffset+32]
	clear(field)
	copy(field, claimed)
	clear(area[header.ChecksumFieldOffset : header.ChecksumFieldOffset+64])
	h := sum()
	h.Write(area)
	copy(area[header.ChecksumFieldOffset:], h.Sum(nil))

	if _, err := f.WriteAt(area, 0); err != nil {
		t.Fatal(err)
	}
}

// TestReadHeaderRefusesAChecksumAlgorithmOtherThanSHA256: the binary header's
// csum_alg field is honored. It used to be ignored and sha256 computed
// regardless, so a header CLAIMING sha1 over a sha256 checksum read cleanly
// here while cryptsetup, which verifies with the named algorithm, refused it.
// sha256 is the only algorithm cryptsetup writes, and the only one accepted.
func TestReadHeaderRefusesAChecksumAlgorithmOtherThanSHA256(t *testing.T) {
	defer parallel(t)()

	tests := []struct {
		name    string
		claimed string
		sum     func() hash.Hash
		accept  bool
	}{
		{name: "sha256 as Format writes it", claimed: "sha256", sum: sha256.New, accept: true},
		{name: "sha256 with bytes after its terminator", claimed: "sha256\x00junk", sum: sha256.New, accept: true},
		{name: "claims sha1 over a sha256 checksum", claimed: "sha1", sum: sha256.New},
		{name: "a consistent sha512 header", claimed: "sha512", sum: sha512.New},
		{name: "a consistent sha384 header", claimed: "sha384", sum: sha512.New384},
		{name: "upper case", claimed: "SHA256", sum: sha256.New},
		{name: "empty", claimed: "", sum: sha256.New},
	}

	for _, tt := range tests {
		path := tokenIDVolume(t, "csum.img")
		restampHeaderChecksum(t, path, []byte(tt.claimed), tt.sum)

		_, _, err := readHeaderForTest(path)
		if tt.accept {
			if err != nil {
				t.Errorf("%s: ReadHeader = %v, want the header accepted", tt.name, err)
			}
			continue
		}
		if !errors.Is(err, ErrUnsupported) || !errors.Is(err, ErrInvalidHeader) {
			t.Errorf("%s: ReadHeader = %v, want ErrUnsupported and ErrInvalidHeader", tt.name, err)
		}
	}
}
