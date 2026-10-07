// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// TestHeaderWriteRead is a black-box round trip through the public API:
// Format writes the header this package used to assemble by hand from
// internal/header types (luks2.KDF, luks2.LUKS2Metadata, luks2.Keyslot,
// luks2.AntiForensic, luks2.KeyslotArea -- all DELETE/UNEXPORT in B.6), and
// Header reads it back, in place of luks2.CreateBinaryHeader/WriteHeader and
// harness.ReadHeader.
func TestHeaderWriteRead(t *testing.T) {
	tmpfile := "/tmp/test-luks-header.bin"
	defer os.Remove(tmpfile)

	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	if err := f.Truncate(64 << 20); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate file: %v", err)
	}
	f.Close()

	ctx := context.Background()
	v, err := luks2.Open(ctx, tmpfile)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryEnclaveCopy([]byte("test-passphrase"))
	if err != nil {
		t.Fatalf("NewMemoryEnclaveCopy failed: %v", err)
	}
	defer func() { _ = pass.Destroy() }()

	if err := v.Format(ctx, pass, luks2.FormatParams{
		Label: "TestVolume",
		KDF:   luks2.KDFParams{Type: luks2.KDFPBKDF2, IterTime: 50 * time.Millisecond},
	}); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	hdr, err := v.Header(ctx)
	if err != nil {
		t.Fatalf("Header failed: %v", err)
	}
	t.Logf("Header read successfully: UUID=%s Label=%s", hdr.UUID(), hdr.Label())
}
