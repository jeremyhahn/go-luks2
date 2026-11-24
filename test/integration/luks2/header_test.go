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

// TestHeaderWriteRead is a black-box round trip: Format writes the header and Header reads it back.
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

	pass, err := enclave.NewMemoryCopy([]byte("test-passphrase"))
	if err != nil {
		t.Fatalf("NewMemoryCopy failed: %v", err)
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
