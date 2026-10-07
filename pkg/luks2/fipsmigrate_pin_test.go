// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"context"
	"crypto/fips140"
	"os"
	"path/filepath"
	"testing"
)

// TestMigrateToFIPSWritesOnlyTheDeviceItLocked (#255): the import resolves the
// device path ONCE. A symlink re-pointed at another volume in the middle of
// the import -- after the lock, the header read and the medium checks, at the
// first key derivation -- must not receive a single byte, and the import must
// finish on the volume it locked.
//
// Not parallel: it substitutes the package's derivation seam.
func TestMigrateToFIPSWritesOnlyTheDeviceItLocked(t *testing.T) {
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	prefix, _, key := crashFixture(t, true)
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked.img")
	other := filepath.Join(dir, "other.img")
	placeImage(t, locked, prefix)
	placeImage(t, other, prefix)
	otherBefore := fileDigest(t, other)

	link := filepath.Join(dir, "device")
	if err := os.Symlink(locked, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	sys := relinkDuring(t, link, other)

	result, err := migrateToFIPSAt(context.Background(), link, migrationPassphrase, cheapMigration(), sys)
	if err != nil {
		t.Fatalf("MigrateToFIPS through a link re-pointed mid-import failed: %v", err)
	}
	if !result.Complete {
		t.Fatalf("the import is incomplete: %+v", result)
	}
	if fileDigest(t, other) != otherBefore {
		t.Fatal("the volume the link was re-pointed at was written to; the import did not stay on the device it locked")
	}

	assertFIPSReady(t, locked)
	if got := volumeKey(t, locked, migrationPassphrase); !bytes.Equal(got, key) {
		t.Fatal("the locked volume no longer opens to its key")
	}
}
