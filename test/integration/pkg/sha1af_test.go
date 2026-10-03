// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package pkg_test

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// SHA-1 anti-forensic volumes on the real kernel (#236).
//
// pkg/luks2 proves, on file images, that this library recovers the same
// volume key as cryptsetup from a SHA-1 AF keyslot. This tier proves the
// DATA: plaintext written through cryptsetup's own mapping of such a volume is
// read back through a mapping luks2.Unlock made, before and after the volume
// is imported for FIPS mode; a process under GODEBUG=fips140=only refuses the
// volume naming SHA-1 until it is imported, and maps it after; cryptsetup maps
// it throughout; and the ciphertext never changes.

// TestSHA1AFVolumesMapTheSameDataOnTheKernel runs that sequence for both
// shapes #236 names: a LUKS2 volume formatted with --hash sha1 at cryptsetup's
// defaults otherwise, and a LUKS1 volume converted to LUKS2.
func TestSHA1AFVolumesMapTheSameDataOnTheKernel(t *testing.T) {
	for _, tc := range []struct {
		name   string
		format func(t *testing.T, image string)
	}{
		{"luks2 --hash sha1", func(t *testing.T, image string) {
			cryptsetupWithPassphrase(t, "luksFormat", "--type", "luks2", "--hash", "sha1", "--batch-mode", image)
		}},
		{"luks1 converted", func(t *testing.T, image string) {
			cryptsetupWithPassphrase(t, "luksFormat", "--type", "luks1", "--hash", "sha1", "--batch-mode", image)
			run(t, "cryptsetup", "convert", "--type", "luks2", "--batch-mode", image)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			image := filepath.Join(t.TempDir(), "sha1-af.img")
			if err := createTestFile(image, 64); err != nil {
				t.Fatalf("creating the image failed: %v", err)
			}
			tc.format(t, image)

			loopDev, err := luks2.SetupLoopDevice(image)
			if err != nil {
				t.Fatalf("SetupLoopDevice failed: %v", err)
			}
			t.Cleanup(func() {
				if err := luks2.DetachLoopDevice(loopDev); err != nil {
					t.Errorf("DetachLoopDevice(%s): %v", loopDev, err)
				}
			})

			_, metadata, err := luks2.ReadHeader(loopDev)
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}
			if ks := metadata.Keyslots["0"]; ks == nil || ks.AF == nil || ks.AF.Hash != "sha1" {
				t.Fatalf("cryptsetup's keyslot 0 is %+v, want an anti-forensic hash of sha1; the test would measure nothing", ks)
			}
			var dataOffset int64
			if _, err := fmt.Sscan(metadata.Segments["0"].Offset, &dataOffset); err != nil {
				t.Fatalf("segment offset %q: %v", metadata.Segments["0"].Offset, err)
			}

			// Plaintext, written through cryptsetup's own mapping.
			plaintext := newFIPSPlaintext(t)
			csWrite := runVolume(t, "sha1af-cs-write")
			defer releaseVolume(t, csWrite)
			cryptsetupWithPassphrase(t, "open", "--type", "luks2", loopDev, csWrite)
			plaintext.write(t, csWrite)
			lockWithRetry(t, csWrite)
			ciphertext := ciphertextDigest(t, loopDev, dataOffset)

			// This library maps it outside FIPS mode, through the SHA-1 merge.
			ours := runVolume(t, "sha1af-library")
			defer releaseVolume(t, ours)
			if err := luks2.Unlock(loopDev, []byte(fipsImportPassphrase), ours); err != nil {
				t.Fatalf("Unlock of the SHA-1 AF volume failed: %v", err)
			}
			plaintext.assertReads(t, ours, "this library, through the SHA-1 anti-forensic merge")
			lockWithRetry(t, ours)

			// A FIPS process refuses it, naming SHA-1, and maps nothing.
			fipsBefore := runVolume(t, "sha1af-fips-before")
			defer releaseVolume(t, fipsBefore)
			code, out := unlockInFIPSProcess(t, loopDev, fipsBefore)
			if code != fipsChildImportRequired || !strings.Contains(out, "anti-forensic hash sha1") {
				t.Fatalf("FIPS unlock of the SHA-1 AF volume exited %d, want %d naming the SHA-1 anti-forensic hash\n%s",
					code, fipsChildImportRequired, out)
			}
			if luks2.IsUnlocked(fipsBefore) {
				t.Fatal("the refused FIPS unlock left a mapping")
			}

			// The import, in this non-FIPS process, with the defaults.
			result, err := luks2.MigrateToFIPS(loopDev, []byte(fipsImportPassphrase), nil)
			if err != nil {
				t.Fatalf("MigrateToFIPS failed: %v", err)
			}
			if !result.Complete || !result.KeyslotAdded {
				t.Fatalf("migration result %+v, want complete with a keyslot added", result)
			}
			if ciphertextDigest(t, loopDev, dataOffset) != ciphertext {
				t.Fatal("the import changed the encrypted data; it must never re-encrypt")
			}
			_, metadata, err = luks2.ReadHeader(loopDev)
			if err != nil {
				t.Fatalf("ReadHeader after the import failed: %v", err)
			}
			for id, ks := range metadata.Keyslots {
				if ks.AF == nil || ks.AF.Hash == "sha1" || ks.KDF == nil || ks.KDF.Hash == "sha1" {
					t.Fatalf("keyslot %s after the import is %+v / %+v, want no SHA-1", id, ks.AF, ks.KDF)
				}
			}

			// A strict FIPS process maps it, and the kernel decrypts the plaintext.
			fipsAfter := runVolume(t, "sha1af-fips-after")
			defer releaseVolume(t, fipsAfter)
			if code, out := unlockInFIPSProcess(t, loopDev, fipsAfter); code != fipsChildOK {
				t.Fatalf("FIPS unlock of the imported volume exited %d\n%s", code, out)
			}
			plaintext.assertReads(t, fipsAfter, "a process under GODEBUG=fips140=only")
			lockWithRetry(t, fipsAfter)

			// And so does cryptsetup.
			csRead := runVolume(t, "sha1af-cs-read")
			defer releaseVolume(t, csRead)
			cryptsetupWithPassphrase(t, "open", "--type", "luks2", loopDev, csRead)
			plaintext.assertReads(t, csRead, "cryptsetup")
			lockWithRetry(t, csRead)
		})
	}
}
