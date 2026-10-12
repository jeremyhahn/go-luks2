// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/fips"
)

// TestVolumeFormatWritesAPBKDF2Container holds (*Volume).Format to a PBKDF2
// keyslot at the iteration floor: real temp file, real derivation, no
// cryptsetup required.
func TestVolumeFormatWritesAPBKDF2Container(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "volume-format-pbkdf2.img")
	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()

	ctx := context.Background()
	if err := v.Format(ctx, pass, FormatParams{
		KDF: KDFParams{Type: KDFPBKDF2, IterTime: 50 * time.Millisecond},
	}); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	kdf := metadata.Keyslots["0"].KDF
	if kdf.Type != kdfTypePBKDF2 || kdf.Hash != "sha256" {
		t.Fatalf("keyslot 0 KDF = %s/%s, want pbkdf2/sha256", kdf.Type, kdf.Hash)
	}
	if got := metadata.Digests["0"].Hash; got != "sha256" {
		t.Fatalf("digest hash = %q, want the default sha256", got)
	}

	key, err := v.Unlock(ctx, pass)
	if err != nil {
		t.Fatalf("Unlock after Format failed: %v", err)
	}
	defer key.Destroy()
	if got := key.Size(); got != DefaultKeySize/8 {
		t.Errorf("key size = %d, want %d", got, DefaultKeySize/8)
	}
}

// TestVolumeFormatWritesAnArgon2idContainer: a zero KDFParams outside FIPS
// mode is Argon2id, at the lane's floor cost (m=64MiB, t=1, p=1). The
// Volume's sys is out of FIPS mode whatever the process is, so this runs in
// a FIPS process too: Format and Unlock derive under the Volume's own mode.
func TestVolumeFormatWritesAnArgon2idContainer(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "volume-format-argon2.img")
	sys := testVolumeSys()
	sys.fipsMode = func() fips.Mode { return false }
	v, err := Open(context.Background(), path, withTestSys(sys))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()

	ctx := context.Background()
	if err := v.Format(ctx, pass, FormatParams{
		KDF: KDFParams{Time: 1, MemoryKiB: minArgon2MemoryKB, Parallel: 1},
	}); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	if got := metadata.Keyslots["0"].KDF.Type; got != kdfTypeArgon2id {
		t.Fatalf("keyslot 0 KDF type = %q, want %q", got, kdfTypeArgon2id)
	}

	key, err := v.Unlock(ctx, pass)
	if err != nil {
		t.Fatalf("Unlock after Format failed: %v", err)
	}
	key.Destroy()
}

// TestVolumeFormatAppliesItsDefaults: a zero FormatParams (beyond the KDF,
// forced to PBKDF2 at the floor so the test stays cheap) writes
// DefaultCipher, DefaultKeySize, DefaultHash and DefaultSectorSize.
func TestVolumeFormatAppliesItsDefaults(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "volume-format-defaults.img")
	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()

	if err := v.Format(context.Background(), pass, FormatParams{
		KDF: KDFParams{Type: KDFPBKDF2, IterTime: 50 * time.Millisecond},
	}); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	segment := metadata.Segments["0"]
	if segment.Encryption != DefaultCipher {
		t.Errorf("segment encryption = %q, want the default %q", segment.Encryption, DefaultCipher)
	}
	if segment.SectorSize != DefaultSectorSize {
		t.Errorf("segment sector size = %d, want the default %d", segment.SectorSize, DefaultSectorSize)
	}
	if got := metadata.Digests["0"].Hash; got != "sha256" {
		t.Errorf("digest hash = %q, want the default (DefaultHash) sha256", got)
	}
	if got := metadata.Keyslots["0"].KeySize * 8; got != DefaultKeySize {
		t.Errorf("key size = %d bits, want the default %d", got, DefaultKeySize)
	}
}

// TestVolumeFormatRefusesArgon2InFIPSMode: KDFParams.Validate's FIPS
// approval check reaches (*Volume).Format before anything
// is claimed or written.
func TestVolumeFormatRefusesArgon2InFIPSMode(t *testing.T) {
	sys := testVolumeSys()
	sys.fipsMode = forceFIPSPolicy(t)

	path := newImage(t, "volume-format-fips.img")
	before := readAreaBytes(t, path, 0, goldenPrefixBytes)

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()), withTestSys(sys))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()

	err = v.Format(context.Background(), pass, FormatParams{
		KDF: KDFParams{Time: 1, MemoryKiB: minArgon2MemoryKB, Parallel: 1},
	})
	if !errors.Is(err, ErrFIPSNotApproved) {
		t.Fatalf("Format with an Argon2 cost under the FIPS policy = %v, want ErrFIPSNotApproved", err)
	}
	if !bytes.Equal(before, readAreaBytes(t, path, 0, goldenPrefixBytes)) {
		t.Fatal("the refused Format wrote to the device")
	}
}

// TestVolumeFormatRefusesAnUnsupportedCipherBeforeTouchingTheDevice: an
// invalid cipher/key-size combination is refused by FormatParams.Validate
// before the device is locked or claimed.
func TestVolumeFormatRefusesAnUnsupportedCipherBeforeTouchingTheDevice(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "volume-format-badcipher.img")
	before := readAreaBytes(t, path, 0, goldenPrefixBytes)

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()

	err = v.Format(context.Background(), pass, FormatParams{Cipher: "aes-cbc-essiv:sha256", KeySize: 512})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Format with an unsupported cipher/key-size = %v, want ErrUnsupported", err)
	}
	if !bytes.Equal(before, readAreaBytes(t, path, 0, goldenPrefixBytes)) {
		t.Fatal("the refused Format wrote to the device")
	}
}

// TestVolumeFormatEnforcesThePassphrasePolicyBeforeTouchingTheDevice: the
// passphrase a container is formatted with is held to
// MinPassphraseLength..MaxPassphraseLength, as the pre-redesign Format held it.
func TestVolumeFormatEnforcesThePassphrasePolicyBeforeTouchingTheDevice(t *testing.T) {
	defer parallel(t)()

	for name, length := range map[string]int{
		"too long":  MaxPassphraseLength + 1,
		"too short": MinPassphraseLength - 1,
	} {
		t.Run(name, func(t *testing.T) {
			path := newImage(t, "volume-format-passphrase.img")
			before := readAreaBytes(t, path, 0, goldenPrefixBytes)

			v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}
			defer func() { _ = v.Close() }()

			pass, err := enclave.NewMemoryEnclaveCopy(bytes.Repeat([]byte("p"), length))
			if err != nil {
				t.Fatalf("NewMemoryEnclaveCopy failed: %v", err)
			}
			defer func() { _ = pass.Destroy() }()

			err = v.Format(context.Background(), pass, FormatParams{
				KDF: KDFParams{Type: KDFPBKDF2, IterTime: time.Millisecond},
			})
			if !errors.Is(err, ErrInvalidCredential) {
				t.Fatalf("Format with a %d-byte passphrase = %v, want ErrInvalidCredential", length, err)
			}
			if !bytes.Equal(before, readAreaBytes(t, path, 0, goldenPrefixBytes)) {
				t.Fatal("the refused Format wrote to the device")
			}
		})
	}
}

func TestVolumeFormatOnAClosedVolumeFailsWithErrClosed(t *testing.T) {
	path := newImage(t, "volume-format-closed.img")
	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if err := v.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()

	if err := v.Format(context.Background(), pass, FormatParams{}); !errors.Is(err, ErrClosed) {
		t.Errorf("Format on a closed Volume = %v, want ErrClosed", err)
	}
}

func TestVolumeFormatOnAReadOnlyVolumeFailsWithErrReadOnly(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "volume-format-readonly.img")
	before := readAreaBytes(t, path, 0, goldenPrefixBytes)

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()), WithReadOnly())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()

	if err := v.Format(context.Background(), pass, FormatParams{}); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Format on a read-only Volume = %v, want ErrReadOnly", err)
	}
	if !bytes.Equal(before, readAreaBytes(t, path, 0, goldenPrefixBytes)) {
		t.Fatal("Format on a read-only Volume wrote to the device")
	}
}

// TestVolumeFormatRefusesAnAlreadyCanceledContext: no lock is taken and
// nothing is written for a context that is already done.
func TestVolumeFormatRefusesAnAlreadyCanceledContext(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "volume-format-canceled.img")
	before := readAreaBytes(t, path, 0, goldenPrefixBytes)

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = v.Format(ctx, pass, FormatParams{KDF: KDFParams{Type: KDFPBKDF2, IterTime: 50 * time.Millisecond}})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Format(canceled ctx) = %v, want context.Canceled", err)
	}
	if !bytes.Equal(before, readAreaBytes(t, path, 0, goldenPrefixBytes)) {
		t.Fatal("Format with a canceled context wrote to the device")
	}
}
