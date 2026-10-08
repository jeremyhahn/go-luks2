// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package interop_test

import (
	"bytes"
	"context"
	"crypto/fips140"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-luks2/pkg/dmcrypt"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/jeremyhahn/go-luks2/test/internal/harness"
)

// The FIPS import (#84) against the real kernel.
//
// pkg/luks2 proves the migration at the header level on file images: what
// cryptsetup and a strict FIPS process recover from the migrated header. What
// only this tier can prove is the DATA: that a default `cryptsetup luksFormat`
// volume holding plaintext written through dm-crypt is, after MigrateToFIPS,
// mapped by a process running under GODEBUG=fips140=only to the same
// plaintext -- through device-mapper, with the key Unlock actually hands the
// kernel -- and that cryptsetup still maps it to the same plaintext too. A
// header that verifies but feeds dm-crypt the wrong key would pass every
// header-level check and fail here.
//
// FIPS mode is fixed when a process starts, so the FIPS open runs in a
// re-execution of this test binary with GODEBUG set for it, and reports the
// mode it actually ran in.

const (
	fipsChildRoleEnv   = "GO_LUKS2_ITEST_FIPS_ROLE"
	fipsChildDeviceEnv = "GO_LUKS2_ITEST_FIPS_DEVICE"
	fipsChildVolumeEnv = "GO_LUKS2_ITEST_FIPS_VOLUME"

	fipsChildRoleUnlock = "unlock"
	// fipsChildRoleStandIn runs the unlock role's whole path with
	// standInActivate in place of dmcrypt.Activate, so it needs no root.
	fipsChildRoleStandIn = "unlock-stand-in"

	fipsChildOK             = 0
	fipsChildImportRequired = 10
	fipsChildFailed         = 12

	fipsImportPassphrase = "fips-import-integration-passphrase"
)

// A child is recognized before TestMain, so it never registers a second suite
// with the harness; it performs one unlock and exits.
func init() {
	if role := os.Getenv(fipsChildRoleEnv); role != "" {
		os.Exit(runFIPSChild(role, os.Getenv(fipsChildDeviceEnv), os.Getenv(fipsChildVolumeEnv)))
	}
}

func runFIPSChild(role, device, volume string) int {
	fmt.Printf("fips140.Enabled=%v\n", fips140.Enabled())
	var activate activator
	switch role {
	case fipsChildRoleUnlock:
		activate = dmcrypt.Activate
	case fipsChildRoleStandIn:
		activate = standInActivate
	default:
		fmt.Printf("unknown role %q\n", role)
		return fipsChildFailed
	}
	// Unrecorded: this process has no suite (see init). The parent records
	// whatever mapping it leaves.
	_, err := activateUnrecorded(context.Background(), device, []byte(fipsImportPassphrase), volume, activate)
	if err == nil {
		return fipsChildOK
	}
	fmt.Println(err)
	if errors.Is(err, luks2.ErrFIPSImportRequired) {
		return fipsChildImportRequired
	}
	return fipsChildFailed
}

// standInActivate is dmcrypt.Activate's stand-in for fipsChildRoleStandIn:
// it requires the volume and the key Unlock recovered and maps nothing.
func standInActivate(_ context.Context, v *luks2.Volume, key *luks2.Key, name string) (*dmcrypt.Mapping, error) {
	if v == nil || key == nil {
		return nil, errors.New("the stand-in activation was given no volume or no key")
	}
	return &dmcrypt.Mapping{Name: name}, nil
}

// unlockInFIPSProcess unlocks and activates device as volume in a child under
// GODEBUG=fips140=only, records any mapping the child left in this run's
// ledger, and returns the child's exit code and output. It fails the test if
// the child did not actually run in FIPS mode.
func unlockInFIPSProcess(t *testing.T, device, volume string) (int, string) {
	t.Helper()
	code, out := runFIPSChildProcess(t, fipsChildRoleUnlock, device, volume)

	// The child has no suite to record in, so a mapping it activated is
	// recorded here, once it has exited -- whatever its exit code says.
	switch m, err := dmcrypt.Lookup(t.Context(), volume); {
	case err == nil:
		if err := recordMapping(volume, m.UUID); err != nil {
			t.Fatalf("the FIPS child's mapping %q: %v", volume, err)
		}
	case !errors.Is(err, dmcrypt.ErrNotActive):
		t.Fatalf("looking up the mapping the FIPS child may have left: %v", err)
	}
	return code, out
}

// runFIPSChildProcess re-executes this test binary as a FIPS child in role,
// and returns its exit code and what it printed after the mode line.
func runFIPSChildProcess(t *testing.T, role, device, volume string) (int, string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0]) // #nosec G204 -- this test binary, re-executed
	env := slices.DeleteFunc(os.Environ(), func(kv string) bool {
		return strings.HasPrefix(kv, "GODEBUG=") || strings.HasPrefix(kv, "GO_LUKS2_ITEST_FIPS_")
	})
	cmd.Env = append(env, "GODEBUG=fips140=only", fipsChildRoleEnv+"="+role,
		fipsChildDeviceEnv+"="+device, fipsChildVolumeEnv+"="+volume)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	code := 0
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	default:
		t.Fatalf("the FIPS child could not be run: %v", err)
	}
	const want = "fips140.Enabled=true\n"
	if !strings.HasPrefix(string(out), want) {
		t.Fatalf("the child given GODEBUG=fips140=only did not run in FIPS mode\nstdout:\n%s\nstderr:\n%s", out, stderr.String())
	}
	// stderr is where a panic's stack goes; without it a crashed child is
	// only an exit code.
	return code, strings.TrimPrefix(string(out), want) + stderr.String()
}

// cryptsetupWithPassphrase runs cryptsetup with the passphrase on stdin and
// fails the test on a non-zero exit.
func cryptsetupWithPassphrase(t *testing.T, args ...string) {
	t.Helper()

	cmd := exec.Command("cryptsetup", args...) // #nosec G204 -- arguments are test constants
	cmd.Stdin = strings.NewReader(fipsImportPassphrase)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cryptsetup %v failed: %v\n%s", args, err, out)
	}
}

// fipsPlaintext is what is written through the mapping: random, so a wrong
// key cannot read back as the right bytes by any coincidence of structure, at
// the start of the data and at its end.
type fipsPlaintext struct {
	head, tail []byte
}

func newFIPSPlaintext(t *testing.T) fipsPlaintext {
	t.Helper()

	p := fipsPlaintext{head: make([]byte, 1<<20), tail: make([]byte, 64<<10)}
	if _, err := rand.Read(p.head); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if _, err := rand.Read(p.tail); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return p
}

// write puts the plaintext through mapping volume and flushes it to the device.
func (p fipsPlaintext) write(t *testing.T, volume string) {
	t.Helper()

	path, err := GetMappedDevicePath(volume)
	if err != nil {
		t.Fatalf("could not resolve the mapped device: %v", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0) // #nosec G304 -- path comes from device-mapper
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		t.Fatalf("size of %s: %v", path, err)
	}
	if _, err := f.WriteAt(p.head, 0); err != nil {
		t.Fatalf("writing through the mapping: %v", err)
	}
	if _, err := f.WriteAt(p.tail, size-int64(len(p.tail))); err != nil {
		t.Fatalf("writing through the mapping: %v", err)
	}
	if err := f.Sync(); err != nil {
		t.Fatalf("syncing the mapping: %v", err)
	}
}

// assertReads requires mapping volume to decrypt to the plaintext, with the
// buffer cache flushed first so the read goes through dm-crypt.
func (p fipsPlaintext) assertReads(t *testing.T, volume, who string) {
	t.Helper()

	path, err := GetMappedDevicePath(volume)
	if err != nil {
		t.Fatalf("could not resolve the mapped device: %v", err)
	}
	run(t, "blockdev", "--flushbufs", path)
	f, err := os.Open(path) // #nosec G304 -- path comes from device-mapper
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		t.Fatalf("size of %s: %v", path, err)
	}
	head := make([]byte, len(p.head))
	tail := make([]byte, len(p.tail))
	if _, err := f.ReadAt(head, 0); err != nil {
		t.Fatalf("reading through the mapping: %v", err)
	}
	if _, err := f.ReadAt(tail, size-int64(len(tail))); err != nil {
		t.Fatalf("reading through the mapping: %v", err)
	}
	if !bytes.Equal(head, p.head) || !bytes.Equal(tail, p.tail) {
		t.Fatalf("%s maps the migrated volume to different plaintext: it is decrypting with a key other than the volume key", who)
	}
}

// ciphertextDigest hashes the device from the data segment to the end: the
// bytes a re-encryption would rewrite and the migration must not.
func ciphertextDigest(t *testing.T, device string, offset int64) [32]byte {
	t.Helper()

	f, err := os.Open(device) // #nosec G304 -- loop device from SetupLoopDevice
	if err != nil {
		t.Fatalf("open %s: %v", device, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		t.Fatalf("seek: %v", err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatalf("read: %v", err)
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

// TestFIPSImportOfADefaultCryptsetupVolumeMapsTheSameData: plaintext written
// through cryptsetup's mapping of a default (Argon2id) volume is refused to a
// FIPS process with the import named; after MigrateToFIPS -- default options,
// on the loop device -- the ciphertext is byte-for-byte unchanged, a process
// under GODEBUG=fips140=only maps the volume and reads the same plaintext, and
// so does cryptsetup.
func TestFIPSImportOfADefaultCryptsetupVolumeMapsTheSameData(t *testing.T) {
	image := filepath.Join(t.TempDir(), "fips-import.img")
	if err := createTestFile(image, 64); err != nil {
		t.Fatalf("creating the image failed: %v", err)
	}
	// cryptsetup's defaults, not a fixture this library wrote.
	cryptsetupWithPassphrase(t, "luksFormat", "--type", "luks2", "--batch-mode", image)

	loopDev, err := harness.SetupLoopDevice(image)
	if err != nil {
		t.Fatalf("SetupLoopDevice failed: %v", err)
	}
	t.Cleanup(func() {
		if err := harness.DetachLoopDevice(loopDev); err != nil {
			t.Errorf("DetachLoopDevice(%s): %v", loopDev, err)
		}
	})

	_, metadata, err := harness.ReadHeader(loopDev)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	if kdf := metadata.Keyslots["0"].KDF; kdf == nil || kdf.Type != "argon2id" {
		t.Fatalf("cryptsetup's default keyslot 0 is %+v, want argon2id; the test would measure nothing", kdf)
	}
	var dataOffset int64
	if _, err := fmt.Sscan(metadata.Segments["0"].Offset, &dataOffset); err != nil {
		t.Fatalf("segment offset %q: %v", metadata.Segments["0"].Offset, err)
	}

	// Plaintext, written through cryptsetup's own mapping.
	plaintext := newFIPSPlaintext(t)
	csWrite := runVolume(t, "fips-import-cs-write")
	defer releaseVolume(t, csWrite)
	cryptsetupWithPassphrase(t, "open", "--type", "luks2", loopDev, csWrite)
	plaintext.write(t, csWrite)
	lockWithRetry(t, csWrite)
	ciphertext := ciphertextDigest(t, loopDev, dataOffset)

	// A FIPS process refuses it, says why, and maps nothing.
	fipsBefore := runVolume(t, "fips-import-before")
	defer releaseVolume(t, fipsBefore)
	code, out := unlockInFIPSProcess(t, loopDev, fipsBefore)
	if code != fipsChildImportRequired {
		t.Fatalf("FIPS unlock of the un-migrated volume exited %d, want %d (ErrFIPSImportRequired)\n%s",
			code, fipsChildImportRequired, out)
	}
	if !strings.Contains(out, "MigrateToFIPS") || !strings.Contains(out, "intact") {
		t.Errorf("the FIPS refusal does not name the import or say the volume is intact:\n%s", out)
	}
	if IsUnlocked(fipsBefore) {
		t.Fatal("the refused FIPS unlock left a mapping")
	}

	// The import, in this (non-FIPS) process, with the defaults.
	result, err := migrateToFIPSForTest(loopDev, []byte(fipsImportPassphrase))
	if err != nil {
		t.Fatalf("MigrateToFIPS failed: %v", err)
	}
	if !result.Complete || !result.KeyslotAdded || !slices.Equal(result.RemovedKeyslots, []int{0}) {
		t.Fatalf("migration result %+v, want complete, a keyslot added and keyslot 0 removed", result)
	}
	if ciphertextDigest(t, loopDev, dataOffset) != ciphertext {
		t.Fatal("the migration changed the encrypted data; it must never re-encrypt")
	}
	_, metadata, err = harness.ReadHeader(loopDev)
	if err != nil {
		t.Fatalf("ReadHeader after the migration failed: %v", err)
	}
	for id, ks := range metadata.Keyslots {
		if ks.KDF == nil || ks.KDF.Type != "pbkdf2" || ks.KDF.Hash != "sha256" {
			t.Errorf("keyslot %s KDF after the migration is %+v, want pbkdf2-sha256", id, ks.KDF)
		}
	}
	for id, d := range metadata.Digests {
		if d.Type != "pbkdf2" || d.Hash != "sha256" {
			t.Errorf("digest %s after the migration is %s-%s, want pbkdf2-sha256", id, d.Type, d.Hash)
		}
	}

	// A strict FIPS process maps it, and the kernel decrypts the plaintext.
	fipsAfter := runVolume(t, "fips-import-after")
	defer releaseVolume(t, fipsAfter)
	if code, out := unlockInFIPSProcess(t, loopDev, fipsAfter); code != fipsChildOK {
		t.Fatalf("FIPS unlock of the migrated volume exited %d\n%s", code, out)
	}
	plaintext.assertReads(t, fipsAfter, "a process under GODEBUG=fips140=only")
	lockWithRetry(t, fipsAfter)

	// And so does cryptsetup: bidirectional conformance survives the import.
	csRead := runVolume(t, "fips-import-cs-read")
	defer releaseVolume(t, csRead)
	cryptsetupWithPassphrase(t, "open", "--type", "luks2", loopDev, csRead)
	plaintext.assertReads(t, csRead, "cryptsetup")
	lockWithRetry(t, csRead)
}

// TestFIPSChildUnlocksAMigratedImageWithoutTheSuite runs the FIPS child's
// unlock path end to end -- a real re-execution under GODEBUG=fips140=only,
// the real Open and Unlock of a migrated cryptsetup-default volume -- with
// only device-mapper stood in, so it needs no root and no loop device.
//
// The child exits from init(), before TestMain registers runSuite, so
// anything on its path that reaches for the suite dereferences nil. That is
// how both kernel tests above once failed with exit 2 (a panic) only AFTER
// the migration: the un-migrated unlock is refused before activation, and
// only a successful activation went on to record the mapping in a ledger the
// child does not have. The parent records it instead (unlockInFIPSProcess).
func TestFIPSChildUnlocksAMigratedImageWithoutTheSuite(t *testing.T) {
	image := filepath.Join(t.TempDir(), "fips-child.img")
	if err := createTestFile(image, 32); err != nil {
		t.Fatalf("creating the image failed: %v", err)
	}
	cryptsetupWithPassphrase(t, "luksFormat", "--type", "luks2", "--batch-mode", image)

	if code, out := runFIPSChildProcess(t, fipsChildRoleStandIn, image, "fips-child-before"); code != fipsChildImportRequired {
		t.Fatalf("FIPS unlock of the un-migrated image exited %d, want %d (ErrFIPSImportRequired)\n%s",
			code, fipsChildImportRequired, out)
	}

	if _, err := migrateToFIPSForTest(image, []byte(fipsImportPassphrase)); err != nil {
		t.Fatalf("MigrateToFIPS failed: %v", err)
	}

	if code, out := runFIPSChildProcess(t, fipsChildRoleStandIn, image, "fips-child-after"); code != fipsChildOK {
		t.Fatalf("FIPS unlock of the migrated image exited %d, want %d\n%s", code, fipsChildOK, out)
	}
}
