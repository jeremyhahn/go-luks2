// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package pkg_test

import (
	"bytes"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// The volume key reaches dm-crypt by kernel-keyring reference (#78).
//
// The unit suite proves what this library HANDS to device-mapper. Only here,
// with real activation, can the other half be proved: that the kernel accepts
// the reference, resolves it, and keeps working after the reference is gone.
// Those are the claims the narrow keyring lifetime rests on, and they are
// claims about the kernel rather than about this package -- so they have to be
// asked of a kernel.
//
// Real dm activation needs CAP_SYS_ADMIN, which is why this file is in the
// containerized suite (`make integration-test`, which runs through
// test/integration/docker-run.sh) and not next to the unit tests.

// hexKey matches a dm-crypt table key given INLINE -- the state this change
// exists to eliminate. A 512-bit XTS volume key is 128 hex characters.
var hexKey = regexp.MustCompile(`^[0-9a-fA-F]{32,}$`)

// keyringReference matches the reference form. The description is a SHA-256
// digest of the volume's dm UUID, not the UUID itself: the reference is one
// space-delimited token in the dm target specification, and the UUID is built
// from 40 bytes read off the device plus a caller-supplied mapping name.
// Hashing gives the token a closed alphabet by construction.
var keyringReference = regexp.MustCompile(`^:(\d+):logon:luks2:([0-9a-f]{64})$`)

func run(t *testing.T, name string, args ...string) string {
	t.Helper()

	out, err := exec.Command(name, args...).CombinedOutput() // #nosec G204 -- arguments are test constants
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, out)
	}
	return string(out)
}

// dmCryptTableKey returns the key field of a live dm-crypt table exactly as the
// KERNEL reports it.
//
// This is the assertion that cannot be faked by anything in this repository:
// dmsetup asks the kernel what the target was constructed with, so whatever
// comes back is what actually crossed the ioctl boundary.
func dmCryptTableKey(t *testing.T, name string) string {
	t.Helper()

	// `0 <sectors> crypt <cipher> <key> <iv offset> <device> <offset> ...`
	fields := strings.Fields(run(t, "dmsetup", "table", "--showkeys", name))
	if len(fields) < 5 {
		t.Fatalf("unexpected dm table for %q: %v", name, fields)
	}
	if fields[2] != "crypt" {
		t.Fatalf("target %q is a %q target, not crypt", name, fields[2])
	}
	return fields[4]
}

// keyringHolds reports whether any key with this description is present in the
// kernel's key list.
//
// /proc/keys is used rather than a keyctl search because the search would have
// to run on the same OS thread that added the key, and the whole point of the
// design is that the caller never learns which thread that was. /proc/keys
// lists every key the caller has view permission on, which as root includes any
// key this process created.
func keyringHolds(t *testing.T, description string) bool {
	t.Helper()

	keys, err := os.ReadFile("/proc/keys")
	if err != nil {
		t.Fatalf("could not read /proc/keys: %v", err)
	}
	return strings.Contains(string(keys), description)
}

// descriptionOf pulls the key description back out of a dm-crypt reference
// (":<size>:<type>:<description>").
func descriptionOf(reference string) string {
	parts := strings.SplitN(reference, ":", 4)
	if len(parts) != 4 {
		return ""
	}
	return parts[3]
}

// TestCheckKeyringAvailablePassesWhereActivationWorks ties the preflight to the
// thing it is predicting.
//
// The preflight exists so a daemon fails at startup rather than at the first
// unlock of a customer volume. That is only useful if the two agree: an
// environment where activation works must pass the preflight, or the check
// would refuse to start a process that would have worked. This suite is the
// only place both halves can be observed, because only here does real dm
// activation happen.
func TestCheckKeyringAvailablePassesWhereActivationWorks(t *testing.T) {
	if err := luks2.CheckKeyringAvailable(); err != nil {
		t.Fatalf("the preflight refused an environment where dm activation demonstrably works: %v", err)
	}
}

// TestUnlockPassesTheVolumeKeyThroughTheKernelKeyring is the end-to-end
// assertion for #78: the kernel accepts a reference, activates from it, and
// reports a reference rather than a key when asked what the target holds.
func TestUnlockPassesTheVolumeKeyThroughTheKernelKeyring(t *testing.T) {
	tmpfile := "/tmp/test-luks-keyring.img"
	volumeName := runVolume(t, "test-keyring")
	var loopDev string
	defer func() { testCleanup(volumeName, loopDev, tmpfile) }()

	if err := createTestFile(tmpfile, 64); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	passphrase := []byte("keyring-test-password")
	if err := luks2.Format(luks2.FormatOptions{
		Device:     tmpfile,
		Passphrase: passphrase,
		KDFType:    "pbkdf2",
	}); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	var err error
	loopDev, err = luks2.SetupLoopDevice(tmpfile)
	if err != nil {
		t.Fatalf("Failed to setup loop device: %v", err)
	}

	_ = luks2.Lock(volumeName)

	// If the reference were malformed, or resolved to nothing, or declared the
	// wrong key size, the kernel would refuse the table load right here -- so
	// a successful Unlock is already most of the proof.
	// Registered BEFORE the mapping can exist, so a partial or rolled-back
	// unlock cannot leave one behind either (#100). Idempotent.
	defer releaseVolume(t, volumeName)
	if err := luks2.Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock through the kernel keyring failed: %v", err)
	}
	if !waitForUnlock(volumeName, 5000) {
		t.Fatal("Volume should be unlocked")
	}

	key := dmCryptTableKey(t, volumeName)

	// THE NEGATIVE. This is the whole point of the change: the kernel must not
	// be holding an inline hex key, because an inline hex key is one that
	// traveled through unwipeable Go strings to get here.
	if hexKey.MatchString(key) {
		t.Fatalf("the dm-crypt table holds the volume key inline as hex; the keyring path was not taken")
	}

	match := keyringReference.FindStringSubmatch(key)
	if match == nil {
		t.Fatalf("the dm-crypt table key %q is not a keyring reference of the expected form", key)
	}
	if size, convErr := strconv.Atoi(match[1]); convErr != nil || size != 64 {
		t.Errorf("the reference declares a key size of %q, not the 64 bytes this volume was formatted with", match[1])
	}

	// The token the kernel actually holds cannot contain a field separator.
	// That is the argv-injection boundary the digest closes; asserting it here
	// checks the closure against the KERNEL's copy of the string rather than
	// against what this process believes it sent.
	if strings.ContainsAny(key, " \t\n\r") {
		t.Errorf("the dm target specification token contains a field separator: %q", key)
	}

	// THE LIFETIME. The entry is released the instant activation returns, so by
	// the time Unlock has come back there must be nothing left in the keyring
	// -- while the mapping below is still perfectly live.
	if keyringHolds(t, descriptionOf(key)) {
		t.Errorf("a keyring entry holding the volume key outlived the activation that needed it")
	}

	// And the claim that makes the short lifetime safe: dm-crypt copied the key
	// during construction and does not consult the keyring again. If that were
	// wrong, the I/O below would fail with the entry already gone.
	assertMappingCarriesData(t, volumeName)

	// Suspend/resume is the operation most likely to re-read the key if
	// anything did, so it is exercised explicitly rather than assumed about.
	run(t, "dmsetup", "suspend", volumeName)
	run(t, "dmsetup", "resume", volumeName)
	assertMappingCarriesData(t, volumeName)

	lockWithRetry(t, volumeName)
	if !waitForLock(volumeName, 5000) {
		t.Fatal("Volume should be locked")
	}
	if keyringHolds(t, descriptionOf(key)) {
		t.Errorf("closing the mapping left a keyring entry holding the volume key")
	}
}

// lockWithRetry closes the mapping, retrying while device-mapper reports it
// busy.
//
// The retry is not covering for Lock. This suite shares the HOST's
// device-mapper -- dm is not namespaced, whatever the container is confined to
// -- and the host's udev is watching: closing a
// block device that was just written to fires a change event, and udev's blkid
// probe holds the device open for a moment afterwards. DM_DEV_REMOVE loses that
// race and returns EBUSY -- correctly, which is why Lock reports it. `dmsetup
// remove --retry` exists for exactly this. No other test here writes to a
// mapped device directly, which is why nothing else needed it.
func lockWithRetry(t *testing.T, volumeName string) {
	t.Helper()

	var err error
	for i := 0; i < 100; i++ {
		if err = luks2.Lock(volumeName); err == nil {
			return
		}
		if !strings.Contains(err.Error(), "busy") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("Lock failed: %v", err)
}

// assertMappingCarriesData writes a pattern through the mapping and reads it
// back off the device, with the buffer cache flushed in between so the read
// goes through dm-crypt rather than being served from memory.
func assertMappingCarriesData(t *testing.T, volumeName string) {
	t.Helper()

	path, err := luks2.GetMappedDevicePath(volumeName)
	if err != nil {
		t.Fatalf("could not resolve the mapped device: %v", err)
	}

	pattern := bytes.Repeat([]byte("go-luks2 keyring activation\n"), 256)[:4096]

	f, err := os.OpenFile(path, os.O_RDWR, 0) // #nosec G304 -- path comes from device-mapper
	if err != nil {
		t.Fatalf("could not open %s: %v", path, err)
	}
	if _, err := f.WriteAt(pattern, 0); err != nil {
		_ = f.Close()
		t.Fatalf("writing through the mapping failed: %v", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		t.Fatalf("syncing the mapping failed: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing the mapping failed: %v", err)
	}

	run(t, "blockdev", "--flushbufs", path)

	f, err = os.Open(path) // #nosec G304 -- path comes from device-mapper
	if err != nil {
		t.Fatalf("could not reopen %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()

	readBack := make([]byte, len(pattern))
	if _, err := f.ReadAt(readBack, 0); err != nil {
		t.Fatalf("reading back through the mapping failed: %v", err)
	}
	if !bytes.Equal(readBack, pattern) {
		t.Fatal("the mapping did not return what was written; dm-crypt is not decrypting with the key it was given")
	}
}
