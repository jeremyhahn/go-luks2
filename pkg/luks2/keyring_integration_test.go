// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// What the KERNEL does, asserted against a kernel.
//
// The unit suite runs against an in-memory keyring, because a container under
// Docker's default seccomp profile -- which is what CI is -- denies add_key,
// keyctl and request_key, and a suite that cannot run everywhere it is asked to
// run is not a gate. That split leaves a real gap, and this file is what fills
// it: everything here is a claim about the kernel's behavior rather than about
// this package's logic, and the fake would only ever agree with itself.
//
// Specifically, the unit tests depend on these kernel behaviors being true:
//
//   - a logon key's payload cannot be read back (why the type is "logon");
//   - the ring reached through KEY_SPEC_SESSION_KEYRING really is a session
//     keyring and not the uid-wide user keyring (the blast radius decision);
//   - add_key UPDATES a key of the same type and description in place instead
//     of failing (the entire reason the pre-add collision guard exists);
//   - a logon description without a subsystem qualifier is refused (why the
//     prefix is load-bearing rather than decoration);
//   - revoking makes a key stop resolving.
//
// If any of those changed, the in-memory model in keyringfake_test.go would be
// wrong and the unit suite would be asserting against fiction. These tests are
// what stop that from being silent.
//
// This file runs in the privileged container alongside the real device-mapper
// activation it pairs with (`make integration-test`).

// integrationTestKey is a stand-in volume key of the length this library
// formats with.
var integrationTestKey = []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

// integrationDMUUID builds a dm UUID of the shape Unlock generates, unique per
// test so that concurrent or repeated runs cannot collide on the deterministic
// description derived from it.
func integrationDMUUID(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("CRYPT-LUKS2-0123456789abcdef0123456789abcdef-%s", strings.ReplaceAll(t.Name(), "/", "-"))
}

// addRealKey places a key in the real kernel keyring and registers its removal.
func addRealKey(t *testing.T, description string) (id, ring int) {
	t.Helper()

	ring, err := keyring.sessionRing()
	if err != nil {
		t.Fatalf("could not resolve the session keyring: %v", err)
	}
	id, err = keyring.add(keyringKeyType, description, integrationTestKey, ring)
	if err != nil {
		t.Fatalf("add_key failed: %v", err)
	}
	t.Cleanup(func() {
		_ = keyring.revoke(id)
		_ = keyring.unlink(id, ring)
	})
	return id, ring
}

// TestKernelRefusesToReadBackALogonPayload is why the key type is "logon" and
// not "user".
//
// A "user" key's payload can be read back with KEYCTL_READ by anything that
// possesses it, which would trade an unwipeable userspace string for a kernel
// buffer that userspace -- including a same-uid neighbor sharing the session --
// can still fetch. A logon key's payload is write-only. That property is the
// whole justification for handing an enclave borrow straight to add_key, so it
// is asked of the kernel rather than assumed.
func TestKernelRefusesToReadBackALogonPayload(t *testing.T) {
	defer pinToOSThread()()

	id, _ := addRealKey(t, keyringDescription(integrationDMUUID(t)))

	buf := make([]byte, 2*len(integrationTestKey))
	n, err := unix.KeyctlBuffer(unix.KEYCTL_READ, id, buf, 0)
	if err == nil {
		t.Fatalf("the kernel handed back %d bytes of the volume key; the key type is not write-only", n)
	}
	if !errors.Is(err, unix.EOPNOTSUPP) {
		t.Fatalf("the read was refused for the wrong reason: %v", err)
	}
}

// TestKernelPutsTheKeyInASessionRingNotTheUserRing pins the blast-radius
// decision against the kernel's own account of where the key went.
//
// Kernel keyrings are not namespaced by container: the user keyring (_uid) is
// shared by every process of that uid on the HOST, across containers. Landing
// in it would be invisible in every functional test -- the volume opens either
// way -- which is exactly why this is asserted rather than reasoned about.
func TestKernelPutsTheKeyInASessionRingNotTheUserRing(t *testing.T) {
	defer pinToOSThread()()

	_, ring := addRealKey(t, keyringDescription(integrationDMUUID(t)))

	described, err := unix.KeyctlString(unix.KEYCTL_DESCRIBE, ring)
	if err != nil {
		t.Fatalf("could not describe the ring: %v", err)
	}
	if !strings.Contains(described, "_ses") {
		t.Fatalf("the ring the key went into is not a session keyring: %q", described)
	}

	if user, err := unix.KeyctlGetKeyringID(unix.KEY_SPEC_USER_KEYRING, false); err == nil && ring == user {
		t.Fatal("the volume key was placed in the uid-wide user keyring, which is shared across containers")
	}
}

// TestKernelUpdatesAKeyInPlaceRatherThanRefusing is the behavior the pre-add
// collision guard exists because of.
//
// If add_key returned an error for a description already in use, the guard in
// addVolumeKeyToKeyring would be redundant and the in-memory model would be
// wrong in the direction that makes the unit suite too easy. It does not: it
// silently updates the existing key and keeps its serial, so a leftover from a
// crashed process would be clobbered without a word.
func TestKernelUpdatesAKeyInPlaceRatherThanRefusing(t *testing.T) {
	defer pinToOSThread()()

	description := keyringDescription(integrationDMUUID(t))
	first, ring := addRealKey(t, description)

	second, err := keyring.add(keyringKeyType, description, []byte("a completely different volume key"), ring)
	if err != nil {
		t.Fatalf("a second add_key on the same description failed, which the collision guard does not expect: %v", err)
	}
	if second != first {
		t.Fatalf("the kernel created a new key %d instead of updating %d; the model in keyringfake_test.go is wrong", second, first)
	}
}

// TestKernelRefusesAnUnqualifiedLogonDescription establishes that the "luks2:"
// prefix is load-bearing rather than decoration.
func TestKernelRefusesAnUnqualifiedLogonDescription(t *testing.T) {
	defer pinToOSThread()()

	ring, err := keyring.sessionRing()
	if err != nil {
		t.Fatalf("could not resolve the session keyring: %v", err)
	}

	if _, err := keyring.add(keyringKeyType, "unqualified", integrationTestKey, ring); err == nil {
		t.Fatal("the kernel accepted a logon key with no subsystem qualifier")
	} else if !errors.Is(err, unix.EINVAL) {
		t.Fatalf("the description was refused for an unexpected reason: %v", err)
	}

	// The control: the description this package actually builds is accepted.
	addRealKey(t, keyringDescription(integrationDMUUID(t)))
}

// TestRealKeyringLifecycle walks add, resolve, release and verify against the
// kernel, which is the sequence unlockLoadTable performs.
func TestRealKeyringLifecycle(t *testing.T) {
	defer pinToOSThread()()

	entry, err := addVolumeKeyToKeyring(integrationDMUUID(t), integrationTestKey)
	if err != nil {
		t.Fatalf("the volume key could not be placed in the kernel keyring: %v", err)
	}

	id, err := keyring.search(entry.ring, keyringKeyType, entry.description)
	if err != nil {
		t.Fatalf("the kernel could not resolve the reference dm-crypt would be given: %v", err)
	}
	if id != entry.id {
		t.Fatalf("the description resolves to key %d, not the one that was added (%d)", id, entry.id)
	}

	if err := entry.release(); err != nil {
		t.Fatalf("release reported a failure: %v", err)
	}
	if _, err := keyring.search(entry.ring, keyringKeyType, entry.description); !errors.Is(err, unix.ENOKEY) {
		t.Fatalf("the volume key is still resolvable after release, or failed oddly: %v", err)
	}

	// Releasing twice is not a failure: the entry is already gone, which is the
	// outcome release wants. The unit suite asserts this against the model; the
	// errnos it tolerates (ENOKEY, ENOENT, EKEYREVOKED) are the kernel's, so
	// they are confirmed here.
	if err := entry.release(); err != nil {
		t.Fatalf("releasing an already-gone entry was reported as a failure: %v", err)
	}
}

// TestRealDescriptionIsAcceptedForEveryHostileInput closes the loop on the
// argv-boundary fix against a real kernel.
//
// The digest gives the description a closed alphabet, so a header UUID full of
// separators must still produce something the kernel accepts as a logon
// description -- a fix that made hostile input unusable rather than harmless
// would trade one failure for another.
func TestRealDescriptionIsAcceptedForEveryHostileInput(t *testing.T) {
	defer pinToOSThread()()

	shape := regexp.MustCompile(`^` + keyringDescriptionPrefix + `:[0-9a-f]{64}$`)

	for i, hostile := range []string{
		"CRYPT-LUKS2-aaaa 0 crypt aes-xts-plain64 0000-victim",
		"CRYPT-LUKS2-aa\nbb-victim",
		"CRYPT-LUKS2-aa\tbb-victim",
		"CRYPT-LUKS2-\x00-victim",
		"",
	} {
		description := keyringDescription(hostile + fmt.Sprint(i))
		if !shape.MatchString(description) {
			t.Fatalf("description %q from hostile input is not the closed-alphabet form", description)
		}
		addRealKey(t, description)
	}
}

// TestCheckKeyringAvailablePassesOnARealKernel is the preflight against the
// thing it predicts. The unit suite can only assert that it cleans up after
// itself; whether it agrees with a real kernel is a question for a real kernel.
func TestCheckKeyringAvailablePassesOnARealKernel(t *testing.T) {
	if err := CheckKeyringAvailable(); err != nil {
		t.Fatalf("the preflight refused an environment where dm activation demonstrably works: %v", err)
	}
}
