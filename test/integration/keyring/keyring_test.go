// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package keyring_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/keyring"
	"github.com/jeremyhahn/go-luks2/pkg/dmcrypt"
)

// What the KERNEL does, asserted against a kernel. See
// keyring_integration_test.go (now moved, from pkg/luks2) for the full
// reasoning: this fills the gap the fake keyring in the unit tier cannot
// close on its own claim.
//
// This package reaches internal/keyring's exported API directly
// (keyring.Live, keyring.AddVolumeKey, keyring.Description,
// keyring.PinOSThread, keyring.KeyType, keyring.DescriptionPrefix) rather
// than through pkg/luks2's own unexported wrappers, since internal/keyring
// is importable module-wide.

// integrationKeyLen is the length of the volume key each test places in the
// kernel keyring; the bytes are drawn fresh by randomKey.
const integrationKeyLen = 64

func randomKey(t *testing.T, n int) []byte {
	t.Helper()

	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("failed to generate %d random bytes: %v", n, err)
	}
	return b
}

func integrationDMUUID(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("CRYPT-LUKS2-0123456789abcdef0123456789abcdef-%s", strings.ReplaceAll(t.Name(), "/", "-"))
}

func addRealKey(t *testing.T, description string) (id, ring int) {
	t.Helper()

	sys := keyring.Live()
	ring, err := sys.SessionRing()
	if err != nil {
		t.Fatalf("could not resolve the session keyring: %v", err)
	}
	id, err = sys.Add(keyring.KeyType, description, randomKey(t, integrationKeyLen), ring)
	if err != nil {
		t.Fatalf("add_key failed: %v", err)
	}
	t.Cleanup(func() {
		_ = sys.Revoke(id)
		_ = sys.Unlink(id, ring)
	})
	return id, ring
}

func TestKernelRefusesToReadBackALogonPayload(t *testing.T) {
	defer keyring.PinOSThread()()

	id, _ := addRealKey(t, keyring.Description(integrationDMUUID(t)))

	buf := make([]byte, 2*integrationKeyLen)
	n, err := unix.KeyctlBuffer(unix.KEYCTL_READ, id, buf, 0)
	if err == nil {
		t.Fatalf("the kernel handed back %d bytes of the volume key; the key type is not write-only", n)
	}
	if !errors.Is(err, unix.EOPNOTSUPP) {
		t.Fatalf("the read was refused for the wrong reason: %v", err)
	}
}

func TestKernelPutsTheKeyInASessionRingNotTheUserRing(t *testing.T) {
	defer keyring.PinOSThread()()

	_, ring := addRealKey(t, keyring.Description(integrationDMUUID(t)))

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

func TestKernelUpdatesAKeyInPlaceRatherThanRefusing(t *testing.T) {
	defer keyring.PinOSThread()()

	description := keyring.Description(integrationDMUUID(t))
	first, ring := addRealKey(t, description)

	sys := keyring.Live()
	second, err := sys.Add(keyring.KeyType, description, randomKey(t, 33), ring)
	if err != nil {
		t.Fatalf("a second add_key on the same description failed, which the collision guard does not expect: %v", err)
	}
	if second != first {
		t.Fatalf("the kernel created a new key %d instead of updating %d", second, first)
	}
}

func TestKernelRefusesAnUnqualifiedLogonDescription(t *testing.T) {
	defer keyring.PinOSThread()()

	sys := keyring.Live()
	ring, err := sys.SessionRing()
	if err != nil {
		t.Fatalf("could not resolve the session keyring: %v", err)
	}

	if _, err := sys.Add(keyring.KeyType, "unqualified", randomKey(t, integrationKeyLen), ring); err == nil {
		t.Fatal("the kernel accepted a logon key with no subsystem qualifier")
	} else if !errors.Is(err, unix.EINVAL) {
		t.Fatalf("the description was refused for an unexpected reason: %v", err)
	}

	addRealKey(t, keyring.Description(integrationDMUUID(t)))
}

func TestRealKeyringLifecycle(t *testing.T) {
	defer keyring.PinOSThread()()

	sys := keyring.Live()
	entry, err := keyring.AddVolumeKey(context.Background(), sys, integrationDMUUID(t), randomKey(t, integrationKeyLen))
	if err != nil {
		t.Fatalf("the volume key could not be placed in the kernel keyring: %v", err)
	}

	id, err := sys.Search(entry.Ring, keyring.KeyType, entry.Description)
	if err != nil {
		t.Fatalf("the kernel could not resolve the reference dm-crypt would be given: %v", err)
	}
	if id != entry.ID {
		t.Fatalf("the description resolves to key %d, not the one that was added (%d)", id, entry.ID)
	}

	if err := entry.Release(sys); err != nil {
		t.Fatalf("Release reported a failure: %v", err)
	}
	if _, err := sys.Search(entry.Ring, keyring.KeyType, entry.Description); !errors.Is(err, unix.ENOKEY) {
		t.Fatalf("the volume key is still resolvable after release, or failed oddly: %v", err)
	}

	if err := entry.Release(sys); err != nil {
		t.Fatalf("releasing an already-gone entry was reported as a failure: %v", err)
	}
}

func TestRealDescriptionIsAcceptedForEveryHostileInput(t *testing.T) {
	defer keyring.PinOSThread()()

	shape := regexp.MustCompile(`^` + keyring.DescriptionPrefix + `:[0-9a-f]{64}$`)

	for i, hostile := range []string{
		"CRYPT-LUKS2-aaaa 0 crypt aes-xts-plain64 0000-victim",
		"CRYPT-LUKS2-aa\nbb-victim",
		"CRYPT-LUKS2-aa\tbb-victim",
		"CRYPT-LUKS2-\x00-victim",
		"",
	} {
		description := keyring.Description(hostile + fmt.Sprint(i))
		if !shape.MatchString(description) {
			t.Fatalf("description %q from hostile input is not the closed-alphabet form", description)
		}
		addRealKey(t, description)
	}
}

func TestCheckKeyringPassesOnARealKernel(t *testing.T) {
	if err := dmcrypt.CheckKeyring(context.Background()); err != nil {
		t.Fatalf("the preflight refused an environment where dm activation demonstrably works: %v", err)
	}
}
