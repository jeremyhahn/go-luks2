// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"errors"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/pkg/dmcrypt"
)

// nonexistentMapping names a device-mapper mapping this process never
// created. It is a VALID name (ValidateName accepts it), so dmcrypt.Lookup
// reaches the real kernel query and comes back ErrNotActive without needing
// root -- the same property pkg/dmcrypt's own unit tests rely on.
const nonexistentMapping = "harness-unit-test-no-such-mapping"

func TestMountOnAnUnmappedDeviceFails(t *testing.T) {
	// dmcrypt.Lookup's own failure mode here depends on whether this host even
	// has a device-mapper control node to query -- a sandbox with none fails
	// the open, one with device-mapper but no such mapping reports
	// ErrNotActive. Either way Mount must refuse rather than reach
	// filesystem.Mount with no source resolved.
	err := Mount(MountOptions{Device: nonexistentMapping, MountPoint: t.TempDir(), FSType: "ext4"})
	if err == nil {
		t.Fatal("Mount against an unmapped device = nil, want dmcrypt.Lookup's failure")
	}
}

func TestUnmountTranslatesEveryFlagAndPassesThrough(t *testing.T) {
	// There is no mount at this path, so the real filesystem.Unmount call
	// this makes is guaranteed to fail -- the point is that Unmount's three
	// flag translations and the call itself all run.
	err := Unmount(filepath.Join(t.TempDir(), "not-a-mountpoint"), unix.MNT_FORCE|unix.MNT_DETACH|unix.MNT_EXPIRE)
	if err == nil {
		t.Fatal("Unmount on a path that was never mounted = nil, want an error")
	}
}

func TestIsMountedOnARegularDirectoryIsFalse(t *testing.T) {
	ok, err := IsMounted(t.TempDir())
	if err != nil {
		t.Fatalf("IsMounted(a plain temp dir) = %v, %v, want false, nil", ok, err)
	}
	if ok {
		t.Error("IsMounted(a plain temp dir) = true, want false")
	}
}

// TestIsMappingMountedOnAnUnmappedNameIsFalse covers both of
// IsMappingMounted's failure returns -- the ErrNotActive mask and the
// otherwise-propagated error -- without assuming which one a Lookup against
// a name nothing maps produces on this host: both return false, and that is
// the one thing a caller may rely on either way.
func TestIsMappingMountedOnAnUnmappedNameIsFalse(t *testing.T) {
	ok, err := IsMappingMounted(nonexistentMapping)
	if ok {
		t.Errorf("IsMappingMounted(%q) = true, %v, want false for a name nothing maps", nonexistentMapping, err)
	}
	if err != nil && !errors.Is(err, dmcrypt.ErrNotActive) {
		t.Logf("IsMappingMounted(%q) propagated %v rather than masking it as ErrNotActive -- "+
			"expected when this host has no device-mapper control node to query", nonexistentMapping, err)
	}
}

func TestIsMappingMountedOnAnInvalidNameFails(t *testing.T) {
	// A name ValidateName refuses fails before the kernel is ever asked, so
	// dmcrypt.Lookup's error here is NOT ErrNotActive -- the branch
	// IsMappingMounted must propagate rather than mask.
	const invalid = "../not/a/valid/mapping/name"
	ok, err := IsMappingMounted(invalid)
	if err == nil {
		t.Fatalf("IsMappingMounted(%q) = %v, nil, want the name validation error propagated", invalid, ok)
	}
	if ok {
		t.Errorf("IsMappingMounted(%q) = true, %v, want false alongside the error", invalid, err)
	}
}
