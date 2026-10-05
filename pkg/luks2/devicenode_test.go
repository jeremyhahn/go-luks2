// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/anatol/devmapper.go"
	"golang.org/x/sys/unix"
)

// Device-node bookkeeping.
//
// This package creates /dev nodes when udev does not, and removes them again on
// close and on a rolled-back unlock. Both halves decode a dm device number into
// a major and a minor, and a decoder that disagrees with the one that CREATED
// the node unlinks the wrong file -- a node belonging to a different device
// entirely, silently, because every error on that path is discarded by design.
//
// dm minors above 255 are routine on any host running LVM or Docker, and the
// removal path runs on Unlock's ERROR path, where an operator is least likely
// to connect a vanished device to what they just ran.

// TestDevNoDecodingMatchesTheKernelEncoding pins the decoder against
// unix.Mkdev, which is the function this package uses to CREATE the node. The
// two must be exact inverses or a node is made under one name and looked for
// under another.
func TestDevNoDecodingMatchesTheKernelEncoding(t *testing.T) {
	cases := []struct {
		major uint32
		minor uint32
	}{
		{253, 0},
		{253, 1},
		{253, 254},
		// 255 is the last minor the truncating form gets right; everything
		// below it is where the two decoders part company.
		{253, 255},
		{253, 256},
		{253, 300},
		{253, 1000},
		{253, 1048575}, // the largest minor the 32-bit encoding holds
		{4095, 42},     // the largest major
	}

	for _, tc := range cases {
		devNo := unix.Mkdev(tc.major, tc.minor)

		major, minor := decodeDevNo(devNo)
		if major != tc.major || minor != tc.minor {
			t.Errorf("decodeDevNo(Mkdev(%d, %d)) = (%d, %d), want (%d, %d)",
				tc.major, tc.minor, major, minor, tc.major, tc.minor)
		}

		// The truncating form this replaced, shown failing for exactly the
		// values that matter. It is asserted rather than merely described so
		// that "minors above 255 differ" is a measured claim.
		if truncated := uint32(devNo & 0xFF); tc.minor > 255 && truncated == tc.minor {
			t.Errorf("fixture is not exercising the defect: minor %d survives truncation", tc.minor)
		}
	}
}

// TestRemoveMappingNodesLeavesAForeignNodeAlone is the regression test.
//
// A dm device with minor 300 truncates to 44 under the old arithmetic, so the
// rollback unlinked /dev/dm-44 -- a node belonging to some other device -- and
// left its own /dev/dm-300 in place. Both halves of that are asserted here,
// because a fix that stopped removing the wrong node while still failing to
// remove the right one would be half a fix.
func TestRemoveMappingNodesLeavesAForeignNodeAlone(t *testing.T) {
	dir := t.TempDir()
	withDevDir(t, dir)

	if err := os.MkdirAll(filepath.Join(dir, "mapper"), 0o755); err != nil {
		t.Fatalf("failed to build the fake /dev: %v", err)
	}

	const (
		major = 253
		ours  = 300
		// 300 & 0xFF == 44, which is the node the truncating decoder unlinked.
		truncated = ours & 0xFF
	)

	ourNode := filepath.Join(dir, "dm-300")
	foreignNode := filepath.Join(dir, "dm-44")
	mapperNode := filepath.Join(dir, "mapper", "ourvolume")

	writeFakeNode(t, ourNode)
	writeFakeNode(t, foreignNode)
	writeFakeNode(t, mapperNode)

	// The fake rdev table stands in for stat(2): our two nodes carry our device
	// number, the foreign one carries somebody else's.
	withNodeRdev(t, map[string]uint64{
		ourNode:     unix.Mkdev(major, ours),
		mapperNode:  unix.Mkdev(major, ours),
		foreignNode: unix.Mkdev(major, truncated),
	})

	info := &devmapper.DeviceInfo{Name: "ourvolume", DevNo: unix.Mkdev(major, ours)}
	removeMappingNodes("ourvolume", info)

	if _, err := os.Lstat(foreignNode); err != nil {
		t.Errorf("a node belonging to another device was unlinked: %s", foreignNode)
	}
	if _, err := os.Lstat(ourNode); err == nil {
		t.Errorf("our own node was left behind: %s", ourNode)
	}
	if _, err := os.Lstat(mapperNode); err == nil {
		t.Errorf("our own mapper entry was left behind: %s", mapperNode)
	}
}

// TestRemoveMappingNodesLeavesANodeWithTheWrongDeviceAlone covers the identity
// check on its own terms: even at the RIGHT path, a node that does not carry
// our device number belongs to something else. udev recycles minors, so the
// name alone proves nothing.
func TestRemoveMappingNodesLeavesANodeWithTheWrongDeviceAlone(t *testing.T) {
	dir := t.TempDir()
	withDevDir(t, dir)

	if err := os.MkdirAll(filepath.Join(dir, "mapper"), 0o755); err != nil {
		t.Fatalf("failed to build the fake /dev: %v", err)
	}

	node := filepath.Join(dir, "dm-7")
	mapperNode := filepath.Join(dir, "mapper", "recycled")
	writeFakeNode(t, node)
	writeFakeNode(t, mapperNode)

	// Both paths are the ones our mapping would use, but the nodes now belong
	// to a device with a different major.
	withNodeRdev(t, map[string]uint64{
		node:       unix.Mkdev(9, 7),
		mapperNode: unix.Mkdev(9, 7),
	})

	removeMappingNodes("recycled", &devmapper.DeviceInfo{Name: "recycled", DevNo: unix.Mkdev(253, 7)})

	if _, err := os.Lstat(node); err != nil {
		t.Error("a node carrying a different device number was unlinked")
	}
	if _, err := os.Lstat(mapperNode); err != nil {
		t.Error("a mapper entry carrying a different device number was unlinked")
	}
}

// TestRemoveMappingNodesRemovesADanglingMapperEntry keeps the cleanup working
// in the order Lock performs it.
//
// Lock removes the dm target first, so by the time the nodes are cleaned the
// /dev/mapper symlink may already point at nothing. A dangling symlink named
// after OUR mapping is ours: refusing to unlink it because it cannot be stat'd
// would leave exactly the stale entry IsUnlocked has to work around.
func TestRemoveMappingNodesRemovesADanglingMapperEntry(t *testing.T) {
	dir := t.TempDir()
	withDevDir(t, dir)

	if err := os.MkdirAll(filepath.Join(dir, "mapper"), 0o755); err != nil {
		t.Fatalf("failed to build the fake /dev: %v", err)
	}

	mapperNode := filepath.Join(dir, "mapper", "gone")
	if err := os.Symlink(filepath.Join(dir, "dm-999"), mapperNode); err != nil {
		t.Fatalf("failed to create the dangling symlink: %v", err)
	}

	withNodeRdev(t, map[string]uint64{})

	removeMappingNodes("gone", &devmapper.DeviceInfo{Name: "gone", DevNo: unix.Mkdev(253, 999)})

	if _, err := os.Lstat(mapperNode); err == nil {
		t.Error("a dangling mapper entry naming our own mapping was left behind")
	}
}

// TestRemoveMappingNodesToleratesAMissingInfo pins the nil path: a rollback may
// have no DeviceInfo at all, and must still clean up what it can name.
func TestRemoveMappingNodesToleratesAMissingInfo(t *testing.T) {
	dir := t.TempDir()
	withDevDir(t, dir)
	withNodeRdev(t, map[string]uint64{})

	// Must not panic, and must not invent a dm-N path out of a nil info.
	removeMappingNodes("nothing", nil)
}

// withDevDir points the device-node helpers at a temporary directory for the
// duration of a test. The real /dev cannot be written to unprivileged, and a
// test that needed root would not run on the way in.
func withDevDir(t *testing.T, dir string) {
	t.Helper()

	previous := devDir
	t.Cleanup(func() { devDir = previous })
	devDir = dir
}

// withNodeRdev replaces the stat(2) lookup with a table, so a test can give a
// plain file the device number of a block device.
func withNodeRdev(t *testing.T, table map[string]uint64) {
	t.Helper()

	previous, previousBlock := nodeRdev, blockNodeRdev
	t.Cleanup(func() { nodeRdev, blockNodeRdev = previous, previousBlock })
	nodeRdev = func(path string) (uint64, error) {
		rdev, ok := table[path]
		if !ok {
			return 0, os.ErrNotExist
		}
		return rdev, nil
	}
	blockNodeRdev = nodeRdev
}

func writeFakeNode(t *testing.T, path string) {
	t.Helper()

	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("failed to create %s: %v", path, err)
	}
}
