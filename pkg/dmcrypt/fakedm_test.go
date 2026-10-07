// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package dmcrypt

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/anatol/devmapper.go"
	"golang.org/x/sys/unix"
)

// fakeDeviceMapper records dm operations against the seams in sys and can be
// told to fail any of them.
//
// internal/dm's own test suite proves the mechanical pieces -- the create
// ioctl, the busy retry, node identity, node placement. What this package
// adds on top -- the transaction Activate runs across them, and the
// rollback it performs when part of that transaction fails -- can only be
// produced for real with root and a real kernel, so it is driven here
// against a fake that records what was asked of it, the same way
// pkg/luks2's pre-split devicemapper tests did.
type fakeDeviceMapper struct {
	// targets is the live dm state: name -> uuid.
	targets map[string]string

	// devNos is each target's device number, set by create. A target a
	// test put in targets directly has fakeDefaultDevNo.
	devNos  map[string]uint64
	nextDev uint64

	createErr error
	loadErr   error
	resumeErr error
	nodeErr   error
	readyErr  error
	removeErr error

	// infoErr, when set, is returned by infoByName INSTEAD of consulting
	// targets, so a test can model an inspection that fails for a reason
	// other than the target being absent.
	infoErr error

	created  []string
	removed  []string
	inspects int

	// loaded records the tables handed to load, so a test can assert on
	// WHAT device-mapper was given and not merely that it was called.
	loaded []devmapper.Table

	// onLoad, when set, runs inside load, so a test can observe state that
	// exists only for the duration of the activation call.
	onLoad func(name, uuid string, tables []devmapper.Table)

	// readyInfo records the identity waitReady was asked to wait for.
	readyInfo *devmapper.DeviceInfo
}

// fakeDefaultDevNo is the device number of a target a test placed directly.
const fakeDefaultDevNo = 0xfe00

func newFakeDeviceMapper() *fakeDeviceMapper {
	return &fakeDeviceMapper{targets: map[string]string{}, devNos: map[string]uint64{}, nextDev: 0xfe10}
}

func (f *fakeDeviceMapper) devNoOf(name string) uint64 {
	if devNo, ok := f.devNos[name]; ok {
		return devNo
	}
	return fakeDefaultDevNo
}

// install replaces the device-mapper seams for the duration of one test.
func (f *fakeDeviceMapper) install(t *testing.T) {
	t.Helper()

	previous := sys
	t.Cleanup(func() { sys = previous })

	sys.create = func(_ context.Context, name, uuid string) (uint64, error) {
		if f.createErr != nil {
			return 0, f.createErr
		}
		if _, exists := f.targets[name]; exists {
			// What the kernel does: a create against a name in use fails.
			return 0, os.NewSyscallError("dm ioctl DM_DEV_CREATE", unix.EBUSY)
		}
		// What the kernel stores: a C string of at most 128 bytes.
		if i := strings.IndexByte(uuid, 0); i >= 0 {
			uuid = uuid[:i]
		}
		if len(uuid) > dmUUIDMaxLength {
			uuid = uuid[:dmUUIDMaxLength]
		}
		f.targets[name] = uuid
		f.devNos[name] = f.nextDev
		f.nextDev++
		f.created = append(f.created, name)
		return f.devNos[name], nil
	}
	sys.load = func(name string, table devmapper.Table) error {
		f.loaded = append(f.loaded, snapshotTable(table))
		if f.onLoad != nil {
			f.onLoad(name, f.targets[name], []devmapper.Table{table})
		}
		return f.loadErr
	}
	sys.resume = func(string) error { return f.resumeErr }
	sys.infoByName = func(name string) (*devmapper.DeviceInfo, error) {
		f.inspects++
		if f.infoErr != nil {
			return nil, f.infoErr
		}
		uuid, exists := f.targets[name]
		if !exists {
			return nil, os.NewSyscallError("dm ioctl", unix.ENXIO)
		}
		return &devmapper.DeviceInfo{Name: name, UUID: uuid, DevNo: f.devNoOf(name)}, nil
	}
	sys.remove = func(name string) error {
		f.removed = append(f.removed, name)
		if f.removeErr != nil {
			return f.removeErr
		}
		delete(f.targets, name)
		delete(f.devNos, name)
		return nil
	}
	sys.ensureNode = func(context.Context, string, *devmapper.DeviceInfo) error { return f.nodeErr }
	sys.waitReady = func(_ context.Context, _ string, info *devmapper.DeviceInfo) error {
		f.readyInfo = info
		return f.readyErr
	}
}

// snapshotTable copies a table for later inspection, taking its own copy of
// any key bytes -- the real device-mapper consumes the table inside the
// borrow window and keeps nothing, and a table carrying a live slice read
// after that window closed would be reading unmapped memory.
func snapshotTable(table devmapper.Table) devmapper.Table {
	crypt, ok := table.(devmapper.CryptTable)
	if !ok {
		return table
	}
	crypt.Key = append([]byte(nil), crypt.Key...)
	return crypt
}

// cryptTable returns the single dm-crypt table that was loaded, failing the
// test if the count is anything other than one.
func (f *fakeDeviceMapper) cryptTable(t *testing.T) devmapper.CryptTable {
	t.Helper()

	if len(f.loaded) != 1 {
		t.Fatalf("expected exactly one table to be loaded, got %d", len(f.loaded))
	}
	table, ok := f.loaded[0].(devmapper.CryptTable)
	if !ok {
		t.Fatalf("the loaded table is a %T, not a devmapper.CryptTable", f.loaded[0])
	}
	return table
}

// live reports whether any dm target is still present.
func (f *fakeDeviceMapper) live() []string {
	names := make([]string, 0, len(f.targets))
	for name := range f.targets {
		names = append(names, name)
	}
	return names
}
