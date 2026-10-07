// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// No build constraint: the unit and the integration tiers both re-point device
// links through it.

package luks2

import (
	"os"
	"testing"
)

// relinkAfterFirstOpen re-points link at to as soon as the first WRITABLE open
// of link has returned -- the lock's open, which every writer makes O_RDWR --
// before anything else the operation does by path. A read-only preflight
// before the lock does not trigger it.
func relinkAfterFirstOpen(t *testing.T, link, to string) volumeSys {
	t.Helper()
	sys := testVolumeSys()
	real := sys.openFile
	moved := false
	sys.openFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		f, err := real(name, flag, perm)
		if name == link && !moved && flag&(os.O_RDWR|os.O_WRONLY) != 0 {
			moved = true
			if rmErr := os.Remove(link); rmErr != nil {
				t.Errorf("remove %s: %v", link, rmErr)
			}
			if lnErr := os.Symlink(to, link); lnErr != nil {
				t.Errorf("symlink %s: %v", link, lnErr)
			}
		}
		return f, err
	}
	return sys
}
