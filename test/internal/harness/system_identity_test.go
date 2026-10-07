// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestIdentityFromStatusCarriesDeviceAndInode(t *testing.T) {
	got := identityFromStatus(&unix.LoopInfo64{Device: 7, Inode: 42})
	if want := (loopIdentity{dev: 7, inode: 42}); got != want {
		t.Errorf("identityFromStatus() = %+v, want %+v", got, want)
	}
}

func TestRemoveMappingOnAnUnknownNameFails(t *testing.T) {
	err := SystemRemover{}.RemoveMapping(nonexistentMapping)
	if err == nil {
		t.Fatal("RemoveMapping on a name nothing backs = nil, want an error")
	}
	if !strings.Contains(err.Error(), nonexistentMapping) {
		t.Errorf("RemoveMapping error = %v, want it to name %q", err, nonexistentMapping)
	}
}
