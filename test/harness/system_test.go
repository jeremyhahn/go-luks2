// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"errors"
	"strings"
	"testing"
)

// TestSystemRemoverRefusesADeviceItCouldNotIdentify tests the REAL remover, not
// the fake, and that distinction is the point.
//
// Every other test of this behavior in this package drives fakeRemover. A fake
// that refuses proves the fake refuses. The finding on 974bf2de was against
// SystemRemover.DetachLoop specifically -- it reached LOOP_CLR_FD on a device it
// had just declared it could not identify -- so the guard has to be asserted
// against the code that issues the ioctl.
//
// It needs no privilege and no loop device, because of WHERE the refusal sits:
// before the open. The device path below does not exist, and that is the
// assertion. If the refusal were moved after the open -- the natural place to
// put it, and where the previous version's equivalent check lived -- this test
// would report "no such file or directory" instead, and fail. So it pins the
// ORDER, which is the property that makes the guard unconditional rather than
// dependent on the device still being there.
func TestSystemRemoverRefusesADeviceItCouldNotIdentify(t *testing.T) {
	capture := errors.New("input/output error")

	err := SystemRemover{}.DetachLoop(LoopDevice{
		Path:          "/dev/loop-does-not-exist",
		Backing:       "/tmp/go-luks2-run-abc/x.img",
		IdentityKnown: false,
		IdentityErr:   capture,
	})
	if err == nil {
		t.Fatal("DetachLoop = nil -- the real remover cleared a device whose identity it never captured")
	}
	if !errors.Is(err, capture) {
		t.Errorf("error = %v, want it to carry why the capture failed", err)
	}
	if strings.Contains(err.Error(), "no such file") {
		t.Errorf("error = %v -- the refusal ran AFTER opening the device, so it is conditional on the "+
			"device still existing rather than on the identity being unknown", err)
	}
	if !strings.Contains(err.Error(), "/dev/loop-does-not-exist") {
		t.Errorf("error = %v, want it to name the device it refused", err)
	}
}

// TestSystemRemoverRefusesADeviceCarryingNoIdentityAtAll covers the same branch
// reached with no reason attached.
//
// IdentityKnown false with a nil IdentityErr is not a state the enumeration
// produces -- but it IS the zero value of LoopDevice, so it is what any future
// caller that builds one by hand will hand over. The dangerous version of this
// code is the one where a zero-valued device is the permissive case.
func TestSystemRemoverRefusesADeviceCarryingNoIdentityAtAll(t *testing.T) {
	err := SystemRemover{}.DetachLoop(LoopDevice{Path: "/dev/loop-does-not-exist"})
	if err == nil {
		t.Fatal("DetachLoop = nil for a zero-valued LoopDevice -- an unidentified device was cleared")
	}
	if strings.Contains(err.Error(), "no such file") {
		t.Errorf("error = %v -- the refusal ran after the open", err)
	}
}

// TestLoopIdentityIsReportedReadably keeps the refusal message useful: it names
// two identities, and "{66307 12345}" in a CI log tells nobody anything.
func TestLoopIdentityIsReportedReadably(t *testing.T) {
	got := loopIdentity{dev: 66307, inode: 16515163}.String()
	for _, want := range []string{"66307", "16515163", "dev", "inode"} {
		if !strings.Contains(got, want) {
			t.Errorf("loopIdentity.String() = %q, want it to contain %q", got, want)
		}
	}
}
