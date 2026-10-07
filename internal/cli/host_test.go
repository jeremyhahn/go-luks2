// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/filesystem"
)

func TestMappingPath(t *testing.T) {
	m := mapping{name: "myvolume"}
	if got := m.path(); got != "/dev/mapper/myvolume" {
		t.Errorf("path() = %q, want /dev/mapper/myvolume", got)
	}
}

// TestRealMounterDelegates exercises every realMounter method against the
// real pkg/filesystem, with inputs chosen only to reach the delegation
// (none of these need root or a real mount): each is expected to fail, and
// the point is that the call reaches pkg/filesystem rather than what it
// answers.
func TestRealMounterDelegates(t *testing.T) {
	var m realMounter
	ctx := context.Background()

	if err := m.mount(ctx, filesystem.MountParams{Source: "/nonexistent", Target: "/nonexistent"}); err == nil {
		t.Error("mount: want an error for a nonexistent target")
	}
	if err := m.unmount(ctx, "/nonexistent", 0); err == nil {
		t.Error("unmount: want an error for a nonexistent target")
	}
	if _, err := m.isMounted(ctx, "/nonexistent"); err != nil {
		t.Errorf("isMounted: %v", err)
	}
	if _, err := m.deviceMounted(ctx, 0, 0); err != nil {
		t.Errorf("deviceMounted: %v", err)
	}
	if _, err := m.detect(ctx, "/nonexistent"); err == nil {
		t.Error("detect: want an error for a nonexistent device")
	}
}
