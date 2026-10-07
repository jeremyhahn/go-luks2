// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux && !integration

package filesystem

import (
	"context"
	"errors"
	"testing"
)

// TestEveryEntryClassifiesACanceledCtxAndStampsOpAndPath is S4 and S12: a
// canceled ctx is an *Error whose Kind is the ctx's own error, never the raw
// ctx.Err(), and every exported entry fills Op and Path.
func TestEveryEntryClassifiesACanceledCtxAndStampsOpAndPath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for _, tc := range []struct {
		op, path string
		call     func() error
	}{
		{"Mount", "/dev/x", func() error { return Mount(ctx, MountParams{Source: "/dev/x", Target: "/t"}) }},
		{"DeviceMounted", "", func() error { _, err := DeviceMounted(ctx, 1, 2); return err }},
		{"Unmount", "/t", func() error { return Unmount(ctx, "/t", 0) }},
		{"IsMounted", "/t", func() error { _, err := IsMounted(ctx, "/t"); return err }},
		{"Make", "/dev/x", func() error { return Make(ctx, "/dev/x", Ext4, MakeParams{}) }},
		{"Check", "/dev/x", func() error { _, err := Check(ctx, "/dev/x", Ext4); return err }},
		{"Repair", "/dev/x", func() error { _, err := Repair(ctx, "/dev/x", Ext4); return err }},
		{"Detect", "/dev/x", func() error { _, err := Detect(ctx, "/dev/x"); return err }},
		{"Inspect", "/dev/x", func() error { _, err := Inspect(ctx, "/dev/x"); return err }},
	} {
		t.Run(tc.op, func(t *testing.T) {
			err := tc.call()
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("%s with a canceled ctx = %#v, want an *Error", tc.op, err)
			}
			if e.Kind != context.Canceled {
				t.Errorf("Kind = %v, want context.Canceled", e.Kind)
			}
			if e.Op != tc.op || e.Path != tc.path {
				t.Errorf("Op, Path = %q, %q; want %q, %q", e.Op, e.Path, tc.op, tc.path)
			}
		})
	}
}

// TestMakeStampsOpAndPathOnARefusal: errors that are not about the ctx are
// stamped too.
func TestMakeStampsOpAndPathOnARefusal(t *testing.T) {
	err := Make(context.Background(), "/dev/x", Type("ntfs"), MakeParams{})
	var e *Error
	if !errors.As(err, &e) || !errors.Is(err, ErrUnsupported) || e.Op != "Make" || e.Path != "/dev/x" {
		t.Fatalf("Make(ntfs) = %#v, want ErrUnsupported with Op Make and Path /dev/x", err)
	}
}
