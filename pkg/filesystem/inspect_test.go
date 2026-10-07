// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux && !integration

package filesystem

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// TestInspectReadsBlkidsExport pins the blkid invocation and the parse: the
// four fields blkid reports are read, anything else -- including a line
// that is not KEY=VALUE -- is ignored.
func TestInspectReadsBlkidsExport(t *testing.T) {
	record := fakeTools(t, map[string]fakeTool{"blkid": {stdout: "DEVNAME=/dev/mapper/vol\n" +
		"UUID=2f6e1b3a-0c1d-4e5f-8a9b-0c1d2e3f4a5b\nBLOCK_SIZE=4096\nTYPE=ext4\nLABEL=data=archive\nnot an assignment\n"}})
	info, err := Inspect(t.Context(), "/dev/mapper/vol")
	if err != nil {
		t.Fatalf("Inspect = %v", err)
	}
	want := Info{Type: Ext4, Label: "data=archive", UUID: "2f6e1b3a-0c1d-4e5f-8a9b-0c1d2e3f4a5b", BlockSize: 4096}
	if *info != want {
		t.Errorf("Inspect = %+v, want %+v", *info, want)
	}
	if got := record("blkid"); !reflect.DeepEqual(got, []string{"-o", "export", "--", "/dev/mapper/vol"}) {
		t.Errorf("blkid ran with %q", got)
	}
}

// TestInspectFailsWhenBlkidDoes: blkid exits 2 when it finds no filesystem,
// and that is an error, not an empty Info a caller would read as "no label,
// no type".
func TestInspectFailsWhenBlkidDoes(t *testing.T) {
	fakeTools(t, map[string]fakeTool{"blkid": {code: 2}})
	if info, err := Inspect(t.Context(), "/dev/mapper/vol"); err == nil || !strings.Contains(err.Error(), "blkid failed") {
		t.Fatalf("Inspect = %+v, %v; want blkid's failure", info, err)
	}
}

// TestInspectRefusesACanceledContext checks the ctx boundary check.
func TestInspectRefusesACanceledContext(t *testing.T) {
	record := fakeTools(t, map[string]fakeTool{"blkid": {}})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Inspect(ctx, "/dev/mapper/vol"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Inspect with a canceled context = %v, want context.Canceled", err)
	}
	if got := record("blkid"); got != nil {
		t.Fatalf("blkid ran with %q, want it not run at all", got)
	}
}
