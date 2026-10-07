// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/pkg/filesystem"
)

func TestRunMountDetectsAndMounts(t *testing.T) {
	target := filepath.Join(t.TempDir(), "mnt")
	e, act, mnt, stdout, _ := newTestEnv(&bytes.Buffer{})
	act.mapping = mapping{name: "myvolume"}
	mnt.detected = filesystem.Ext4

	if err := runMount(context.Background(), e, []string{"myvolume", target}); err != nil {
		t.Fatalf("runMount: %v", err)
	}
	if len(mnt.mountCalls) != 1 {
		t.Fatalf("mountCalls = %d, want 1", len(mnt.mountCalls))
	}
	got := mnt.mountCalls[0]
	if got.Source != "/dev/mapper/myvolume" {
		t.Errorf("Source = %q, want /dev/mapper/myvolume", got.Source)
	}
	if got.Target != target {
		t.Errorf("Target = %q, want %q", got.Target, target)
	}
	if got.Type != filesystem.Ext4 {
		t.Errorf("Type = %q, want ext4", got.Type)
	}
	if !strings.Contains(stdout.String(), "Mounted") {
		t.Errorf("stdout = %q, want it to report success", stdout.String())
	}
}

func TestRunMountExplicitType(t *testing.T) {
	target := filepath.Join(t.TempDir(), "mnt")
	e, act, mnt, _, _ := newTestEnv(&bytes.Buffer{})
	act.mapping = mapping{name: "myvolume"}

	if err := runMount(context.Background(), e, []string{"--type", "xfs", "myvolume", target}); err != nil {
		t.Fatalf("runMount: %v", err)
	}
	if mnt.mountCalls[0].Type != filesystem.XFS {
		t.Errorf("Type = %q, want xfs", mnt.mountCalls[0].Type)
	}
}

// TestRunMountDefaultsToNosuidNodev is S3: a filesystem on an encrypted volume
// is untrusted content, so setuid files and device nodes on it are inert
// unless the operator opts in.
func TestRunMountDefaultsToNosuidNodev(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want uintptr
	}{
		{nil, unix.MS_NOSUID | unix.MS_NODEV},
		{[]string{"--allow-suid"}, unix.MS_NODEV},
		{[]string{"--allow-dev"}, unix.MS_NOSUID},
		{[]string{"--allow-suid", "--allow-dev"}, 0},
	} {
		e, act, mnt, _, _ := newTestEnv(&bytes.Buffer{})
		act.mapping = mapping{name: "myvolume"}
		mnt.detected = filesystem.Ext4

		args := append(tc.args, "myvolume", filepath.Join(t.TempDir(), "mnt"))
		if err := runMount(context.Background(), e, args); err != nil {
			t.Fatalf("runMount %v: %v", tc.args, err)
		}
		if got := mnt.mountCalls[0].Flags; got != tc.want {
			t.Errorf("runMount %v: Flags = %#x, want %#x", tc.args, got, tc.want)
		}
	}
}

// TestRunMountMakesTheTargetAbsolute is S3: a relative mount point is
// resolved against the working directory once, before anything uses it.
func TestRunMountMakesTheTargetAbsolute(t *testing.T) {
	t.Chdir(t.TempDir())
	e, act, mnt, _, _ := newTestEnv(&bytes.Buffer{})
	act.mapping = mapping{name: "myvolume"}
	mnt.detected = filesystem.Ext4

	if err := runMount(context.Background(), e, []string{"myvolume", "./a/../mnt"}); err != nil {
		t.Fatalf("runMount: %v", err)
	}
	got := mnt.mountCalls[0].Target
	if !filepath.IsAbs(got) || filepath.Base(got) != "mnt" || strings.Contains(got, "..") {
		t.Errorf("Target = %q, want a clean absolute path ending in mnt", got)
	}
}

func TestRunMountRefusesAnAlreadyMountedTarget(t *testing.T) {
	target := filepath.Join(t.TempDir(), "mnt")
	e, _, mnt, _, _ := newTestEnv(&bytes.Buffer{})
	mnt.mounted = true

	if err := runMount(context.Background(), e, []string{"myvolume", target}); err == nil {
		t.Fatal("runMount: want an error when the target is already mounted")
	}
	if len(mnt.mountCalls) != 0 {
		t.Error("mount should not have been called")
	}
}

func TestRunMountLookupFailurePropagates(t *testing.T) {
	e, act, _, _, _ := newTestEnv(&bytes.Buffer{})
	act.lookupErr = errors.New("no such mapping")

	if err := runMount(context.Background(), e, []string{"myvolume", "/mnt/x"}); err == nil {
		t.Fatal("runMount: want the lookup error")
	}
}

func TestRunMountMissingArgs(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	if err := runMount(context.Background(), e, []string{"onlyone"}); err == nil {
		t.Fatal("runMount: want a usage error with one argument")
	}
}

func TestRunUnmount(t *testing.T) {
	e, _, mnt, stdout, _ := newTestEnv(&bytes.Buffer{})
	mnt.mounted = true

	if err := runUnmount(context.Background(), e, []string{"/mnt/x"}); err != nil {
		t.Fatalf("runUnmount: %v", err)
	}
	if len(mnt.unmountCalls) != 1 || mnt.unmountCalls[0] != "/mnt/x" {
		t.Errorf("unmountCalls = %v, want [/mnt/x]", mnt.unmountCalls)
	}
	if !strings.Contains(stdout.String(), "Unmounted") {
		t.Errorf("stdout = %q, want it to report success", stdout.String())
	}
}

// TestRunUnmountRefusesWhenNotMounted also locks docs/volumes/cli.md's
// "Not mounted" text, which the pre-rewrite CLI printed on stderr for this
// refusal.
func TestRunUnmountRefusesWhenNotMounted(t *testing.T) {
	e, _, mnt, _, stderr := newTestEnv(&bytes.Buffer{})
	mnt.mounted = false

	if err := runUnmount(context.Background(), e, []string{"/mnt/x"}); err == nil {
		t.Fatal("runUnmount: want an error when the target is not mounted")
	}
	if len(mnt.unmountCalls) != 0 {
		t.Error("unmount should not have been called")
	}
	if !strings.Contains(stderr.String(), "Not mounted") {
		t.Errorf("stderr = %q, want it to report 'Not mounted'", stderr.String())
	}
}

func TestRunUnmountMissingArgs(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	if err := runUnmount(context.Background(), e, nil); err == nil {
		t.Fatal("runUnmount: want a usage error with no arguments")
	}
}
