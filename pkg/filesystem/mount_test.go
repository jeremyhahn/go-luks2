// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux && !integration

package filesystem

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// withSys substitutes sys for the duration of the test and restores it with
// t.Cleanup.
func withSys(t *testing.T, mutate func(*sysT)) {
	t.Helper()
	previous := sys
	t.Cleanup(func() { sys = previous })
	mutate(&sys)
}

func TestIsMountedEmptyFile(t *testing.T) {
	tmpDir := t.TempDir()

	mounted, err := IsMounted(t.Context(), tmpDir)
	if err != nil {
		t.Fatalf("IsMounted() error = %v", err)
	}
	if mounted {
		t.Error("IsMounted() = true for non-mounted directory")
	}
}

func TestIsMountedInvalidPath(t *testing.T) {
	mounted, err := IsMounted(t.Context(), "/nonexistent/path/12345")
	if err != nil {
		t.Fatalf("IsMounted() error = %v", err)
	}
	if mounted {
		t.Error("IsMounted() = true for nonexistent path")
	}
}

// recordUnmounts replaces the umount2 seam with one that records its
// arguments and returns result, restoring it afterwards.
func recordUnmounts(t *testing.T, result error) *[]string {
	t.Helper()

	var calls []string
	withSys(t, func(s *sysT) {
		s.unmount = func(target string, _ int) error {
			calls = append(calls, target)
			return result
		}
	})
	return &calls
}

// TestUnmountAsksTheKernelAboutAMountPointWhoseNameHasASpace is the
// regression test for the defect review found in #87, in the #70 change
// that introduced it.
//
// Unmount used to consult IsMounted before calling the syscall. /proc/mounts
// ESCAPES its fields -- a real mount at "/mnt/my disk" is written there as
// "/mnt/my\040disk" -- so the string comparison missed it and Unmount
// returned ErrNotMounted WITHOUT ASKING THE KERNEL, for a mount the kernel
// would have unmounted quite happily.
//
// The assertion is on WHERE IT STOPPED, not on the error: "not a mount
// point" and "refused before asking" are the same value to a caller, and
// only the syscall's absence distinguishes them.
func TestUnmountAsksTheKernelAboutAMountPointWhoseNameHasASpace(t *testing.T) {
	for _, mountPoint := range []string{
		"/mnt/my disk",  // \040, the case review named
		"/mnt/my\tdisk", // \011
		"/mnt/my\ndisk", // \012
		"/mnt/my\\disk", // \134
		"/mnt/ordinary", // the control: an unescaped path must behave the same
	} {
		t.Run(strconv.Quote(mountPoint), func(t *testing.T) {
			calls := recordUnmounts(t, nil)

			if err := Unmount(t.Context(), mountPoint, 0); err != nil {
				t.Fatalf("Unmount = %v, want success once the kernel accepts it", err)
			}
			if len(*calls) != 1 || (*calls)[0] != mountPoint {
				t.Fatalf("the kernel was asked %v, want exactly [%q]", *calls, mountPoint)
			}
		})
	}
}

// TestUnmountReportsTheKernelsRefusalAsErrNotMounted keeps what #70 was for:
// the classification survives, it is just the kernel's answer being
// classified rather than a guess made ahead of it.
func TestUnmountReportsTheKernelsRefusalAsErrNotMounted(t *testing.T) {
	calls := recordUnmounts(t, unix.EINVAL)

	err := Unmount(t.Context(), "/mnt/not-a-mount-point", 0)
	if err == nil {
		t.Fatal("Unmount reported success when the kernel refused")
	}
	if !errors.Is(err, ErrNotMounted) {
		t.Fatalf("Unmount = %v, want an error wrapping ErrNotMounted", err)
	}
	if len(*calls) != 1 {
		t.Fatalf("the kernel was asked %d times, want exactly once", len(*calls))
	}
}

// TestUnmountDoesNotClaimNotMountedForAnyOtherFailure is the other half.
// EINVAL is the only errno that may be read as "not a mount point", and
// reading a busy or unprivileged failure as one would send an operator to
// look at the wrong thing entirely.
func TestUnmountDoesNotClaimNotMountedForAnyOtherFailure(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EBUSY, syscall.EPERM, syscall.ENOENT, syscall.EIO} {
		t.Run(errno.Error(), func(t *testing.T) {
			recordUnmounts(t, errno)

			err := Unmount(t.Context(), "/mnt/somewhere", 0)
			if err == nil {
				t.Fatalf("Unmount reported success on %v", errno)
			}
			if errors.Is(err, ErrNotMounted) {
				t.Fatalf("a %v failure was reported as not-a-mount-point: %v", errno, err)
			}
			if !errors.Is(err, errno) {
				t.Fatalf("the underlying %v is no longer reachable: %v", errno, err)
			}
		})
	}
}

// TestUnmountRefusesFlagsTheKernelWouldAlsoCallEINVAL is what makes the
// classification above sound rather than lucky.
//
// umount2(2) has exactly three causes for EINVAL: the target is not a mount
// point, Expire combined with Force or Detach, and an undefined flag value.
// The last two are the caller's own argument, so refusing them here --
// before the syscall, where no drift is possible -- leaves the first as the
// only reading of an EINVAL that comes back.
func TestUnmountRefusesFlagsTheKernelWouldAlsoCallEINVAL(t *testing.T) {
	refused := []struct {
		name  string
		flags UnmountFlags
	}{
		{"a bit this package does not define", 1 << 10},
		{"Expire with Force", Expire | Force},
		{"Expire with Detach", Expire | Detach},
	}
	for _, tt := range refused {
		t.Run(tt.name, func(t *testing.T) {
			calls := recordUnmounts(t, nil)

			err := Unmount(t.Context(), "/mnt/somewhere", tt.flags)
			if err == nil {
				t.Fatal("Unmount accepted flags the kernel would refuse as EINVAL")
			}
			// Refused as flags and NOT as a missing mount point: reporting
			// this as ErrNotMounted is the exact ambiguity the check removes.
			if errors.Is(err, ErrNotMounted) {
				t.Fatalf("bad flags were reported as not-a-mount-point: %v", err)
			}
			if len(*calls) != 0 {
				t.Fatalf("the syscall was made with flags it would refuse: %v", *calls)
			}
		})
	}

	accepted := []struct {
		name  string
		flags UnmountFlags
	}{
		{"no flags", 0},
		{"Force", Force},
		{"Detach", Detach},
		{"Expire alone", Expire},
	}
	for _, tt := range accepted {
		t.Run(tt.name+" is passed through", func(t *testing.T) {
			calls := recordUnmounts(t, nil)

			if err := Unmount(t.Context(), "/mnt/somewhere", tt.flags); err != nil {
				t.Fatalf("Unmount refused a legal flag combination: %v", err)
			}
			if len(*calls) != 1 {
				t.Fatalf("a legal flag combination did not reach the kernel: %v", *calls)
			}
		})
	}
}

// TestUnmountRefusesACanceledContext checks the ctx boundary check.
func TestUnmountRefusesACanceledContext(t *testing.T) {
	calls := recordUnmounts(t, nil)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := Unmount(ctx, "/mnt/somewhere", 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("Unmount with a canceled context = %v, want context.Canceled", err)
	}
	if len(*calls) != 0 {
		t.Fatalf("the syscall ran with a canceled context: %v", *calls)
	}
}

// TestMountPointListedDecodesTheEscapesTheKernelWrites is the parsing half
// of the same defect, and it matters beyond Unmount: IsMounted is EXPORTED,
// and callers use it to ask whether a path is already mounted.
//
// The table is written by the test rather than read from the host, because
// there is no way to make the host mount something at a path with a newline
// in it -- and that is precisely the case the escaping exists for.
func TestMountPointListedDecodesTheEscapesTheKernelWrites(t *testing.T) {
	// Exactly the four bytes fs/proc_namespace.c mangles.
	const table = "sysfs /sys sysfs rw,nosuid 0 0\n" +
		"/dev/sda1 /mnt/my\\040disk ext4 rw 0 0\n" +
		"/dev/sda2 /mnt/my\\011disk ext4 rw 0 0\n" +
		"/dev/sda3 /mnt/my\\012disk ext4 rw 0 0\n" +
		"/dev/sda4 /mnt/my\\134disk ext4 rw 0 0\n"

	for _, mountPoint := range []string{
		"/sys",
		"/mnt/my disk",
		"/mnt/my\tdisk",
		"/mnt/my\ndisk",
		"/mnt/my\\disk",
	} {
		t.Run(strconv.Quote(mountPoint), func(t *testing.T) {
			listed, err := mountPointListed(strings.NewReader(table), mountPoint)
			if err != nil {
				t.Fatalf("mountPointListed failed: %v", err)
			}
			if !listed {
				t.Fatalf("%q is in the table and was not found; the escapes are being compared raw", mountPoint)
			}
		})
	}

	// And it must not start matching things that are not there -- an
	// unescaper that mangled every field would pass the cases above and
	// break this one.
	for _, absent := range []string{"/mnt/my", "/mnt/my\\040disk", "/mnt/elsewhere"} {
		t.Run("absent "+strconv.Quote(absent), func(t *testing.T) {
			listed, err := mountPointListed(strings.NewReader(table), absent)
			if err != nil {
				t.Fatalf("mountPointListed failed: %v", err)
			}
			if listed {
				t.Fatalf("%q is not in the table and was reported as mounted", absent)
			}
		})
	}
}

// TestIsMountedReadsTheRealMountTable is the control for the wrapper the
// tests above bypass: whatever mountPointListed does, IsMounted has to be
// reading /proc/mounts and handing it over.
func TestIsMountedReadsTheRealMountTable(t *testing.T) {
	mounted, err := IsMounted(t.Context(), "/proc")
	if err != nil {
		t.Fatalf("IsMounted(/proc) failed: %v", err)
	}
	if !mounted {
		t.Fatal("IsMounted does not see /proc as a mount point")
	}

	dir := t.TempDir()
	if mounted, err := IsMounted(t.Context(), dir); err != nil || mounted {
		t.Fatalf("IsMounted(%s) = %v, %v; want false, nil", dir, mounted, err)
	}
}

// TestDeviceMountedMatchesTheDeviceNumber pins DeviceMounted's matching
// rule: it compares the DEVICE NUMBER mountinfo records (field 3, proc(5)),
// not a path, so a filesystem mounted through a different alias to the same
// device is still seen, and a different device at the same-looking number is
// not confused with it.
func TestDeviceMountedMatchesTheDeviceNumber(t *testing.T) {
	const table = "1 2 253:7 / /mnt/a rw - ext4 /dev/dm-7 rw\n" +
		"3 4 253:70 / /mnt/b rw - ext4 /dev/dm-70 rw\n"

	dir := t.TempDir()
	path := dir + "/mountinfo"
	if err := os.WriteFile(path, []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	withSys(t, func(s *sysT) { s.mountInfoPath = path })

	if mounted, err := DeviceMounted(t.Context(), 253, 7); err != nil || !mounted {
		t.Fatalf("DeviceMounted(253, 7) = %v, %v; want true", mounted, err)
	}
	// 253:70 must not be matched by a prefix comparison against "253:7".
	if mounted, err := DeviceMounted(t.Context(), 253, 700); err != nil || mounted {
		t.Fatalf("DeviceMounted(253, 700) = %v, %v; want false", mounted, err)
	}
	if mounted, err := DeviceMounted(t.Context(), 253, 99); err != nil || mounted {
		t.Fatalf("DeviceMounted(253, 99) = %v, %v; want false", mounted, err)
	}
}

// TestDeviceMountedFailsWhenTheTableCannotBeOpened makes the error path
// explicit rather than silently reporting "not mounted".
func TestDeviceMountedFailsWhenTheTableCannotBeOpened(t *testing.T) {
	withSys(t, func(s *sysT) { s.mountInfoPath = "/nonexistent/mountinfo/path" })
	if _, err := DeviceMounted(t.Context(), 1, 1); err == nil {
		t.Fatal("DeviceMounted succeeded reading a path that does not exist")
	}
}

// TestMountRefusesAMissingMountPoint checks the early stat before any probe
// or syscall.
func TestMountRefusesAMissingMountPoint(t *testing.T) {
	err := Mount(t.Context(), MountParams{Source: "/dev/mapper/vol", Target: "/nonexistent/mount/point", Type: Ext4})
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("Mount = %v, want a refusal naming the missing mount point", err)
	}
}

// TestMountDetectsTheFilesystemWhenNoTypeIsNamed pins Mount's auto-detect
// path through to the real mount(2) seam, using a fake blkid so it needs
// neither root nor a real device.
func TestMountDetectsTheFilesystemWhenNoTypeIsNamed(t *testing.T) {
	fakeTools(t, map[string]fakeTool{"blkid": {stdout: "TYPE=xfs\nUSAGE=filesystem\n"}})

	var gotFSType string
	withSys(t, func(s *sysT) {
		s.mount = func(source, target, fstype string, flags uintptr, data string) error {
			gotFSType = fstype
			return nil
		}
	})

	dir := t.TempDir()
	if err := Mount(t.Context(), MountParams{Source: "/dev/mapper/vol", Target: dir}); err != nil {
		t.Fatalf("Mount = %v, want nil", err)
	}
	if gotFSType != "xfs" {
		t.Fatalf("mount(2) was called with fstype %q, want the detected xfs", gotFSType)
	}
}

// TestMountReportsAnUndetectedFilesystem: with no Type and nothing blkid
// recognizes, Mount is refused rather than guessing, and the mount(2)
// syscall never runs.
func TestMountReportsAnUndetectedFilesystem(t *testing.T) {
	fakeTools(t, map[string]fakeTool{"blkid": {code: blkidNothingFound}})

	called := false
	withSys(t, func(s *sysT) {
		s.mount = func(source, target, fstype string, flags uintptr, data string) error {
			called = true
			return nil
		}
	})

	dir := t.TempDir()
	err := Mount(t.Context(), MountParams{Source: "/dev/mapper/vol", Target: dir})
	if !errors.Is(err, ErrNotDetected) {
		t.Fatalf("Mount = %v, want ErrNotDetected", err)
	}
	if called {
		t.Fatal("mount(2) was called although the filesystem could not be detected")
	}
}

// TestMountRefusesACanceledContext checks the ctx boundary check.
func TestMountRefusesACanceledContext(t *testing.T) {
	called := false
	withSys(t, func(s *sysT) {
		s.mount = func(source, target, fstype string, flags uintptr, data string) error {
			called = true
			return nil
		}
	})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	dir := t.TempDir()
	if err := Mount(ctx, MountParams{Source: "/dev/mapper/vol", Target: dir, Type: Ext4}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Mount with a canceled context = %v, want context.Canceled", err)
	}
	if called {
		t.Fatal("mount(2) was called with a canceled context")
	}
}
