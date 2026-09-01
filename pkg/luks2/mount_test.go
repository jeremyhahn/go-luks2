// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestIsMounted_EmptyFile(t *testing.T) {
	// Test with a non-mounted path
	tmpDir, err := os.MkdirTemp("", "luks-mount-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	mounted, err := IsMounted(tmpDir)
	if err != nil {
		t.Fatalf("IsMounted() error = %v", err)
	}
	if mounted {
		t.Error("IsMounted() = true for non-mounted directory")
	}
}

func TestIsMounted_InvalidPath(t *testing.T) {
	mounted, err := IsMounted("/nonexistent/path/12345")
	if err != nil {
		t.Fatalf("IsMounted() error = %v", err)
	}
	if mounted {
		t.Error("IsMounted() = true for nonexistent path")
	}
}

func TestMountOptions_Defaults(t *testing.T) {
	opts := MountOptions{
		Device:     "test-device",
		MountPoint: "/mnt/test",
		FSType:     "ext4",
	}

	if opts.Device != "test-device" {
		t.Errorf("Device = %q, want %q", opts.Device, "test-device")
	}
	if opts.MountPoint != "/mnt/test" {
		t.Errorf("MountPoint = %q, want %q", opts.MountPoint, "/mnt/test")
	}
	if opts.FSType != "ext4" {
		t.Errorf("FSType = %q, want %q", opts.FSType, "ext4")
	}
	if opts.Flags != 0 {
		t.Errorf("Flags = %d, want 0", opts.Flags)
	}
	if opts.Data != "" {
		t.Errorf("Data = %q, want empty string", opts.Data)
	}
}

// ErrNotMounted and ErrVolumeNotUnlocked were declared and returned by nothing
// (#70). ErrAlreadyMounted was DELETED rather than wired -- see Mount's doc
// comment: Linux permits stacking a mount over an existing mount point, so
// "already mounted" is a legal state and not a condition this package can
// honestly refuse.

// recordUnmounts replaces the umount2 seam with one that records its arguments
// and returns result, restoring it afterwards.
func recordUnmounts(t *testing.T, result error) *[]string {
	t.Helper()

	previous := unmountFunc
	t.Cleanup(func() { unmountFunc = previous })

	var calls []string
	unmountFunc = func(target string, _ int) error {
		calls = append(calls, target)
		return result
	}
	return &calls
}

// TestUnmountAsksTheKernelAboutAMountPointWhoseNameHasASpace is the regression
// test for the defect review found in #87, in the #70 change that introduced
// it.
//
// Unmount consulted IsMounted before calling the syscall. /proc/mounts ESCAPES
// its fields -- a real mount at "/mnt/my disk" is written there as
// "/mnt/my\040disk" -- so the string comparison missed it and Unmount returned
// ErrNotMounted WITHOUT ASKING THE KERNEL, for a mount the kernel would have
// unmounted quite happily.
//
// The assertion is on WHERE IT STOPPED, not on the error: "not a mount point"
// and "refused before asking" are the same value to a caller, and only the
// syscall's absence distinguishes them.
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

			if err := Unmount(mountPoint, 0); err != nil {
				t.Fatalf("Unmount = %v, want success once the kernel accepts it", err)
			}
			if len(*calls) != 1 || (*calls)[0] != mountPoint {
				t.Fatalf("the kernel was asked %v, want exactly [%q]", *calls, mountPoint)
			}
		})
	}
}

// TestUnmountReportsTheKernelsRefusalAsErrNotMounted keeps what #70 was for:
// the classification survives, it is just the kernel's answer being classified
// rather than a guess made ahead of it.
func TestUnmountReportsTheKernelsRefusalAsErrNotMounted(t *testing.T) {
	calls := recordUnmounts(t, unix.EINVAL)

	err := Unmount("/mnt/not-a-mount-point", 0)
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

// TestUnmountDoesNotClaimNotMountedForAnyOtherFailure is the other half. EINVAL
// is the only errno that may be read as "not a mount point", and reading a busy
// or unprivileged failure as one would send an operator to look at the wrong
// thing entirely.
func TestUnmountDoesNotClaimNotMountedForAnyOtherFailure(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EBUSY, syscall.EPERM, syscall.ENOENT, syscall.EIO} {
		t.Run(errno.Error(), func(t *testing.T) {
			recordUnmounts(t, errno)

			err := Unmount("/mnt/somewhere", 0)
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
// point, MNT_EXPIRE combined with MNT_FORCE or MNT_DETACH, and an undefined
// flag value. The last two are the caller's own argument, so refusing them here
// -- before the syscall, where no drift is possible -- leaves the first as the
// only reading of an EINVAL that comes back.
func TestUnmountRefusesFlagsTheKernelWouldAlsoCallEINVAL(t *testing.T) {
	refused := []struct {
		name  string
		flags int
	}{
		{"a bit umount2 does not define", 1 << 20},
		{"MNT_EXPIRE with MNT_FORCE", unix.MNT_EXPIRE | unix.MNT_FORCE},
		{"MNT_EXPIRE with MNT_DETACH", unix.MNT_EXPIRE | unix.MNT_DETACH},
	}
	for _, tt := range refused {
		t.Run(tt.name, func(t *testing.T) {
			calls := recordUnmounts(t, nil)

			err := Unmount("/mnt/somewhere", tt.flags)
			if err == nil {
				t.Fatal("Unmount accepted flags the kernel would refuse as EINVAL")
			}
			// Refused as flags and NOT as a missing mount point: reporting this
			// as ErrNotMounted is the exact ambiguity the check removes.
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
		flags int
	}{
		{"no flags", 0},
		{"MNT_FORCE", unix.MNT_FORCE},
		{"MNT_DETACH", unix.MNT_DETACH},
		{"MNT_EXPIRE alone", unix.MNT_EXPIRE},
		{"UMOUNT_NOFOLLOW with MNT_DETACH", unix.UMOUNT_NOFOLLOW | unix.MNT_DETACH},
	}
	for _, tt := range accepted {
		t.Run(tt.name+" is passed through", func(t *testing.T) {
			calls := recordUnmounts(t, nil)

			if err := Unmount("/mnt/somewhere", tt.flags); err != nil {
				t.Fatalf("Unmount refused a legal flag combination: %v", err)
			}
			if len(*calls) != 1 {
				t.Fatalf("a legal flag combination did not reach the kernel: %v", *calls)
			}
		})
	}
}

// TestMountPointListedDecodesTheEscapesTheKernelWrites is the parsing half of
// the same defect, and it matters beyond Unmount: IsMounted is EXPORTED, the
// CLI branches on it in three places, and Mount's doc comment points callers at
// it as the way to ask whether a path is already mounted.
//
// The table is written by the test rather than read from the host, because
// there is no way to make the host mount something at a path with a newline in
// it -- and that is precisely the case the escaping exists for.
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

	// And it must not start matching things that are not there -- an unescaper
	// that mangled every field would pass the cases above and break this one.
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

// TestIsMountedReadsTheRealMountTable is the control for the wrapper the tests
// above bypass: whatever mountPointListed does, IsMounted has to be reading
// /proc/mounts and handing it over.
func TestIsMountedReadsTheRealMountTable(t *testing.T) {
	mounted, err := IsMounted("/proc")
	if err != nil {
		t.Fatalf("IsMounted(/proc) failed: %v", err)
	}
	if !mounted {
		t.Fatal("IsMounted does not see /proc as a mount point")
	}

	dir := t.TempDir()
	if mounted, err := IsMounted(dir); err != nil || mounted {
		t.Fatalf("IsMounted(%s) = %v, %v; want false, nil", dir, mounted, err)
	}
}

// TestMountReportsAVolumeThatIsNotUnlocked pins ErrVolumeNotUnlocked on the
// other path that raises it. The message was already right ("is it unlocked?");
// what was missing was the type a caller can branch on.
func TestMountReportsAVolumeThatIsNotUnlocked(t *testing.T) {
	withDevDir(t, t.TempDir())

	err := Mount(MountOptions{
		Device:     "no-such-mapping",
		MountPoint: t.TempDir(),
		FSType:     "ext4",
	})
	if err == nil {
		t.Fatal("Mount reported success for a volume that is not unlocked")
	}
	if !errors.Is(err, ErrVolumeNotUnlocked) {
		t.Fatalf("Mount = %v, want an error wrapping ErrVolumeNotUnlocked", err)
	}
}
