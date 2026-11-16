// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package dm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anatol/devmapper.go"
	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/clock"
)

func TestCreateTargetRefusesANameTheIoctlWouldCut(t *testing.T) {
	if _, err := CreateTarget(context.Background(), strings.Repeat("n", 128), "u"); !errors.Is(err, ErrNameTooLong) {
		t.Fatalf("CreateTarget with an oversized name = %v, want ErrNameTooLong", err)
	}
	if _, err := CreateTarget(context.Background(), "n", strings.Repeat("u", 129)); !errors.Is(err, ErrNameTooLong) {
		t.Fatalf("CreateTarget with an oversized UUID = %v, want ErrNameTooLong", err)
	}
	if _, err := CreateTarget(context.Background(), "n\x00ame", "uuid"); !errors.Is(err, ErrNameTooLong) {
		t.Fatalf("CreateTarget with an embedded NUL in the name = %v, want ErrNameTooLong", err)
	}
	if _, err := CreateTarget(context.Background(), "name", "uu\x00id"); !errors.Is(err, ErrNameTooLong) {
		t.Fatalf("CreateTarget with an embedded NUL in the UUID = %v, want ErrNameTooLong", err)
	}
}

func TestCreateTargetHonoursACanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := CreateTarget(ctx, "name", "uuid"); !errors.Is(err, context.Canceled) {
		t.Fatalf("CreateTarget on a canceled context = %v, want context.Canceled", err)
	}
}

func TestRetryWhileBusySucceedsOnTheFirstAttemptWithoutWaiting(t *testing.T) {
	clk := clock.NewFake(t)
	calls := 0
	attempts, err := RetryWhileBusy(context.Background(), clk, func() error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("RetryWhileBusy = %v, want success", err)
	}
	if attempts != 1 || calls != 1 {
		t.Fatalf("RetryWhileBusy ran %d/%d times, want exactly one attempt", attempts, calls)
	}
}

func TestRetryWhileBusyRidesOutATransientHold(t *testing.T) {
	clk := clock.NewFake(t)
	calls := 0
	attempts, err := RetryWhileBusy(context.Background(), clk, func() error {
		calls++
		if calls <= 2 {
			return os.NewSyscallError("dm ioctl", unix.EBUSY)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("RetryWhileBusy = %v, want success once the hold clears", err)
	}
	if attempts != 3 {
		t.Fatalf("RetryWhileBusy attempts = %d, want 3", attempts)
	}
}

func TestRetryWhileBusyGivesUpAtTheBudget(t *testing.T) {
	clk := clock.NewFake(t)
	attempts, err := RetryWhileBusy(context.Background(), clk, func() error {
		return os.NewSyscallError("dm ioctl", unix.EBUSY)
	})
	if !errors.Is(err, unix.EBUSY) {
		t.Fatalf("RetryWhileBusy = %v, want a wrapped EBUSY after the budget is spent", err)
	}
	if attempts < 2 {
		t.Fatalf("RetryWhileBusy attempts = %d, want more than one attempt before giving up", attempts)
	}
}

// The documented budget for a transient hold: 3 seconds in total, starting at
// a 20 ms wait and doubling, with the last wait clipped to what is left.
func TestRetryWhileBusyBacksOffFromTwentyMillisecondsWithinThreeSeconds(t *testing.T) {
	if RemoveRetryBudget != 3*time.Second || RemoveRetryInitialDelay != 20*time.Millisecond {
		t.Fatalf("retry budget = %v from %v, want 3s from 20ms", RemoveRetryBudget, RemoveRetryInitialDelay)
	}
	clk := clock.NewFake(t)
	attempts, _ := RetryWhileBusy(context.Background(), clk, func() error {
		return os.NewSyscallError("dm ioctl", unix.EBUSY)
	})
	waits := clk.Waits()
	if len(waits) != attempts-1 {
		t.Fatalf("waits = %d for %d attempts, want one wait between each pair", len(waits), attempts)
	}
	want := RemoveRetryInitialDelay
	var total time.Duration
	for i, w := range waits {
		if i < len(waits)-1 && w != want {
			t.Fatalf("wait %d = %v, want %v (doubling from %v)", i, w, want, RemoveRetryInitialDelay)
		}
		if i == len(waits)-1 && (w <= 0 || w > want) {
			t.Fatalf("last wait = %v, want the remainder, at most %v", w, want)
		}
		total += w
		want *= 2
	}
	if total != RemoveRetryBudget || clk.Elapsed() != RemoveRetryBudget {
		t.Fatalf("waited %v (elapsed %v), want exactly the %v budget", total, clk.Elapsed(), RemoveRetryBudget)
	}
}

func TestRetryWhileBusyDoesNotRetryWhatCannotClear(t *testing.T) {
	clk := clock.NewFake(t)
	sentinel := errors.New("not EBUSY")
	calls := 0
	_, err := RetryWhileBusy(context.Background(), clk, func() error {
		calls++
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("RetryWhileBusy = %v, want the non-EBUSY error unchanged", err)
	}
	if calls != 1 {
		t.Fatalf("RetryWhileBusy called attempt %d times for a non-EBUSY failure, want exactly one", calls)
	}
}

// TestRetryWhileBusyCancelledDuringWaitReturnsCtxErr is D.2's "dm busy-retry"
// row: a ctx canceled while the backoff is waiting out an EBUSY hold
// surfaces ctx.Err() rather than the wrapped EBUSY, and attempt is not run
// again afterward.
func TestRetryWhileBusyCancelledDuringWaitReturnsCtxErr(t *testing.T) {
	clk := clock.NewFake(t)
	ctx, cancel := context.WithCancel(context.Background())
	clk.OnWait(func(time.Time) { cancel() })

	calls := 0
	attempts, err := RetryWhileBusy(ctx, clk, func() error {
		calls++
		return os.NewSyscallError("dm ioctl", unix.EBUSY)
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RetryWhileBusy canceled mid-wait = %v, want context.Canceled", err)
	}
	if attempts != 1 || calls != 1 {
		t.Fatalf("RetryWhileBusy ran %d/%d attempts after cancellation, want exactly one", attempts, calls)
	}
}

func TestPollUntilReturnsAsSoonAsDoneIsTrue(t *testing.T) {
	clk := clock.NewFake(t)
	calls := 0
	if met, err := PollUntil(context.Background(), clk, time.Second, time.Millisecond, func() bool { calls++; return true }); err != nil || !met {
		t.Fatalf("PollUntil = %v, %v, want true, nil on the first check", met, err)
	}
	if calls != 1 {
		t.Fatalf("PollUntil checked done %d times, want exactly one", calls)
	}
}

func TestPollUntilGivesUpAtTheDeadline(t *testing.T) {
	clk := clock.NewFake(t)
	if met, err := PollUntil(context.Background(), clk, time.Second, 10*time.Millisecond, func() bool { return false }); met || err != nil {
		t.Fatalf("PollUntil = %v, %v, want false, nil when done never succeeds", met, err)
	}
}

// TestPollUntilCancelledDuringWaitReturnsCtxErr is D.2's "/dev/mapper
// readiness, node placement" row: a ctx canceled between polls stops the
// wait and reports ctx.Err(), and done is not consulted again afterward.
func TestPollUntilCancelledDuringWaitReturnsCtxErr(t *testing.T) {
	clk := clock.NewFake(t)
	ctx, cancel := context.WithCancel(context.Background())
	clk.OnWait(func(time.Time) { cancel() })

	calls := 0
	met, err := PollUntil(ctx, clk, time.Second, 10*time.Millisecond, func() bool { calls++; return false })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("PollUntil canceled mid-wait = %v, %v, want ctx.Canceled", met, err)
	}
	if met {
		t.Fatal("PollUntil canceled mid-wait reported met = true")
	}
	if calls != 1 {
		t.Fatalf("PollUntil checked done %d times after cancellation, want exactly one", calls)
	}
}

func TestNodePathMapperPathAndMapperDir(t *testing.T) {
	if got, want := NodePath("/dev", 7), "/dev/dm-7"; got != want {
		t.Errorf("NodePath = %q, want %q", got, want)
	}
	if got, want := MapperPath("/dev", "cryptroot"), "/dev/mapper/cryptroot"; got != want {
		t.Errorf("MapperPath = %q, want %q", got, want)
	}
	if got, want := MapperDir("/dev"), "/dev/mapper"; got != want {
		t.Errorf("MapperDir = %q, want %q", got, want)
	}
}

func TestIsOurNodeTreatsNilInfoAndStatFailureAsNotOurs(t *testing.T) {
	rdev := func(path string) (uint64, error) { return 0, os.ErrNotExist }
	if IsOurNode(rdev, "/dev/dm-3", nil) {
		t.Fatal("IsOurNode = true for nil info, want false")
	}
	okRdev := func(path string) (uint64, error) { return unix.Mkdev(250, 3), nil }
	if IsOurNode(okRdev, "/dev/dm-3", nil) {
		t.Fatal("IsOurNode = true for nil info even with a resolvable path, want false")
	}
	info := &devmapper.DeviceInfo{DevNo: unix.Mkdev(250, 3)}
	if IsOurNode(rdev, "/dev/dm-3", info) {
		t.Fatal("IsOurNode = true when the node cannot be stat'd, want false")
	}
}

// A node is this mapping's only when its device number is the one
// device-mapper reports for the target, including a minor above 255.
func TestIsOurNodeMatchesOnlyTheTargetsDeviceNumber(t *testing.T) {
	info := &devmapper.DeviceInfo{DevNo: unix.Mkdev(253, 300)}
	for _, tc := range []struct {
		name string
		rdev uint64
		want bool
	}{
		{"same device", unix.Mkdev(253, 300), true},
		{"another minor", unix.Mkdev(253, 44), false},
		{"another major", unix.Mkdev(254, 300), false},
	} {
		got := IsOurNode(func(string) (uint64, error) { return tc.rdev, nil }, "/dev/dm-300", info)
		if got != tc.want {
			t.Errorf("%s: IsOurNode = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestIsDanglingSymlink(t *testing.T) {
	dir := t.TempDir()

	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(dir, "live")
	if err := os.Symlink(target, live); err != nil {
		t.Fatal(err)
	}
	if IsDanglingSymlink(live) {
		t.Error("IsDanglingSymlink = true for a symlink whose target exists, want false")
	}

	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "gone"), dangling); err != nil {
		t.Fatal(err)
	}
	if !IsDanglingSymlink(dangling) {
		t.Error("IsDanglingSymlink = false for a symlink whose target is gone, want true")
	}

	if IsDanglingSymlink(target) {
		t.Error("IsDanglingSymlink = true for a regular file, want false")
	}
	if IsDanglingSymlink(filepath.Join(dir, "absent")) {
		t.Error("IsDanglingSymlink = true for a path that does not exist, want false")
	}
}

func TestIsNoSuchDevice(t *testing.T) {
	if !IsNoSuchDevice(unix.ENXIO) {
		t.Error("IsNoSuchDevice(ENXIO) = false, want true")
	}
	if !IsNoSuchDevice(unix.ENODEV) {
		t.Error("IsNoSuchDevice(ENODEV) = false, want true")
	}
	if IsNoSuchDevice(unix.ENOENT) {
		t.Error("IsNoSuchDevice(ENOENT) = true, want false (see the doc comment: ENOENT is not the kernel's answer for an unknown dm target)")
	}
	if IsNoSuchDevice(unix.EPERM) {
		t.Error("IsNoSuchDevice(EPERM) = true, want false")
	}
}

func TestRemoveMappingNodesRemovesOnlyMatchingNodes(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "mapper"), 0o750); err != nil {
		t.Fatal(err)
	}

	info := &devmapper.DeviceInfo{DevNo: unix.Mkdev(250, 3)}
	mapperPath := MapperPath(dir, "ours")
	if err := os.WriteFile(mapperPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	dmPath := NodePath(dir, 3)
	if err := os.WriteFile(dmPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	// blockNodeRdev reports the mapper entry as ours and the dm node as
	// somebody else's, so only the mapper entry should be removed.
	rdev := func(path string) (uint64, error) {
		if path == mapperPath {
			return info.DevNo, nil
		}
		return unix.Mkdev(1, 2), nil
	}
	RemoveMappingNodes(context.Background(), dir, rdev, "ours", info)

	if _, err := os.Lstat(mapperPath); !os.IsNotExist(err) {
		t.Errorf("the matching mapper entry survived removal: %v", err)
	}
	if _, err := os.Lstat(dmPath); err != nil {
		t.Errorf("a non-matching dm node was removed: %v", err)
	}
}

func TestRemoveMappingNodesRemovesADanglingMapperSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "mapper"), 0o750); err != nil {
		t.Fatal(err)
	}
	mapperPath := MapperPath(dir, "stale")
	if err := os.Symlink(filepath.Join(dir, "gone"), mapperPath); err != nil {
		t.Fatal(err)
	}
	rdev := func(path string) (uint64, error) { return 0, os.ErrNotExist }

	RemoveMappingNodes(context.Background(), dir, rdev, "stale", nil)

	if _, err := os.Lstat(mapperPath); !os.IsNotExist(err) {
		t.Errorf("the dangling symlink survived removal: %v", err)
	}
}

func TestPlaceNodeReplacesAStaleSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node")
	if err := os.Symlink(filepath.Join(dir, "old-target"), path); err != nil {
		t.Fatal(err)
	}

	created := false
	err := PlaceNode(context.Background(), path, func(tmp string) error {
		created = true
		return os.WriteFile(tmp, []byte("new"), 0o600)
	})
	if err != nil {
		t.Fatalf("PlaceNode = %v, want success replacing a stale symlink", err)
	}
	if !created {
		t.Fatal("PlaceNode did not call create")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "new" {
		t.Fatalf("PlaceNode left %q, %v; want the new content in place", got, err)
	}
}

func TestPlaceNodeRefusesToReplaceSomethingElses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "control")
	if err := os.WriteFile(path, []byte("not ours"), 0o600); err != nil {
		t.Fatal(err)
	}

	created := false
	err := PlaceNode(context.Background(), path, func(string) error { created = true; return nil })
	if !errors.Is(err, ErrNodeUnverified) {
		t.Fatalf("PlaceNode over a regular file = %v, want ErrNodeUnverified", err)
	}
	if created {
		t.Fatal("PlaceNode called create before refusing a non-stale entry")
	}
}

func TestPlaceNodePropagatesACreateFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node")
	sentinel := errors.New("create failed")

	if err := PlaceNode(context.Background(), path, func(string) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("PlaceNode = %v, want the create error unchanged", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Error("PlaceNode left an entry behind after create failed")
	}
}
