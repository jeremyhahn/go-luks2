// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRemover is a kernel stand-in whose success returns are backed by the same
// state change the real one makes: RemoveMapping actually deletes from the map
// it reports from. A fake that reported success without changing its own state
// would make every assertion below decoration.
type fakeRemover struct {
	mappings map[string]string   // name -> uuid
	loops    map[string][]string // backing file -> devices

	removeErr  map[string]error
	detachErr  map[string]error
	inspectErr map[string]error

	removed  []string
	detached []string

	// refuseToActuallyRemove models the dangerous case: the kernel returns
	// success and the resource is still there.
	refuseToActuallyRemove bool

	// holdLoopUntilMappingGone models the kernel refusing to release a loop
	// device while a dm target still sits on it: device -> holding mapping.
	holdLoopUntilMappingGone map[string]string

	// detachVisibleAfterQueries models the asynchronous half of LOOP_CLR_FD:
	// the detach succeeds, but sysfs keeps reporting the device for this many
	// further queries.
	detachVisibleAfterQueries int
	pendingDetach             map[string]int

	// failVerificationAfterRemoval models the kernel becoming unreadable at the
	// worst moment: the removal succeeds and the CONFIRMATION errors, so the
	// reaper knows it acted and does not know whether it worked.
	failVerificationAfterRemoval bool
	loopQueryErr                 error

	// loopLookupErr fails the FIRST enumeration, modeling a sysfs read that
	// cannot be completed at all.
	loopLookupErr error

	// reassignBeforeDetach models the loop number being released and reused
	// between enumeration and detach: device -> its new backing file.
	reassignBeforeDetach map[string]string

	// releaseBeforeDetach models the device being released -- bound to nothing
	// -- between enumeration and detach, which is what a test's own cleanup
	// does and what the kernel reports as ENXIO.
	releaseBeforeDetach map[string]bool

	// identityUnknown models the enumeration failing to capture a device's
	// identity: device -> true. The device is still enumerated, carrying the
	// failure, because a scan that silently dropped it would report the ledger
	// entry AlreadyGone for a device that is still attached.
	identityUnknown map[string]bool

	removeDirErr map[string]error
	removedDirs  []string
}

func newFakeRemover() *fakeRemover {
	return &fakeRemover{
		mappings:     map[string]string{},
		loops:        map[string][]string{},
		removeErr:    map[string]error{},
		removeDirErr: map[string]error{},
		detachErr:    map[string]error{},
		inspectErr:   map[string]error{},
	}
}

func (f *fakeRemover) MappingIdentity(name string) (string, bool, error) {
	if err := f.inspectErr[name]; err != nil {
		return "", false, err
	}
	if f.failVerificationAfterRemoval && slices.Contains(f.removed, name) {
		return "", false, errors.New("dm inventory is temporarily unreadable")
	}
	uuid, ok := f.mappings[name]
	return uuid, ok, nil
}

func (f *fakeRemover) RemoveMapping(name string) error {
	if err := f.removeErr[name]; err != nil {
		return err
	}
	f.removed = append(f.removed, name)
	if !f.refuseToActuallyRemove {
		delete(f.mappings, name)
	}
	return nil
}

func (f *fakeRemover) LoopDevicesFor(backingFile string) ([]LoopDevice, error) {
	var out []LoopDevice
	for _, dev := range f.loops[backingFile] {
		out = append(out, f.enumerate(dev, backingFile))
	}
	return f.visible(out), nil
}

// visible applies the settle delay: a device whose detach has been issued is
// still reported until its countdown reaches zero, which is what sysfs does.
func (f *fakeRemover) visible(devices []LoopDevice) []LoopDevice {
	out := devices
	for dev, left := range f.pendingDetach {
		if left <= 0 {
			continue
		}
		f.pendingDetach[dev] = left - 1
		if !slices.ContainsFunc(out, func(d LoopDevice) bool { return d.Path == dev }) {
			out = append(out, f.enumerate(dev, "pending"))
		}
	}
	slices.SortFunc(out, func(a, b LoopDevice) int { return strings.Compare(a.Path, b.Path) })
	return out
}

func (f *fakeRemover) LoopDevicesUnder(dir string) ([]LoopDevice, error) {
	if f.loopLookupErr != nil {
		return nil, f.loopLookupErr
	}
	if f.loopQueryErr != nil && len(f.detached) > 0 {
		return nil, f.loopQueryErr
	}
	var out []LoopDevice
	prefix := dir + "/"
	for backing, devices := range f.loops {
		if !strings.HasPrefix(backing, prefix) {
			continue
		}
		for _, dev := range devices {
			out = append(out, f.enumerate(dev, backing))
		}
	}
	return f.visible(out), nil
}

// enumerate builds the LoopDevice the real enumeration would build: the device,
// what it is backed by, and the kernel identity of that binding.
//
// identityUnknown models the capture FAILING -- the ioctl returning something
// other than ENXIO -- which the real enumeration carries through rather than
// dropping, so the detach can refuse it by name.
func (f *fakeRemover) enumerate(device, backing string) LoopDevice {
	if f.identityUnknown[device] {
		return LoopDevice{
			Path:        device,
			Backing:     backing,
			IdentityErr: fmt.Errorf("reading the status of %s to capture its identity: input/output error", device),
		}
	}
	return LoopDevice{
		Path:          device,
		Backing:       backing,
		Identity:      fakeIdentityOf(backing),
		IdentityKnown: true,
	}
}

// fakeIdentityOf stands in for lo_device/lo_inode. The property that matters is
// the one the kernel has: the identity follows the BOUND FILE, so re-binding a
// device to something else changes it, and nothing about the device NUMBER
// appears in it.
func fakeIdentityOf(backing string) loopIdentity {
	h := fnv.New64a()
	_, _ = h.Write([]byte(backing))
	return loopIdentity{dev: 66307, inode: h.Sum64()}
}

// currentBacking is what the fake KERNEL would report for a device now --
// which is what DetachLoop checks against, and what a reassignment changes.
func (f *fakeRemover) currentBacking(device string) string {
	if backing, reused := f.reassignBeforeDetach[device]; reused {
		f.loops[backing] = []string{device}
		return backing
	}
	for backing, devices := range f.loops {
		if slices.Contains(devices, device) {
			return backing
		}
	}
	return ""
}

func (f *fakeRemover) RemoveDir(path string) error {
	if err := f.removeDirErr[path]; err != nil {
		return err
	}
	f.removedDirs = append(f.removedDirs, path)
	return nil
}

func (f *fakeRemover) DetachLoop(dev LoopDevice) error {
	device := dev.Path

	// The real remover refuses a device it could not identify. The fake must
	// too, or the tests below would be asserting against a more permissive
	// kernel than the one that ships.
	if !dev.IdentityKnown {
		return fmt.Errorf("refusing to detach %s: its identity could not be captured when it was enumerated: %w",
			device, dev.IdentityErr)
	}
	if err := f.detachErr[device]; err != nil {
		return err
	}
	if f.releaseBeforeDetach[device] {
		// Already free: nothing to detach, and not an error. ENXIO from
		// LOOP_GET_STATUS64 is the only way the real remover reaches this.
		for backing, devices := range f.loops {
			if i := slices.Index(devices, device); i >= 0 {
				f.loops[backing] = slices.Delete(devices, i, i+1)
				if len(f.loops[backing]) == 0 {
					delete(f.loops, backing)
				}
			}
		}
		return nil
	}
	// The real remover refuses when the loop number has been reused; the fake
	// must too, or every test above it would be decoration.
	if actual := f.currentBacking(device); actual != "" && fakeIdentityOf(actual) != dev.Identity {
		return fmt.Errorf("refusing to detach %s: it is now bound to %s, not the %s it carried when it was "+
			"enumerated as backing %q -- the loop number was reused",
			device, fakeIdentityOf(actual), dev.Identity, dev.Backing)
	}
	if holder, held := f.holdLoopUntilMappingGone[device]; held {
		if _, stillThere := f.mappings[holder]; stillThere {
			return fmt.Errorf("device or resource busy: %s is held by dm %q", device, holder)
		}
	}
	if f.detachVisibleAfterQueries > 0 {
		if f.pendingDetach == nil {
			f.pendingDetach = map[string]int{}
		}
		f.pendingDetach[device] = f.detachVisibleAfterQueries
	}
	f.detached = append(f.detached, device)
	for backing, devices := range f.loops {
		if i := slices.Index(devices, device); i >= 0 {
			f.loops[backing] = slices.Delete(devices, i, i+1)
			if len(f.loops[backing]) == 0 {
				delete(f.loops, backing)
			}
		}
	}
	return nil
}

// loopPaths reduces enumerated devices to their paths, for assertions that are
// about WHICH devices were found rather than what they were backed by.
func loopPaths(devices []LoopDevice) []string {
	out := make([]string, 0, len(devices))
	for _, d := range devices {
		out = append(out, d.Path)
	}
	return out
}

// unremoved reports whether the reap recorded a failure to remove `value`.
//
// The tests below assert BOTH halves: the reap refuses (a device left on the
// host is not a host to run on), and the specific resource is named in the
// report. Asserting only the error would not distinguish "refused for this
// reason" from "refused for any reason", which is the shutdown-assertion trap.
func unremoved(r Report, value string) bool {
	for _, f := range r.Unremoved {
		if f.Entry.Value == value {
			return true
		}
	}
	return false
}

// stateDir returns a directory suitable to be a LEDGER STATE DIRECTORY.
//
// t.TempDir() cannot be used directly: it creates its per-test leaf with
// os.Mkdir(dir, 0777), so under a umask of 002 the result is 0775 --
// group-writable, which ensureTrustedStateDir refuses. The refusal is correct
// (a group-writable directory lets anyone in that group aim the privileged
// reaper); it is the FIXTURE that has to meet the requirement, not the
// requirement that has to bend for the fixture.
//
// The real deployments already comply: Docker creates a missing bind-mount
// source as root:root 0755, and `make host-integration-test` runs under sudo so
// the harness creates it 0700 itself.
func stateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("creating the state dir fixture: %v", err)
	}
	return dir
}

// writeLedger writes a ledger for a run that died without cleaning up.
func writeLedger(t *testing.T, dir, runID string, entries ...Entry) string {
	t.Helper()
	ledger, err := OpenLedger(dir, runID)
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	for _, e := range entries {
		if err := ledger.Record(e.Kind, e.Value, e.Identity); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if err := ledger.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return ledger.Path()
}

// TestReapRemovesTheStateAKilledRunLeftBehind is the core of #96: a run dies
// with mappings live on the host, and the NEXT run removes them before the #85
// guard looks.
func TestReapRemovesTheStateAKilledRunLeftBehind(t *testing.T) {
	dir := stateDir(t)
	path := writeLedger(t, dir, "dead-run",
		Entry{Kind: KindMapping, Value: "test-mount", Identity: "uuid-test-mount"},
		Entry{Kind: KindMapping, Value: "test-fs-ext3", Identity: "uuid-test-fs-ext3"},
		Entry{Kind: KindLoopBacking, Value: "/tmp/TestX/001/img", Identity: ""},
	)

	rm := newFakeRemover()
	rm.mappings["test-mount"] = "uuid-test-mount"
	rm.mappings["test-fs-ext3"] = "uuid-test-fs-ext3"
	rm.loops["/tmp/TestX/001/img"] = []string{"/dev/loop3"}

	report, err := Reap(dir, "live-run", rm, io.Discard)
	if err != nil {
		t.Fatalf("Reap: %v", err)
	}

	// The damage plane first: the host must actually be clean.
	if len(rm.mappings) != 0 {
		t.Fatalf("mappings still on the host after the reap: %v", rm.mappings)
	}
	if len(rm.loops) != 0 {
		t.Fatalf("loop devices still on the host after the reap: %v", rm.loops)
	}

	if len(report.Removed) != 3 {
		t.Fatalf("report.Removed = %v, want 3 entries", report.Removed)
	}
	// The ledger is consumed, so the next run does not try again.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the ledger survived a complete reap: %v", err)
	}
}

// TestReapLeavesAReusedNameAlone is the property that makes this safe to run on
// a machine that is not a disposable runner.
//
// dm names are a flat host-wide namespace. Between the record and the reap,
// something else can create a mapping under a name the suite also uses. A
// cleanup keyed to the NAME removes a stranger's device; keyed to the recorded
// identity, it does not.
func TestReapLeavesAReusedNameAlone(t *testing.T) {
	dir := stateDir(t)
	path := writeLedger(t, dir, "dead-run",
		Entry{Kind: KindMapping, Value: "test-mount", Identity: "uuid-ours"},
	)

	rm := newFakeRemover()
	rm.mappings["test-mount"] = "uuid-SOMEONE-ELSES"

	report, err := Reap(dir, "live-run", rm, io.Discard)
	if err != nil {
		t.Fatalf("Reap: %v", err)
	}

	if len(rm.removed) != 0 {
		t.Fatalf("the reaper removed %v; the live mapping was not the recorded one", rm.removed)
	}
	if got := rm.mappings["test-mount"]; got != "uuid-SOMEONE-ELSES" {
		t.Fatalf("the foreign mapping was disturbed: uuid is now %q", got)
	}
	if len(report.NotOurs) != 1 {
		t.Fatalf("report.NotOurs = %v, want the reused name reported", report.NotOurs)
	}
	// It is still consumed: we know it is not ours, so there is nothing left to
	// do about it and keeping the ledger would fail every future run.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the ledger survived: %v", err)
	}
}

// TestReapWithNoRecordedIdentityRefusesToRemove pins the fail-closed direction.
// An entry with no identity cannot be attributed, so it must be left alone --
// never removed on the strength of its name.
func TestReapWithNoRecordedIdentityRefusesToRemove(t *testing.T) {
	dir := stateDir(t)
	writeLedger(t, dir, "dead-run", Entry{Kind: KindMapping, Value: "test-mount", Identity: ""})

	rm := newFakeRemover()
	rm.mappings["test-mount"] = "uuid-something"

	if _, err := Reap(dir, "live-run", rm, io.Discard); err != nil {
		t.Fatalf("Reap: %v", err)
	}
	if len(rm.removed) != 0 {
		t.Fatalf("the reaper removed %v on the strength of a name alone", rm.removed)
	}
}

func TestReapTreatsAlreadyCleanedStateAsOrdinary(t *testing.T) {
	dir := stateDir(t)
	writeLedger(t, dir, "clean-ish-run",
		Entry{Kind: KindMapping, Value: "test-mount", Identity: "uuid-ours"},
		Entry{Kind: KindLoopBacking, Value: "/tmp/gone", Identity: ""},
	)

	rm := newFakeRemover() // nothing on the host

	report, err := Reap(dir, "live-run", rm, io.Discard)
	if err != nil {
		t.Fatalf("Reap: %v", err)
	}
	if len(report.AlreadyGone) != 2 {
		t.Fatalf("report.AlreadyGone = %v, want both entries", report.AlreadyGone)
	}
	if len(report.Removed) != 0 {
		t.Fatalf("report.Removed = %v, want none", report.Removed)
	}
}

// TestReapNeverTouchesTheLiveRunsOwnLedger is the deadlock guard: reaping our
// own ledger would tear down the mappings the running tests are using.
func TestReapNeverTouchesTheLiveRunsOwnLedger(t *testing.T) {
	dir := stateDir(t)
	writeLedger(t, dir, "live-run", Entry{Kind: KindMapping, Value: "in-use", Identity: "uuid-in-use"})

	rm := newFakeRemover()
	rm.mappings["in-use"] = "uuid-in-use"

	if _, err := Reap(dir, "live-run", rm, io.Discard); err != nil {
		t.Fatalf("Reap: %v", err)
	}
	if len(rm.removed) != 0 {
		t.Fatalf("the reaper removed %v from the LIVE run's own ledger", rm.removed)
	}
}

// TestReapKeepsTheLedgerWhenItCannotFinish is what stops a partial reap being
// reported as a clean host. The ledger has to survive so the next run retries.
func TestReapKeepsTheLedgerWhenItCannotFinish(t *testing.T) {
	dir := stateDir(t)
	path := writeLedger(t, dir, "dead-run",
		Entry{Kind: KindMapping, Value: "stuck", Identity: "uuid-stuck"},
		Entry{Kind: KindMapping, Value: "fine", Identity: "uuid-fine"},
	)

	rm := newFakeRemover()
	rm.mappings["stuck"] = "uuid-stuck"
	rm.mappings["fine"] = "uuid-fine"
	rm.removeErr["stuck"] = errors.New("device or resource busy")

	report, err := Reap(dir, "live-run", rm, io.Discard)
	if !errors.Is(err, ErrReapIncomplete) {
		t.Fatalf("error = %v, want ErrReapIncomplete: a DEVICE left on the host refuses the run", err)
	}
	if !unremoved(report, "stuck") {
		t.Fatal("Reap did not report the resource it could not remove")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the ledger was deleted despite an incomplete reap: %v", err)
	}
	// The half that could be removed still was, so a retry has less to do.
	if len(report.Removed) != 1 || report.Removed[0].Value != "fine" {
		t.Fatalf("report.Removed = %v, want the removable entry", report.Removed)
	}
}

// TestReapRefusesARemovalThatDidNotTakeEffect covers the shape where the kernel
// returns success and the resource is still live. Reporting that as a clean
// reap would have the next run fail the guard with this one claiming success.
func TestReapRefusesARemovalThatDidNotTakeEffect(t *testing.T) {
	dir := stateDir(t)
	writeLedger(t, dir, "dead-run", Entry{Kind: KindMapping, Value: "ghost", Identity: "uuid-ghost"})

	rm := newFakeRemover()
	rm.mappings["ghost"] = "uuid-ghost"
	rm.refuseToActuallyRemove = true

	report, err := Reap(dir, "live-run", rm, io.Discard)
	if !errors.Is(err, ErrReapIncomplete) {
		t.Fatalf("error = %v, want ErrReapIncomplete", err)
	}
	if !unremoved(report, "ghost") {
		t.Fatal("Reap accepted a removal that left the mapping live, without reporting it")
	}
}

// TestReapRefusesToProceedPastAnUnreadableLedger: an unparseable ledger means
// the set of recorded state is unknown, and a reap over an unknown subset must
// not be reported as a clean host.
func TestReapRefusesToProceedPastAnUnreadableLedger(t *testing.T) {
	dir := stateDir(t)
	if err := os.WriteFile(filepath.Join(dir, "broken.ledger"), []byte("this is not a record\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	rm := newFakeRemover()
	_, err := Reap(dir, "live-run", rm, io.Discard)
	if err == nil {
		t.Fatal("Reap accepted an unparseable ledger")
	}
	if !errors.Is(err, ErrLedgerCorrupt) {
		t.Fatalf("error = %v, want it to match ErrLedgerCorrupt", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "broken.ledger")); err != nil {
		t.Fatalf("the unreadable ledger was deleted: %v", err)
	}
}

func TestReapOnAHostWithNothingRecordedIsANoOp(t *testing.T) {
	dir := stateDir(t)
	rm := newFakeRemover()
	rm.mappings["someones-root"] = "CRYPT-LUKS2-deadbeef-someones-root"

	report, err := Reap(dir, "live-run", rm, io.Discard)
	if err != nil {
		t.Fatalf("Reap: %v", err)
	}
	if len(report.Removed) != 0 || len(rm.removed) != 0 {
		t.Fatalf("the reaper removed %v with no ledger telling it to", rm.removed)
	}
	// The whole file must contain no sweep: an unrecorded mapping is never
	// this package's business, however much it looks like test litter.
	if _, ok := rm.mappings["someones-root"]; !ok {
		t.Fatal("an unrecorded mapping was removed")
	}
}

func TestReapDetachesEveryLoopDeviceBackedByARecordedFile(t *testing.T) {
	dir := stateDir(t)
	writeLedger(t, dir, "dead-run", Entry{Kind: KindLoopBacking, Value: "/tmp/img", Identity: ""})

	rm := newFakeRemover()
	// One backing file can be attached to more than one loop device.
	rm.loops["/tmp/img"] = []string{"/dev/loop2", "/dev/loop5"}

	if _, err := Reap(dir, "live-run", rm, io.Discard); err != nil {
		t.Fatalf("Reap: %v", err)
	}
	if !slices.Equal(rm.detached, []string{"/dev/loop2", "/dev/loop5"}) {
		t.Fatalf("detached = %v, want both devices", rm.detached)
	}
}

func TestNormalizeBackingFileStripsTheDeletedMarker(t *testing.T) {
	// This is what makes the loop half work at all after a container is gone:
	// the file is unlinked, and the kernel keeps reporting the path with a
	// suffix. Comparing raw would match nothing, and every leaked loop device
	// would be invisible to the reaper.
	for _, tc := range []struct{ raw, want string }{
		{"/tmp/TestX/001/img\n", "/tmp/TestX/001/img"},
		{"/tmp/TestX/001/img (deleted)\n", "/tmp/TestX/001/img"},
		{"  /tmp/img (deleted)  \n", "/tmp/img"},
	} {
		if got := normalizeBackingFile(tc.raw); got != tc.want {
			t.Errorf("normalizeBackingFile(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// stubBoundIdentity stands in for the LOOP_GET_STATUS64 capture in the
// enumeration tests, which run against a fake /sys tree where /dev/loopN does
// not exist. Every device is bound, with an identity of its own.
func stubBoundIdentity(device string) (loopIdentity, bool, error) {
	return fakeIdentityOf(device), true, nil
}

func TestLoopDevicesForReadsTheKernelsView(t *testing.T) {
	// A sysfs stand-in, so the resolution logic is testable without a loop
	// device. The layout mirrors /sys/block/loop<N>/loop/backing_file exactly.
	root := t.TempDir()
	write := func(dev, backing string) {
		t.Helper()
		dir := filepath.Join(root, dev, "loop")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "backing_file"), []byte(backing), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	write("loop0", "/tmp/other.img\n")
	write("loop3", "/tmp/ours.img (deleted)\n")
	write("loop4", "/tmp/ours.img\n")
	// An unused loop device has no backing_file at all.
	if err := os.MkdirAll(filepath.Join(root, "loop7"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	got, err := loopDevicesForIn(root, "/tmp/ours.img", stubBoundIdentity)
	if err != nil {
		t.Fatalf("loopDevicesForIn: %v", err)
	}
	want := []string{"/dev/loop3", "/dev/loop4"}
	if !slices.Equal(loopPaths(got), want) {
		t.Fatalf("loopDevicesForIn = %v, want %v", got, want)
	}
}

func TestLoopDevicesForRefusesAnEmptyBackingPath(t *testing.T) {
	// An empty path would match every unused loop device on the host, which is
	// the global sweep this package must never perform.
	if _, err := loopDevicesForIn(t.TempDir(), "", stubBoundIdentity); err == nil {
		t.Fatal("loopDevicesForIn accepted an empty backing path")
	}
}

func TestReapReportsEveryFailureNotJustTheFirst(t *testing.T) {
	dir := stateDir(t)
	writeLedger(t, dir, "dead-run",
		Entry{Kind: KindMapping, Value: "a", Identity: "uuid-a"},
		Entry{Kind: KindMapping, Value: "b", Identity: "uuid-b"},
	)

	rm := newFakeRemover()
	rm.mappings["a"] = "uuid-a"
	rm.mappings["b"] = "uuid-b"
	rm.removeErr["a"] = errors.New("busy")
	rm.removeErr["b"] = errors.New("busy")

	report, err := Reap(dir, "live-run", rm, io.Discard)
	if !errors.Is(err, ErrReapIncomplete) {
		t.Fatalf("error = %v, want ErrReapIncomplete", err)
	}
	// An operator deciding whether the host is usable needs the whole list;
	// stopping at the first under-reports the damage.
	if len(report.Unremoved) != 2 {
		t.Fatalf("Unremoved = %v, want both", report.Unremoved)
	}
	for _, name := range []string{"a", "b"} {
		if !containsEntry(report.Unremoved, name) {
			t.Errorf("failures do not mention %q: %v", name, report.Unremoved)
		}
	}
}

func containsEntry(failures []ReapFailure, value string) bool {
	for _, f := range failures {
		if f.Entry.Value == value {
			return true
		}
	}
	return false
}

func TestReapProcessesEveryStaleLedger(t *testing.T) {
	dir := stateDir(t)
	for i := 0; i < 3; i++ {
		writeLedger(t, dir, fmt.Sprintf("dead-%d", i),
			Entry{Kind: KindMapping, Value: fmt.Sprintf("vol-%d", i), Identity: fmt.Sprintf("uuid-%d", i)})
	}

	rm := newFakeRemover()
	for i := 0; i < 3; i++ {
		rm.mappings[fmt.Sprintf("vol-%d", i)] = fmt.Sprintf("uuid-%d", i)
	}

	report, err := Reap(dir, "live-run", rm, io.Discard)
	if err != nil {
		t.Fatalf("Reap: %v", err)
	}
	// A host can accumulate several dead runs before anyone looks; reaping only
	// the newest would leave the guard refusing on the rest.
	if len(report.LedgersProcessed) != 3 {
		t.Fatalf("processed %v, want 3 ledgers", report.LedgersProcessed)
	}
	if len(rm.mappings) != 0 {
		t.Fatalf("mappings survived: %v", rm.mappings)
	}
}

// TestReapDetachesLoopDevicesUnderARecordedRoot is the loop half of #96.
//
// A loop device cannot be recorded before it exists -- the kernel picks the
// minor in LOOP_CTL_GET_FREE -- so what is recorded write-ahead is the
// DIRECTORY the run created and pointed TMPDIR at. Every backing file the suite
// allocates, through t.TempDir() or os.CreateTemp(""), lands underneath it.
func TestReapDetachesLoopDevicesUnderARecordedRoot(t *testing.T) {
	dir := stateDir(t)
	writeLedger(t, dir, "dead-run", Entry{Kind: KindLoopRoot, Value: "/tmp/go-luks2-run-dead-run-1"})

	rm := newFakeRemover()
	rm.loops["/tmp/go-luks2-run-dead-run-1/TestLoopDeviceCleanup/001/x.img"] = []string{"/dev/loop3"}
	rm.loops["/tmp/go-luks2-run-dead-run-1/TestLoopDeviceMultiple/002/y.img"] = []string{"/dev/loop4"}
	// Another run's root, and a developer's own image. Neither is ours.
	rm.loops["/tmp/go-luks2-run-other-run-2/other.img"] = []string{"/dev/loop6"}
	rm.loops["/var/lib/libvirt/images/backup.img"] = []string{"/dev/loop7"}

	if _, err := Reap(dir, "live-run", rm, io.Discard); err != nil {
		t.Fatalf("Reap: %v", err)
	}

	if !slices.Equal(rm.detached, []string{"/dev/loop3", "/dev/loop4"}) {
		t.Fatalf("detached = %v, want only the devices under the recorded root", rm.detached)
	}
	if _, ok := rm.loops["/var/lib/libvirt/images/backup.img"]; !ok {
		t.Fatal("a developer's own loop device was detached")
	}
	if _, ok := rm.loops["/tmp/go-luks2-run-other-run-2/other.img"]; !ok {
		t.Fatal("another run's loop device was detached")
	}
}

func TestLoopDevicesUnderRefusesARootThatIsNotOne(t *testing.T) {
	// "" and "/" would match every loop device on the host. That is the global
	// sweep #85 removed from this repository, wearing a path instead of a name.
	for _, dir := range []string{"", "/"} {
		if _, err := loopDevicesUnderIn(t.TempDir(), dir, stubBoundIdentity); err == nil {
			t.Errorf("loopDevicesUnderIn accepted %q as a root", dir)
		}
	}
}

func TestLoopDevicesUnderDoesNotMatchASiblingWithASharedPrefix(t *testing.T) {
	// "/tmp/go-luks2-run-1" must not match "/tmp/go-luks2-run-10": a plain string prefix would
	// have one run detach the next run's devices.
	root := t.TempDir()
	write := func(dev, backing string) {
		t.Helper()
		d := filepath.Join(root, dev, "loop")
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(filepath.Join(d, "backing_file"), []byte(backing), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	write("loop1", "/tmp/go-luks2-run-1/a.img\n")
	write("loop2", "/tmp/go-luks2-run-10/b.img\n")

	got, err := loopDevicesUnderIn(root, "/tmp/go-luks2-run-1", stubBoundIdentity)
	if err != nil {
		t.Fatalf("loopDevicesUnderIn: %v", err)
	}
	if !slices.Equal(loopPaths(got), []string{"/dev/loop1"}) {
		t.Fatalf("loopDevicesUnderIn = %v, want only /dev/loop1", got)
	}
}

// TestReapLeavesALiveRunsLedgerCompletelyAlone is the property that makes this
// safe on a shared runner, and it is the one snapshot-and-diff could not have.
//
// Several jobs run concurrently on one host. A ledger sitting in the state
// directory may belong to a suite that is running RIGHT NOW, whose mappings and
// loop devices are in use. Removing them fails a different run in a way that
// reads as a flaky test on a host that looks clean -- strictly worse than the
// leak, which fails loudly and a human can fix.
//
// Nothing about the device itself can tell the two apart. Measured 2026-09-01
// on a shared CI runner: a live job's loop device showed empty `holders` and empty
// `fuser`, identical to the orphans swept minutes earlier. The only difference
// was that a job owned it. So ownership is asserted with a lock the owner holds
// for its lifetime, which the kernel releases on death and not before.
func TestReapLeavesALiveRunsLedgerCompletelyAlone(t *testing.T) {
	dir := stateDir(t)

	// A live sibling: it holds its ledger open and locked, exactly as a running
	// suite does.
	sibling, err := OpenLedger(dir, "concurrent-sibling")
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	t.Cleanup(func() { _ = sibling.Close() })
	if err := sibling.Record(KindMapping, "siblings-volume", "uuid-sibling"); err != nil {
		t.Fatalf("Record: %v", err)
	}

	rm := newFakeRemover()
	rm.mappings["siblings-volume"] = "uuid-sibling"

	report, err := Reap(dir, "some-other-run", rm, io.Discard)
	if err != nil {
		t.Fatalf("Reap: %v", err)
	}

	// The damage plane first: the sibling's device must still be there.
	if _, ok := rm.mappings["siblings-volume"]; !ok {
		t.Fatal("the reaper removed a LIVE run's mapping")
	}
	if len(rm.removed) != 0 {
		t.Fatalf("the reaper removed %v from a live run's ledger", rm.removed)
	}
	if _, err := os.Stat(sibling.Path()); err != nil {
		t.Fatalf("the reaper deleted a live run's ledger: %v", err)
	}
	if len(report.LedgersSkippedAlive) != 1 {
		t.Fatalf("report.LedgersSkippedAlive = %v, want the sibling's ledger reported", report.LedgersSkippedAlive)
	}
}

// TestReapConsumesALedgerOnceItsOwnerIsGone is the other half: the same ledger,
// after the owner releases it, IS reaped. Without this the liveness check could
// be permanently stuck and the leak would never be cleaned -- a guard that
// always says "leave it" is not a guard.
func TestReapConsumesALedgerOnceItsOwnerIsGone(t *testing.T) {
	dir := stateDir(t)

	owner, err := OpenLedger(dir, "run-that-dies")
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	if err := owner.Record(KindMapping, "left-behind", "uuid-left-behind"); err != nil {
		t.Fatalf("Record: %v", err)
	}
	path := owner.Path()

	rm := newFakeRemover()
	rm.mappings["left-behind"] = "uuid-left-behind"

	// While it is alive, nothing happens.
	if _, err := Reap(dir, "next-run", rm, io.Discard); err != nil {
		t.Fatalf("Reap: %v", err)
	}
	if len(rm.removed) != 0 {
		t.Fatalf("the reaper acted on a live ledger: %v", rm.removed)
	}

	// The run dies. Close is what the kernel does for a SIGKILLed process: the
	// descriptor goes away and the lock with it.
	if err := owner.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := Reap(dir, "next-run", rm, io.Discard); err != nil {
		t.Fatalf("Reap: %v", err)
	}
	if _, ok := rm.mappings["left-behind"]; ok {
		t.Fatal("the reaper did not remove state left by a run that is gone")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the ledger survived a complete reap: %v", err)
	}
}

// TestTwoConcurrentRunsGetSeparateLedgers pins per-run scoping. Two suites on
// one host must not share a ledger, or one would reap the other's records as
// its own and the liveness lock would be meaningless.
func TestTwoConcurrentRunsGetSeparateLedgers(t *testing.T) {
	dir := stateDir(t)

	a, err := OpenLedger(dir, NewRunID(1, 1000))
	if err != nil {
		t.Fatalf("OpenLedger(a): %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })

	// Same pid -- which is the NORM in containers, where everything is pid 1.
	b, err := OpenLedger(dir, NewRunID(1, 2000))
	if err != nil {
		t.Fatalf("OpenLedger(b): a second concurrent run could not open its own ledger: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	if a.Path() == b.Path() {
		t.Fatalf("both runs opened %q; two concurrent suites would share one record", a.Path())
	}

	if err := a.Record(KindMapping, "a-vol", "uuid-a"); err != nil {
		t.Fatalf("Record(a): %v", err)
	}
	if err := b.Record(KindMapping, "b-vol", "uuid-b"); err != nil {
		t.Fatalf("Record(b): %v", err)
	}

	for _, tc := range []struct {
		ledger *Ledger
		want   string
	}{{a, "a-vol"}, {b, "b-vol"}} {
		entries, err := ReadLedger(tc.ledger.Path())
		if err != nil {
			t.Fatalf("ReadLedger: %v", err)
		}
		if len(entries) != 1 || entries[0].Value != tc.want {
			t.Fatalf("%s holds %v, want only %q -- the two runs' records are mixed",
				tc.ledger.Path(), entries, tc.want)
		}
	}
}

// TestOpenLedgerRefusesToShareARunID is the failure mode behind the scoping: if
// two runs somehow chose the same id, the second must not silently append to
// the first's record and reap it later.
func TestOpenLedgerRefusesToShareARunID(t *testing.T) {
	dir := stateDir(t)

	first, err := OpenLedger(dir, "same-id")
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	t.Cleanup(func() { _ = first.Close() })

	if _, err := OpenLedger(dir, "same-id"); err == nil {
		t.Fatal("a second run opened a ledger already held by a live one")
	} else if !errors.Is(err, ErrLedgerUnavailable) {
		t.Fatalf("error = %v, want it to match ErrLedgerUnavailable", err)
	}
}

// TestReapOwnCleansWhatAPassingRunLeaked is the regression test for the defect
// a privileged CI runner surfaced on 2026-09-01, which no local reasoning had
// found.
//
// pkg/luks2 reported `ok` in 87.6s while TestLoopDeviceCleanup left /dev/loop1
// attached. The suite then discarded its ledger on the strength of the exit
// code, destroying the only record of the device it had just leaked, and the
// NEXT run reaped a ledger describing nothing and honestly reported "already
// gone" while the device sat on the host.
//
// A green suite and a leaked device are not mutually exclusive. The exit code
// cannot tell them apart, so the record is checked against the host instead.
func TestReapOwnCleansWhatAPassingRunLeaked(t *testing.T) {
	dir := stateDir(t)
	ledger, err := OpenLedger(dir, "passing-run")
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	t.Cleanup(func() { _ = ledger.Close() })

	if err := ledger.Record(KindLoopRoot, "/tmp/go-luks2-run-passing-run-1", ""); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := ledger.Record(KindMapping, "tidy-volume", "uuid-tidy"); err != nil {
		t.Fatalf("Record: %v", err)
	}

	rm := newFakeRemover()
	// The test cleaned up its mapping, as a passing test does...
	// ...and leaked a loop device anyway, which is the measured shape.
	rm.loops["/tmp/go-luks2-run-passing-run-1/TestLoopDeviceCleanup/001/x.img"] = []string{"/dev/loop1"}

	report, err := ReapOwn(ledger, rm, io.Discard)
	if err != nil {
		t.Fatalf("ReapOwn: %v", err)
	}

	if len(rm.loops) != 0 {
		t.Fatalf("a passing run left %v on the host after its own cleanup", rm.loops)
	}
	if len(report.Removed) != 1 || report.Removed[0].Kind != KindLoopRoot {
		t.Fatalf("report.Removed = %v, want the leaked loop root", report.Removed)
	}
	// The mapping the test did clean up is reported as already gone, not as a
	// removal -- otherwise the count would overstate what was wrong.
	if len(report.AlreadyGone) != 1 {
		t.Fatalf("report.AlreadyGone = %v, want the mapping the test removed itself", report.AlreadyGone)
	}
}

// TestReapOwnDoesNotNeedTheLedgerUnlocked pins that a run can reap its OWN
// ledger while holding the lock on it. The cross-run reaper refuses a locked
// ledger by design; if ReapOwn shared that check it would refuse every ledger
// it is ever called with, and a run could never clean up after itself.
func TestReapOwnDoesNotNeedTheLedgerUnlocked(t *testing.T) {
	dir := stateDir(t)
	ledger, err := OpenLedger(dir, "live-run")
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	if err := ledger.Record(KindMapping, "mine", "uuid-mine"); err != nil {
		t.Fatalf("Record: %v", err)
	}

	rm := newFakeRemover()
	rm.mappings["mine"] = "uuid-mine"

	if _, err := ReapOwn(ledger, rm, io.Discard); err != nil {
		t.Fatalf("ReapOwn refused a ledger its own caller holds: %v", err)
	}
	if _, ok := rm.mappings["mine"]; ok {
		t.Fatal("ReapOwn did not remove the run's own leaked mapping")
	}
}

// TestSuiteFinishCleansUpEvenWhenTheTestsPassed is the Suite-level regression
// test for that runner defect, and it exists because the first version of Finish
// was wrong here and nothing could have caught it: Finish called the kernel
// directly, so no test could reach the decision.
//
// The decision under test is the one that was wrong: whether a green suite is
// evidence of a clean host. It is not.
func TestSuiteFinishCleansUpEvenWhenTheTestsPassed(t *testing.T) {
	dir := stateDir(t)
	ledger, err := OpenLedger(dir, "green-but-leaky")
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	if err := ledger.Record(KindLoopRoot, "/tmp/go-luks2-run-green-but-leaky-1", ""); err != nil {
		t.Fatalf("Record: %v", err)
	}

	rm := newFakeRemover()
	rm.loops["/tmp/go-luks2-run-green-but-leaky-1/TestLoopDeviceCleanup/001/x.img"] = []string{"/dev/loop1"}

	suite := &Suite{Ledger: ledger, TempDir: t.TempDir(), RunID: "green-but-leaky", Remover: rm}

	// code 0: the tests PASSED. The host is leaky anyway.
	if got := suite.Finish(0, io.Discard); got != 0 {
		t.Fatalf("Finish returned %d after cleaning up successfully, want 0", got)
	}

	if len(rm.loops) != 0 {
		t.Fatalf("Finish left %v on the host after a passing run", rm.loops)
	}
	if _, err := os.Stat(ledger.Path()); !os.IsNotExist(err) {
		t.Fatalf("Finish kept the ledger despite having cleaned everything: %v", err)
	}
}

// TestSuiteFinishKeepsTheLedgerWhenItCannotClean is the other direction: if the
// run cannot remove what it created, the record must survive so the next run
// can finish the job. Discarding here would lose the only description of state
// that is still on the host.
func TestSuiteFinishKeepsTheLedgerWhenItCannotClean(t *testing.T) {
	dir := stateDir(t)
	ledger, err := OpenLedger(dir, "stuck-run")
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	if err := ledger.Record(KindMapping, "stuck", "uuid-stuck"); err != nil {
		t.Fatalf("Record: %v", err)
	}

	rm := newFakeRemover()
	rm.mappings["stuck"] = "uuid-stuck"
	rm.removeErr["stuck"] = errors.New("device or resource busy")

	suite := &Suite{Ledger: ledger, TempDir: t.TempDir(), RunID: "stuck-run", Remover: rm}
	if got := suite.Finish(0, io.Discard); got == 0 {
		t.Fatal("Finish returned 0 after failing to remove host state; CI would report success on a dirty host")
	}

	if _, err := os.Stat(ledger.Path()); err != nil {
		t.Fatalf("Finish discarded a ledger describing state still on the host: %v", err)
	}
}

// TestReapersSerializeSoALockedLedgerAlwaysMeansALiveSuite is the fix for the
// P2 finding on the local Codex review, and it is a correctness issue rather
// than a tidiness one.
//
// Two reapers starting together were indistinguishable from a reaper and a live
// suite: reaper A takes a stale ledger's lock, reaper B gets EWOULDBLOCK and
// classifies the ledger as "the owner is still alive". B then returns SUCCESS
// and proceeds -- even though A might still be working, or might have failed
// and left the recorded state exactly where it was. A fail-closed path defeated
// by a lock that was misread.
//
// Serializing the reapers removes the ambiguity at its source: while the host
// reaper mutex is held, a locked ledger can only be a live SUITE.
func TestReapersSerializeSoALockedLedgerAlwaysMeansALiveSuite(t *testing.T) {
	dir := stateDir(t)
	writeLedger(t, dir, "dead-run", Entry{Kind: KindMapping, Value: "left", Identity: "uuid-left"})

	// Reaper A is mid-sweep: it holds the host mutex.
	_, unlockA, err := lockReaper(dir)
	if err != nil {
		t.Fatalf("lockReaper: %v", err)
	}

	rm := newFakeRemover()
	rm.mappings["left"] = "uuid-left"

	// Reaper B must WAIT rather than sail past. Its wait is held still at its
	// first sleep -- on a clock only the wait moves (#233) -- so "B has not
	// finished while A holds the mutex" is observed, not raced against a
	// timer: B has tried the lock, been refused, and is waiting to retry.
	clk := useFakeClock(t)
	waiting := make(chan struct{})
	proceed := make(chan struct{})
	var once sync.Once
	clk.onSleep = func(time.Time) {
		once.Do(func() {
			close(waiting)
			<-proceed
		})
	}

	done := make(chan error, 1)
	go func() {
		_, err := Reap(dir, "reaper-b", rm, io.Discard)
		done <- err
	}()

	// Either B parks at its first retry, or it returned without waiting --
	// the regression -- and is reported at once rather than hanging.
	select {
	case err := <-done:
		unlockA()
		t.Fatalf("a second reaper completed (%v) while another held the host mutex", err)
	case <-waiting:
	}

	// A finishes without having removed anything -- the failure case that made
	// B's early success dangerous -- and B's wait resumes.
	unlockA()
	close(proceed)

	// No wall-clock guard: a B that never completes hangs, and the test
	// binary's -timeout ends the run naming this test.
	if err := <-done; err != nil {
		t.Fatalf("Reap: %v", err)
	}

	// B did A's unfinished work rather than assuming it was handled.
	if _, ok := rm.mappings["left"]; ok {
		t.Fatal("the second reaper left recorded state on the host after the first released the mutex")
	}
}

// TestReapTimesOutRatherThanRunningOnAnUnknownHost pins the fail-closed
// direction of the wait. A reaper that gives up and proceeds is a reaper that
// runs on a host in a state nobody established.
func TestReapTimesOutRatherThanRunningOnAnUnknownHost(t *testing.T) {
	dir := stateDir(t)
	writeLedger(t, dir, "dead-run", Entry{Kind: KindMapping, Value: "left", Identity: "uuid-left"})

	_, unlockA, err := lockReaper(dir)
	if err != nil {
		t.Fatalf("lockReaper: %v", err)
	}
	t.Cleanup(unlockA)

	// The real bound and poll, on a controlled clock (#233): five minutes of
	// waiting costs nothing, and how long it waited is exact.
	clk := useFakeClock(t)

	rm := newFakeRemover()
	rm.mappings["left"] = "uuid-left"

	_, err = Reap(dir, "reaper-b", rm, io.Discard)
	if err == nil {
		t.Fatal("Reap reported success without ever taking the host reaper mutex")
	}
	if waited := clk.elapsed(); waited <= reaperLockTimeoutForTest || waited > reaperLockTimeoutForTest+reaperLockPoll {
		t.Fatalf("gave up after %s, want just past the %s bound", waited, reaperLockTimeoutForTest)
	}
	if !errors.Is(err, ErrReapIncomplete) {
		t.Fatalf("error = %v, want it to match ErrReapIncomplete", err)
	}
	if _, ok := rm.mappings["left"]; !ok {
		t.Fatal("the reaper acted on the host without holding the mutex")
	}
}

// TestReaperLockFileIsNotMistakenForALedger: the mutex lives in the same
// directory as the ledgers, so a sweep that treated it as one would try to
// parse it and fail the whole reap.
func TestReaperLockFileIsNotMistakenForALedger(t *testing.T) {
	dir := stateDir(t)
	sd, unlock, err := lockReaper(dir)
	if err != nil {
		t.Fatalf("lockReaper: %v", err)
	}
	defer unlock()

	paths, err := staleLedgers(sd, "anything")
	if err != nil {
		t.Fatalf("staleLedgers: %v", err)
	}
	if len(paths) != 0 {
		t.Fatalf("staleLedgers returned %v; the reaper lock file is not a ledger", paths)
	}
}

// TestReapRemovesTheHolderBeforeTheDeviceItHolds is the first P2 from the local
// Codex review, and the ordering is not cosmetic.
//
// The ledger's write order is the OPPOSITE of the removal order, and not by
// accident: BeginSuite records the run's loop root before a single test runs --
// that is what makes the record precede the resource -- while dm mappings are
// recorded later, as tests create them. So a killed run that left a LUKS
// mapping stacked on a loop device produces a ledger whose loop entry comes
// first, and reaping in that order tries to detach a device the mapping is
// still holding.
func TestReapRemovesTheHolderBeforeTheDeviceItHolds(t *testing.T) {
	dir := stateDir(t)
	// Written in the order a real run produces: loop root first.
	writeLedger(t, dir, "dead-run",
		Entry{Kind: KindLoopRoot, Value: "/tmp/go-luks2-run-dead-run-1"},
		Entry{Kind: KindMapping, Value: "stacked-on-loop", Identity: "uuid-stacked"},
	)

	rm := newFakeRemover()
	rm.mappings["stacked-on-loop"] = "uuid-stacked"
	rm.loops["/tmp/go-luks2-run-dead-run-1/x.img"] = []string{"/dev/loop3"}
	// The kernel refuses to release a loop device a dm target still holds.
	rm.holdLoopUntilMappingGone = map[string]string{"/dev/loop3": "stacked-on-loop"}

	if _, err := Reap(dir, "next-run", rm, io.Discard); err != nil {
		t.Fatalf("Reap: %v -- the holder was not removed before the device it holds", err)
	}
	if len(rm.loops) != 0 {
		t.Fatalf("loop devices survived: %v", rm.loops)
	}
	if len(rm.mappings) != 0 {
		t.Fatalf("mappings survived: %v", rm.mappings)
	}
}

// TestInRemovalOrderPutsMappingsFirstAndIsStable pins the ordering at the
// value, so it does not depend on assembling a whole fake kernel.
func TestInRemovalOrderPutsMappingsFirstAndIsStable(t *testing.T) {
	in := []Entry{
		{Kind: KindLoopRoot, Value: "root"},
		{Kind: KindMapping, Value: "dm-a"},
		{Kind: KindLoopBacking, Value: "backing"},
		{Kind: KindMapping, Value: "dm-b"},
	}
	got := inRemovalOrder(in)

	want := []string{"dm-a", "dm-b", "root", "backing"}
	for i, w := range want {
		if got[i].Value != w {
			t.Fatalf("inRemovalOrder = %v, want mappings first then loops in ledger order (%v)", got, want)
		}
	}
	// The input must not be mutated: the caller still reports on it.
	if in[0].Value != "root" {
		t.Fatal("inRemovalOrder mutated its input")
	}
}

// TestReapWaitsForADetachToBecomeObservable is the second P2. A successful
// LOOP_CLR_FD is not necessarily visible in sysfs immediately -- loopdev.go
// waits for this exact race, with a measurement behind it. Re-querying
// instantly turns a successful cleanup into ErrReapIncomplete and fails the
// NEXT run over a device that was already on its way out.
func TestReapWaitsForADetachToBecomeObservable(t *testing.T) {
	dir := stateDir(t)
	writeLedger(t, dir, "dead-run", Entry{Kind: KindLoopRoot, Value: "/tmp/go-luks2-run-dead-run-1"})

	rm := newFakeRemover()
	rm.loops["/tmp/go-luks2-run-dead-run-1/x.img"] = []string{"/dev/loop3"}
	// The detach succeeds, but sysfs keeps reporting the device for two more
	// queries -- the kernel finishing the release asynchronously.
	rm.detachVisibleAfterQueries = 2

	clk := useFakeClock(t)

	if _, err := Reap(dir, "next-run", rm, io.Discard); err != nil {
		t.Fatalf("Reap: %v -- a detach that had not yet settled was reported as a failure", err)
	}
	// It waited for the two further queries and no longer: two polls.
	if waited := clk.elapsed(); waited != 2*detachSettlePoll {
		t.Fatalf("waited %s for a release two queries away, want %s", waited, 2*detachSettlePoll)
	}
}

// TestReapStillFailsOnADeviceThatNeverGoesAway is the control on that wait: the
// bound must not turn a genuinely stuck device into a pass. Reaching it means
// something still HOLDS the device, which is a real failure.
func TestReapStillFailsOnADeviceThatNeverGoesAway(t *testing.T) {
	dir := stateDir(t)
	writeLedger(t, dir, "dead-run", Entry{Kind: KindLoopRoot, Value: "/tmp/go-luks2-run-dead-run-1"})

	rm := newFakeRemover()
	rm.loops["/tmp/go-luks2-run-dead-run-1/x.img"] = []string{"/dev/loop3"}
	rm.detachVisibleAfterQueries = 1 << 30 // never

	clk := useFakeClock(t)

	report, err := Reap(dir, "next-run", rm, io.Discard)
	if waited := clk.elapsed(); waited <= detachSettleTimeout || waited > detachSettleTimeout+detachSettlePoll {
		t.Fatalf("gave up after %s, want just past the %s bound", waited, detachSettleTimeout)
	}
	if !errors.Is(err, ErrReapIncomplete) {
		t.Fatalf("error = %v, want ErrReapIncomplete", err)
	}
	if !unremoved(report, "/tmp/go-luks2-run-dead-run-1") {
		t.Fatal("Reap passed over a loop device that never detached, without reporting it")
	}
}

// TestFinishFailsTheRunWhenCleanupFails is the first blocking finding from the
// hosted Codex review, and it is the fail-open path this whole harness exists
// to close, reintroduced at its last step.
//
// Finish used to log a cleanup failure and return. The caller then exited with
// m.Run()'s code, so a GREEN suite that could not remove its own dm mapping
// still exited 0 -- CI reporting success while the host kept the state and the
// ledger. The exit code has to come from the cleanup, not from the verdict.
func TestFinishFailsTheRunWhenCleanupFails(t *testing.T) {
	for _, tc := range []struct {
		name     string
		testCode int
		wantCode int
	}{
		{"green tests, failed cleanup", 0, 1},
		{"failed tests, failed cleanup keeps the original code", 3, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := stateDir(t)
			ledger, err := OpenLedger(dir, "run")
			if err != nil {
				t.Fatalf("OpenLedger: %v", err)
			}
			t.Cleanup(func() { _ = ledger.Close() })
			if err := ledger.Record(KindMapping, "stuck", "uuid-stuck"); err != nil {
				t.Fatalf("Record: %v", err)
			}

			rm := newFakeRemover()
			rm.mappings["stuck"] = "uuid-stuck"
			rm.removeErr["stuck"] = errors.New("device or resource busy")

			suite := &Suite{Ledger: ledger, TempDir: t.TempDir(), RunID: "run", Remover: rm}
			if got := suite.Finish(tc.testCode, io.Discard); got != tc.wantCode {
				t.Fatalf("Finish(%d) = %d, want %d", tc.testCode, got, tc.wantCode)
			}
		})
	}
}

// TestFinishPassesThroughACleanRunAndAFailingOne is the control: the exit code
// must not become a blunt instrument that reports failure whenever cleanup runs.
func TestFinishPassesThroughACleanRunAndAFailingOne(t *testing.T) {
	for _, code := range []int{0, 2} {
		dir := stateDir(t)
		ledger, err := OpenLedger(dir, "run")
		if err != nil {
			t.Fatalf("OpenLedger: %v", err)
		}
		if err := ledger.Record(KindMapping, "tidy", "uuid-tidy"); err != nil {
			t.Fatalf("Record: %v", err)
		}

		rm := newFakeRemover() // the test cleaned up after itself
		suite := &Suite{Ledger: ledger, TempDir: t.TempDir(), RunID: "run", Remover: rm}
		if got := suite.Finish(code, io.Discard); got != code {
			t.Fatalf("Finish(%d) = %d on a clean host, want it unchanged", code, got)
		}
	}
}

// TestReapOwnRemovesTheHolderBeforeTheDeviceItHolds is the second blocking
// finding: ReapOwn iterated the ledger directly while the cross-run Reap had
// been fixed to order holders first. The same defect in the sibling function.
//
// A passing run that leaked BOTH a dm mapping and its loop backing would try to
// detach the device its own mapping still held, get a busy error, and report an
// incomplete cleanup -- now also failing the run, which makes the ordering bug
// visible rather than merely wasteful.
func TestReapOwnRemovesTheHolderBeforeTheDeviceItHolds(t *testing.T) {
	dir := stateDir(t)
	ledger, err := OpenLedger(dir, "leaky-run")
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	t.Cleanup(func() { _ = ledger.Close() })

	// Ledger order, as BeginSuite produces it: loop root first.
	if err := ledger.Record(KindLoopRoot, "/tmp/go-luks2-run-leaky-run-1", ""); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := ledger.Record(KindMapping, "stacked", "uuid-stacked"); err != nil {
		t.Fatalf("Record: %v", err)
	}

	rm := newFakeRemover()
	rm.mappings["stacked"] = "uuid-stacked"
	rm.loops["/tmp/go-luks2-run-leaky-run-1/x.img"] = []string{"/dev/loop3"}
	rm.holdLoopUntilMappingGone = map[string]string{"/dev/loop3": "stacked"}

	if _, err := ReapOwn(ledger, rm, io.Discard); err != nil {
		t.Fatalf("ReapOwn: %v -- the holder was not removed before the device it holds", err)
	}
	if len(rm.loops) != 0 || len(rm.mappings) != 0 {
		t.Fatalf("state survived: loops=%v mappings=%v", rm.loops, rm.mappings)
	}
}

// TestUnconfirmedRemovalIsReportedAndTheRecordSurvives covers both P2 findings
// from the local review, and they are one defect at two sites.
//
// THE EXIT CODE MOVED, THE PROPERTY DID NOT. This asserted a fatal reap when
// removal could not be confirmed. It now asserts the two things that actually
// protect the host: the failure is REPORTED, and the LEDGER SURVIVES so a later
// run retries. "Fails closed" here means the record is not consumed on an
// unconfirmed removal -- which was always the expensive half -- not that the
// job dies. Making it fatal latched a runner twice (see Reap's exit-code
// policy), and the safety it was supposed to buy is bought by the #85 guard,
// which runs afterwards and refuses on any dm mapping still present.
//
// The verification was written `if err == nil && stillThere { fail }`, so an
// ERROR from the confirming query fell through to "removed" -- a check that
// reports clean precisely when it cannot see. The consequence is worse than a
// wrong status: reporting success lets the ledger be DELETED, destroying the
// only record of state nobody has confirmed is gone.
//
// "Present", "absent" and "unknown" are three answers. Only the second may
// consume the record.
func TestReapFailsClosedWhenItCannotConfirmRemoval(t *testing.T) {
	t.Run("dm removal that cannot be confirmed", func(t *testing.T) {
		dir := stateDir(t)
		path := writeLedger(t, dir, "dead-run",
			Entry{Kind: KindMapping, Value: "gone-maybe", Identity: "uuid-gone-maybe"})

		rm := newFakeRemover()
		rm.mappings["gone-maybe"] = "uuid-gone-maybe"
		rm.failVerificationAfterRemoval = true

		report, err := Reap(dir, "next-run", rm, io.Discard)
		if !errors.Is(err, ErrReapIncomplete) {
			t.Fatalf("error = %v, want ErrReapIncomplete", err)
		}
		if !unremoved(report, "gone-maybe") {
			t.Fatal("a removal that could not be confirmed was not reported")
		}
		// The record must survive: it is the only description of state whose
		// fate is unknown. THIS is the assertion that matters.
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("the ledger was consumed despite an unconfirmed removal: %v", err)
		}
	})

	t.Run("loop detach that cannot be confirmed", func(t *testing.T) {
		dir := stateDir(t)
		path := writeLedger(t, dir, "dead-run", Entry{Kind: KindLoopRoot, Value: "/tmp/go-luks2-run-dead-run-1"})

		rm := newFakeRemover()
		rm.loops["/tmp/go-luks2-run-dead-run-1/x.img"] = []string{"/dev/loop3"}
		rm.loopQueryErr = errors.New("sysfs read failed")

		report, err := Reap(dir, "next-run", rm, io.Discard)
		if !errors.Is(err, ErrReapIncomplete) {
			t.Fatalf("error = %v, want ErrReapIncomplete", err)
		}
		if !unremoved(report, "/tmp/go-luks2-run-dead-run-1") {
			t.Fatal("a detach that could not be confirmed was not reported")
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("the ledger was consumed despite an unconfirmed detach: %v", err)
		}
	})
}

// TestBeginSuiteRefusesToRunIfTempAllocationsEscapeTheRecordedRoot is the
// mechanism checking its own precondition.
//
// The loop half of the ledger is worth exactly nothing if the suite's backing
// files do not land under the recorded root: every run would record a root
// covering no devices, and every leaked loop device would be invisible to the
// next reaper -- the fail-open path this exists to close, wearing the costume
// of a working mechanism.
//
// os.TempDir() reads $TMPDIR on every call and t.TempDir() allocates through
// it, so the redirection does hold. But that is an assumption about the
// ENVIRONMENT, and the mechanism's correctness depends on it, so the mechanism
// checks it rather than trusting the documentation. This test drives the check
// directly with a root nothing allocates under.
func TestBeginSuiteRefusesToRunIfTempAllocationsEscapeTheRecordedRoot(t *testing.T) {
	// A directory that exists but that TMPDIR does not point at, so allocations
	// demonstrably land elsewhere -- exactly the state the guard must catch.
	elsewhere := t.TempDir()

	err := verifyAllocationsLandUnder(elsewhere)
	if err == nil {
		t.Fatal("verifyAllocationsLandUnder accepted a root that temp allocations do not land under")
	}
	if !errors.Is(err, ErrLedgerUnavailable) {
		t.Fatalf("error = %v, want it to match ErrLedgerUnavailable so the suite refuses to start", err)
	}
	// The operator has to be able to see both halves of the mismatch.
	if !strings.Contains(err.Error(), elsewhere) {
		t.Errorf("error = %q, want it to name the recorded root", err)
	}
	if !strings.Contains(err.Error(), "invisible to the next run's reaper") {
		t.Errorf("error = %q, want it to say what the consequence would be", err)
	}
}

// TestVerifyAllocationsLandUnderAcceptsTheRealRedirection is the positive
// control, and it is the one that would fail if TMPDIR ever stopped working:
// it sets TMPDIR the way BeginSuite does and asserts the probe agrees.
//
// Without this the guard above could pass while rejecting everything,
// including the correct configuration -- a check that always says no is not a
// check either.
func TestVerifyAllocationsLandUnderAcceptsTheRealRedirection(t *testing.T) {
	root, err := os.MkdirTemp("", "verify-root-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	saved, had := os.LookupEnv("TMPDIR")
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("TMPDIR", saved)
		} else {
			_ = os.Unsetenv("TMPDIR")
		}
	})
	if err := os.Setenv("TMPDIR", root); err != nil {
		t.Fatalf("Setenv: %v", err)
	}

	if err := verifyAllocationsLandUnder(root); err != nil {
		t.Fatalf("verifyAllocationsLandUnder rejected the real redirection: %v -- "+
			"either the guard is wrong or TMPDIR genuinely does not redirect temp allocations here", err)
	}
}

// TestLoopDiscoveryDistinguishesAbsentFromUnreadable is the sixth instance in
// this branch of the same idea, and it was in the code written to stop it.
//
// Both sysfs scans skipped a loop device whenever reading its backing_file
// failed, for ANY reason. ENOENT genuinely means unused -- or detached while
// the scan was running -- and skipping it is right. Every other failure means
// the backing file COULD NOT BE VERIFIED, and treating that as "no backing
// file" makes the scan return an empty list, which makes the reaper report
// AlreadyGone and DELETE the ledger for a device that may still be attached.
//
// The fault is injected by filesystem SHAPE -- backing_file as a directory,
// giving EISDIR -- not by permission bits, which root bypasses and which would
// make this pass vacuously in the CI containers.
func TestLoopDiscoveryDistinguishesAbsentFromUnreadable(t *testing.T) {
	root := t.TempDir()
	mk := func(dev string) string {
		t.Helper()
		d := filepath.Join(root, dev, "loop")
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		return filepath.Join(d, "backing_file")
	}

	// loop0: a real backing file we are looking for.
	if err := os.WriteFile(mk("loop0"), []byte("/tmp/go-luks2-run-x/x.img\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// loop1: no backing_file at all -- genuinely unused, must be skipped.
	if err := os.MkdirAll(filepath.Join(root, "loop1", "loop"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	t.Run("an unused device is skipped, not an error", func(t *testing.T) {
		got, err := loopDevicesUnderIn(root, "/tmp/go-luks2-run-x", stubBoundIdentity)
		if err != nil {
			t.Fatalf("loopDevicesUnderIn: %v", err)
		}
		if !slices.Equal(loopPaths(got), []string{"/dev/loop0"}) {
			t.Fatalf("= %v, want [/dev/loop0]", got)
		}
	})

	// loop2: backing_file exists but cannot be read. EISDIR for every uid.
	if err := os.Mkdir(mk("loop2"), 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	t.Run("an unreadable device fails the scan", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			call func() ([]LoopDevice, error)
		}{
			{"under a root", func() ([]LoopDevice, error) {
				return loopDevicesUnderIn(root, "/tmp/go-luks2-run-x", stubBoundIdentity)
			}},
			{"for an exact path", func() ([]LoopDevice, error) {
				return loopDevicesForIn(root, "/tmp/go-luks2-run-x/x.img", stubBoundIdentity)
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				got, err := tc.call()
				if err == nil {
					t.Fatalf("= %v, nil -- an unreadable backing_file was treated as no backing file, "+
						"so the reaper would report AlreadyGone and consume the ledger", got)
				}
				if !strings.Contains(err.Error(), "loop2") {
					t.Errorf("error = %q, want it to name the device it could not read", err)
				}
			})
		}
	})
}

// TestReapKeepsTheLedgerWhenLoopDiscoveryFails is the consequence at the level
// that matters: the record must survive, because it is the only description of
// a device nobody could confirm is gone.
func TestReapKeepsTheLedgerWhenLoopDiscoveryFails(t *testing.T) {
	dir := stateDir(t)
	path := writeLedger(t, dir, "dead-run", Entry{Kind: KindLoopRoot, Value: "/tmp/go-luks2-run-dead-run-1"})

	rm := newFakeRemover()
	rm.loopLookupErr = errors.New("reading /sys/block/loop2/loop/backing_file: is a directory")

	report, err := Reap(dir, "next-run", rm, io.Discard)
	if !errors.Is(err, ErrReapIncomplete) {
		t.Fatalf("error = %v, want ErrReapIncomplete", err)
	}
	if !unremoved(report, "/tmp/go-luks2-run-dead-run-1") {
		t.Fatal("an unenumerable device list was not reported")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the ledger was consumed despite an unreadable device list: %v", err)
	}
}

// TestStaleLedgersPropagatesAReadErrorRatherThanReportingNoLedgers closes the
// last place in the sweep where the recurring collapse could have hidden.
//
// staleLedgers returning (nil, nil) means "this host has no records", and Reap
// then prints "nothing recorded to remove" and exits 0. If a directory it
// cannot READ produced the same answer, a host full of ledgers would be
// reported clean -- the sixth instance's shape, one function over.
//
// ENOENT is the one error that legitimately means no records: the state
// directory does not exist, so nothing was ever written. Everything else must
// propagate.
//
// The fault is a regular file used as a directory component (ENOTDIR), which
// holds for every uid -- not a permission bit, which root bypasses.
func TestStaleLedgersPropagatesAReadErrorRatherThanReportingNoLedgers(t *testing.T) {
	base := stateDir(t)

	t.Run("absent means no records", func(t *testing.T) {
		// The reaper creates a missing state directory (0700) rather than
		// failing on it: nothing was ever written, so nothing is recorded.
		report, err := Reap(filepath.Join(base, "never-created"), "self", newFakeRemover(), io.Discard)
		if err != nil {
			t.Fatalf("Reap: %v", err)
		}
		if len(report.LedgersProcessed) != 0 {
			t.Fatalf("= %v, want none", report.LedgersProcessed)
		}
	})

	t.Run("unreadable does not", func(t *testing.T) {
		notADir := filepath.Join(base, "file")
		if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := Reap(filepath.Join(notADir, "sub"), "self", newFakeRemover(), io.Discard); err == nil {
			t.Fatal("a state directory that could not be opened was reported as having no ledgers")
		}
	})

	t.Run("a listing failure propagates", func(t *testing.T) {
		dir := stateDir(t)
		sd, unlock, err := lockReaper(dir)
		if err != nil {
			t.Fatalf("lockReaper: %v", err)
		}
		unlock() // closes the handle: listing through it must now fail, not report nothing
		if paths, err := staleLedgers(sd, "self"); err == nil {
			t.Fatalf("= %v, nil -- a directory that could not be listed was reported as having no ledgers", paths)
		}
	})
}

// TestDetachRefusesAReusedLoopNumber is the TOCTOU the local reviewer found:
// /dev/loopN is a REUSABLE name, and between enumerating a device by its
// backing path and clearing it, the number can be released and reassigned. A
// privileged reaper would then detach a stranger's device while believing it
// was removing its own, and the post-detach query cannot reveal the mistake --
// the device it looked for is gone either way.
func TestDetachRefusesAReusedLoopNumber(t *testing.T) {
	dir := stateDir(t)
	path := writeLedger(t, dir, "dead-run", Entry{Kind: KindLoopRoot, Value: "/tmp/go-luks2-run-dead-run-1"})

	rm := newFakeRemover()
	rm.loops["/tmp/go-luks2-run-dead-run-1/x.img"] = []string{"/dev/loop3"}
	// Between enumeration and detach, loop3 is reassigned to a stranger.
	rm.reassignBeforeDetach = map[string]string{"/dev/loop3": "/var/lib/libvirt/images/someone-elses.img"}

	report, err := Reap(dir, "next-run", rm, io.Discard)
	if !errors.Is(err, ErrReapIncomplete) {
		t.Fatalf("error = %v, want ErrReapIncomplete", err)
	}
	if !unremoved(report, "/tmp/go-luks2-run-dead-run-1") {
		t.Fatal("the refusal to detach a reassigned device was not reported")
	}
	// The damage plane, and this assertion is unchanged because it is the one
	// that matters: the stranger's device must still be attached.
	if _, ok := rm.loops["/var/lib/libvirt/images/someone-elses.img"]; !ok {
		t.Fatal("the reassigned device was detached")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the ledger was consumed despite refusing the detach: %v", err)
	}
}

// TestTheLoopIdentityIsTheBackingInodeNotItsName pins WHY the detach
// re-validates on lo_device/lo_inode, against what the kernel was MEASURED to
// do rather than against what three previous versions of this code assumed.
//
// Measured on Linux 6.8.0-58-generic, 2026-09-02, with LOOP_GET_STATUS64
// read directly:
//
//	bind a 21-byte path with losetup   name="/tmp/loopexp/dd/f.img"  len=21
//	  then unlink the backing file     name="/tmp/loopexp/dd/f.img"  len=21
//	bind a 91-byte path with losetup   name=<first 63 bytes>         len=63
//	  then unlink the backing file     name=<first 63 bytes>         len=63
//	bind with LOOP_SET_FD alone        name=""                       len=0
//	  ...and lo_inode is the real inode of the file in every one of them
//
// Three beliefs died there, and each had been load-bearing in this file:
//
//  1. "an empty name means the backing file was unlinked" -- FALSE. Unlinking
//     does not touch the name at all; sysfs gains " (deleted)" and the ioctl
//     reports exactly what it did before.
//  2. "an empty name means the path was too long for the 64-byte field" --
//     FALSE. An over-long path is truncated to 63 bytes, never emptied.
//  3. "an empty name is a rare corner" -- FALSE, and this is the one that
//     mattered. lo_file_name is written by USERSPACE through LOOP_SET_STATUS64;
//     pkg/luks2/loopdev.go binds with LOOP_SET_FD alone and never sets it, so
//     an empty name is what EVERY loop device this library creates reports. The
//     "unverifiable" branch was the normal path for our own devices, which is
//     why refusing on it would have latched the runner and why proceeding on it
//     was a blanket license to detach unidentified devices.
//
// The inode has none of those properties: the kernel maintains it, it is
// populated for a LOOP_SET_FD-only binding, unlinking does not disturb it, and
// a detach clears it -- re-binding a device reports the NEW inode, never a
// stale one, so a match cannot be inherited from a previous tenant.
func TestTheLoopIdentityIsTheBackingInodeNotItsName(t *testing.T) {
	// The property under test is the one the kernel has: identity follows the
	// bound FILE. Two devices carrying the same file are the same identity; the
	// device number contributes nothing.
	if fakeIdentityOf("/tmp/a.img") == fakeIdentityOf("/tmp/b.img") {
		t.Fatal("two different backings share an identity; a reassignment would compare equal")
	}
	if fakeIdentityOf("/tmp/a.img") != fakeIdentityOf("/tmp/a.img") {
		t.Fatal("one backing has two identities; every detach would refuse itself")
	}
}

// TestADeviceWhoseIdentityIsUnknownIsRefusedNotDetached is the finding from
// Codex on 974bf2de, and the reason the identity moved off the name.
//
// The previous version reached LOOP_CLR_FD on a device it had just declared it
// could not identify, on the strength of a sysfs scan taken earlier. That is
// uncertainty converted into a destructive action against a device number that
// the kernel is free to have reassigned in between.
//
// Refusing is only safe because of the measurement above: with the identity on
// the inode, capture succeeds for every device this suite creates, so this
// branch is a genuine anomaly rather than the everyday path. Refusing the
// everyday path is what would latch the runner.
func TestADeviceWhoseIdentityIsUnknownIsRefusedNotDetached(t *testing.T) {
	dir := stateDir(t)
	path := writeLedger(t, dir, "dead-run", Entry{Kind: KindLoopRoot, Value: "/tmp/go-luks2-run-dead-run-1"})

	rm := newFakeRemover()
	rm.loops["/tmp/go-luks2-run-dead-run-1/x.img"] = []string{"/dev/loop3"}
	rm.identityUnknown = map[string]bool{"/dev/loop3": true}

	report, err := Reap(dir, "next-run", rm, io.Discard)
	if !errors.Is(err, ErrReapIncomplete) {
		t.Fatalf("error = %v, want ErrReapIncomplete: a device that could not be identified must refuse the run", err)
	}
	if !unremoved(report, "/tmp/go-luks2-run-dead-run-1") {
		t.Fatal("the refusal was not reported")
	}

	// The damage plane. This is the assertion the finding is about: an
	// unidentifiable device must still be attached afterwards.
	if len(rm.detached) != 0 {
		t.Fatalf("detached %v -- a device whose identity could not be captured was cleared anyway", rm.detached)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the ledger was consumed despite refusing the detach: %v", err)
	}
}

// TestAnUnidentifiableDeviceIsStillEnumerated is the other half, and it is the
// half that is easy to get wrong in the safe-looking direction.
//
// Dropping the device from the scan would also avoid detaching it -- and would
// report the ledger entry as AlreadyGone, delete the record, and leave the
// device attached with nothing left that remembers it. Fail-closed means the
// device survives to be REFUSED, not that it vanishes from the report.
func TestAnUnidentifiableDeviceIsStillEnumerated(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "loop5", "loop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "backing_file"), []byte("/tmp/go-luks2-run-x/x.img\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	failing := func(device string) (loopIdentity, bool, error) {
		return loopIdentity{}, false, fmt.Errorf("reading the status of %s: input/output error", device)
	}

	got, err := loopDevicesUnderIn(root, "/tmp/go-luks2-run-x", failing)
	if err != nil {
		t.Fatalf("loopDevicesUnderIn: %v", err)
	}
	if !slices.Equal(loopPaths(got), []string{"/dev/loop5"}) {
		t.Fatalf("= %v, want [/dev/loop5] -- a device whose identity could not be read was dropped from the "+
			"scan, so the reaper would report AlreadyGone and consume the ledger for a device still attached", got)
	}
	if got[0].IdentityKnown {
		t.Error("the device claims a known identity after the capture failed")
	}
	if got[0].IdentityErr == nil {
		t.Error("the device carries no reason for the refusal to report")
	}
}

// TestADeviceReleasedBetweenScanAndCaptureIsDropped is the opposite answer to
// the same question, and the two must not be collapsed.
//
// ENXIO is the kernel saying the device is bound to nothing. There is nothing
// to detach and nothing wrong, so it leaves the list entirely -- unlike a
// capture that FAILED, which stays and refuses. This is the same
// absent-versus-unreadable distinction readBackingFile makes one layer up,
// applied at the layer that was added after it.
func TestADeviceReleasedBetweenScanAndCaptureIsDropped(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "loop6", "loop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "backing_file"), []byte("/tmp/go-luks2-run-x/x.img\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	unbound := func(string) (loopIdentity, bool, error) { return loopIdentity{}, false, nil }

	got, err := loopDevicesUnderIn(root, "/tmp/go-luks2-run-x", unbound)
	if err != nil {
		t.Fatalf("loopDevicesUnderIn: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("= %v, want nothing -- a device the kernel reports as unbound has nothing to detach", got)
	}
}

// TestReapSucceedsWhenTheDeviceWasAlreadyReleased is the CI-measured case at
// the level that matters: a run must not FAIL because something it was about
// to clean up had already been cleaned up.
//
// This is instance seven of the same idea in this branch, and the first found
// by the integration leg rather than by review: "not bound to anything" was
// collapsed into "bound to something else". The guard script cannot see it --
// it is semantic, not syntactic - which is worth knowing about the guard's
// reach as well as about the bug.
func TestReapSucceedsWhenTheDeviceWasAlreadyReleased(t *testing.T) {
	dir := stateDir(t)
	path := writeLedger(t, dir, "dead-run", Entry{Kind: KindLoopRoot, Value: "/tmp/go-luks2-run-dead-run-1"})

	rm := newFakeRemover()
	rm.loops["/tmp/go-luks2-run-dead-run-1/x.img"] = []string{"/dev/loop1"}
	// Released between the scan and the detach, as a test's own cleanup does.
	rm.releaseBeforeDetach = map[string]bool{"/dev/loop1": true}

	if _, err := Reap(dir, "next-run", rm, io.Discard); err != nil {
		t.Fatalf("Reap: %v -- a device that was already released was treated as a failure", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the ledger survived a reap with nothing left to do: %v", err)
	}
}

// TestTempRootIsRemovedAndItsFailureIsReported covers the blocking finding on
// b4c3838, which my own sweep had classified as cosmetic.
//
// The run temp root holds the disk images the tests create -- tens of
// megabytes each. Finish used to discard the ledger and THEN ignore
// os.RemoveAll, so a removal that failed left the images behind, the run
// exited 0, and the only record of where they were had already been destroyed.
// Repeated, that exhausts the runner's filesystem.
//
// I classified it as cosmetic because I asked only what host DEVICE state was
// behind it, and never asked what else the ledger was the record of. The
// directory is the other half.
func TestTempRootIsRemovedAndItsFailureIsReported(t *testing.T) {
	newSuite := func(t *testing.T, rm *fakeRemover) *Suite {
		t.Helper()
		dir := stateDir(t)
		ledger, err := OpenLedger(dir, "run")
		if err != nil {
			t.Fatalf("OpenLedger: %v", err)
		}
		t.Cleanup(func() { _ = ledger.Close() })
		return &Suite{Ledger: ledger, TempDir: "/tmp/go-luks2-run-test", RunID: "run", Remover: rm}
	}

	t.Run("a clean run removes it", func(t *testing.T) {
		rm := newFakeRemover()
		s := newSuite(t, rm)
		if got := s.Finish(0, io.Discard); got != 0 {
			t.Fatalf("Finish = %d, want 0", got)
		}
		if !slices.Contains(rm.removedDirs, "/tmp/go-luks2-run-test") {
			t.Fatalf("removedDirs = %v, want the temp root", rm.removedDirs)
		}
	})

	t.Run("a failed removal fails the run and keeps the ledger", func(t *testing.T) {
		rm := newFakeRemover()
		rm.removeDirErr["/tmp/go-luks2-run-test"] = errors.New("input/output error")
		s := newSuite(t, rm)
		path := s.Ledger.Path()

		if got := s.Finish(0, io.Discard); got == 0 {
			t.Fatal("Finish reported success after failing to remove the temp root")
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("the ledger was discarded despite an unremoved temp root: %v", err)
		}
	})
}

// TestReapRemovesTheTempRootOfAKilledRun is the other half of the finding: a
// killed run's directory was never removed at all. reapLoopRoot detached the
// devices and left the images.
func TestReapRemovesTheTempRootOfAKilledRun(t *testing.T) {
	dir := stateDir(t)
	path := writeLedger(t, dir, "dead-run", Entry{Kind: KindLoopRoot, Value: "/tmp/go-luks2-run-dead-run-1"})

	rm := newFakeRemover()
	rm.loops["/tmp/go-luks2-run-dead-run-1/x.img"] = []string{"/dev/loop3"}

	if _, err := Reap(dir, "next-run", rm, io.Discard); err != nil {
		t.Fatalf("Reap: %v", err)
	}
	if !slices.Contains(rm.removedDirs, "/tmp/go-luks2-run-dead-run-1") {
		t.Fatalf("removedDirs = %v -- the dead run's images were left on the runner", rm.removedDirs)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the ledger survived a complete reap: %v", err)
	}
}

// TestReapKeepsTheLedgerWhenTheTempRootCannotBeRemoved: the directory is state
// this run recorded, so failing to remove it is failing to clean up, and the
// record must survive for the retry.
func TestReapKeepsTheLedgerWhenTheTempRootCannotBeRemoved(t *testing.T) {
	dir := stateDir(t)
	path := writeLedger(t, dir, "dead-run", Entry{Kind: KindLoopRoot, Value: "/tmp/go-luks2-run-dead-run-1"})

	rm := newFakeRemover()
	rm.removeDirErr["/tmp/go-luks2-run-dead-run-1"] = errors.New("device or resource busy")

	report, err := Reap(dir, "next-run", rm, io.Discard)
	if err != nil {
		t.Fatalf("Reap: %v -- a directory is disk, not a device; it must not block the runner", err)
	}
	if len(report.DirsLeft) != 1 {
		t.Fatalf("DirsLeft = %v, want the unremoved root reported", report.DirsLeft)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the ledger was consumed despite an unremoved temp root: %v", err)
	}
}

// TestRemoveDirRefusesAPathThatCouldNotBeOurs bounds the blast radius of the
// one unbounded operation in this package.
//
// The path comes from a ledger, and the state directory is validated before
// anything in it is read -- so a forged entry is not the expected case. But
// os.RemoveAll aimed by a corrupt line is the worst thing here, and the check
// is nearly free. It is NOT the ownership decision: ownership comes from the
// record, as everywhere else.
func TestRemoveDirRefusesAPathThatCouldNotBeOurs(t *testing.T) {
	for _, tc := range []struct{ name, path string }{
		{"empty", ""},
		{"the filesystem root", "/"},
		{"relative", "some/dir"},
		{"a home directory", "/home/dev"},
		{"a system path", "/var/lib"},
		{"the right parent, the wrong name", "/tmp/important-data"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := safeToRemove(tc.path); err == nil {
				t.Fatalf("safeToRemove accepted %q", tc.path)
			}
		})
	}

	// The accept side: a directory named the way BeginSuite names them.
	if err := safeToRemove("/tmp/go-luks2-run-1405067156"); err != nil {
		t.Fatalf("safeToRemove refused a real run root: %v", err)
	}
}

// TestAnUnremovableDirectoryDoesNotLatchTheRunner keeps the latch guard where
// the non-fatal policy actually lives now: directories.
//
// A directory that will not delete must not make every future run on that host
// refuse. Trace what that would do: the reap fails, keeps the ledger "so the
// next run can finish the job", and the next run meets the same permanent
// condition and fails identically -- forever, on a condition that endangers
// nothing. Disk is not a device: the #85 guard never looks at it and no run
// trips over it.
//
// DEVICES ARE DELIBERATELY NOT IN THIS TEST. An earlier version of this file
// asserted the same non-fatal outcome for a stuck loop device, on the evidence
// that one had latched a runner permanently -- and that evidence turned out to
// be my own defect (an empty lo_file_name read as "already free", so
// LOOP_CLR_FD was never called). With that fixed, a retained device refuses the
// run, because the #85 guard inventories dm only and a loop device sails past
// it into the suite.
//
// The reap runs TWICE against an unchanged, permanently stuck directory and
// both must succeed. One run proves the classification; two prove it does not
// latch.
func TestAnUnremovableDirectoryDoesNotLatchTheRunner(t *testing.T) {
	dir := stateDir(t)
	path := writeLedger(t, dir, "dead-run", Entry{Kind: KindLoopRoot, Value: "/tmp/go-luks2-run-dead-run-1"})

	rm := newFakeRemover()
	rm.removeDirErr["/tmp/go-luks2-run-dead-run-1"] = errors.New("device or resource busy")

	for attempt := 1; attempt <= 2; attempt++ {
		report, err := Reap(dir, "next-run", rm, io.Discard)
		if err != nil {
			t.Fatalf("attempt %d: Reap failed on a permanently stuck DIRECTORY: %v -- "+
				"this is the latch: the next run would refuse identically, forever", attempt, err)
		}
		if len(report.DirsLeft) != 1 {
			t.Fatalf("attempt %d: DirsLeft = %v; a stuck directory must be visible, not silent",
				attempt, report.DirsLeft)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("attempt %d: the ledger was consumed; the record must survive for the retry: %v",
				attempt, err)
		}
	}

	// And the moment the condition clears, the retry finishes the job.
	delete(rm.removeDirErr, "/tmp/go-luks2-run-dead-run-1")

	report, err := Reap(dir, "next-run", rm, io.Discard)
	if err != nil {
		t.Fatalf("Reap: %v", err)
	}
	if len(report.DirsLeft) != 0 {
		t.Fatalf("DirsLeft = %v, want none once the condition cleared", report.DirsLeft)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the ledger survived a reap that removed everything: %v", err)
	}
}

// TestARetainedDeviceRefusesTheRun is the other side of that line, and it is
// the finding this policy came from: the #85 guard inventories `dmsetup ls`
// only, so a retained LOOP device passes it untouched and reaches the suite as
// a minor the host quietly no longer has (#104's threshold is four).
//
// Continuing on that is running on a contaminated host, which is a different
// thing from leaving some disk behind.
func TestARetainedDeviceRefusesTheRun(t *testing.T) {
	dir := stateDir(t)
	path := writeLedger(t, dir, "dead-run", Entry{Kind: KindLoopRoot, Value: "/tmp/go-luks2-run-dead-run-1"})

	rm := newFakeRemover()
	rm.loops["/tmp/go-luks2-run-dead-run-1/x.img"] = []string{"/dev/loop3"}
	rm.detachErr["/dev/loop3"] = errors.New("device or resource busy")

	report, err := Reap(dir, "next-run", rm, io.Discard)
	if !errors.Is(err, ErrReapIncomplete) {
		t.Fatalf("error = %v, want ErrReapIncomplete: a live device left on the host refuses the run", err)
	}
	if !unremoved(report, "/tmp/go-luks2-run-dead-run-1") {
		t.Fatal("the retained device was not named in the report")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the ledger was consumed despite a retained device: %v", err)
	}
}

// TestUnknownStateStillFailsClosed is the boundary of the change above, and
// without it the correction would be a license rather than a distinction.
//
// NOT KNOWING what is on the host is different from knowing and being unable to
// remove it. The first must still stop the job, because no useful record can be
// kept either: an untrusted state directory or an unreadable ledger means the
// reaper cannot say what it is looking at.
func TestUnknownStateStillFailsClosed(t *testing.T) {
	t.Run("an unreadable ledger", func(t *testing.T) {
		dir := stateDir(t)
		if err := os.WriteFile(filepath.Join(dir, "broken.ledger"), []byte("not a record\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := Reap(dir, "next-run", newFakeRemover(), io.Discard); err == nil {
			t.Fatal("Reap proceeded past a ledger it could not read")
		}
	})

	t.Run("an untrusted state directory", func(t *testing.T) {
		base := t.TempDir()
		target := filepath.Join(base, "real")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		link := filepath.Join(base, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		if _, err := Reap(link, "next-run", newFakeRemover(), io.Discard); err == nil {
			t.Fatal("Reap acted on ledgers in a directory it could not trust")
		}
	})
}

// TestReapEntryRefusesAKindItDoesNotKnow: ReadLedger already rejects unknown
// kinds, and this is the second line -- an entry nobody knows how to remove is
// a failure, not something to skip as removed.
func TestReapEntryRefusesAKindItDoesNotKnow(t *testing.T) {
	out, err := reapEntry(Entry{Kind: "zram", Value: "/dev/zram0"}, "dead-run", newFakeRemover(), io.Discard)
	if err == nil || out != outcomeNotOurs || !strings.Contains(err.Error(), `unknown record kind "zram"`) {
		t.Fatalf("reapEntry = %v, %v; want a refusal naming the kind", out, err)
	}
}

// TestReapErrorUnwrapsToEveryFailure: a caller asking errors.Is about one
// specific cause must find it whichever failure in the list carries it.
func TestReapErrorUnwrapsToEveryFailure(t *testing.T) {
	first := errors.New("device or resource busy")
	second := errors.New("input/output error")
	err := error(&ReapError{Failures: []ReapFailure{
		{Entry: Entry{Kind: KindMapping, Value: "a"}, Err: first},
		{Entry: Entry{Kind: KindLoopBacking, Value: "/b.img"}, Err: second},
	}})
	if !errors.Is(err, first) || !errors.Is(err, second) || !errors.Is(err, ErrReapIncomplete) {
		t.Fatalf("errors.Is did not reach every cause and the sentinel through %v", err)
	}
}

// TestFinishReportsAndLeavesANameSomethingElseNowHolds: a mapping this run
// recorded whose name now carries another identity is not ours to remove.
// Finish leaves it, says so, and still passes the run and discards the ledger
// -- nothing of ours is left under the name.
func TestFinishReportsAndLeavesANameSomethingElseNowHolds(t *testing.T) {
	ledger, err := OpenLedger(stateDir(t), "run")
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	if err := ledger.Record(KindMapping, "reused", "uuid-ours"); err != nil {
		t.Fatalf("Record: %v", err)
	}
	rm := newFakeRemover()
	rm.mappings["reused"] = "uuid-a-strangers"

	var out strings.Builder
	suite := &Suite{Ledger: ledger, TempDir: t.TempDir(), RunID: "run", Remover: rm}
	if got := suite.Finish(0, &out); got != 0 {
		t.Fatalf("Finish = %d, want 0: a name held by something else is not a failed cleanup", got)
	}
	if rm.mappings["reused"] != "uuid-a-strangers" {
		t.Fatal("Finish removed a mapping carrying someone else's identity")
	}
	if !strings.Contains(out.String(), "1 recorded name(s) are now held by something else") {
		t.Errorf("Finish output %q does not report the name it left alone", out.String())
	}
	if _, err := os.Stat(ledger.Path()); !os.IsNotExist(err) {
		t.Errorf("the ledger survived a Finish with nothing of ours outstanding: %v", err)
	}
}

// TestFinishFailsTheRunWhenTheLedgerCannotBeDiscarded: every resource is gone
// and the record of them cannot be deleted. That is safe -- the next run reaps
// it as a dead run's -- but it is not a clean finish, and a silent pass would
// hide a state directory nobody can write to.
func TestFinishFailsTheRunWhenTheLedgerCannotBeDiscarded(t *testing.T) {
	ledger, err := OpenLedger(stateDir(t), "run")
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	// Close the ledger's FILE only, so Discard's own close of it fails. The
	// state directory's handle stays open: ReapOwn reads the ledger through it.
	if err := ledger.f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	t.Cleanup(func() { _ = ledger.dir.Close() })

	var out strings.Builder
	suite := &Suite{Ledger: ledger, TempDir: t.TempDir(), RunID: "run", Remover: newFakeRemover()}
	if got := suite.Finish(0, &out); got != 1 {
		t.Fatalf("Finish = %d, want 1 when the ledger could not be discarded", got)
	}
	if !strings.Contains(out.String(), "could not discard the run ledger") {
		t.Errorf("Finish output %q does not say what failed", out.String())
	}
}
