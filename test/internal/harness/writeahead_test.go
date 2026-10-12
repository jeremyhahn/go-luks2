// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMappingUUIDIsCryptsetupsFormat(t *testing.T) {
	got := MappingUUID("0f6e0a3b-6f2c-4a52-9d6e-2b8c1f0e9a11", "vol")
	const want = "CRYPT-LUKS2-0f6e0a3b6f2c4a529d6e2b8c1f0e9a11-vol"
	if got != want {
		t.Fatalf("MappingUUID = %q, want %q", got, want)
	}
}

func TestMappingUUIDIsCutToTheKernelsLength(t *testing.T) {
	got := MappingUUID("0f6e0a3b-6f2c-4a52-9d6e-2b8c1f0e9a11", strings.Repeat("n", 127))
	if len(got) != dmUUIDMaxLength {
		t.Fatalf("len(MappingUUID) = %d, want %d", len(got), dmUUIDMaxLength)
	}
	if !strings.HasPrefix(got, "CRYPT-LUKS2-0f6e0a3b6f2c4a529d6e2b8c1f0e9a11-nnn") {
		t.Fatalf("MappingUUID = %q; the cut must keep the prefix", got)
	}
}

// The FIPS child of #348: the mapping is activated in another process, and the
// run is canceled after that process exits and before the parent does
// anything more. The entry written ahead is all that run leaves, and it must be
// enough for the next run's reaper to remove the mapping.
func TestAMappingRecordedAheadIsReapedAfterTheRunDiesMidActivation(t *testing.T) {
	image := formatRawHeaderFixture(t)
	dir := stateDir(t)
	ledger, err := OpenLedger(dir, "killed-run")
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	uuid, err := ledger.RecordMappingAhead(image, "fips-child")
	if err != nil {
		t.Fatalf("RecordMappingAhead: %v", err)
	}

	hdr, _, err := ReadHeader(image)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if want := MappingUUID(strings.TrimRight(string(hdr.UUID[:]), "\x00"), "fips-child"); uuid != want {
		t.Fatalf("recorded identity %q, want %q", uuid, want)
	}

	// The activation, in the child, after the record; then the run dies.
	rm := newFakeRemover()
	rm.mappings["fips-child"] = uuid
	if err := ledger.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	report, err := Reap(dir, "next-run", rm, io.Discard)
	if err != nil {
		t.Fatalf("Reap: %v", err)
	}
	if len(rm.mappings) != 0 || len(report.Removed) != 1 {
		t.Fatalf("the reaper left %v on the host and removed %v; want the mapping removed", rm.mappings, report.Removed)
	}
}

func TestAMappingRecordedAheadButNeverCreatedIsAlreadyGone(t *testing.T) {
	image := formatRawHeaderFixture(t)
	dir := stateDir(t)
	ledger, err := OpenLedger(dir, "killed-run")
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	if _, err := ledger.RecordMappingAhead(image, "never-activated"); err != nil {
		t.Fatalf("RecordMappingAhead: %v", err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	report, err := Reap(dir, "next-run", newFakeRemover(), io.Discard)
	if err != nil {
		t.Fatalf("Reap: %v", err)
	}
	if len(report.AlreadyGone) != 1 {
		t.Fatalf("report.AlreadyGone = %v, want the one entry", report.AlreadyGone)
	}
}

func TestRecordMappingAheadOfAnUnreadableHeaderRecordsNothing(t *testing.T) {
	dir := stateDir(t)
	ledger, err := OpenLedger(dir, "run")
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	defer func() { _ = ledger.Close() }()

	_, err = ledger.RecordMappingAhead(filepath.Join(t.TempDir(), "missing.img"), "vol")
	var recErr *RecordError
	if !errors.As(err, &recErr) {
		t.Fatalf("RecordMappingAhead of a missing device = %v, want a *RecordError", err)
	}
	entries, err := ReadLedger(ledger.Path())
	if err != nil {
		t.Fatalf("ReadLedger: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("the ledger holds %v; a mapping with no derivable identity must not be recorded", entries)
	}
}

func TestCheckRecordedMapping(t *testing.T) {
	inspect := errors.New("dm inventory unreadable")
	rm := newFakeRemover()
	rm.mappings["ours"] = "uuid-ours"
	rm.mappings["drifted"] = "uuid-live"
	rm.inspectErr["unreadable"] = inspect

	if err := CheckRecordedMapping(rm, "ours", "uuid-ours"); err != nil {
		t.Errorf("a live mapping carrying the recorded identity: %v", err)
	}
	if err := CheckRecordedMapping(rm, "absent", "uuid-absent"); err != nil {
		t.Errorf("no live mapping: %v", err)
	}
	if err := CheckRecordedMapping(rm, "drifted", "uuid-recorded"); err == nil {
		t.Error("a live mapping carrying another identity passed; the reaper would not remove it")
	}
	if err := CheckRecordedMapping(rm, "unreadable", "uuid"); !errors.Is(err, inspect) {
		t.Errorf("an inventory that cannot be read = %v, want %v", err, inspect)
	}
}

// TestActivateRecordedAheadRecordsBeforeActivating is #348's in-process gap:
// the Unlock helpers recorded the mapping only once Activate had returned, so
// a run killed in between left one no ledger attributed.
func TestActivateRecordedAheadRecordsBeforeActivating(t *testing.T) {
	image := formatRawHeaderFixture(t)
	ledger, err := OpenLedger(stateDir(t), "live-run")
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	hdr, _, err := ReadHeader(image)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	want := MappingUUID(strings.TrimRight(string(hdr.UUID[:]), "\x00"), "vol")

	rm := newFakeRemover()
	activated := false
	err = ledger.ActivateRecordedAhead(rm, image, "vol", func() error {
		activated = true
		entries, err := ledger.entries()
		if err != nil {
			t.Fatalf("reading the ledger during the activation: %v", err)
		}
		recorded := false
		for _, e := range entries {
			recorded = recorded || e == (Entry{Kind: KindMapping, Value: "vol", Identity: want})
		}
		if !recorded {
			t.Errorf("the ledger held %v when the activation started, want the mapping %q recorded", entries, want)
		}
		rm.mappings["vol"] = want
		return nil
	})
	if err != nil || !activated {
		t.Fatalf("ActivateRecordedAhead = %v (activated %v), want the activation run and checked", err, activated)
	}
}

func TestActivateRecordedAheadReportsWhatTheReaperCouldNotMatch(t *testing.T) {
	image := formatRawHeaderFixture(t)
	ledger, err := OpenLedger(stateDir(t), "live-run")
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	rm := newFakeRemover()

	refused := errors.New("activation refused")
	rm.inspectErr["refused"] = errors.New("the check ran after a refused activation")
	if err := ledger.ActivateRecordedAhead(rm, image, "refused", func() error { return refused }); !errors.Is(err, refused) {
		t.Errorf("a refused activation = %v, want %v as it is", err, refused)
	}

	if err := ledger.ActivateRecordedAhead(rm, image, "drifted", func() error {
		rm.mappings["drifted"] = "CRYPT-LUKS2-someone-else-drifted"
		return nil
	}); err == nil {
		t.Error("a mapping live under another identity passed; the reaper would not remove it")
	}

	err = ledger.ActivateRecordedAhead(rm, filepath.Join(t.TempDir(), "missing.img"), "unreadable", func() error {
		t.Error("the activation ran without a record ahead of it")
		return nil
	})
	var recordErr *RecordError
	if !errors.As(err, &recordErr) {
		t.Errorf("an unreadable header = %v, want a *RecordError", err)
	}
}

// TestSetupLoopDeviceRefusesAFileOutsideTheRecordedRunRoot is #348's loop
// gap: a device backed outside the recorded root is one the next run's reaper
// cannot attribute, so it is refused before anything is attached.
func TestSetupLoopDeviceRefusesAFileOutsideTheRecordedRunRoot(t *testing.T) {
	saved := recordedRunRoot
	t.Cleanup(func() { recordedRunRoot = saved })

	root := filepath.Join(t.TempDir(), runRootPrefix+"live-run-1")
	outside := filepath.Join(t.TempDir(), "outside.img")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(root, "inside.img")
	for _, f := range []string{outside, inside} {
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	escape := filepath.Join(root, "escape.img")
	if err := os.Symlink(outside, escape); err != nil {
		t.Fatal(err)
	}
	beside := root + "-sibling.img"
	if err := os.WriteFile(beside, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	recordedRunRoot = ""
	var rootErr *RunRootError
	if _, err := SetupLoopDevice(inside); !errors.As(err, &rootErr) {
		t.Errorf("attaching with no recorded run root = %v, want a *RunRootError", err)
	}

	recordedRunRoot = root
	for name, file := range map[string]string{
		"outside the root":             outside,
		"a symlink out of the root":    escape,
		"beside the root, same prefix": beside,
		"a file that does not exist":   filepath.Join(root, "absent.img"),
	} {
		if _, err := SetupLoopDevice(file); !errors.As(err, &rootErr) {
			t.Errorf("attaching %s = %v, want a *RunRootError", name, err)
		}
	}
	if err := checkBackedUnderRunRoot(inside); err != nil {
		t.Errorf("a file below the recorded root was refused: %v", err)
	}
}
