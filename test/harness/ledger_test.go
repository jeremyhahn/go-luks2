// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestLedgerRecordIsDurableBeforeItReturns(t *testing.T) {
	dir := stateDir(t)
	ledger, err := OpenLedger(dir, "run-1")
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	t.Cleanup(func() { _ = ledger.Close() })

	if err := ledger.Record(KindMapping, "test-mount", "CRYPT-LUKS2-abc-test-mount"); err != nil {
		t.Fatalf("Record: %v", err)
	}

	// Read it back through a SEPARATE file handle, which is what a reaper in
	// another process does. The record must already be there: the guarantee is
	// that nothing is created before it is durable, so a Record that returns
	// with the line still buffered would leave the exact unattributable state
	// this package exists to prevent.
	entries, err := ReadLedger(filepath.Join(dir, "run-1.ledger"))
	if err != nil {
		t.Fatalf("ReadLedger: %v", err)
	}
	want := []Entry{{Kind: KindMapping, Value: "test-mount", Identity: "CRYPT-LUKS2-abc-test-mount"}}
	if len(entries) != 1 || entries[0] != want[0] {
		t.Fatalf("entries = %v, want %v", entries, want)
	}
}

func TestLedgerRecordRejectsValuesThatWouldCorruptTheRecord(t *testing.T) {
	dir := stateDir(t)
	ledger, err := OpenLedger(dir, "run-1")
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	t.Cleanup(func() { _ = ledger.Close() })

	for _, tc := range []struct{ name, value, identity string }{
		{"newline in value", "test\nmount", "uuid"},
		{"tab in value", "test\tmount", "uuid"},
		{"newline in identity", "test-mount", "uu\nid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ledger.Record(KindMapping, tc.value, tc.identity)
			if err == nil {
				t.Fatal("Record accepted a value carrying a record separator")
			}
			// The caller must be able to treat this as "do not create the
			// resource", which is what the sentinel says.
			if !errors.Is(err, ErrLedgerUnavailable) {
				t.Fatalf("error = %v, want it to match ErrLedgerUnavailable", err)
			}
		})
	}

	// Nothing was written, so a later read still parses.
	if _, err := ReadLedger(filepath.Join(dir, "run-1.ledger")); err != nil {
		t.Fatalf("a rejected record corrupted the ledger: %v", err)
	}
}

func TestLedgerRecordIsSafeUnderConcurrentUse(t *testing.T) {
	dir := stateDir(t)
	ledger, err := OpenLedger(dir, "run-1")
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	t.Cleanup(func() { _ = ledger.Close() })

	const writers = 16
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := "vol-" + string(rune('a'+i))
			if err := ledger.Record(KindMapping, name, "uuid-"+name); err != nil {
				t.Errorf("Record(%s): %v", name, err)
			}
		}(i)
	}
	wg.Wait()

	// The suite creates mappings from concurrent tests, so an interleaved write
	// would produce a line the reaper cannot parse -- and an unparseable ledger
	// is state nothing will ever clean up.
	entries, err := ReadLedger(filepath.Join(dir, "run-1.ledger"))
	if err != nil {
		t.Fatalf("concurrent records produced an unparseable ledger: %v", err)
	}
	if len(entries) != writers {
		t.Fatalf("read %d entries, want %d", len(entries), writers)
	}
}

func TestLedgerSurvivesCloseAndIsDeletedOnlyByDiscard(t *testing.T) {
	dir := stateDir(t)
	ledger, err := OpenLedger(dir, "run-1")
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	if err := ledger.Record(KindMapping, "test-mount", "uuid"); err != nil {
		t.Fatalf("Record: %v", err)
	}
	path := ledger.Path()

	// Close is what a run that ENDED does, cleanly or otherwise. The file must
	// remain: its presence is the signal that this run may have left state.
	if err := ledger.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("Close deleted the ledger; a killed run would then leave no record: %v", err)
	}

	ledger2, err := OpenLedger(dir, "run-2")
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	if err := ledger2.Discard(); err != nil {
		t.Fatalf("Discard: %v", err)
	}
	if _, err := os.Stat(ledger2.Path()); !os.IsNotExist(err) {
		t.Fatalf("Discard left the ledger behind: %v", err)
	}
}

func TestReadLedgerRefusesACorruptFileRatherThanSkippingLines(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"too few fields", "dm\ttest-mount\n"},
		{"too many fields", "dm\ttest-mount\tuuid\textra\n"},
		{"unknown kind", "mapping\ttest-mount\tuuid\n"},
		{"empty value", "dm\t\tuuid\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "run-1.ledger")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			_, err := ReadLedger(path)
			if err == nil {
				t.Fatal("ReadLedger accepted a corrupt ledger")
			}
			if !errors.Is(err, ErrLedgerCorrupt) {
				t.Fatalf("error = %v, want it to match ErrLedgerCorrupt", err)
			}
			// The operator has to be able to find the line.
			if !strings.Contains(err.Error(), path) {
				t.Errorf("error = %q, want it to name the file", err)
			}
		})
	}
}

func TestReadLedgerIgnoresBlankLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "run-1.ledger")
	if err := os.WriteFile(path, []byte("dm\ta\tuuid-a\n\ndm\tb\tuuid-b\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	entries, err := ReadLedger(path)
	if err != nil {
		t.Fatalf("ReadLedger: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("read %d entries, want 2", len(entries))
	}
}

func TestNewRunIDDistinguishesRunsWithTheSamePID(t *testing.T) {
	// A container's pid namespace makes pid 1 the norm, so two runs on one host
	// collide on the pid alone -- and a collision has a live run reaping its own
	// state out from under itself, because Reap skips the ledger it is told is
	// the current one.
	a := NewRunID(1, 1000)
	b := NewRunID(1, 2000)
	if a == b {
		t.Fatalf("NewRunID returned %q for two different runs with the same pid", a)
	}
}
