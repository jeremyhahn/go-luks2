// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/test/harness"
)

// kernel is a Remover over an in-memory device-mapper table. RemoveMapping
// really deletes from the table it reports from, so a reap that claims to have
// removed a mapping is checked against the state it changed, not against a
// recorded call.
type kernel struct {
	mappings  map[string]string // name -> dm uuid
	removeErr error
	removed   []string
}

func (k *kernel) MappingIdentity(name string) (string, bool, error) {
	uuid, ok := k.mappings[name]
	return uuid, ok, nil
}

func (k *kernel) RemoveMapping(name string) error {
	if k.removeErr != nil {
		return k.removeErr
	}
	k.removed = append(k.removed, name)
	delete(k.mappings, name)
	return nil
}

func (k *kernel) LoopDevicesFor(string) ([]harness.LoopDevice, error)   { return nil, nil }
func (k *kernel) LoopDevicesUnder(string) ([]harness.LoopDevice, error) { return nil, nil }
func (k *kernel) RemoveDir(path string) error                           { return os.RemoveAll(path) }
func (k *kernel) DetachLoop(harness.LoopDevice) error {
	return errors.New("no loop device was recorded, so none may be detached")
}

// stateDir is a ledger directory the harness will trust: 0700 and ours.
// t.TempDir() itself is created 0777 &^ umask, which a umask of 002 leaves
// group-writable, and the harness rightly refuses that.
func stateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("creating the state directory: %v", err)
	}
	return dir
}

// deadRun leaves the ledger of a run that recorded a mapping and died without
// removing it.
func deadRun(t *testing.T, dir, mapping, uuid string) {
	t.Helper()
	ledger, err := harness.OpenLedger(dir, "4242-dead")
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	if err := ledger.Record(harness.KindMapping, mapping, uuid); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestRunReportsAHostWithNothingRecordedAsClean(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-state-dir", stateDir(t)}, &kernel{}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d, want 0; stderr: %s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("a clean reap wrote to stderr: %q", stderr.String())
	}
}

func TestRunRemovesWhatADeadRunRecorded(t *testing.T) {
	dir := stateDir(t)
	deadRun(t, dir, "luks-dead-run", "CRYPT-LUKS2-dead")
	k := &kernel{mappings: map[string]string{"luks-dead-run": "CRYPT-LUKS2-dead"}}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-state-dir", dir}, k, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d, want 0; stderr: %s", code, stderr.String())
	}
	if _, still := k.mappings["luks-dead-run"]; still {
		t.Fatal("the recorded mapping is still in the table after a reap that exited 0")
	}
}

func TestRunFailsWhenRecordedStateCannotBeRemoved(t *testing.T) {
	dir := stateDir(t)
	deadRun(t, dir, "luks-stuck", "CRYPT-LUKS2-stuck")
	k := &kernel{
		mappings:  map[string]string{"luks-stuck": "CRYPT-LUKS2-stuck"},
		removeErr: errors.New("device or resource busy"),
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-state-dir", dir}, k, &stdout, &stderr); code != 1 {
		t.Fatalf("exit %d, want 1: a mapping the reaper could not remove leaves the host unknown", code)
	}
	if !strings.Contains(stderr.String(), "not known to be clean") {
		t.Errorf("stderr = %q, want it to say the host is not known to be clean", stderr.String())
	}
}

func TestRunWarnsAboutAndLeavesAMappingThatIsNotTheOneRecorded(t *testing.T) {
	dir := stateDir(t)
	deadRun(t, dir, "luks-reused", "CRYPT-LUKS2-recorded")
	k := &kernel{mappings: map[string]string{"luks-reused": "CRYPT-LUKS2-someone-else"}}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-state-dir", dir}, k, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d, want 0; stderr: %s", code, stderr.String())
	}
	if len(k.removed) != 0 {
		t.Fatalf("removed %v: a mapping carrying a different identity is not ours", k.removed)
	}
	if !strings.Contains(stderr.String(), `WARNING: dm "luks-reused"`) {
		t.Errorf("stderr = %q, want a warning naming the mapping it left alone", stderr.String())
	}
}

func TestRunWithAnEmptyStateDirLooksAtNothing(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-state-dir", ""}, &kernel{}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d, want 0", code)
	}
	if !strings.Contains(stderr.String(), "nothing to look at") {
		t.Errorf("stderr = %q, want it to say there is nothing to look at", stderr.String())
	}
}

func TestRunRefusesAnInvocationItCannotParse(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-all"}, &kernel{}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit %d, want 1: an unparsed invocation has not examined the host", code)
	}
	if !strings.Contains(stderr.String(), "-all") {
		t.Errorf("stderr = %q, want it to name the flag it refused", stderr.String())
	}
}
