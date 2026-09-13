// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"bytes"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// The keyslot priority tests that need a REAL cryptsetup container.
//
// The unit tier covers the mapping from a *int to a KeyslotInfo. What it cannot
// establish is the premise the mapping rests on: that cryptsetup actually omits
// the member, so that "absent" is the case this package meets in practice
// rather than a corner one. That is a fact about another program, and asserting
// it from a hand-built fixture would be asserting it from this package's own
// belief about cryptsetup -- which is exactly how the defect survived.

// runCryptsetupConfig sets a keyslot priority through cryptsetup, so the
// container this package reads was written by the reference implementation.
func runCryptsetupConfig(t *testing.T, path, priority string, slot int) {
	t.Helper()

	out, err := exec.Command("cryptsetup", "config", // #nosec G204 -- arguments are test constants
		"--priority", priority,
		"--key-slot", strconv.Itoa(slot),
		path,
	).CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("cryptsetup config --priority %s exited %d\n%s", priority, exitErr.ExitCode(), out)
		}
		t.Fatalf("failed to run cryptsetup config: %v\n%s", err, out)
	}
}

// TestCryptsetupOmitsANormalPriorityAndWeReadItAsNormal is the measurement the
// read-side fix rests on, and the regression test for it in one.
//
// Before the fix, ListKeyslots reported priority 0 -- IGNORE -- for the keyslot
// of a container cryptsetup had just created, because cryptsetup writes no
// priority member for a normal keyslot and the absent member was read as the
// zero value. Any consumer using priority to decide which keyslots to try would
// have skipped every slot of every cryptsetup-made volume.
func TestCryptsetupOmitsANormalPriorityAndWeReadItAsNormal(t *testing.T) {
	requireCryptsetupDeclared(t)

	path := canonicalImage(t, "cs-priority.img")
	formatWithCryptsetupCheap(t, path)

	// The premise, measured rather than assumed: cryptsetup's own container has
	// no priority member at all.
	if json := readJSONArea(t, path); bytes.Contains(json, []byte(`"priority"`)) {
		t.Fatalf("cryptsetup wrote a priority member, so this test no longer measures what it claims\n%s", json)
	}

	slots, err := ListKeyslots(path)
	if err != nil {
		t.Fatalf("ListKeyslots failed: %v", err)
	}
	if len(slots) != 1 {
		t.Fatalf("ListKeyslots returned %d slots, want 1", len(slots))
	}
	if slots[0].Priority != KeyslotPriorityNormal {
		t.Fatalf("a cryptsetup keyslot with no priority member is reported as %d, want %d (normal). "+
			"%d is IGNORE, which tells an operator -- and any priority-aware unlock -- to skip a perfectly good keyslot.",
			slots[0].Priority, KeyslotPriorityNormal, slots[0].Priority)
	}
}

// TestCryptsetupPrioritiesRoundTrip is the control: the default must be a
// default, not a constant. A read path that returned normal unconditionally
// would pass the test above and lose every real priority.
//
// It also pins the direction of the scale against cryptsetup itself -- `prefer`
// is 2 and `ignore` is 0 -- which is the fact addKey had backwards.
func TestCryptsetupPrioritiesRoundTrip(t *testing.T) {
	requireCryptsetupDeclared(t)

	tests := []struct {
		name    string
		spelled string
		want    int
		member  bool
	}{
		{"prefer", "prefer", KeyslotPriorityPrefer, true},
		{"ignore", "ignore", KeyslotPriorityIgnore, true},
		{"normal", "normal", KeyslotPriorityNormal, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := canonicalImage(t, "cs-priority.img")
			formatWithCryptsetupCheap(t, path)
			runCryptsetupConfig(t, path, tt.spelled, 0)

			// Whether cryptsetup writes the member at all is itself part of
			// the contract: it DELETES it for normal, which is why absent has
			// to mean normal.
			hasMember := bytes.Contains(readJSONArea(t, path), []byte(`"priority"`))
			if hasMember != tt.member {
				t.Fatalf("cryptsetup --priority %s: priority member present = %v, want %v",
					tt.spelled, hasMember, tt.member)
			}

			slots, err := ListKeyslots(path)
			if err != nil {
				t.Fatalf("ListKeyslots failed: %v", err)
			}
			if len(slots) != 1 {
				t.Fatalf("ListKeyslots returned %d slots, want 1", len(slots))
			}
			if slots[0].Priority != tt.want {
				t.Fatalf("cryptsetup --priority %s is read as %d, want %d", tt.spelled, slots[0].Priority, tt.want)
			}
		})
	}
}

// TestAddKeyWritesNoPriorityMember is the write half against the third party.
//
// addKey used to set priority 2 under a comment reading "Lower priority than
// original keyslot". 2 is PREFER: every key this package added was marked as
// the one to try FIRST, the opposite of the stated intent, and cryptsetup would
// have honored it. cryptsetup's own luksAddKey writes no member, which is
// asserted here alongside so the two cannot drift.
func TestAddKeyWritesNoPriorityMember(t *testing.T) {
	requireCryptsetupDeclared(t)

	path := canonicalImage(t, "addkey-priority.img")
	formatWithLibraryCheap(t, path)

	if err := AddKey(path, []byte(canonicalPassphrase), []byte("a-second-credential"), &AddKeyOptions{
		KDFType:         KDFTypePBKDF2,
		Hash:            "sha512",
		PBKDFIterations: canonicalCheapIterations,
	}); err != nil {
		t.Fatalf("AddKey failed: %v", err)
	}

	if json := readJSONArea(t, path); bytes.Contains(json, []byte(`"priority"`)) {
		t.Fatalf("AddKey wrote a priority member; a newly added key gets no special treatment\n%s", json)
	}

	slots, err := ListKeyslots(path)
	if err != nil {
		t.Fatalf("ListKeyslots failed: %v", err)
	}
	if len(slots) != 2 {
		t.Fatalf("ListKeyslots returned %d slots, want 2", len(slots))
	}
	for _, slot := range slots {
		if slot.Priority != KeyslotPriorityNormal {
			t.Errorf("keyslot %d is reported as priority %d, want %d (normal)",
				slot.ID, slot.Priority, KeyslotPriorityNormal)
		}
	}

	// cryptsetup must still open the container, with the credential this
	// package added. Without this the test would be satisfied by an AddKey that
	// wrote no priority and no usable keyslot either.
	cmd := exec.Command("cryptsetup", "luksOpen", "--test-passphrase", path) // #nosec G204 -- path is under t.TempDir()
	cmd.Stdin = strings.NewReader("a-second-credential")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cryptsetup cannot open the container with the key this package added: %v\n%s", err, out)
	}
}
