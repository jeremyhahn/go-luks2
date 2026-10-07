// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2_test

import (
	"bytes"
	"errors"
	"os/exec"
	"strconv"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/jeremyhahn/go-luks2/test/internal/harness"
)

// The keyslot priority tests that need a REAL cryptsetup container; see
// pkg/luks2's own (now-moved) keyslotpriority_integration_test.go for why.

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

func TestCryptsetupOmitsANormalPriorityAndWeReadItAsNormal(t *testing.T) {
	requireCryptsetupDeclared(t)

	path := canonicalImage(t, "cs-priority.img")
	formatWithCryptsetupCheap(t, path)

	if json := readJSONArea(t, path); bytes.Contains(json, []byte(`"priority"`)) {
		t.Fatalf("cryptsetup wrote a priority member, so this test no longer measures what it claims\n%s", json)
	}

	slots, err := harness.ListKeyslots(path)
	if err != nil {
		t.Fatalf("ListKeyslots failed: %v", err)
	}
	if len(slots) != 1 {
		t.Fatalf("ListKeyslots returned %d slots, want 1", len(slots))
	}
	if slots[0].Priority != luks2.PriorityNormal {
		t.Fatalf("a cryptsetup keyslot with no priority member is reported as %d, want %d (normal).",
			slots[0].Priority, luks2.PriorityNormal)
	}
}

func TestCryptsetupPrioritiesRoundTrip(t *testing.T) {
	requireCryptsetupDeclared(t)

	tests := []struct {
		name    string
		spelled string
		want    luks2.Priority
		member  bool
	}{
		{"prefer", "prefer", luks2.PriorityPrefer, true},
		{"ignore", "ignore", luks2.PriorityIgnore, true},
		{"normal", "normal", luks2.PriorityNormal, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := canonicalImage(t, "cs-priority.img")
			formatWithCryptsetupCheap(t, path)
			runCryptsetupConfig(t, path, tt.spelled, 0)

			hasMember := bytes.Contains(readJSONArea(t, path), []byte(`"priority"`))
			if hasMember != tt.member {
				t.Fatalf("cryptsetup --priority %s: priority member present = %v, want %v",
					tt.spelled, hasMember, tt.member)
			}

			slots, err := harness.ListKeyslots(path)
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

func TestAddKeyWritesNoPriorityMember(t *testing.T) {
	requireCryptsetupDeclared(t)

	path := canonicalImage(t, "addkey-priority.img")
	formatWithLibraryCheap(t, path)

	if _, err := AddKey(path, []byte(canonicalPassphrase), []byte("a-second-credential"), &AddKeyOptions{
		KDFType:         "pbkdf2",
		Hash:            "sha512",
		PBKDFIterations: canonicalCheapIterations,
	}); err != nil {
		t.Fatalf("AddKey failed: %v", err)
	}

	if json := readJSONArea(t, path); bytes.Contains(json, []byte(`"priority"`)) {
		t.Fatalf("AddKey wrote a priority member; a newly added key gets no special treatment\n%s", json)
	}

	slots, err := harness.ListKeyslots(path)
	if err != nil {
		t.Fatalf("ListKeyslots failed: %v", err)
	}
	if len(slots) != 2 {
		t.Fatalf("ListKeyslots returned %d slots, want 2", len(slots))
	}
	for _, slot := range slots {
		if slot.Priority != luks2.PriorityNormal {
			t.Errorf("keyslot %d is reported as priority %d, want %d (normal)",
				slot.ID, slot.Priority, luks2.PriorityNormal)
		}
	}

	cmd := exec.Command("cryptsetup", "luksOpen", "--test-passphrase", path) // #nosec G204 -- path is under t.TempDir()
	cmd.Stdin = bytes.NewReader([]byte("a-second-credential"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cryptsetup cannot open the container with the key this package added: %v\n%s", err, out)
	}
}
