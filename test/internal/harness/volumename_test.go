// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"errors"
	"strings"
	"testing"
)

// TestVolumeNameRefusesAMissingTerm is the assertion that matters: a name
// missing its scope or run id is host-global again, and would pass every test
// until two runs overlapped.
func TestVolumeNameRefusesAMissingTerm(t *testing.T) {
	tests := []struct {
		name               string
		base, scope, runID string
		wantTerm           string
	}{
		{"no base", "", "abc123", "1-xyz", "base"},
		{"no scope", "luks-rapid", "", "1-xyz", "scope"},
		{"no run id", "luks-rapid", "abc123", "", "run id"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VolumeName(tt.base, tt.scope, tt.runID)
			if err == nil {
				t.Fatalf("VolumeName(%q,%q,%q) = %q, want a refusal",
					tt.base, tt.scope, tt.runID, got)
			}
			if got != "" {
				t.Errorf("VolumeName returned %q alongside its error; a partial name must not escape", got)
			}
			if !errors.Is(err, ErrVolumeName) {
				t.Errorf("error = %v, want errors.Is(_, ErrVolumeName)", err)
			}
			var nameErr *VolumeNameError
			if !errors.As(err, &nameErr) {
				t.Fatalf("error = %v, want a *VolumeNameError", err)
			}
			if nameErr.Term != tt.wantTerm {
				t.Errorf("Term = %q, want %q", nameErr.Term, tt.wantTerm)
			}
		})
	}
}

// TestVolumeNameSanitizesEveryTerm pins that the rule is enforced where the name
// is built, not inherited from whatever produced the terms.
func TestVolumeNameSanitizesEveryTerm(t *testing.T) {
	got, err := VolumeName("luks/base", "host_name.local", "1:2")
	if err != nil {
		t.Fatalf("VolumeName failed: %v", err)
	}
	if want := "luks-base-host-name-local-1-2"; got != want {
		t.Errorf("VolumeName = %q, want %q", got, want)
	}
	for _, r := range got {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
		default:
			t.Errorf("VolumeName = %q contains %q, which device-mapper does not accept", got, r)
		}
	}
}

// TestTwoScopesNeverShareAName is the property the whole mechanism exists for.
func TestTwoScopesNeverShareAName(t *testing.T) {
	first, err := VolumeName("test-workflow", "containerA", "1-aaa")
	if err != nil {
		t.Fatalf("VolumeName failed: %v", err)
	}
	second, err := VolumeName("test-workflow", "containerB", "1-aaa")
	if err != nil {
		t.Fatalf("VolumeName failed: %v", err)
	}
	if first == second {
		t.Fatalf("two containers produced the same name %q from the same base and pid", first)
	}
}

func TestNewScopeIsUsableAsANameTerm(t *testing.T) {
	previous := hostname
	t.Cleanup(func() { hostname = previous })

	// A hostname of this test's choosing, carrying every kind of byte
	// device-mapper refuses, rather than whatever this machine is called.
	hostname = func() (string, error) { return "build_07.example.com", nil }
	scope, err := NewScope()
	if err != nil {
		t.Fatalf("NewScope failed: %v", err)
	}
	if want := "build-07-example-com"; scope != want {
		t.Errorf("NewScope = %q, want the sanitized hostname %q", scope, want)
	}
	for _, r := range scope {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
		default:
			t.Errorf("NewScope = %q contains %q, which device-mapper does not accept", scope, r)
		}
	}

	// No hostname is a refusal, never an empty scope VolumeName would have to
	// catch.
	hostname = func() (string, error) { return "", errors.New("uname failed") }
	if scope, err := NewScope(); !errors.Is(err, ErrVolumeName) || scope != "" {
		t.Errorf("NewScope with no hostname = %q, %v; want ErrVolumeName", scope, err)
	}

	// And the real one, on this machine: whatever it is, it sanitizes.
	hostname = previous
	if scope, err := NewScope(); err != nil || scope == "" {
		t.Errorf("NewScope on this host = %q, %v", scope, err)
	}
}

// TestSuiteVolumeNameUsesTheSuitesOwnTerms proves the method cannot be paired
// with another run's identity.
func TestSuiteVolumeNameUsesTheSuitesOwnTerms(t *testing.T) {
	s := &Suite{RunID: "7-zzz", Scope: "cid"}
	got, err := s.VolumeName("test-keyring")
	if err != nil {
		t.Fatalf("Suite.VolumeName failed: %v", err)
	}
	if want := "test-keyring-cid-7-zzz"; got != want {
		t.Errorf("Suite.VolumeName = %q, want %q", got, want)
	}
	if !strings.Contains(got, s.RunID) || !strings.Contains(got, s.Scope) {
		t.Errorf("Suite.VolumeName = %q, want it to carry both %q and %q", got, s.Scope, s.RunID)
	}
}

func TestSuiteVolumeNameRefusesAnIncompleteSuite(t *testing.T) {
	s := &Suite{RunID: "", Scope: "cid"}
	if got, err := s.VolumeName("test-keyring"); err == nil {
		t.Fatalf("Suite.VolumeName = %q on a suite with no run id, want a refusal", got)
	}
}

// TestVolumeNameErrorNamesTheEmptyTerm: the refusal is read in a CI log by
// someone who did not write the call, so it says which term was empty and
// what the other two were.
func TestVolumeNameErrorNamesTheEmptyTerm(t *testing.T) {
	_, err := VolumeName("luks", "", "123-abc")
	if !errors.Is(err, ErrVolumeName) {
		t.Fatalf("VolumeName with no scope = %v, want ErrVolumeName", err)
	}
	for _, want := range []string{"scope is empty", `base="luks"`, `run id="123-abc"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not carry %q", err, want)
		}
	}
}
