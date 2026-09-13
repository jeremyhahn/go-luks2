// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestVolumeNameCarriesBothScopeAndRunID(t *testing.T) {
	got, err := VolumeName("luks-rapid", "abc123", "1-xyz")
	if err != nil {
		t.Fatalf("VolumeName failed: %v", err)
	}
	if want := "luks-rapid-abc123-1-xyz"; got != want {
		t.Errorf("VolumeName = %q, want %q", got, want)
	}
}

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
	scope, err := NewScope()
	if err != nil {
		t.Fatalf("NewScope failed: %v", err)
	}
	if scope == "" {
		t.Fatal("NewScope returned an empty scope, which VolumeName must refuse")
	}
	for _, r := range scope {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
		default:
			t.Errorf("NewScope = %q contains %q, which device-mapper does not accept", scope, r)
		}
	}
	host, err := os.Hostname()
	if err != nil {
		t.Skip("hostname unavailable; NewScope already reported usable output above")
	}
	if want := SanitizeNameTerm(host); scope != want {
		t.Errorf("NewScope = %q, want the sanitized hostname %q", scope, want)
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
