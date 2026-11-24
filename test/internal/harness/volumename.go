// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// Device-mapper names are host-wide, so each is <base>-<scope>-<run id>: scope names the container, run id the process and its ledger.

// ErrVolumeName is returned when a run-scoped name cannot be built.
var ErrVolumeName = errors.New("harness: cannot build a run-scoped volume name")

// VolumeNameError reports which term was missing or unusable.
type VolumeNameError struct {
	Base  string
	Scope string
	RunID string
	Term  string
}

func (e *VolumeNameError) Error() string {
	return fmt.Sprintf("%v: %s is empty (base=%q scope=%q run id=%q)",
		ErrVolumeName, e.Term, e.Base, e.Scope, e.RunID)
}

func (e *VolumeNameError) Unwrap() error { return ErrVolumeName }

// SanitizeNameTerm replaces anything outside [A-Za-z0-9-] with '-'.
func SanitizeNameTerm(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

// hostname is os.Hostname, as a variable so a test can give NewScope a
// hostname of its choosing -- and a failure -- instead of depending on the
// machine it runs on. Nothing else changes it.
var hostname = os.Hostname

// NewScope returns the token identifying this container: its hostname.
func NewScope() (string, error) {
	host, err := hostname()
	if err != nil {
		return "", fmt.Errorf("%w: hostname unavailable: %v", ErrVolumeName, err)
	}
	return SanitizeNameTerm(host), nil
}

// VolumeName returns a device-mapper name unique to this container and process, refusing an empty term.
func VolumeName(base, scope, runID string) (string, error) {
	switch {
	case base == "":
		return "", &VolumeNameError{Base: base, Scope: scope, RunID: runID, Term: "base"}
	case scope == "":
		return "", &VolumeNameError{Base: base, Scope: scope, RunID: runID, Term: "scope"}
	case runID == "":
		return "", &VolumeNameError{Base: base, Scope: scope, RunID: runID, Term: "run id"}
	}
	return SanitizeNameTerm(base) + "-" + SanitizeNameTerm(scope) + "-" + SanitizeNameTerm(runID), nil
}

// VolumeName is the Suite's form: the scope and run id are the suite's own, so
// a caller cannot pair a name with the wrong run.
func (s *Suite) VolumeName(base string) (string, error) {
	return VolumeName(base, s.Scope, s.RunID)
}
