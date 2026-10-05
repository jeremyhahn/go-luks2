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

// Device-mapper names are a FLAT, HOST-WIDE namespace, and device-mapper is not
// namespaced by containers: two suites running at once on one machine see and
// contend for each other's mappings no matter how they were started. A constant
// name is therefore a collision waiting for a second run, and the loser fails
// with something that reads like a library defect:
//
//	Unlock failed on cycle 1: volume already unlocked: the device-mapper name
//	"luks-rapid" is already in use
//
// Worse, a test that "cleans up leftover state" by closing the name first does
// not clean up -- it tears down whichever SIBLING RUN currently holds it.
//
// So every name this suite creates carries two terms:
//
//	<base>-<scope>-<run id>
//
//	scope   identifies the CONTAINER. Shared by the three test binaries that
//	        run inside one container, and different for every container, which
//	        is what lets the entrypoint guard recognize this invocation's own
//	        mappings without knowing anything about the binaries.
//	run id  identifies the PROCESS, and is the same id the ledger records, so
//	        a name and its cleanup record agree.
//
// The ledger (#96) does not make this unnecessary. It governs CLEANUP -- what a
// run created, so a later run can remove exactly that. It says nothing about
// ALLOCATION, and nothing in it stops two runs choosing the same name.

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

// SanitizeNameTerm keeps a term inside what device-mapper accepts.
//
// Anything outside [A-Za-z0-9-] becomes '-'. The callers' inputs -- a hostname
// and "<pid>-<base36 nanos>" -- are already safe, but this does not depend on
// that: enforcing the rule is the job of the code that builds the name, not
// something to inherit from producers that may change.
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

// NewScope returns the token identifying this CONTAINER.
//
// It is the hostname, which Docker sets to the container's own id: unique per
// container, and identical for every process inside one -- exactly the two
// properties the scope term needs, with no environment variable to plumb
// through and therefore no way for the guard and the suite to disagree about
// what this invocation is called.
//
// Outside a container the hostname is the machine's, which is shared between
// concurrent runs. Names stay unique anyway because the run id term is
// per-process; only the entrypoint guard's notion of "mine" widens, and that
// guard runs in the container.
func NewScope() (string, error) {
	host, err := hostname()
	if err != nil {
		return "", fmt.Errorf("%w: hostname unavailable: %v", ErrVolumeName, err)
	}
	return SanitizeNameTerm(host), nil
}

// VolumeName returns a device-mapper name unique to this container and process.
//
// It REFUSES an empty term rather than dropping it. A name silently missing its
// scope or run id is host-global again, and it would pass every test until two
// runs happened to overlap -- the failure this exists to remove, reintroduced
// invisibly.
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
