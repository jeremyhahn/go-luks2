// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"fmt"
	"path/filepath"
	"strings"
)

// dmUUIDMaxLength is the longest dm UUID the kernel stores: DM_UUID_LEN less
// its terminating NUL. pkg/dmcrypt cuts at the same length.
const dmUUIDMaxLength = 128

// MappingUUID is the dm UUID a mapping gets when the LUKS2 container whose
// header UUID is headerUUID is activated under name:
// "CRYPT-LUKS2-<header uuid without dashes>-<name>", cut to the kernel's
// length. It is cryptsetup's format, and dmcrypt.Activate follows it, so one
// derivation covers a mapping either of them creates.
//
// It exists so a mapping can be recorded BEFORE it exists (#348). Recording
// what an activation returned leaves a window in which the mapping is on the
// host and in no ledger; when the activation runs in another process -- a
// FIPS child, cryptsetup -- that window lasts until the parent sees the child
// exit, and a canceled run dies in it. Being a copy of the derivation, it is
// checked against the live mapping after every activation that relies on it
// (CheckRecordedMapping), so a drift fails the run that introduced it instead
// of leaving a mapping the reaper will not touch.
func MappingUUID(headerUUID, name string) string {
	uuid := "CRYPT-LUKS2-" + strings.ReplaceAll(headerUUID, "-", "") + "-" + name
	if len(uuid) > dmUUIDMaxLength {
		uuid = uuid[:dmUUIDMaxLength]
	}
	return uuid
}

// RecordMappingAhead records the dm mapping that activating device under name
// will create, before anything creates it, and returns the identity it
// recorded. A run killed at any point of the activation then leaves an entry
// the reaper matches by that identity; an entry whose mapping was never
// created is reaped as already gone.
func (l *Ledger) RecordMappingAhead(device, name string) (string, error) {
	hdr, _, err := ReadHeader(device)
	if err != nil {
		return "", &RecordError{Kind: KindMapping, Value: name,
			Err: fmt.Errorf("reading the header of %s to derive the mapping's identity: %w", device, err)}
	}
	headerUUID := strings.TrimRight(string(hdr.UUID[:]), "\x00")
	if headerUUID == "" {
		// An empty header UUID derives an identity that names no container;
		// recording it would make the reaper's identity check meaningless.
		return "", &RecordError{Kind: KindMapping, Value: name,
			Err: fmt.Errorf("the header of %s carries no UUID to derive the mapping's identity from", device)}
	}
	uuid := MappingUUID(headerUUID, name)
	if err := l.Record(KindMapping, name, uuid); err != nil {
		return "", err
	}
	return uuid, nil
}

// CheckRecordedMapping confirms that the mapping called name, if one is live,
// carries the identity recorded for it ahead of its activation. A mismatch is
// an error: the reaper would leave that mapping alone, so it is host state no
// ledger attributes. No live mapping is not an error -- the activation may
// have been refused, or the test already removed it.
func CheckRecordedMapping(rm Remover, name, recorded string) error {
	uuid, present, err := rm.MappingIdentity(name)
	if err != nil {
		return err
	}
	if present && uuid != recorded {
		return fmt.Errorf("dm %q carries uuid %q, not the %q recorded ahead of its activation; "+
			"the reaper will not remove it", name, uuid, recorded)
	}
	return nil
}

// ActivateRecordedAhead runs activate, which maps device as name, with the
// mapping recorded in l before activate starts (#348), then checks the live
// mapping against that record. Recording what activate created once it has
// returned is too late: a run killed in between leaves a mapping no ledger
// attributes, and the next run's reaper refuses the host.
//
// An error from activate is returned as it is, so a caller can still tell a
// refused activation by its sentinel. If the check fails the mapping exists
// under an identity the reaper will not match; removing it is the caller's
// job, since this package does not activate anything itself.
func (l *Ledger) ActivateRecordedAhead(rm Remover, device, name string, activate func() error) error {
	uuid, err := l.RecordMappingAhead(device, name)
	if err != nil {
		return err
	}
	if err := activate(); err != nil {
		return err
	}
	return CheckRecordedMapping(rm, name, uuid)
}

// recordedRunRoot is the temp root BeginSuite recorded in this process's
// ledger, or empty while no suite has. Every loop device the suite attaches
// must be backed below it: the reaper finds a dead run's devices by their
// backing files under that root, and has no other record of them.
var recordedRunRoot string

// checkBackedUnderRunRoot refuses file unless it resolves to a path below
// recordedRunRoot. The comparison is against the resolved path because that
// is what the kernel reports as the backing file, and so what the reaper sees.
func checkBackedUnderRunRoot(file string) error {
	const action = "attach a loop device to"
	if recordedRunRoot == "" {
		return &RunRootError{Action: action, Path: file,
			Problem: "no suite has recorded a run root in this process (TestMain must call BeginSuite)"}
	}
	resolved, err := filepath.EvalSymlinks(file)
	if err != nil {
		return &RunRootError{Action: action, Path: file,
			Problem: fmt.Sprintf("its location cannot be resolved: %v", err)}
	}
	if abs, err := filepath.Abs(resolved); err == nil {
		resolved = abs
	}
	if !strings.HasPrefix(resolved, filepath.Clean(recordedRunRoot)+string(filepath.Separator)) {
		return &RunRootError{Action: action, Path: file,
			Problem: fmt.Sprintf("it is not below the run root %q this run recorded, so the next run's "+
				"reaper could not attribute the device", recordedRunRoot)}
	}
	return nil
}
