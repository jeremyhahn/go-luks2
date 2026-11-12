// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/header"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// stampMandatoryRequirement declares requirement in the primary header's
// config.requirements.mandatory, bypassing the write path's own guard (which
// refuses a requirement it does not implement) the way a header written by
// another implementation would arrive.
func stampMandatoryRequirement(t *testing.T, device, requirement string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Clean(device), os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("could not open the image: %v", err)
	}
	defer func() { _ = f.Close() }()

	hdr, metadata, err := header.ReadHeaderCopyFrom(f, header.PrimaryHeaderOffset)
	if err != nil {
		t.Fatalf("reading the header failed: %v", err)
	}
	metadata.Config.Requirements = &header.Requirements{Mandatory: []string{requirement}}
	hdr.SequenceID++
	jsonData, area, err := header.EncodeMetadataIgnoringRequirements(hdr, metadata)
	if err != nil {
		t.Fatalf("encoding the header failed: %v", err)
	}
	if err := header.WriteEncodedHeader(f, hdr, jsonData, area, (*os.File).Sync); err != nil {
		t.Fatalf("writing the header failed: %v", err)
	}
}

// assertRequirementInError is the caller's view of an unsupported mandatory
// requirement: a *luks2.Error whose Kind is ErrUnsupportedRequirement and
// whose Detail names the requirement and says it is mandatory. No named
// requirement type is exported; Kind and Detail carry it.
func assertRequirementInError(t *testing.T, op string, err error, requirement string) {
	t.Helper()
	for _, problem := range requirementErrorProblems(op, err, requirement, luks2.ErrUnsupportedRequirement) {
		t.Error(problem)
	}
}

// requirementErrorProblems lists how err falls short of a *luks2.Error of
// kind wantKind whose Detail names the mandatory requirement and whose chain
// errors.Is finds ErrUnsupportedRequirement in. It returns nothing when err
// holds all of that.
func requirementErrorProblems(op string, err error, requirement string, wantKind error) []string {
	var lerr *luks2.Error
	if !errors.As(err, &lerr) {
		return []string{fmt.Sprintf("%s = %v (%T), want a *luks2.Error", op, err, err)}
	}
	var problems []string
	if lerr.Kind != wantKind {
		problems = append(problems, fmt.Sprintf("%s: Kind = %v, want %v", op, lerr.Kind, wantKind))
	}
	if !strings.Contains(lerr.Detail, requirement) {
		problems = append(problems, fmt.Sprintf("%s: Detail = %q, want it to name %q", op, lerr.Detail, requirement))
	}
	if !strings.Contains(lerr.Detail, "mandatory") {
		problems = append(problems, fmt.Sprintf("%s: Detail = %q, want it to say the requirement is mandatory", op, lerr.Detail))
	}
	if !errors.Is(err, luks2.ErrUnsupportedRequirement) {
		problems = append(problems, fmt.Sprintf("%s: errors.Is(err, ErrUnsupportedRequirement) = false for %v", op, err))
	}
	return problems
}

// TestUnsupportedRequirementIsReadableFromLuks2Error pins the caller's
// contract for a container declaring a mandatory requirement this library
// does not implement (here inline-hw-tags, LUKS2 On-Disk Format 1.1.4): Unlock
// and the header writes (AddKeyslot, ChangeKeyslot, RemoveKeyslot) all refuse
// with a *luks2.Error carrying the requirement in Kind and Detail, from
// outside the package.
func TestUnsupportedRequirementIsReadableFromLuks2Error(t *testing.T) {
	const requirement = "inline-hw-tags"
	path := filepath.Join(t.TempDir(), "requirement.img")
	if err := createSeamImage(path); err != nil {
		t.Fatal(err)
	}

	v, err := luks2.Open(context.Background(), path, luks2.WithTestSysForTest())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })
	if err := v.Format(context.Background(), seamSecret(t, seamPassphrase), luks2.FormatParams{KDF: seamKDF()}); err != nil {
		t.Fatalf("Format failed: %v", err)
	}
	// The key is recovered before the requirement is declared, so the write
	// below is refused for the requirement and not for want of a key.
	key := seamUnlock(t, v, seamPassphrase)
	// A second keyslot, so the removal below is refused for the requirement
	// and not as the last keyslot.
	spare, err := v.AddKeyslot(context.Background(), key, seamSecret(t, "seam-passphrase-spare"), luks2.KeyslotParams{KDF: seamKDF()})
	if err != nil {
		t.Fatalf("AddKeyslot before the requirement failed: %v", err)
	}

	stampMandatoryRequirement(t, path, requirement)

	_, err = v.Unlock(context.Background(), seamSecret(t, seamPassphrase))
	assertRequirementInError(t, "Unlock", err, requirement)

	_, err = v.AddKeyslot(context.Background(), key, seamSecret(t, "seam-passphrase-two"), luks2.KeyslotParams{KDF: seamKDF()})
	assertRequirementInError(t, "AddKeyslot", err, requirement)

	_, err = v.ChangeKeyslot(context.Background(), key, seamSecret(t, "seam-passphrase-three"), luks2.KeyslotParams{KDF: seamKDF()})
	assertRequirementInError(t, "ChangeKeyslot", err, requirement)

	err = v.RemoveKeyslot(context.Background(), spare.ID)
	assertRequirementInError(t, "RemoveKeyslot", err, requirement)
}

// migrationRequirement is the mandatory requirement the migration case
// stamps on its volume; the child reads the error for it.
const migrationRequirement = "inline-hw-tags"

// TestRequirementThatStopsMigrationKeepsTheMigrationKind: in a non-FIPS
// process, MigrateToFIPS on an Argon2 volume that declares an unsupported
// mandatory requirement fails as a migration. Kind stays ErrFIPSMigration,
// Detail names the requirement, and both errors.Is for
// ErrUnsupportedRequirement and errors.As to *FIPSMigrationError hold. The
// Argon2 volume is made and migrated in a child with FIPS off, so the case
// runs the same under the FIPS gate.
func TestRequirementThatStopsMigrationKeepsTheMigrationKind(t *testing.T) {
	path := filepath.Join(t.TempDir(), "migration-requirement.img")
	if err := createSeamImage(path); err != nil {
		t.Fatal(err)
	}
	runSeamChildOK(t, seamRoleFormatArgon2, path, "fips140=off", false)

	stampMandatoryRequirement(t, path, migrationRequirement)

	if out := runSeamChildOK(t, seamRoleMigrateRequirement, path, "fips140=off", false); out != "" {
		t.Fatalf("migration child: %s", out)
	}
}

// seamMigrateRequirement is the migration case's child body: it migrates
// the stamped Argon2 volume and reports every way the error falls short.
func seamMigrateRequirement(ctx context.Context, image string, pass enclave.ByteAccess) error {
	v, err := luks2.Open(ctx, image, luks2.WithTestSysForTest())
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()
	_, err = v.MigrateToFIPS(ctx, pass, luks2.MigrateParams{KDF: seamKDF()})
	problems := requirementErrorProblems("MigrateToFIPS", err, migrationRequirement, luks2.ErrFIPSMigration)
	var merr *luks2.FIPSMigrationError
	if !errors.As(err, &merr) {
		problems = append(problems, fmt.Sprintf("MigrateToFIPS: %v (%T) is not a *FIPSMigrationError", err, err))
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "\n"))
	}
	return nil
}
