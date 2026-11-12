// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	var lerr *luks2.Error
	if !errors.As(err, &lerr) {
		t.Fatalf("%s = %v (%T), want a *luks2.Error", op, err, err)
	}
	if lerr.Kind != luks2.ErrUnsupportedRequirement {
		t.Errorf("%s: Kind = %v, want ErrUnsupportedRequirement", op, lerr.Kind)
	}
	if !strings.Contains(lerr.Detail, requirement) {
		t.Errorf("%s: Detail = %q, want it to name %q", op, lerr.Detail, requirement)
	}
	if !strings.Contains(lerr.Detail, "mandatory") {
		t.Errorf("%s: Detail = %q, want it to say the requirement is mandatory", op, lerr.Detail)
	}
	if !errors.Is(err, luks2.ErrUnsupportedRequirement) {
		t.Errorf("%s: errors.Is(err, ErrUnsupportedRequirement) = false for %v", op, err)
	}
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
