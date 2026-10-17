// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package header

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// config.requirements (#152).
//
// LUKS2 spells this member as an OBJECT carrying a mandatory array. It was
// modeled as a flat []string, so the decode failed outright and this package
// could not read ANY container mid-reencryption -- not "read it with a member
// missing", unreadable. That inverted the mechanism: requirements exists so an
// implementation that does not understand a feature refuses the container
// instead of damaging it, and the member carrying that warning was the one
// that would not parse.

// realRequirementsConfig is the shape cryptsetup writes during an online
// reencryption.
const realRequirementsConfig = `{
	"json_size": "12288",
	"keyslots_size": "16744448",
	"requirements": {"mandatory": ["online-reencrypt-v3"]}
}`

func TestConfigDecodesTheRequirementsObject(t *testing.T) {
	var config Config
	if err := json.Unmarshal([]byte(realRequirementsConfig), &config); err != nil {
		t.Fatalf("decoding a config with requirements: %v", err)
	}
	if config.Requirements == nil {
		t.Fatal("Requirements is nil; the object did not decode")
	}
	if got, want := config.Requirements.Mandatory, []string{"online-reencrypt-v3"}; len(got) != 1 || got[0] != want[0] {
		t.Errorf("Mandatory = %v, want %v", got, want)
	}
}

// TestConfigWithoutRequirementsLeavesItNil keeps the ordinary container free
// of an empty object: a member LUKS2 did not write must not appear because
// this package modeled it.
func TestConfigWithoutRequirementsLeavesItNil(t *testing.T) {
	var config Config
	if err := json.Unmarshal([]byte(`{"json_size":"12288","keyslots_size":"16744448"}`), &config); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if config.Requirements != nil {
		t.Errorf("Requirements = %+v, want nil for a container that declares none", config.Requirements)
	}

	out, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("re-encoding: %v", err)
	}
	if strings.Contains(string(out), "requirements") {
		t.Errorf("re-encoding invented a requirements member\n got: %s", out)
	}
}

func TestRequirementsRoundTripsWithUnmodeledMembers(t *testing.T) {
	const withExtras = `{"mandatory":["online-reencrypt-v3"],"advisory":["vendor-hint"]}`

	var requirements Requirements
	if err := json.Unmarshal([]byte(withExtras), &requirements); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	// Value, not pointer: the receiver hazard pinned for every other object.
	out, err := json.Marshal(requirements)
	if err != nil {
		t.Fatalf("re-encoding: %v", err)
	}
	for _, want := range []string{`"mandatory"`, `"online-reencrypt-v3"`, `"advisory"`, `"vendor-hint"`} {
		if !strings.Contains(string(out), want) {
			t.Errorf("%s did not survive the round trip\n got: %s", want, out)
		}
	}
}

// TestAnUnimplementedRequirementRefusesTheWrite is the decision this issue
// carried: the refusal lands on the WRITE, because that is where corruption
// happens, and it lands before the device is touched.
func TestAnUnimplementedRequirementRefusesTheWrite(t *testing.T) {
	metadata := minimalValidMetadata()
	metadata.Config.Requirements = &Requirements{Mandatory: []string{"online-reencrypt-v3"}}

	hdr := &BinaryHeader{HeaderSize: HeaderSize + DefaultSize}
	err := CheckHeaderWritable(hdr, metadata)
	if err == nil {
		t.Fatal("CheckHeaderWritable accepted a container with an unimplemented mandatory requirement")
	}
	if !errors.Is(err, ErrUnsupportedRequirement) {
		t.Fatalf("error = %v, want errors.Is(_, ErrUnsupportedRequirement)", err)
	}

	var reqErr *UnsupportedRequirementError
	if !errors.As(err, &reqErr) {
		t.Fatalf("error = %v, want an *UnsupportedRequirementError", err)
	}
	if reqErr.Requirement != "online-reencrypt-v3" {
		t.Errorf("Requirement = %q, want %q", reqErr.Requirement, "online-reencrypt-v3")
	}
	if len(reqErr.Mandatory) != 1 {
		t.Errorf("Mandatory = %v, want the whole declared list", reqErr.Mandatory)
	}
	if !strings.Contains(err.Error(), "online-reencrypt-v3") {
		t.Errorf("Error() = %q, want it to name the requirement", err.Error())
	}
}

// TestInlineHWTagsIsKeptAndRefusesTheWrite is LUKS2 On-Disk Format 1.1.4's
// inline-hw-tags requirement: the segment's authentication tags live in the
// device's per-sector inline hardware tags, with dm-crypt alone and every
// dm-integrity option ignored. This package has no inline hardware tag
// support, so the flag is read and re-encoded exactly, and a write refuses
// with the requirement named rather than dropping it.
func TestInlineHWTagsIsKeptAndRefusesTheWrite(t *testing.T) {
	const config = `{"json_size":"12288","keyslots_size":"16744448","requirements":{"mandatory":["inline-hw-tags"]}}`

	var decoded Config
	if err := json.Unmarshal([]byte(config), &decoded); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	out, err := MarshalCanonicalJSON(&decoded)
	if err != nil {
		t.Fatalf("MarshalCanonicalJSON: %v", err)
	}
	if string(out) != config {
		t.Errorf("the requirement did not round-trip byte for byte\n got: %s\nwant: %s", out, config)
	}

	metadata := minimalValidMetadata()
	metadata.Config.Requirements = decoded.Requirements
	hdr := &BinaryHeader{HeaderSize: HeaderSize + DefaultSize}
	err = CheckHeaderWritable(hdr, metadata)
	var reqErr *UnsupportedRequirementError
	if !errors.As(err, &reqErr) || !errors.Is(err, ErrUnsupportedRequirement) {
		t.Fatalf("CheckHeaderWritable = %v, want an *UnsupportedRequirementError", err)
	}
	if reqErr.Requirement != "inline-hw-tags" {
		t.Errorf("Requirement = %q, want %q", reqErr.Requirement, "inline-hw-tags")
	}
}

// TestNoRequirementsWritesNormally is the control: the guard must not refuse
// an ordinary container. Without it, the test above would pass against a
// guard that refused everything.
func TestNoRequirementsWritesNormally(t *testing.T) {
	metadata := minimalValidMetadata()

	hdr := &BinaryHeader{HeaderSize: HeaderSize + DefaultSize}
	if err := CheckHeaderWritable(hdr, metadata); err != nil {
		t.Fatalf("CheckHeaderWritable refused an ordinary container: %v", err)
	}

	// And an empty mandatory list is not a requirement either.
	metadata.Config.Requirements = &Requirements{}
	if err := CheckHeaderWritable(hdr, metadata); err != nil {
		t.Fatalf("CheckHeaderWritable refused a container whose mandatory list is empty: %v", err)
	}
}

// TestAnImplementedRequirementIsAccepted proves the set is consulted rather
// than the refusal being unconditional, so adding support to
// implementedRequirements is all it takes to stop refusing.
func TestAnImplementedRequirementIsAccepted(t *testing.T) {
	const pretend = "pretend-implemented-v1"
	implementedRequirements[pretend] = true
	defer delete(implementedRequirements, pretend)

	metadata := minimalValidMetadata()
	metadata.Config.Requirements = &Requirements{Mandatory: []string{pretend}}

	hdr := &BinaryHeader{HeaderSize: HeaderSize + DefaultSize}
	if err := CheckHeaderWritable(hdr, metadata); err != nil {
		t.Fatalf("CheckHeaderWritable refused an implemented requirement: %v", err)
	}
}

// TestTheFirstUnimplementedRequirementIsReported pins the diagnosis as
// deterministic: the same container must always name the same entry.
func TestTheFirstUnimplementedRequirementIsReported(t *testing.T) {
	metadata := minimalValidMetadata()
	metadata.Config.Requirements = &Requirements{
		Mandatory: []string{"first-unknown", "second-unknown"},
	}

	hdr := &BinaryHeader{HeaderSize: HeaderSize + DefaultSize}
	var reqErr *UnsupportedRequirementError
	for i := 0; i < 5; i++ {
		err := CheckHeaderWritable(hdr, metadata)
		if !errors.As(err, &reqErr) {
			t.Fatalf("error = %v, want an *UnsupportedRequirementError", err)
		}
		if reqErr.Requirement != "first-unknown" {
			t.Fatalf("Requirement = %q, want the first declared entry", reqErr.Requirement)
		}
	}
}
