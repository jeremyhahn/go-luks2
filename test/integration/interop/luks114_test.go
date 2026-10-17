// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package interop_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/header"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/jeremyhahn/go-luks2/test/internal/harness"
)

// LUKS2 On-Disk Format 1.1.4 added two things: the optional integrity.key_size
// of a crypt segment and the inline-hw-tags requirement flag. cryptsetup
// gained both in 2.8.0; the integration image ships 2.7.5, which can write
// neither. So each fixture here is a cryptsetup-formatted volume whose header
// this test rewrites by hand to what the 1.1.4 text specifies, and the
// interop checked is the one 2.7.5 can show: it reads our header, it
// rewrites it, and we read its rewrite.

// TestCompatIntegrityKeySizeSurvivesBothTools: a crypt segment carrying
// integrity.key_size is read by both tools, cryptsetup's rewrite keeps the
// member, and our reading of the rewrite re-encodes the segment byte for
// byte. The volume stays an integrity volume this library refuses to map.
func TestCompatIntegrityKeySizeSurvivesBothTools(t *testing.T) {
	requireCryptsetupDeclared(t)
	defer parallel(t)()

	loop := csVolume(t, "--integrity", "hmac-sha256", "--integrity-no-wipe", "--key-size", "512")
	hdr, metadata, err := harness.ReadHeader(loop)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := metadata.Segments["0"].IntegrityKeySize(); present {
		t.Fatal("cryptsetup 2.7.5 wrote an integrity.key_size; absent must read as absent")
	}

	// 1.1.4 section 3.3 (integrity object): key_size [integer,optional], in
	// bytes. 32 is hmac(sha256)'s own default, so a 2.8 reader agrees on it.
	metadata.Segments["0"].SetUnknownMember("integrity",
		json.RawMessage(`{"type":"hmac(sha256)","journal_encryption":"none","journal_integrity":"none","key_size":32}`))
	hdr.SequenceID++
	writeRawMetadata(t, loop, hdr, metadata)
	ours, err := header.MarshalCanonicalJSON(metadata.Segments["0"])
	if err != nil {
		t.Fatal(err)
	}

	if out := mustCryptsetupPassphrase(t, "", "luksDump", "--dump-json-metadata", loop); !strings.Contains(out, `"key_size":32`) {
		t.Fatalf("cryptsetup does not show the integrity key_size\n%s", out)
	}
	mustCryptsetupPassphrase(t, "", "config", "--label", "luks114", loop)

	_, rewritten, err := harness.ReadHeader(loop)
	if err != nil {
		t.Fatalf("reading cryptsetup's rewrite: %v", err)
	}
	if size, present := rewritten.Segments["0"].IntegrityKeySize(); size != 32 || !present {
		t.Fatalf("IntegrityKeySize() after cryptsetup's rewrite = %d, %v, want 32, true", size, present)
	}
	theirs, err := header.MarshalCanonicalJSON(rewritten.Segments["0"])
	if err != nil {
		t.Fatal(err)
	}
	if string(theirs) != string(ours) {
		t.Fatalf("the segment changed across cryptsetup's rewrite\n ours: %s\ntheirs: %s", ours, theirs)
	}

	name := runVolume(t, matrixName("matrix-intkeysize"))
	t.Cleanup(func() { releaseVolume(t, name) })
	if err := Unlock(loop, []byte(matrixPassphrase), name); !errors.Is(err, luks2.ErrUnsupported) {
		t.Fatalf("Unlock of an integrity volume = %v, want ErrUnsupported", err)
	}
	csClose(t, csMapping(t, loop, []byte(matrixPassphrase)))
}

// TestCompatInlineHWTagsIsKeptAndRefusedByBothTools: a header declaring the
// inline-hw-tags requirement (1.1.4 section 3.5) reads in both tools with the
// requirement intact. This library implements no inline hardware tags, so it
// refuses unlock and every write naming the requirement and leaves the device
// untouched; cryptsetup 2.7.5 does not know the flag and refuses activation
// and header writes as an unmet requirement.
func TestCompatInlineHWTagsIsKeptAndRefusedByBothTools(t *testing.T) {
	requireCryptsetupDeclared(t)
	defer parallel(t)()

	loop := csVolume(t)
	hdr, metadata, err := harness.ReadHeader(loop)
	if err != nil {
		t.Fatal(err)
	}
	metadata.Config.Requirements = &header.Requirements{Mandatory: []string{"inline-hw-tags"}}
	hdr.SequenceID++
	writeRawMetadata(t, loop, hdr, metadata)
	before := deviceDigest(t, loop, 16<<20)

	if _, read, err := harness.ReadHeader(loop); err != nil || read.Config.Requirements == nil ||
		len(read.Config.Requirements.Mandatory) != 1 || read.Config.Requirements.Mandatory[0] != "inline-hw-tags" {
		t.Fatalf("our reader lost the requirement: err=%v", err)
	}

	wantRefusal := func(what string, err error) {
		t.Helper()
		var reqErr *header.UnsupportedRequirementError
		if !errors.Is(err, luks2.ErrUnsupportedRequirement) || !errors.As(err, &reqErr) || reqErr.Requirement != "inline-hw-tags" {
			t.Fatalf("%s = %v, want ErrUnsupportedRequirement naming inline-hw-tags", what, err)
		}
	}
	name := runVolume(t, matrixName("matrix-inlinehw"))
	t.Cleanup(func() { releaseVolume(t, name) })
	wantRefusal("Unlock", Unlock(loop, []byte(matrixPassphrase), name))
	if IsUnlocked(name) {
		t.Fatal("a mapping exists after the refused Unlock")
	}
	wantRefusal("AddKey", AddKey(loop, []byte(matrixPassphrase), []byte(matrixNew), matrixAddKeyOptions))
	if deviceDigest(t, loop, 16<<20) != before {
		t.Fatal("a refused operation changed the device")
	}

	if out := mustCryptsetupPassphrase(t, "", "luksDump", loop); !strings.Contains(out, "inline-hw-tags") {
		t.Fatalf("cryptsetup does not show the requirement\n%s", out)
	}
	theirs := matrixName("matrix-inlinehw-cs")
	if out, ok := cryptsetupWithStdin(t, matrixPassphrase, "open", loop, theirs); ok || !strings.Contains(out, "requirements") {
		if ok {
			csClose(t, theirs)
		}
		t.Fatalf("cryptsetup open of an inline-hw-tags header: ok=%v\n%s", ok, out)
	}
	if out, ok := cryptsetupWithStdin(t, "", "config", "--label", "luks114", loop); ok || !strings.Contains(out, "requirements") {
		t.Fatalf("cryptsetup config of an inline-hw-tags header: ok=%v\n%s", ok, out)
	}
	if deviceDigest(t, loop, 16<<20) != before {
		t.Fatal("cryptsetup's refusals changed the device")
	}
}
