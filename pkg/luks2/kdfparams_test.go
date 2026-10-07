// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"context"
	"crypto"
	"crypto/fips140"
	"errors"
	"testing"
)

// TestDefaultKDFTypeFollowsTheProcessMode holds the new, typed
// DefaultKDFType (DESIGN.md §B.2) to the same mode-dependent default
// DefaultKDFSpec has always returned, just without a hash: KDFPBKDF2 in
// FIPS 140-3 mode, KDFArgon2id otherwise.
func TestDefaultKDFTypeFollowsTheProcessMode(t *testing.T) {
	want := KDFArgon2id
	if fips140.Enabled() {
		want = KDFPBKDF2
	}
	if got := DefaultKDFType(); got != want {
		t.Fatalf("DefaultKDFType() = %q with fips140.Enabled() = %v, want %q", got, fips140.Enabled(), want)
	}
}

// TestProductionEntryPointsRefuseArgon2InTheProcessFIPSMode proves the public
// entry points, with no injected policy, consult the real probe: under
// GODEBUG=fips140=on they refuse Argon2; otherwise they accept it. The
// forced-policy tests cover the same gates through the injectable cores; this
// is the test that fails if a public wrapper stops reading the process mode.
func TestProductionEntryPointsRefuseArgon2InTheProcessFIPSMode(t *testing.T) {
	inFIPS := fips140.Enabled()
	argon2 := KDFParams{Type: KDFArgon2id, Time: 1, MemoryKiB: minArgon2MemoryKB, Parallel: 1}

	check := func(name string, err error) {
		t.Helper()
		if inFIPS != errors.Is(err, ErrFIPSNotApproved) {
			t.Fatalf("%s with fips140.Enabled() = %v returned %v", name, inFIPS, err)
		}
		if !inFIPS && err != nil {
			t.Fatalf("%s outside FIPS mode returned %v, want nil", name, err)
		}
	}

	check("KDFParams.Validate", argon2.Validate())

	_, err := createKDFStrict(formatOptionsForTest{KDFType: kdfTypeArgon2id}, 64)
	check("CreateKDF", err)

	path := newImage(t, "production-fips.img")
	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()
	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()
	check("Volume.Format", v.Format(context.Background(), pass, FormatParams{KDF: argon2}))
}

func TestDefaultKDFTypeUnderTheFIPSPolicy(t *testing.T) {
	forced := forceFIPSPolicy(t)

	if got := defaultKDFTypeWith(forced); got != KDFPBKDF2 {
		t.Fatalf("DefaultKDFType under the FIPS policy = %q, want %q", got, KDFPBKDF2)
	}
}

func TestKDFParamsValidate(t *testing.T) {
	tests := []struct {
		name    string
		p       KDFParams
		wantErr error
	}{
		{"zero value", KDFParams{}, nil},
		{"named pbkdf2", KDFParams{Type: KDFPBKDF2}, nil},
		{"named argon2id", KDFParams{Type: KDFArgon2id}, nil},
		{"named argon2i", KDFParams{Type: KDFArgon2i}, nil},
		{"an unknown type", KDFParams{Type: "scrypt"}, ErrUnsupported},
		{"argon2 cost at the floor", KDFParams{Time: 1, MemoryKiB: minArgon2MemoryKB, Parallel: 1}, nil},
		{"argon2 memory below the floor", KDFParams{MemoryKiB: minArgon2MemoryKB - 1}, ErrInvalidArgument},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.p.Validate(); !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestKDFParamsValidateRefusesArgon2UnderFIPS: an Argon2 KDF, named or only
// implied by a nonzero cost, is refused under the FIPS policy -- the
// approval check DESIGN.md §B.2 calls out on KDFParams.Validate.
func TestKDFParamsValidateRefusesArgon2UnderFIPS(t *testing.T) {
	forced := forceFIPSPolicy(t)

	tests := []struct {
		name string
		p    KDFParams
	}{
		{"named argon2id", KDFParams{Type: KDFArgon2id}},
		{"named argon2i", KDFParams{Type: KDFArgon2i}},
		{"implied by a cost, no type named", KDFParams{MemoryKiB: minArgon2MemoryKB}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.p.validateWith(forced); !errors.Is(err, ErrFIPSNotApproved) {
				t.Fatalf("Validate() under the FIPS policy = %v, want ErrFIPSNotApproved", err)
			}
		})
	}

	// The default (no type, no cost) still resolves to PBKDF2 and is approved.
	if err := (KDFParams{}).validateWith(forced); err != nil {
		t.Fatalf("Validate() on the zero value under the FIPS policy = %v, want nil", err)
	}
}

func TestFormatParamsValidate(t *testing.T) {
	tests := []struct {
		name    string
		p       FormatParams
		wantErr error
	}{
		{"zero value", FormatParams{}, nil},
		{"default cipher spelled out", FormatParams{Cipher: DefaultCipher}, nil},
		{"an unsupported cipher/key-size combination", FormatParams{Cipher: "aes-cbc-essiv:sha256", KeySize: 512}, ErrUnsupported},
		{"an unsupported key size alone", FormatParams{KeySize: 384}, ErrInvalidArgument},
		{"an unsupported sector size", FormatParams{SectorSize: 1024}, ErrInvalidArgument},
		{"a label that does not fit", FormatParams{Label: string(make([]byte, maxLabelLength+1))}, ErrInvalidArgument},
		{"an unsupported metadata size", FormatParams{MetadataSize: 12288}, ErrInvalidArgument},
		{"a KDF Validate refuses", FormatParams{KDF: KDFParams{Type: "scrypt"}}, ErrUnsupported},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.p.Validate(); !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestHashAlgoName(t *testing.T) {
	tests := []struct {
		h    crypto.Hash
		want string
	}{
		{0, ""},
		{crypto.SHA1, "sha1"},
		{crypto.SHA256, "sha256"},
		{crypto.SHA384, "sha384"},
		{crypto.SHA512, "sha512"},
	}
	for _, tt := range tests {
		if got := hashAlgoName(tt.h); got != tt.want {
			t.Errorf("hashAlgoName(%v) = %q, want %q", tt.h, got, tt.want)
		}
	}
}

func TestSplitCipherSpec(t *testing.T) {
	tests := []struct {
		spec       string
		wantCipher string
		wantMode   string
	}{
		{"aes-xts-plain64", "aes", "xts-plain64"},
		{"aes-cbc-essiv:sha256", "aes", "cbc-essiv:sha256"},
		{"nohyphen", "nohyphen", ""},
	}
	for _, tt := range tests {
		cipher, mode := splitCipherSpec(tt.spec)
		if cipher != tt.wantCipher || mode != tt.wantMode {
			t.Errorf("splitCipherSpec(%q) = (%q, %q), want (%q, %q)", tt.spec, cipher, mode, tt.wantCipher, tt.wantMode)
		}
	}
}
