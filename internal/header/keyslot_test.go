// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package header

import (
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

func validKeyslot() *Keyslot {
	return &Keyslot{
		Type: "luks2", KeySize: 64,
		Area: &KeyslotArea{Type: "raw", Offset: "32768", Size: "258048"},
		KDF:  &KDF{Type: "pbkdf2", Hash: "sha256", Salt: "AAAA"},
		AF:   &AntiForensic{Type: "luks1", Stripes: 4000, Hash: "sha256"},
	}
}

func TestValidateKeyslot(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Keyslot)
		nilSlot bool
		wantErr string
	}{
		{name: "valid", mutate: func(*Keyslot) {}},
		{name: "nil keyslot", nilSlot: true, wantErr: "is null"},
		{name: "no area", mutate: func(k *Keyslot) { k.Area = nil }, wantErr: "no area object"},
		{name: "area offset not a number", mutate: func(k *Keyslot) { k.Area.Offset = "x" }, wantErr: "not a number"},
		{name: "negative area offset", mutate: func(k *Keyslot) { k.Area.Offset = "-1" }, wantErr: "negative area offset"},
		{name: "area size not a number", mutate: func(k *Keyslot) { k.Area.Size = "x" }, wantErr: "not a number"},
		{name: "area size zero", mutate: func(k *Keyslot) { k.Area.Size = "0" }, wantErr: "outside the range"},
		{name: "area size too large", mutate: func(k *Keyslot) { k.Area.Size = "999999999999" }, wantErr: "outside the range"},
		{name: "area offset overflow", mutate: func(k *Keyslot) {
			k.Area.Offset = "9223372036854775807"
			k.Area.Size = "100"
		}, wantErr: "runs past the end"},
		{name: "reencrypt type skips luks2 checks", mutate: func(k *Keyslot) {
			k.Type, k.KDF, k.AF = "reencrypt", nil, nil
		}},
		{name: "no kdf", mutate: func(k *Keyslot) { k.KDF = nil }, wantErr: "no kdf object"},
		{name: "no af", mutate: func(k *Keyslot) { k.AF = nil }, wantErr: "no anti-forensic object"},
		{name: "key size zero", mutate: func(k *Keyslot) { k.KeySize = 0 }, wantErr: "accepted range is 1"},
		{name: "key size too large", mutate: func(k *Keyslot) { k.KeySize = MaxKeyslotKeySize + 1 }, wantErr: "accepted range is 1"},
		{name: "stripes zero", mutate: func(k *Keyslot) { k.AF.Stripes = 0 }, wantErr: "accepted range is 1"},
		{name: "stripes too many", mutate: func(k *Keyslot) { k.AF.Stripes = MaxKeyslotStripes + 1 }, wantErr: "accepted range is 1"},
		{name: "af material does not fit the area", mutate: func(k *Keyslot) {
			k.KeySize, k.AF.Stripes, k.Area.Size = 100, 4000, "1000"
		}, wantErr: "anti-forensic material"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var k *Keyslot
			if !tc.nilSlot {
				k = validKeyslot()
				tc.mutate(k)
			}
			err := ValidateKeyslot("0", k)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("a valid keyslot was refused: %v", err)
				}
				return
			}
			if !errors.Is(err, errs.ErrInvalidKeyslot) {
				t.Fatalf("got %v, want ErrInvalidKeyslot", err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %q, want it to contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestValidateKeyslotLabelsAnEmptyID(t *testing.T) {
	err := ValidateKeyslot("", nil)
	if !strings.Contains(err.Error(), "a keyslot is null") {
		t.Fatalf("got %q, want it to describe %q", err.Error(), "a keyslot")
	}
}

func TestToKDFParams(t *testing.T) {
	iters := 1000
	k := &KDF{Type: "pbkdf2", Hash: "sha256", Salt: "c2FsdA==", Iterations: &iters}
	p := ToKDFParams(k)
	if p.Type != "pbkdf2" || p.Hash != "sha256" || p.Salt != "c2FsdA==" || p.Iterations == nil || *p.Iterations != 1000 {
		t.Errorf("ToKDFParams = %+v", p)
	}
}

func TestValidateKDFCost(t *testing.T) {
	if err := ValidateKDFCost(nil); err == nil {
		t.Error("nil KDF: want an error")
	}
	iters := MinKDFIterations
	if err := ValidateKDFCost(&KDF{Type: "pbkdf2", Hash: "sha256", Iterations: &iters}); err != nil {
		t.Errorf("a cheap legal PBKDF2 KDF was refused: %v", err)
	}
	tooFew := MinKDFIterations - 1
	if MinKDFIterations > 0 {
		if err := ValidateKDFCost(&KDF{Type: "pbkdf2", Hash: "sha256", Iterations: &tooFew}); err == nil {
			t.Error("below the floor: want an error")
		}
	}
}
