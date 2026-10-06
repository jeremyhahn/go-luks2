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

func validCryptMetadata() (*Metadata, *Segment) {
	m := minimalValidMetadata()
	m.Config.Flags = []string{"same-cpu-crypt", "no-read-workqueue"}
	return m, m.Segments["0"]
}

func TestCryptTableParams(t *testing.T) {
	m, s := validCryptMetadata()
	params, err := CryptTableParams(m, "0", s)
	if err != nil {
		t.Fatalf("CryptTableParams: %v", err)
	}
	if params.Encryption != s.Encryption || params.SectorSize != 512 {
		t.Errorf("params = %+v", params)
	}
	if len(params.Flags) != 2 || params.Flags[0] != "same_cpu_crypt" || params.Flags[1] != "no_read_workqueue" {
		t.Errorf("Flags = %v", params.Flags)
	}
}

func TestCryptTableParamsRefusesASegmentInsideTheKeyslotsArea(t *testing.T) {
	m, s := validCryptMetadata()
	s.Offset = "4096"
	_, err := CryptTableParams(m, "0", s)
	if !errors.Is(err, errs.ErrInvalidHeader) {
		t.Fatalf("got %v, want ErrInvalidHeader", err)
	}
}

func TestCryptTableParamsNamesADetachedHeader(t *testing.T) {
	m, s := validCryptMetadata()
	s.Offset = "0"
	_, err := CryptTableParams(m, "0", s)
	if !errors.Is(err, errs.ErrInvalidHeader) || !strings.Contains(err.Error(), "detached") {
		t.Fatalf("got %v, want ErrInvalidHeader naming a detached header", err)
	}
}

func TestCryptTableParamsRefusesAnUnacceptedSectorSize(t *testing.T) {
	m, s := validCryptMetadata()
	s.SectorSize = 256
	_, err := CryptTableParams(m, "0", s)
	if !errors.Is(err, errs.ErrInvalidHeader) {
		t.Fatalf("got %v, want ErrInvalidHeader", err)
	}
}

func TestCryptTableParamsRefusesABadIVTweak(t *testing.T) {
	m, s := validCryptMetadata()
	s.IVTweak = "not-a-number"
	_, err := CryptTableParams(m, "0", s)
	if !errors.Is(err, errs.ErrInvalidHeader) {
		t.Fatalf("got %v, want ErrInvalidHeader", err)
	}
}

func TestValidateSegmentEncryptionWhitelist(t *testing.T) {
	tests := []struct {
		name       string
		encryption string
		wantErr    bool
	}{
		{"empty", "", true},
		{"ordinary", "aes-xts-plain64", false},
		{"essiv", "aes-cbc-essiv:sha256", false},
		{"capi form", "capi:authenc(hmac(sha256),xts(aes))-plain64", false},
		{"space injects a field", "aes-xts-plain64 :32:logon:attacker", true},
		{"too long", strings.Repeat("a", MaxSegmentEncryptionLength+1), true},
	}
	for _, tc := range tests {
		err := validateSegmentEncryption("segment \"0\"", tc.encryption)
		if tc.wantErr != (err != nil) {
			t.Errorf("%s: got %v, want error=%v", tc.name, err, tc.wantErr)
		}
	}
}

func TestAcceptedSectorSizesIsSortedAndMeasured(t *testing.T) {
	s := acceptedSectorSizes()
	if !strings.Contains(s, "512") || !strings.Contains(s, "4096") || !strings.Contains(s, "measured against cryptsetup") {
		t.Errorf("acceptedSectorSizes() = %q", s)
	}
}
