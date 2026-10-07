// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package areacipher

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/fips"
)

// FIPS 140-3 (IG C.I, SP 800-38E) forbids an AES-XTS key whose cipher and
// tweak halves are equal. In FIPS mode the transform refuses one in both
// directions, before the cipher is keyed; outside it the same key still
// opens, as it does for the kernel.
func TestXTSRefusesEqualKeyHalvesInFIPSMode(t *testing.T) {
	half := mustRandom(t, 32)
	weak := append(append([]byte{}, half...), half...)
	data := mustRandom(t, 1024)

	inFIPS := Default().WithFIPS(fips.Mode(true))
	if _, err := inFIPS.EncryptEnclave(testCustody, enclaveFrom(t, data), enclaveFrom(t, weak)); !errors.Is(err, fips.ErrNotApproved) {
		t.Fatalf("EncryptEnclave with equal XTS key halves in FIPS mode = %v, want fips.ErrNotApproved", err)
	}
	if _, err := inFIPS.DecryptEnclave(testCustody, data, enclaveFrom(t, weak)); !errors.Is(err, fips.ErrNotApproved) {
		t.Fatalf("DecryptEnclave with equal XTS key halves in FIPS mode = %v, want fips.ErrNotApproved", err)
	}

	if _, err := inFIPS.EncryptEnclave(testCustody, enclaveFrom(t, data), enclaveFrom(t, mustRandom(t, 64))); err != nil {
		t.Fatalf("EncryptEnclave with distinct XTS key halves in FIPS mode failed: %v", err)
	}
	if _, err := Default().EncryptEnclave(testCustody, enclaveFrom(t, data), enclaveFrom(t, weak)); err != nil {
		t.Fatalf("EncryptEnclave with equal XTS key halves outside FIPS mode failed: %v", err)
	}
}
