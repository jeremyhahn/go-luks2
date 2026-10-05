// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// katKey and katPlaintext are the inputs the known answers below were
// produced from by the Linux kernel's dm-crypt: `cryptsetup open --type plain
// --cipher <spec> --key-size <bits> --key-file <katKey prefix> --offset 0`,
// katPlaintext written through the mapping with O_DIRECT, and the two raw
// sectors read back from the device (cryptsetup 2.7.5, Linux 6.8). The
// answers are dm-crypt's, not a second run of this implementation.
func katKey(n int) []byte {
	k := make([]byte, n)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func katPlaintext() []byte {
	p := make([]byte, 1024)
	for i := range p {
		p[i] = byte(i % 251)
	}
	return p
}

func TestKeyslotAreaSectorsMatchDMCrypt(t *testing.T) {
	defer parallel(t)()

	for _, tc := range []struct {
		spec   string
		keyLen int
		sha256 string
	}{
		{"aes-cbc-essiv:sha256", 16, "5c43fd38df155534b6aaf774db1a9758b890a32786abc5a26553f0051c2502c8"},
		{"aes-cbc-essiv:sha256", 32, "5ee2e58d557cee9bdb5c5853e399db1f00b5c784c7a7002ee6499b76a5c3a131"},
		{"aes-cbc-plain64", 16, "f5c7e988c7e476bc670a025de6aff2fd1dcd9fd9ec1c293445e33493c4db657d"},
		{"aes-cbc-plain64", 32, "81bf6e0c661354ff7d1c7de7d3018dd5458a5464b21dca5f252cef9ebd4f0a4e"},
		{"aes-cbc-plain", 16, "f5c7e988c7e476bc670a025de6aff2fd1dcd9fd9ec1c293445e33493c4db657d"},
		{"aes-cbc-plain", 32, "81bf6e0c661354ff7d1c7de7d3018dd5458a5464b21dca5f252cef9ebd4f0a4e"},
		{"aes-xts-plain64", 32, "32accdebf57e0a6e4b33191d522226ed6267e75c14cf1e74c0e40080ab9e3250"},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			transform, err := parseKeyslotAreaEncryption(tc.spec)
			if err != nil {
				t.Fatalf("parseKeyslotAreaEncryption: %v", err)
			}
			if err := transform.validateKeySize(tc.keyLen); err != nil {
				t.Fatalf("validateKeySize(%d): %v", tc.keyLen, err)
			}
			plain := katPlaintext()
			ciphertext := make([]byte, len(plain))
			if err := keyslotAreaSectors(transform, ciphertext, plain, katKey(tc.keyLen), keyslotSectorSize, false); err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			sum := sha256.Sum256(ciphertext)
			if got := hex.EncodeToString(sum[:]); got != tc.sha256 {
				t.Fatalf("ciphertext sha256 %s, dm-crypt's %s", got, tc.sha256)
			}
			back := make([]byte, len(plain))
			if err := keyslotAreaSectors(transform, back, ciphertext, katKey(tc.keyLen), keyslotSectorSize, true); err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(back, plain) {
				t.Fatal("decrypting dm-crypt's ciphertext does not give the plaintext back")
			}
		})
	}
}

func TestCBCSectorsRefusesWhatItCannotRun(t *testing.T) {
	defer parallel(t)()

	buf := make([]byte, 1024)
	for name, run := range map[string]func() error{
		"a 64-byte key":          func() error { return cbcSectors(areaIVPlain64, buf, buf, katKey(64), 512, true) },
		"mismatched buffers":     func() error { return cbcSectors(areaIVPlain64, buf[:512], buf, katKey(32), 512, true) },
		"a partial sector":       func() error { return cbcSectors(areaIVPlain64, buf[:700], buf[:700], katKey(32), 512, true) },
		"a sector size of zero":  func() error { return cbcSectors(areaIVPlain64, buf, buf, katKey(32), 0, true) },
		"a sector not in blocks": func() error { return cbcSectors(areaIVPlain64, buf, buf, katKey(32), 100, true) },
		"an XTS key that is odd": func() error {
			return keyslotAreaSectors(areaTransform{mode: areaModeXTS}, buf, buf, katKey(40), 512, true)
		},
		"a CBC key size of 40":    func() error { return (areaTransform{mode: areaModeCBC}).validateKeySize(40) },
		"a volume key size of 40": func() error { return validateVolumeKeySize(40) },
	} {
		if run() == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	for _, n := range []int{16, 24, 32, 48, 64} {
		if err := validateVolumeKeySize(n); err != nil {
			t.Errorf("a %d-byte volume key was refused: %v", n, err)
		}
	}
}

func TestWritableAreaKeySize(t *testing.T) {
	for volume, want := range map[int]int{16: 64, 24: 64, 32: 32, 48: 48, 64: 64, 96: 64} {
		if got := writableAreaKeySize(volume); got != want {
			t.Errorf("writableAreaKeySize(%d) = %d, want %d", volume, got, want)
		}
	}
}
