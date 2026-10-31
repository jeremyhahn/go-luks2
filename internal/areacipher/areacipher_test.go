// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package areacipher

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave"
	"golang.org/x/crypto/xts"

	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// testCustody is the production custody.
var testCustody = secret.System()

// xtsEncrypt runs the transform this module writes over data, in 512-byte
// sectors, onto the ordinary heap -- for tests over synthetic material only.
func xtsEncrypt(data, key []byte) ([]byte, error) {
	out := make([]byte, len(data))
	if err := Default().run(testCustody, out, data, key, SectorSize, encrypt); err != nil {
		return nil, err
	}
	return out, nil
}

// xtsDecrypt is xtsEncrypt's inverse, in sectorSize sectors.
func xtsDecrypt(data, key []byte, sectorSize int) ([]byte, error) {
	out := make([]byte, len(data))
	if err := Default().run(testCustody, out, data, key, sectorSize, decrypt); err != nil {
		return nil, err
	}
	return out, nil
}

// enclaveFrom returns an enclave holding a COPY of b, destroyed when the test
// ends.
func enclaveFrom(t *testing.T, b []byte) enclave.ByteAccess {
	t.Helper()
	e, err := enclave.NewMemoryCopy(b)
	if err != nil {
		t.Fatalf("could not allocate a test enclave: %v", err)
	}
	t.Cleanup(func() { mustDestroy(t, e) })
	return e
}

// mustDestroy destroys e and fails the test if the release is reported.
func mustDestroy(tb testing.TB, e enclave.ByteAccess) {
	tb.Helper()
	if err := e.Destroy(); err != nil {
		tb.Errorf("releasing a test enclave was reported: %v", err)
	}
}

func mustRandom(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("failed to generate %d random bytes: %v", n, err)
	}
	return b
}

// lockedKiB reports the process's currently mlock'd memory, in kibibytes.
func lockedKiB(t *testing.T) int {
	t.Helper()
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatalf("/proc/self/status is unavailable: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if fields := strings.Fields(line); len(fields) >= 2 && fields[0] == "VmLck:" {
			n, err := strconv.Atoi(fields[1])
			if err != nil {
				break
			}
			return n
		}
	}
	t.Fatalf("/proc/self/status reports no VmLck line:\n%s", data)
	return 0
}

// lockedSlackKiB is the tolerance the leak assertion allows: one page.
const lockedSlackKiB = 4

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
			transform, ok := Parse(tc.spec)
			if !ok {
				t.Fatalf("Parse(%q) refused a spec it accepts", tc.spec)
			}
			if err := transform.ValidateKeySize(tc.keyLen); err != nil {
				t.Fatalf("ValidateKeySize(%d): %v", tc.keyLen, err)
			}
			plain := katPlaintext()
			ciphertext := make([]byte, len(plain))
			if err := transform.run(testCustody, ciphertext, plain, katKey(tc.keyLen), SectorSize, encrypt); err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			sum := sha256.Sum256(ciphertext)
			if got := hex.EncodeToString(sum[:]); got != tc.sha256 {
				t.Fatalf("ciphertext sha256 %s, dm-crypt's %s", got, tc.sha256)
			}
			back := make([]byte, len(plain))
			if err := transform.run(testCustody, back, ciphertext, katKey(tc.keyLen), SectorSize, decrypt); err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(back, plain) {
				t.Fatal("decrypting dm-crypt's ciphertext does not give the plaintext back")
			}
		})
	}
}

func TestCBCSectorsRefusesWhatItCannotRun(t *testing.T) {
	buf := make([]byte, 1024)
	for name, run := range map[string]func() error{
		"a 64-byte key":          func() error { return cbcSectors(ivPlain64, buf, buf, katKey(64), 512, decrypt) },
		"mismatched buffers":     func() error { return cbcSectors(ivPlain64, buf[:512], buf, katKey(32), 512, decrypt) },
		"a partial sector":       func() error { return cbcSectors(ivPlain64, buf[:700], buf[:700], katKey(32), 512, decrypt) },
		"a sector size of zero":  func() error { return cbcSectors(ivPlain64, buf, buf, katKey(32), 0, decrypt) },
		"a sector not in blocks": func() error { return cbcSectors(ivPlain64, buf, buf, katKey(32), 100, decrypt) },
		"an XTS key that is odd": func() error {
			return Transform{mode: modeXTS}.run(testCustody, buf, buf, katKey(40), 512, decrypt)
		},
		"a CBC key size of 40":    func() error { return (Transform{mode: modeCBC}).ValidateKeySize(40) },
		"a volume key size of 40": func() error { return ValidateVolumeKeySize(40) },
	} {
		if run() == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	for _, n := range []int{16, 24, 32, 48, 64} {
		if err := ValidateVolumeKeySize(n); err != nil {
			t.Errorf("a %d-byte volume key was refused: %v", n, err)
		}
	}
}

func TestWritableAreaKeySize(t *testing.T) {
	for volume, want := range map[int]int{16: 64, 24: 64, 32: 32, 48: 48, 64: 64, 96: 64} {
		if got := WritableAreaKeySize(volume); got != want {
			t.Errorf("WritableAreaKeySize(%d) = %d, want %d", volume, got, want)
		}
	}
}

func TestEncryptDecryptKeyMaterial(t *testing.T) {
	tests := []struct {
		name     string
		dataSize int
		keySize  int
		cipher   string
		wantErr  bool
	}{
		{
			name:     "AES-XTS with 256-bit key (32 bytes)",
			dataSize: 4096,
			keySize:  32,
			cipher:   "aes",
			wantErr:  false,
		},
		{
			name:     "AES-XTS with 512-bit key (64 bytes)",
			dataSize: 8192,
			keySize:  64,
			cipher:   "aes",
			wantErr:  false,
		},
		{
			name:     "Small data with 256-bit key",
			dataSize: 512,
			keySize:  32,
			cipher:   "aes",
			wantErr:  false,
		},
		{
			name:     "Large data with 512-bit key",
			dataSize: 16384,
			keySize:  64,
			cipher:   "aes",
			wantErr:  false,
		},
		{
			name:     "Multiple sectors with 512-bit key",
			dataSize: 2048,
			keySize:  64,
			cipher:   "aes",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate test data
			originalData := make([]byte, tt.dataSize)
			if _, err := rand.Read(originalData); err != nil {
				t.Fatalf("Failed to generate test data: %v", err)
			}

			// Generate key
			key := make([]byte, tt.keySize)
			if _, err := rand.Read(key); err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			// Encrypt
			encrypted, err := xtsEncrypt(originalData, key)
			if tt.wantErr {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			if len(encrypted) != len(originalData) {
				t.Fatalf("Encrypted size mismatch: got %d, want %d", len(encrypted), len(originalData))
			}

			// Verify data is actually encrypted (should differ from original)
			if bytes.Equal(originalData, encrypted) {
				t.Fatal("Encrypted data identical to original")
			}

			// Decrypt
			decrypted, err := xtsDecrypt(encrypted, key, 512)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if len(decrypted) != len(originalData) {
				t.Fatalf("Decrypted size mismatch: got %d, want %d", len(decrypted), len(originalData))
			}

			// Verify round-trip produces original data
			if !bytes.Equal(originalData, decrypted) {
				t.Fatal("Decrypted data doesn't match original")
			}
		})
	}
}

// TestEncryptKeyMaterialUnsupportedCipher tests error handling for unsupported ciphers
func TestEncryptKeyMaterialInvalidKeySize(t *testing.T) {
	data := make([]byte, 512)

	tests := []struct {
		name    string
		keySize int
	}{
		{"8-bit key", 1},
		{"16-bit key", 2},
		{"128-bit key (16 bytes)", 16},
		{"odd-sized key", 33},
		{"very small key", 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			_, err := xtsEncrypt(data, key)
			if err == nil {
				t.Fatal("Expected error for invalid key size, got nil")
			}
		})
	}
}

// TestDecryptKeyMaterialInvalidKeySize tests error handling for invalid key sizes
func TestDecryptKeyMaterialInvalidKeySize(t *testing.T) {
	data := make([]byte, 512)

	tests := []struct {
		name    string
		keySize int
	}{
		{"8-bit key", 1},
		{"16-bit key", 2},
		{"128-bit key (16 bytes)", 16},
		{"odd-sized key", 33},
		{"very small key", 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			_, err := xtsDecrypt(data, key, 512)
			if err == nil {
				t.Fatal("Expected error for invalid key size, got nil")
			}
		})
	}
}

// TestEncryptKeyMaterialDifferentSectorSizes tests encryption with various data sizes
func TestEncryptKeyMaterialDifferentSectorSizes(t *testing.T) {
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	tests := []struct {
		name     string
		dataSize int
	}{
		{"Exactly one sector", 512},
		{"One and a half sectors", 768},
		{"Two sectors", 1024},
		{"Partial sector", 256},
		{"Three sectors plus partial", 1792},
		{"Large multi-sector", 8192},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.dataSize)
			if _, err := rand.Read(data); err != nil {
				t.Fatalf("Failed to generate test data: %v", err)
			}

			encrypted, err := xtsEncrypt(data, key)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			decrypted, err := xtsDecrypt(encrypted, key, 512)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if !bytes.Equal(data, decrypted) {
				t.Fatal("Round-trip failed for data size")
			}
		})
	}
}

// TestEncryptKeyMaterialDeterministic tests that encryption with same sector number produces same result
func TestEncryptKeyMaterialDeterministic(t *testing.T) {
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	data := make([]byte, 512)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("Failed to generate test data: %v", err)
	}

	// Encrypt same data multiple times
	encrypted1, err := xtsEncrypt(data, key)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	encrypted2, err := xtsEncrypt(data, key)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	// Same input should produce same output with XTS (deterministic with same IV)
	if !bytes.Equal(encrypted1, encrypted2) {
		t.Fatal("Encryption not deterministic for same input")
	}
}

// TestDecryptKeyMaterialCorruptedData tests decryption behavior with corrupted ciphertext
func TestDecryptKeyMaterialCorruptedData(t *testing.T) {
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	originalData := make([]byte, 1024)
	if _, err := rand.Read(originalData); err != nil {
		t.Fatalf("Failed to generate test data: %v", err)
	}

	// Encrypt
	encrypted, err := xtsEncrypt(originalData, key)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Corrupt the ciphertext
	corrupted := make([]byte, len(encrypted))
	copy(corrupted, encrypted)
	corrupted[100] ^= 0xFF // Flip bits

	// Decrypt corrupted data (XTS doesn't have authentication, so no error expected)
	decrypted, err := xtsDecrypt(corrupted, key, 512)
	if err != nil {
		t.Fatalf("Decryption of corrupted data failed: %v", err)
	}

	// Decrypted data should differ from original (corruption detected by comparison)
	if bytes.Equal(originalData, decrypted) {
		t.Fatal("Corrupted data decrypted to original (unexpected)")
	}
}

// TestDecryptKeyMaterialWrongKey tests decryption with incorrect key
func TestDecryptKeyMaterialWrongKey(t *testing.T) {
	correctKey := make([]byte, 64)
	if _, err := rand.Read(correctKey); err != nil {
		t.Fatalf("Failed to generate correct key: %v", err)
	}

	wrongKey := make([]byte, 64)
	if _, err := rand.Read(wrongKey); err != nil {
		t.Fatalf("Failed to generate wrong key: %v", err)
	}

	originalData := make([]byte, 1024)
	if _, err := rand.Read(originalData); err != nil {
		t.Fatalf("Failed to generate test data: %v", err)
	}

	// Encrypt with correct key
	encrypted, err := xtsEncrypt(originalData, correctKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Decrypt with wrong key (no error expected, but data will be garbage)
	decrypted, err := xtsDecrypt(encrypted, wrongKey, 512)
	if err != nil {
		t.Fatalf("Decryption with wrong key failed: %v", err)
	}

	// Data should differ (wrong key produces garbage)
	if bytes.Equal(originalData, decrypted) {
		t.Fatal("Wrong key produced correct plaintext (unexpected)")
	}
}

// legacyXtsSectors is the per-sector scratch-buffer loop that xtsSectors
// replaced, kept as the oracle for the in-place rewrite.
func legacyXtsSectors(dst, src, key []byte, sectorSize int, decrypt bool) error {
	xtsCipher, err := xts.NewCipher(aes.NewCipher, key)
	if err != nil {
		return err
	}

	numSectors := (len(src) + sectorSize - 1) / sectorSize
	for i := 0; i < numSectors; i++ {
		start := i * sectorSize
		end := start + sectorSize
		if end > len(src) {
			end = len(src)
		}

		sector := make([]byte, sectorSize)
		copy(sector, src[start:end])

		out := make([]byte, sectorSize)
		if decrypt {
			xtsCipher.Decrypt(out, sector, uint64(i))
		} else {
			xtsCipher.Encrypt(out, sector, uint64(i))
		}

		copy(dst[start:end], out[:end-start])
	}

	return nil
}

// TestXtsSectorsMatchesThePerSectorScratchFormulation pins the transform that
// stopped copying every sector through two fresh heap buffers.
//
// The lengths deliberately include one that is NOT a whole number of sectors,
// because that is the only case where the two formulations do anything
// different: the rewrite transforms whole sectors between the caller's buffers
// and keeps the zero-padded scratch path only for a trailing partial sector.
func TestXtsSectorsMatchesThePerSectorScratchFormulation(t *testing.T) {
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate a key: %v", err)
	}

	for _, length := range []int{512, 1024, 4096, 100, 600, 1500} {
		t.Run(strconv.Itoa(length)+" bytes", func(t *testing.T) {
			src := make([]byte, length)
			if _, err := rand.Read(src); err != nil {
				t.Fatalf("failed to generate plaintext: %v", err)
			}

			got := make([]byte, length)
			want := make([]byte, length)

			if err := xtsSectors(testCustody, got, src, key, 512, encrypt); err != nil {
				t.Fatalf("xtsSectors failed: %v", err)
			}
			if err := legacyXtsSectors(want, src, key, 512, false); err != nil {
				t.Fatalf("legacyXtsSectors failed: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("encryption differs from the formulation it replaced")
			}

			// Decryption is checked against the same oracle rather than by
			// round trip, because a round trip is not something this transform
			// can promise for every length -- see
			// TestKeyMaterialTransformDoesNotRoundTripAPartialSector.
			gotBack := make([]byte, length)
			wantBack := make([]byte, length)

			if err := xtsSectors(testCustody, gotBack, got, key, 512, decrypt); err != nil {
				t.Fatalf("xtsSectors decrypt failed: %v", err)
			}
			if err := legacyXtsSectors(wantBack, want, key, 512, true); err != nil {
				t.Fatalf("legacyXtsSectors decrypt failed: %v", err)
			}
			if !bytes.Equal(gotBack, wantBack) {
				t.Fatal("decryption differs from the formulation it replaced")
			}

			if length%512 == 0 && !bytes.Equal(gotBack, src) {
				t.Fatal("a whole-sector round trip did not recover the plaintext")
			}
		})
	}
}

// TestKeyMaterialTransformDoesNotRoundTripAPartialSector records a PRE-EXISTING
// limitation rather than asserting a desirable property.
//
// A final sector shorter than 512 bytes is zero-padded to a whole sector before
// the transform, in both directions. On the way out only the first n ciphertext
// bytes are kept; on the way back those n bytes are padded with zeros again,
// which is not the ciphertext that was produced. XTS decrypts each 16-byte
// block independently, so everything past the last whole AES block inside that
// final sector comes back as garbage.
//
// This is not reachable from any LUKS2 path: keyslot material is
// keySize*stripes bytes -- 128000 or 256000 -- both whole numbers of sectors,
// and unlockKeyslot rounds its decryption length UP to a sector boundary
// precisely so it stays that way. It is pinned here so that the limitation is
// recorded where someone reusing these helpers will meet it, and so that a
// future fix is visible as a change in behavior rather than an accident.
func TestKeyMaterialTransformDoesNotRoundTripAPartialSector(t *testing.T) {
	key := mustRandom(t, 64)
	src := mustRandom(t, 600) // one whole sector plus 88 bytes

	enc, err := xtsEncrypt(src, key)
	if err != nil {
		t.Fatalf("encryptKeyMaterial failed: %v", err)
	}

	back, err := xtsDecrypt(enc, key, 512)
	if err != nil {
		t.Fatalf("decryptKeyMaterial failed: %v", err)
	}

	if bytes.Equal(back, src) {
		t.Fatal("the partial-sector round trip now succeeds; this limitation was fixed and the note above is stale")
	}

	// The damage is confined to the tail of the final partial sector: whole AES
	// blocks within it still decrypt correctly.
	const intact = 512 + 80 // 88 bytes of tail, of which 5 whole 16-byte blocks
	if !bytes.Equal(back[:intact], src[:intact]) {
		t.Fatal("the corruption reaches further than the incomplete AES block at the end")
	}
}

func TestXtsSectorsRefusesMismatchedBuffers(t *testing.T) {
	key := make([]byte, 64)

	if err := xtsSectors(testCustody, make([]byte, 512), make([]byte, 1024), key, 512, encrypt); err == nil {
		t.Fatal("xtsSectors accepted buffers of different lengths")
	}
	if err := xtsSectors(testCustody, make([]byte, 512), make([]byte, 512), key, 0, encrypt); err == nil {
		t.Fatal("xtsSectors accepted a zero sector size")
	}
}

func TestEncryptAndDecryptKeyMaterialEnclaveRoundTrip(t *testing.T) {
	key := enclaveFrom(t, mustRandom(t, 64))

	plaintext := mustRandom(t, 2048)
	held := enclaveFrom(t, plaintext)

	ciphertext, err := Default().EncryptEnclave(testCustody, held, key)
	if err != nil {
		t.Fatalf("EncryptEnclave failed: %v", err)
	}
	defer clear(ciphertext)

	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("the ciphertext equals the plaintext")
	}

	recovered, err := (Transform{mode: modeXTS}).DecryptEnclave(testCustody, ciphertext, key)
	if err != nil {
		t.Fatalf("DecryptEnclave failed: %v", err)
	}
	defer mustDestroy(t, recovered)

	// The plaintext comes back INSIDE an enclave -- it is the AF-split master
	// key on a real volume, so it must never be produced as a slice.
	if ok, err := recovered.EqualTo(plaintext); err != nil || !ok {
		t.Fatal("the enclave round trip did not recover the key material")
	}
}

func TestDecryptKeyMaterialEnclaveReleasesOnFailure(t *testing.T) {
	key := enclaveFrom(t, mustRandom(t, 64))

	if _, err := (Transform{mode: modeXTS}).DecryptEnclave(testCustody, nil, key); err == nil {
		t.Fatal("DecryptEnclave accepted empty ciphertext")
	}

	before := lockedKiB(t)

	// A key the transform cannot take -- 64 bytes for AES-CBC -- fails AFTER
	// the destination enclave has been allocated, which is exactly the path on
	// which a missed Destroy would leak locked pages that nobody holds a
	// handle to any more.
	for i := 0; i < 32; i++ {
		if _, err := (Transform{mode: modeCBC, iv: ivESSIVSHA256}).DecryptEnclave(testCustody, make([]byte, 64<<10), key); err == nil {
			t.Fatal("DecryptEnclave accepted a key its transform cannot take")
		}
	}

	if after := lockedKiB(t); after > before+lockedSlackKiB {
		t.Fatalf("locked memory grew from %d KiB to %d KiB across 32 failed decryptions", before, after)
	}
}

// TestParseAcceptsExactlyTheSpecsCryptsetupWrites pins the transform each
// accepted spec runs, that Specs names every one of them, and that Default is
// the one WriteSpec names.
func TestParseAcceptsExactlyTheSpecsCryptsetupWrites(t *testing.T) {
	accepted := map[string]Transform{
		"aes-xts-plain64":      {mode: modeXTS, iv: ivPlain64},
		"aes-xts-plain":        {mode: modeXTS, iv: ivPlain},
		"aes-cbc-essiv:sha256": {mode: modeCBC, iv: ivESSIVSHA256},
		"aes-cbc-plain64":      {mode: modeCBC, iv: ivPlain64},
		"aes-cbc-plain":        {mode: modeCBC, iv: ivPlain},
	}
	for spec, want := range accepted {
		got, ok := Parse(spec)
		if !ok || got != want {
			t.Errorf("Parse(%q) = %+v, %v; want %+v", spec, got, ok, want)
		}
		if !strings.Contains(Specs(), spec) {
			t.Errorf("Specs() = %q does not name %q", Specs(), spec)
		}
		if got.XTS() != (want.mode == modeXTS) {
			t.Errorf("Parse(%q).XTS() = %v", spec, got.XTS())
		}
	}
	for _, spec := range []string{"", "aes", "aes-xts", "AES-XTS-PLAIN64", "serpent-xts-plain64", "aes-xts-essiv:sha256"} {
		if got, ok := Parse(spec); ok {
			t.Errorf("Parse(%q) accepted as %+v", spec, got)
		}
	}
	if Default() != accepted[WriteSpec] {
		t.Fatalf("Default() = %+v, not the transform WriteSpec names", Default())
	}
}

// TestEncryptEnclaveRefusesAKeyTheTransformCannotTake: the write path fails
// rather than writing material under a key its cipher refuses.
func TestEncryptEnclaveRefusesAKeyTheTransformCannotTake(t *testing.T) {
	data := enclaveFrom(t, mustRandom(t, 1024))
	if out, err := Default().EncryptEnclave(testCustody, data, enclaveFrom(t, mustRandom(t, 40))); err == nil {
		t.Fatalf("EncryptEnclave with a 40-byte XTS key returned %d bytes", len(out))
	}
}

// TestKeyslotAreaRoundTripAES192CBCVolumeKey reproduces the exact on-disk
// shape the pkg/luks2 write and unlock paths build around EncryptEnclave and
// DecryptEnclave: EncryptEnclave sized by the AF-split length alone,
// writeArea's zero padding out to the keyslot area's 4096-byte alignment,
// and DecryptEnclave fed exactly plan.decryptLen bytes (the AF-split length
// rounded up to a whole sector).
//
// A cryptsetup AES-192-CBC volume's master key is 24 bytes; 4000 AF stripes
// puts the split at 96000 bytes, 256 bytes short of a whole sector --
// WritableAreaKeySize(24) falls back to a 64-byte AES-256-XTS area key, so
// this exercises xtsPartialSector on the write side, not cbcSectors.
func TestKeyslotAreaRoundTripAES192CBCVolumeKey(t *testing.T) {
	const afSplitSize = 24 * 4000 // 96000: a cryptsetup AES-192-CBC master key, AF-split over 4000 stripes
	const keyslotAreaAlignment = 4096

	areaKey := enclaveFrom(t, mustRandom(t, 64))
	afData := mustRandom(t, afSplitSize)
	held := enclaveFrom(t, afData)

	ciphertext, err := Default().EncryptEnclave(testCustody, held, areaKey)
	if err != nil {
		t.Fatalf("EncryptEnclave failed: %v", err)
	}
	defer clear(ciphertext)
	t.Logf("EncryptEnclave produced %d ciphertext bytes for %d plaintext bytes", len(ciphertext), afSplitSize)

	// screenKeyslot/recoverKeyslotKey (pkg/luks2): decryptLen is the AF-split
	// length rounded UP to a whole sector, never the raw AF-split length --
	// so the unlock path always asks for a whole number of sectors' worth of
	// ciphertext. cryptsetup writes exactly that many ciphertext bytes (the
	// final sector's padding is encrypted, not left off the device); a
	// ciphertext shorter than decryptLen means the bytes beyond it are
	// on-disk zero padding (writeArea) standing in for real ciphertext, which
	// is not what cryptsetup would have written for the same AF split.
	decryptLen := ((afSplitSize + SectorSize - 1) / SectorSize) * SectorSize
	if len(ciphertext) != decryptLen {
		t.Fatalf("EncryptEnclave produced %d ciphertext bytes, want %d (afSplitSize rounded up to a whole %d-byte sector, as cryptsetup writes it)",
			len(ciphertext), decryptLen, SectorSize)
	}

	// writeArea (pkg/luks2/keyslotdevice.go): write the ciphertext, then
	// zero-pad out to the area's 4096-byte alignment.
	alignedSize := ((len(ciphertext) + keyslotAreaAlignment - 1) / keyslotAreaAlignment) * keyslotAreaAlignment
	onDisk := make([]byte, alignedSize)
	copy(onDisk, ciphertext)

	if decryptLen > len(onDisk) {
		t.Fatalf("decryptLen %d exceeds the written area of %d bytes", decryptLen, len(onDisk))
	}

	decrypted, err := Default().DecryptEnclave(testCustody, onDisk[:decryptLen], areaKey)
	if err != nil {
		t.Fatalf("DecryptEnclave failed: %v", err)
	}
	defer mustDestroy(t, decrypted)

	if decrypted.Size() < afSplitSize {
		t.Fatalf("decrypted material is %d bytes, need at least %d", decrypted.Size(), afSplitSize)
	}

	err = secret.Borrow("decrypted keyslot material", decrypted, func(got []byte) error {
		if !bytes.Equal(got[:afSplitSize], afData) {
			t.Fatal("AF-split material did not round trip through the keyslot area write/read shape")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("borrowing the decrypted material failed: %v", err)
	}
}
