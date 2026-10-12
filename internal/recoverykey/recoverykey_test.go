// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package recoverykey

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// testCustody is the production custody.
var testCustody = secret.System()

// enclaveFrom returns an enclave holding a COPY of b, destroyed when the test
// ends.
func enclaveFrom(t *testing.T, b []byte) *enclave.Memory {
	t.Helper()
	e, err := enclave.NewMemoryCopy(b)
	if err != nil {
		t.Fatalf("could not allocate a test enclave: %v", err)
	}
	t.Cleanup(func() { mustDestroy(t, e) })
	return e
}

// mustDestroy destroys e and fails the test if the release is reported.
func mustDestroy(tb testing.TB, e *enclave.Memory) {
	tb.Helper()
	if err := e.Destroy(); err != nil {
		tb.Errorf("releasing a test enclave was reported: %v", err)
	}
}

// openSecret copies the material out of an enclave so a test can assert on it.
func openSecret(t *testing.T, e *enclave.Memory) []byte {
	t.Helper()
	var out []byte
	if err := e.WithBytes(func(b []byte) error {
		out = append([]byte(nil), b...)
		return nil
	}); err != nil {
		t.Fatalf("could not read a test enclave: %v", err)
	}
	return out
}

// refusing is a custody every constructor of which refuses.
func refusing() secret.Custody {
	return secret.Admitted(func() (*enclave.Allocator, error) { return nil, errors.New("no locked memory") })
}

// TestFormatDashedKey pins the dashed rendering byte for byte.
//
// It matters more than it looks: the rendering is now built IN PLACE inside
// locked memory, by encoding the hex right-aligned in the destination and
// expanding it leftward around the separators, rather than by joining strings.
// These fixtures are what stands between that rewrite and a recovery key that
// prints differently from the one that was stored.
func TestFormatDashedKey(t *testing.T) {
	tests := []struct {
		name     string
		key      []byte
		expected string
	}{
		{
			name:     "simple 6 bytes",
			key:      []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			expected: "010203-040506",
		},
		{
			name:     "12 bytes",
			key:      []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
			expected: "AABBCC-DDEEFF-112233-445566",
		},
		{
			name:     "uneven bytes",
			key:      []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			expected: "010203-0405",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dst := make([]byte, Len(len(tt.key), Dashed))
			renderInto(dst, tt.key, Dashed)

			if result := string(dst); result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestDecodeHex(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  []byte
		expectErr bool
	}{
		{
			name:     "lowercase hex",
			input:    "aabbccdd",
			expected: []byte{0xAA, 0xBB, 0xCC, 0xDD},
		},
		{
			name:     "uppercase hex",
			input:    "AABBCCDD",
			expected: []byte{0xAA, 0xBB, 0xCC, 0xDD},
		},
		{
			name:     "with whitespace",
			input:    "  aabbccdd  ",
			expected: []byte{0xAA, 0xBB, 0xCC, 0xDD},
		},
		{
			name:      "invalid hex chars",
			input:     "gghhii",
			expectErr: true,
		},
		{
			name:      "odd length",
			input:     "aabbc",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// decodeHex takes bytes and expects them already trimmed and
			// lower-cased -- the caller normalises in place inside locked
			// memory rather than through strings.TrimSpace/ToLower, which each
			// yield an unwipeable copy of the credential. The test does the
			// same normalisation the parser does.
			normalized := []byte(tt.input)
			normalized = trimASCIISpace(normalized)
			lowerASCII(normalized)

			result, err := decodeHex(testCustody, normalized)

			if tt.expectErr {
				if err == nil {
					mustDestroy(t, result)
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			defer mustDestroy(t, result)

			// The decode writes straight into locked memory, so what is
			// asserted on here is a test-only copy taken back out of it.
			if got := openSecret(t, result); hex.EncodeToString(got) != hex.EncodeToString(tt.expected) {
				t.Errorf("expected %x, got %x", tt.expected, got)
			}
		})
	}
}

// TestRenderWritesEachFormatAndDecodeReadsItBack: every rendering of the same
// bytes has the length Len promises, matches the stdlib encoding, hashes to
// the SHA-256 of its text, and decodes back to the bytes.
func TestRenderWritesEachFormatAndDecodeReadsItBack(t *testing.T) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	key := enclaveFrom(t, raw)
	for _, tc := range []struct {
		name   string
		format Format
		want   string
	}{
		{"hex", Hex, hex.EncodeToString(raw)},
		{"base64", Base64, base64.StdEncoding.EncodeToString(raw)},
		{"dashed", Dashed, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			credential, err := Render(testCustody, key, tc.format)
			if err != nil {
				t.Fatal(err)
			}
			defer mustDestroy(t, credential)
			text := openSecret(t, credential)
			if len(text) != Len(len(raw), tc.format) {
				t.Fatalf("rendering is %d bytes, Len says %d", len(text), Len(len(raw), tc.format))
			}
			if tc.want != "" && string(text) != tc.want {
				t.Fatalf("rendering %q, want %q", text, tc.want)
			}
			sum := sha256.Sum256(text)
			if got, err := Hash(credential); err != nil || got != hex.EncodeToString(sum[:]) {
				t.Fatalf("Hash = %q, %v; want the SHA-256 of the text", got, err)
			}
			back, err := Decode(testCustody, credential)
			if err != nil {
				t.Fatal(err)
			}
			defer mustDestroy(t, back)
			if !bytes.Equal(openSecret(t, back), raw) {
				t.Fatal("decoding the rendering does not give the bytes back")
			}
		})
	}
	if Len(0, Dashed) != 0 {
		t.Fatalf("Len(0, Dashed) = %d", Len(0, Dashed))
	}
}

// TestDecodeIsTolerantOfCaseAndSeparators: a rendering is decoded, not
// reproduced, so case, dashes and surrounding whitespace do not matter.
func TestDecodeIsTolerantOfCaseAndSeparators(t *testing.T) {
	want := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	for _, in := range []string{"aabbcc-ddeeff", "AABBCC-DDEEFF", "  aabbccddeeff\n", "AABBCCDDEEFF", base64.StdEncoding.EncodeToString(want)} {
		got, err := Decode(testCustody, enclaveFrom(t, []byte(in)))
		if err != nil {
			t.Errorf("Decode(%q) = %v", in, err)
			continue
		}
		if !bytes.Equal(openSecret(t, got), want) {
			t.Errorf("Decode(%q) = %x, want %x", in, openSecret(t, got), want)
		}
		mustDestroy(t, got)
	}
	for _, in := range []string{"   ", "zz-zz", "aabbc", "!!!!"} {
		if got, err := Decode(testCustody, enclaveFrom(t, []byte(in))); err == nil {
			mustDestroy(t, got)
			t.Errorf("Decode(%q) succeeded", in)
		}
	}
}

// TestCredentialTrimsAndNothingElse: the credential is the text, so only the
// whitespace a paste adds is removed; an empty or multi-line text is refused.
func TestCredentialTrimsAndNothingElse(t *testing.T) {
	got, err := Credential(testCustody, enclaveFrom(t, []byte("  9F3a2C-4b81DE \r\n")))
	if err != nil {
		t.Fatal(err)
	}
	defer mustDestroy(t, got)
	if string(openSecret(t, got)) != "9F3a2C-4b81DE" {
		t.Fatalf("credential %q", openSecret(t, got))
	}
	for _, in := range []string{" \t\n", "first\nsecond"} {
		if c, err := Credential(testCustody, enclaveFrom(t, []byte(in))); err == nil {
			mustDestroy(t, c)
			t.Errorf("Credential(%q) succeeded", in)
		}
	}
}

// TestFirstLineSkipsBlankLinesAndComments: the line is located in place.
func TestFirstLineSkipsBlankLinesAndComments(t *testing.T) {
	contents := []byte("# LUKS recovery key\n\n   \n  KEY-LINE  \nsecond\n")
	line := FirstLine(contents)
	if string(line) != "KEY-LINE" {
		t.Fatalf("FirstLine = %q", line)
	}
	if &line[0] != &contents[bytes.Index(contents, []byte("KEY-LINE"))] {
		t.Fatal("FirstLine copied the line instead of returning a sub-slice")
	}
	if FirstLine([]byte("# only a comment\n\n")) != nil || FirstLine([]byte("last-line-no-newline")) == nil {
		t.Fatal("FirstLine mishandled a file with no key, or one with no trailing newline")
	}
}

// TestEveryStepFailsClosed: with no locked memory, nothing is rendered,
// trimmed or decoded onto the heap instead.
func TestEveryStepFailsClosed(t *testing.T) {
	c := refusing()
	key := enclaveFrom(t, make([]byte, 32))
	if _, err := Render(c, key, Dashed); !errors.Is(err, secret.ErrProtectedMemory) {
		t.Errorf("Render = %v", err)
	}
	if _, err := Credential(c, enclaveFrom(t, []byte("text"))); !errors.Is(err, secret.ErrProtectedMemory) {
		t.Errorf("Credential = %v", err)
	}
	for _, in := range []string{"aabb-ccdd", "aabbccdd", "qrst"} {
		if _, err := Decode(c, enclaveFrom(t, []byte(in))); !errors.Is(err, secret.ErrProtectedMemory) {
			t.Errorf("Decode(%q) = %v", in, err)
		}
	}
	dead := enclaveFrom(t, []byte("x"))
	mustDestroy(t, dead)
	if _, err := Hash(dead); !errors.Is(err, secret.ErrProtectedMemory) {
		t.Errorf("Hash of a destroyed credential = %v", err)
	}
}
